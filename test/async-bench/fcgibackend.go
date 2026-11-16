// FastCGI benchmark backend (net/http/fcgi): GET /?d=MS sleeps MS
// milliseconds, answers 512 bytes. GET /?s=BYTES[&c=CHUNK][&i=US] answers
// BYTES written CHUNK bytes at a time (64KB by default), each flushed, with
// US microseconds between them, after the delay if any; a POST has its body
// read, then gets 512 bytes after the delay.
//
// With -raw ADDR, a minimal responder of its own on ADDR misbehaves for the
// error checks: once the request is read, it sleeps d=MS then closes the
// connection without answering (close=0), or after a response head and a
// part of the body (close=1), never sending FCGI_END_REQUEST.
package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/fcgi"
	"net/url"
	"strconv"
	"time"
)

func delay(q url.Values) {
	if ms, err := strconv.Atoi(q.Get("d")); err == nil && ms > 0 {
		time.Sleep(time.Duration(ms) * time.Millisecond)
	}
}

func serve(w http.ResponseWriter, r *http.Request, body []byte) {
	q := r.URL.Query()
	if r.Method == http.MethodPost {
		io.Copy(io.Discard, r.Body)
		delay(q)
		w.Header().Set("Content-Type", "text/plain")
		w.Write(body)
		return
	}
	delay(q)
	size, err := strconv.ParseInt(q.Get("s"), 10, 64)
	if err != nil || size <= 0 {
		w.Header().Set("Content-Type", "text/plain")
		w.Write(body)
		return
	}
	chunk := 65536
	if c, err := strconv.Atoi(q.Get("c")); err == nil && c > 0 {
		chunk = c
	}
	pause := 0
	if i, err := strconv.Atoi(q.Get("i")); err == nil && i > 0 {
		pause = i
	}
	buf := make([]byte, chunk)
	for i := range buf {
		buf[i] = 'x'
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	flusher, _ := w.(http.Flusher)
	for left := size; left > 0; {
		n := int64(chunk)
		if n > left {
			n = left
		}
		if _, err := w.Write(buf[:n]); err != nil {
			return
		}
		left -= n
		if flusher != nil {
			flusher.Flush()
		}
		if pause > 0 && left > 0 {
			time.Sleep(time.Duration(pause) * time.Microsecond)
		}
	}
}

// FastCGI record types used by the raw responder
const (
	typeParams = 4
	typeStdin  = 5
	typeStdout = 6
)

func readRecord(br *bufio.Reader) (byte, []byte, error) {
	var h [8]byte
	if _, err := io.ReadFull(br, h[:]); err != nil {
		return 0, nil, err
	}
	clen := int(binary.BigEndian.Uint16(h[4:6]))
	plen := int(h[6])
	content := make([]byte, clen+plen)
	if _, err := io.ReadFull(br, content); err != nil {
		return 0, nil, err
	}
	return h[1], content[:clen], nil
}

func paramLen(b []byte) (int, []byte) {
	if len(b) == 0 {
		return 0, b
	}
	if b[0]&0x80 == 0 {
		return int(b[0]), b[1:]
	}
	if len(b) < 4 {
		return 0, nil
	}
	return int(binary.BigEndian.Uint32(b[:4]) & 0x7fffffff), b[4:]
}

func parseParams(b []byte) map[string]string {
	m := map[string]string{}
	for len(b) > 0 {
		var nl, vl int
		nl, b = paramLen(b)
		vl, b = paramLen(b)
		if b == nil || len(b) < nl+vl {
			break
		}
		m[string(b[:nl])] = string(b[nl : nl+vl])
		b = b[nl+vl:]
	}
	return m
}

func writeRecord(conn net.Conn, typ byte, content []byte) {
	h := []byte{1, typ, 0, 1, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(h[4:6], uint16(len(content)))
	conn.Write(append(h, content...))
}

func serveRaw(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	var params []byte
	for {
		typ, content, err := readRecord(br)
		if err != nil {
			return
		}
		if typ == typeParams {
			params = append(params, content...)
		}
		if typ == typeStdin && len(content) == 0 {
			break
		}
	}
	q, _ := url.ParseQuery(parseParams(params)["QUERY_STRING"])
	delay(q)
	if q.Get("close") == "1" {
		writeRecord(conn, typeStdout,
			[]byte("Content-Type: text/plain\r\n\r\npartial body"))
	}
}

func main() {
	addr := flag.String("addr", "127.0.0.1:18521", "listen address")
	raw := flag.String("raw", "", "listen address of the misbehaving responder")
	flag.Parse()
	body := make([]byte, 512)
	for i := range body {
		body[i] = 'x'
	}
	if *raw != "" {
		rl, err := net.Listen("tcp", *raw)
		if err != nil {
			log.Fatal(err)
		}
		go func() {
			for {
				conn, err := rl.Accept()
				if err != nil {
					log.Fatal(err)
				}
				go serveRaw(conn)
			}
		}()
	}
	l, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(fcgi.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serve(w, r, body)
	})))
}
