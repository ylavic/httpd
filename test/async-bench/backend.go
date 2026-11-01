// Benchmark backend: GET /?d=MS[&st=STATUS] sleeps MS milliseconds, answers
// 512 bytes (with STATUS, 200 by default).
// A request with "Upgrade: echo" gets a 101 and then its bytes echoed back
// (the tunnels of tunnelgen). GET /?s=BYTES[&c=CHUNK][&i=US] answers BYTES
// written CHUNK bytes at a time (64KB by default), each flushed, with US
// microseconds between them; a POST has its body read, then gets 512 bytes
// (the large bodies of bodybench).
package main

import (
	"flag"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:18501", "listen address")
	flag.Parse()
	body := make([]byte, 512)
	for i := range body {
		body[i] = 'x'
	}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.EqualFold(r.Header.Get("Upgrade"), "echo") {
			conn, rw, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\n" +
				"Upgrade: echo\r\nConnection: Upgrade\r\n\r\n"))
			io.Copy(conn, rw.Reader)
			return
		}
		if r.Method == http.MethodPost {
			io.Copy(io.Discard, r.Body)
			w.Header().Set("Content-Length", "512")
			w.Write(body)
			return
		}
		if size, err := strconv.ParseInt(r.URL.Query().Get("s"), 10, 64); err == nil && size > 0 {
			chunk := 65536
			if c, err := strconv.Atoi(r.URL.Query().Get("c")); err == nil && c > 0 {
				chunk = c
			}
			pause := 0
			if i, err := strconv.Atoi(r.URL.Query().Get("i")); err == nil && i > 0 {
				pause = i
			}
			buf := make([]byte, chunk)
			for i := range buf {
				buf[i] = 'x'
			}
			w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
			flusher, _ := w.(http.Flusher)
			for left := size; left > 0; {
				n := int64(chunk)
				if n > left {
					n = left
				}
				if _, err := w.Write(buf[:n]); err != nil {
					return
				}
				if flusher != nil {
					flusher.Flush()
				}
				left -= n
				if pause > 0 && left > 0 {
					time.Sleep(time.Duration(pause) * time.Microsecond)
				}
			}
			return
		}
		if d, err := strconv.Atoi(r.URL.Query().Get("d")); err == nil && d > 0 {
			time.Sleep(time.Duration(d) * time.Millisecond)
		}
		w.Header().Set("Content-Length", "512")
		if st, err := strconv.Atoi(r.URL.Query().Get("st")); err == nil && st >= 200 {
			w.WriteHeader(st)
		}
		w.Write(body)
	})
	srv := &http.Server{Addr: *addr}
	srv.ListenAndServe()
}
