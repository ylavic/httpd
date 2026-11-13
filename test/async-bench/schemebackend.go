// Minimal AJP13, SCGI and uwsgi backends for the async checks: one request
// per connection (AJP keeps its connections), whose query string says what
// to do: d=MS sleeps MS milliseconds before answering, s=BYTES answers BYTES
// (512 by default), close=0 closes the connection without answering after
// the delay, proto=P (uwsgi) answers with the protocol P in its status line
// (HTTP/1.1 by default). A request body is read (and its length answered in
// X-Body).
package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type reply struct {
	delay   time.Duration
	size    int
	close   bool
	bodyLen int
	proto   string
}

func parseQuery(qs string, bodyLen int) reply {
	q, _ := url.ParseQuery(qs)
	rp := reply{size: 512, bodyLen: bodyLen, proto: "HTTP/1.1"}
	if p := q.Get("proto"); p != "" {
		rp.proto = p
	}
	if ms, err := strconv.Atoi(q.Get("d")); err == nil && ms > 0 {
		rp.delay = time.Duration(ms) * time.Millisecond
	}
	if n, err := strconv.Atoi(q.Get("s")); err == nil && n >= 0 {
		rp.size = n
	}
	rp.close = q.Get("close") == "0"
	return rp
}

func body(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'x'
	}
	return b
}

func listen(addr string, serve func(net.Conn)) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				log.Fatal(err)
			}
			go serve(c)
		}
	}()
}

// SCGI: a netstring of NUL separated headers, then CONTENT_LENGTH bytes;
// the response is CGI-like (Status: header).
func serveSCGI(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	lenStr, err := br.ReadString(':')
	if err != nil {
		return
	}
	n, err := strconv.Atoi(strings.TrimSuffix(lenStr, ":"))
	if err != nil {
		return
	}
	hdrs := make([]byte, n+1) // with the netstring's ','
	if _, err := io.ReadFull(br, hdrs); err != nil {
		return
	}
	env := map[string]string{}
	f := strings.Split(string(hdrs[:n]), "\x00")
	for i := 0; i+1 < len(f); i += 2 {
		env[f[i]] = f[i+1]
	}
	cl, _ := strconv.Atoi(env["CONTENT_LENGTH"])
	io.CopyN(io.Discard, br, int64(cl))
	rp := parseQuery(env["QUERY_STRING"], cl)
	time.Sleep(rp.delay)
	if rp.close {
		return
	}
	fmt.Fprintf(c, "Status: 200 OK\r\nContent-Type: text/plain\r\nX-Body: %d\r\n\r\n", rp.bodyLen)
	c.Write(body(rp.size))
}

// uwsgi: a 4-byte header (modifier1, little-endian vars size, modifier2),
// the vars (le16 sized keys and values), then the body; the response is
// HTTP.
func serveUWSGI(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	var h [4]byte
	if _, err := io.ReadFull(br, h[:]); err != nil {
		return
	}
	vars := make([]byte, binary.LittleEndian.Uint16(h[1:3]))
	if _, err := io.ReadFull(br, vars); err != nil {
		return
	}
	env := map[string]string{}
	for len(vars) >= 2 {
		kl := int(binary.LittleEndian.Uint16(vars))
		if len(vars) < 2+kl+2 {
			break
		}
		k := string(vars[2 : 2+kl])
		vars = vars[2+kl:]
		vl := int(binary.LittleEndian.Uint16(vars))
		if len(vars) < 2+vl {
			break
		}
		env[k] = string(vars[2 : 2+vl])
		vars = vars[2+vl:]
	}
	cl, _ := strconv.Atoi(env["CONTENT_LENGTH"])
	io.CopyN(io.Discard, br, int64(cl))
	rp := parseQuery(env["QUERY_STRING"], cl)
	time.Sleep(rp.delay)
	if rp.close {
		return
	}
	fmt.Fprintf(c, "%s 200 OK\r\nContent-Type: text/plain\r\nX-Body: %d\r\n\r\n", rp.proto, rp.bodyLen)
	c.Write(body(rp.size))
}

// AJP13: packets 0x1234 + le16... (big-endian) size from the server, "AB" +
// size to it. The forward request (prefix 2) carries the query string in
// its attributes (0x05); its body follows in data packets (2-byte length
// prefixed), the first sent unasked, the next ones asked with
// GET_BODY_CHUNK (6).
type ajpReader struct {
	b []byte
}

func (r *ajpReader) u8() byte {
	if len(r.b) < 1 {
		return 0xFF
	}
	v := r.b[0]
	r.b = r.b[1:]
	return v
}

func (r *ajpReader) u16() int {
	if len(r.b) < 2 {
		return 0
	}
	v := int(binary.BigEndian.Uint16(r.b))
	r.b = r.b[2:]
	return v
}

func (r *ajpReader) str() string {
	n := r.u16()
	if n == 0xFFFF || len(r.b) < n+1 {
		return ""
	}
	s := string(r.b[:n])
	r.b = r.b[n+1:]
	return s
}

func ajpRead(br *bufio.Reader) ([]byte, error) {
	var h [4]byte
	if _, err := io.ReadFull(br, h[:]); err != nil {
		return nil, err
	}
	p := make([]byte, binary.BigEndian.Uint16(h[2:]))
	_, err := io.ReadFull(br, p)
	return p, err
}

func ajpWrite(c net.Conn, payload []byte) error {
	h := []byte{'A', 'B', 0, 0}
	binary.BigEndian.PutUint16(h[2:], uint16(len(payload)))
	_, err := c.Write(append(h, payload...))
	return err
}

func ajpStr(s string) []byte {
	b := []byte{0, 0}
	binary.BigEndian.PutUint16(b, uint16(len(s)))
	return append(append(b, s...), 0)
}

func serveAJP(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	for {
		p, err := ajpRead(br)
		if err != nil {
			return
		}
		if len(p) == 1 && p[0] == 10 { // CPING
			ajpWrite(c, []byte{9}) // CPONG
			continue
		}
		if len(p) == 0 || p[0] != 2 {
			return
		}
		r := &ajpReader{b: p[1:]}
		r.u8()  // method
		r.str() // protocol
		r.str() // req_uri
		r.str() // remote_addr
		r.str() // remote_host
		r.str() // server_name
		r.u16() // port
		r.u8()  // is_ssl
		cl := 0
		for n := r.u16(); n > 0; n-- {
			var name string
			if len(r.b) >= 2 && r.b[0] == 0xA0 {
				code := r.u16()
				if code == 0xA008 {
					name = "content-length"
				}
			} else {
				name = strings.ToLower(r.str())
			}
			v := r.str()
			if name == "content-length" {
				cl, _ = strconv.Atoi(v)
			}
		}
		qs := ""
		for {
			code := r.u8()
			if code == 0xFF {
				break
			}
			if code == 0x0A { // req_attribute: name and value
				r.str()
				r.str()
				continue
			}
			if code == 0x0B { // ssl_key_size: an integer
				r.u16()
				continue
			}
			v := r.str()
			if code == 0x05 {
				qs = v
			}
		}
		for got := 0; got < cl; {
			if got > 0 {
				ajpWrite(c, []byte{6, 0x1F, 0xF0}) // GET_BODY_CHUNK 8176
			}
			d, err := ajpRead(br)
			if err != nil || len(d) < 2 {
				return
			}
			n := int(binary.BigEndian.Uint16(d))
			if n == 0 {
				break
			}
			got += n
		}
		rp := parseQuery(qs, cl)
		time.Sleep(rp.delay)
		if rp.close {
			return
		}
		hdr := []byte{4, 0, 200}
		hdr = append(hdr, ajpStr("OK")...)
		hdr = append(hdr, 0, 2)
		hdr = append(hdr, 0xA0, 0x01) // Content-Type
		hdr = append(hdr, ajpStr("text/plain")...)
		hdr = append(hdr, ajpStr("X-Body")...)
		hdr = append(hdr, ajpStr(strconv.Itoa(rp.bodyLen))...)
		ajpWrite(c, hdr)
		b := body(rp.size)
		for len(b) > 0 {
			n := len(b)
			if n > 8000 {
				n = 8000
			}
			chunk := []byte{3, byte(n >> 8), byte(n)}
			chunk = append(append(chunk, b[:n]...), 0)
			if ajpWrite(c, chunk) != nil {
				return
			}
			b = b[n:]
		}
		ajpWrite(c, []byte{5, 1}) // END_RESPONSE, reuse
	}
}

func main() {
	ajp := flag.String("ajp", "", "AJP13 listen address")
	scgi := flag.String("scgi", "", "SCGI listen address")
	uwsgi := flag.String("uwsgi", "", "uwsgi listen address")
	flag.Parse()
	if *ajp != "" {
		listen(*ajp, serveAJP)
	}
	if *scgi != "" {
		listen(*scgi, serveSCGI)
	}
	if *uwsgi != "" {
		listen(*uwsgi, serveUWSGI)
	}
	select {}
}
