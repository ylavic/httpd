// Benchmark backend: GET /?d=MS sleeps MS milliseconds, answers 512 bytes.
// A request with "Upgrade: echo" gets a 101 and then its bytes echoed back
// (the tunnels of tunnelgen).
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
		if d, err := strconv.Atoi(r.URL.Query().Get("d")); err == nil && d > 0 {
			time.Sleep(time.Duration(d) * time.Millisecond)
		}
		w.Header().Set("Content-Length", "512")
		w.Write(body)
	})
	srv := &http.Server{Addr: *addr}
	srv.ListenAndServe()
}
