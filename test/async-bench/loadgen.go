// Load generator: C clients with kept-alive connections (or a new connection
// per request with -k=false), each sending GETs in a loop for D seconds
// (closed loop), or requests sent at a fixed rate R/s (open loop, -rate),
// the latency then measured from each request's scheduled time; reports
// requests/s, errors, latency percentiles. With -upload, POSTs a body of that
// size written -wchunk bytes at a time every -wdelay; with -rchunk, reads the
// response -rchunk bytes at a time every -rdelay (a slow reader); either also
// reports the body bytes/s (both ways). -rcvbuf sets the receive buffer of the
// connections (fixed, no autotuning), for a reader really slower than httpd.
package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"sync"
	"syscall"
	"time"
)

// An upload body of left bytes, read chunk bytes at a time every delay
type pacedReader struct {
	left    int64
	chunk   int
	delay   time.Duration
	started bool
}

func (p *pacedReader) Read(b []byte) (int, error) {
	if p.left <= 0 {
		return 0, io.EOF
	}
	if p.started && p.delay > 0 {
		time.Sleep(p.delay)
	}
	p.started = true
	n := len(b)
	if n > p.chunk {
		n = p.chunk
	}
	if int64(n) > p.left {
		n = int(p.left)
	}
	for i := range b[:n] {
		b[i] = 'u'
	}
	p.left -= int64(n)
	return n, nil
}

func main() {
	url := flag.String("url", "http://127.0.0.1:18500/b?d=0", "URL")
	conc := flag.Int("c", 64, "concurrent clients (closed loop)")
	rate := flag.Float64("rate", 0, "requests per second (open loop), 0 for closed loop")
	dur := flag.Duration("d", 10*time.Second, "duration")
	warm := flag.Duration("w", 2*time.Second, "warm-up (not measured)")
	keepalive := flag.Bool("k", true, "keep connections alive")
	label := flag.String("label", "", "label printed first")
	upload := flag.Int64("upload", 0, "POST a body of this many bytes")
	wchunk := flag.Int("wchunk", 65536, "upload chunk size")
	wdelay := flag.Duration("wdelay", 0, "delay between upload chunks")
	rchunk := flag.Int("rchunk", 0, "read the response this many bytes at a time")
	rdelay := flag.Duration("rdelay", 0, "delay between response reads")
	rcvbuf := flag.Int("rcvbuf", 0, "receive buffer of the connections (0: the system's)")
	flag.Parse()
	bodies := *upload > 0 || *rchunk > 0
	var nbytes int64 // body bytes of the measured requests

	conns := *conc
	if *rate > 0 {
		conns = 0 // unlimited
	}
	tr := &http.Transport{MaxIdleConnsPerHost: *conc, MaxConnsPerHost: conns,
		DisableCompression: true, DisableKeepAlives: !*keepalive}
	if *rcvbuf > 0 {
		// Before connecting, for the TCP window to be negotiated with it
		dialer := &net.Dialer{Timeout: 30 * time.Second,
			Control: func(network, address string, c syscall.RawConn) error {
				var serr error
				err := c.Control(func(fd uintptr) {
					serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET,
						syscall.SO_RCVBUF, *rcvbuf)
				})
				if err != nil {
					return err
				}
				return serr
			}}
		tr.DialContext = dialer.DialContext
	}
	client := &http.Client{Transport: tr, Timeout: 30 * time.Second}

	var mu sync.Mutex
	var lats []time.Duration
	errs := 0
	start := time.Now()
	measureFrom := start.Add(*warm)
	end := measureFrom.Add(*dur)

	one := func(scheduled time.Time) {
		var resp *http.Response
		var err error
		var n int64
		if *upload > 0 {
			var req *http.Request
			req, err = http.NewRequest(http.MethodPost, *url,
				&pacedReader{left: *upload, chunk: *wchunk, delay: *wdelay})
			if err == nil {
				req.ContentLength = *upload
				resp, err = client.Do(req)
			}
			n = *upload
		} else {
			resp, err = client.Get(*url)
		}
		ok := err == nil
		if ok {
			if *rchunk > 0 {
				buf := make([]byte, *rchunk)
				for {
					m, rerr := io.ReadFull(resp.Body, buf)
					n += int64(m)
					if rerr != nil {
						break
					}
					if *rdelay > 0 {
						time.Sleep(*rdelay)
					}
				}
			} else {
				m, _ := io.Copy(io.Discard, resp.Body)
				n += m
			}
			resp.Body.Close()
			ok = resp.StatusCode == 200
		}
		if scheduled.After(measureFrom) && scheduled.Before(end) {
			mu.Lock()
			if ok {
				lats = append(lats, time.Since(scheduled))
				nbytes += n
			} else {
				errs++
			}
			mu.Unlock()
		}
	}

	var wg sync.WaitGroup
	if *rate > 0 {
		interval := time.Duration(float64(time.Second) / *rate)
		for next := start; next.Before(end); next = next.Add(interval) {
			if d := time.Until(next); d > 0 {
				time.Sleep(d)
			}
			wg.Add(1)
			go func(scheduled time.Time) {
				defer wg.Done()
				one(scheduled)
			}(next)
		}
	} else {
		for i := 0; i < *conc; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					t0 := time.Now()
					if t0.After(end) {
						break
					}
					one(t0)
				}
			}()
		}
	}
	wg.Wait()

	sort.Slice(lats, func(a, b int) bool { return lats[a] < lats[b] })
	pct := func(p float64) float64 {
		if len(lats) == 0 {
			return 0
		}
		return float64(lats[int(float64(len(lats)-1)*p)].Microseconds()) / 1000
	}
	if *label != "" {
		fmt.Printf("%s ", *label)
	}
	fmt.Printf("rps %.0f errors %d p50 %.2fms p99 %.2fms max %.2fms n %d",
		float64(len(lats))/dur.Seconds(), errs, pct(0.5), pct(0.99), pct(1), len(lats))
	if bodies {
		fmt.Printf(" mbps %.1f", float64(nbytes)/dur.Seconds()/1e6)
	}
	fmt.Printf("\n")
}
