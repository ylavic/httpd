// Load generator: C clients with kept-alive connections (or a new connection
// per request with -k=false), each sending GETs in a loop for D seconds
// (closed loop), or requests sent at a fixed rate R/s (open loop, -rate),
// the latency then measured from each request's scheduled time; reports
// requests/s, errors, latency percentiles.
package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"time"
)

func main() {
	url := flag.String("url", "http://127.0.0.1:18500/b?d=0", "URL")
	conc := flag.Int("c", 64, "concurrent clients (closed loop)")
	rate := flag.Float64("rate", 0, "requests per second (open loop), 0 for closed loop")
	dur := flag.Duration("d", 10*time.Second, "duration")
	warm := flag.Duration("w", 2*time.Second, "warm-up (not measured)")
	keepalive := flag.Bool("k", true, "keep connections alive")
	label := flag.String("label", "", "label printed first")
	flag.Parse()

	conns := *conc
	if *rate > 0 {
		conns = 0 // unlimited
	}
	tr := &http.Transport{MaxIdleConnsPerHost: *conc, MaxConnsPerHost: conns,
		DisableCompression: true, DisableKeepAlives: !*keepalive}
	client := &http.Client{Transport: tr, Timeout: 30 * time.Second}

	var mu sync.Mutex
	var lats []time.Duration
	errs := 0
	start := time.Now()
	measureFrom := start.Add(*warm)
	end := measureFrom.Add(*dur)

	one := func(scheduled time.Time) {
		resp, err := client.Get(*url)
		ok := err == nil
		if ok {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			ok = resp.StatusCode == 200
		}
		if scheduled.After(measureFrom) && scheduled.Before(end) {
			mu.Lock()
			if ok {
				lats = append(lats, time.Since(scheduled))
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
	fmt.Printf("rps %.0f errors %d p50 %.2fms p99 %.2fms max %.2fms n %d\n",
		float64(len(lats))/dur.Seconds(), errs, pct(0.5), pct(0.99), pct(1), len(lats))
}
