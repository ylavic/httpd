// Tunnel load generator: C tunnels (HTTP/1.1 "Upgrade: echo", answered by
// the bench backend through httpd), each sending a message of S bytes every
// I and reading its echo, for D seconds after a warm-up W (the tunnels are
// all established first); reports the messages/s, errors, latency percentiles
// of the echoes and their count, in loadgen's format.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:18500", "httpd address")
	path := flag.String("path", "/t", "path proxied to the backend's echo")
	conc := flag.Int("c", 1000, "tunnels")
	interval := flag.Duration("i", time.Second, "interval between messages per tunnel")
	size := flag.Int("s", 64, "message size")
	dur := flag.Duration("d", 10*time.Second, "measured duration")
	warm := flag.Duration("w", 2*time.Second, "warm-up (not measured)")
	label := flag.String("label", "", "label printed first")
	flag.Parse()

	var mu sync.Mutex
	var lats []time.Duration
	errs, up := 0, 0
	fail := func(err error) {
		mu.Lock()
		if errs < 3 {
			fmt.Fprintln(os.Stderr, "tunnelgen:", err)
		}
		errs++
		mu.Unlock()
	}

	// Establish all the tunnels first (at most 64 handshakes at once)
	conns := make([]net.Conn, *conc)
	readers := make([]*bufio.Reader, *conc)
	sem := make(chan struct{}, 64)
	var wg sync.WaitGroup
	for i := 0; i < *conc; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			c, err := net.DialTimeout("tcp", *addr, 10*time.Second)
			if err != nil {
				fail(err)
				return
			}
			c.SetDeadline(time.Now().Add(10 * time.Second))
			fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: localhost\r\n"+
				"Upgrade: echo\r\nConnection: Upgrade\r\n\r\n", *path)
			br := bufio.NewReader(c)
			status, err := br.ReadString('\n')
			if err == nil && !strings.Contains(status, " 101 ") {
				err = fmt.Errorf("upgrade refused: %s", strings.TrimSpace(status))
			}
			for err == nil {
				var line string
				line, err = br.ReadString('\n')
				if line == "\r\n" {
					break
				}
			}
			if err != nil {
				fail(err)
				c.Close()
				return
			}
			c.SetDeadline(time.Time{})
			conns[i], readers[i] = c, br
			mu.Lock()
			up++
			mu.Unlock()
		}(i)
	}
	wg.Wait()

	start := time.Now()
	measureFrom := start.Add(*warm)
	end := measureFrom.Add(*dur)
	msg := make([]byte, *size)
	for i := range msg {
		msg[i] = 'm'
	}
	for i := 0; i < *conc; i++ {
		if conns[i] == nil {
			continue
		}
		wg.Add(1)
		go func(c net.Conn, br *bufio.Reader) {
			defer wg.Done()
			defer c.Close()
			buf := make([]byte, len(msg))
			// Spread the tunnels over the interval
			next := start.Add(time.Duration(rand.Int63n(int64(*interval))))
			// Stop at the end, also when the messages fall behind the
			// interval (a closed loop with a tiny -i)
			for next.Before(end) && time.Now().Before(end) {
				time.Sleep(time.Until(next))
				t0 := time.Now()
				c.SetDeadline(t0.Add(10 * time.Second))
				if _, err := c.Write(msg); err != nil {
					fail(err)
					return
				}
				if _, err := io.ReadFull(br, buf); err != nil {
					fail(err)
					return
				}
				if t0.After(measureFrom) && t0.Before(end) {
					mu.Lock()
					lats = append(lats, time.Since(t0))
					mu.Unlock()
				}
				next = next.Add(*interval)
			}
			// Close all the tunnels at the end, not after their last message
			time.Sleep(time.Until(end))
		}(conns[i], readers[i])
	}
	wg.Wait()

	sort.Slice(lats, func(a, b int) bool { return lats[a] < lats[b] })
	pct := func(p float64) float64 {
		if len(lats) == 0 {
			return 0
		}
		i := int(p * float64(len(lats)-1))
		return float64(lats[i].Microseconds()) / 1000
	}
	if *label != "" {
		fmt.Printf("%s ", *label)
	}
	fmt.Printf("tunnels %d mps %.0f errors %d p50 %.2fms p99 %.2fms max %.2fms n %d\n",
		up, float64(len(lats))/dur.Seconds(), errs, pct(0.5), pct(0.99), pct(1), len(lats))
}
