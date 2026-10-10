// Command loadgen is a load generator for DoH (RFC 8484 POST) endpoints:
// it drives a mixed A/AAAA/HTTPS query stream at a configurable concurrency
// and rate, then reports per-type latency percentiles, error counts and a
// slow-threshold tally (default 1137ms — the Chromium DNS task timeout
// observed in the field) so upstream tail behavior and rewrite-path costs
// can be attributed locally.
//
// Typical use against a local full stack (fake-upstream + cfdoh):
//
//	loadgen -target http://127.0.0.1:8787/dns-query \
//	        -mix A:2,AAAA:1,HTTPS:3 -concurrency 32 -duration 30s -unique
//
// -unique prefixes every query name with a random label, forcing cache
// misses; drop it to measure the hit path instead.
package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"math"
	mathrand "math/rand"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jnuse/cfdoh/internal/wire"
)

type sample struct {
	qtype  string
	dur    time.Duration
	status int        // HTTP status; 0 on transport error/timeout
	err    string     // non-empty on failure
	slow   bool       // duration exceeded the slow threshold
}

type mixEntry struct {
	qtype string
	t     uint16
}

func main() {
	target := flag.String("target", "", "DoH endpoint URL (required)")
	duration := flag.Duration("duration", 30*time.Second, "test duration")
	concurrency := flag.Int("concurrency", 8, "parallel workers")
	qps := flag.Float64("qps", 0, "global rate cap; 0 = unbounded")
	mix := flag.String("mix", "A:2,AAAA:1,HTTPS:3", "query mix as type:weight pairs")
	names := flag.String("names", "idcflare.com", "comma-separated query base names")
	unique := flag.Bool("unique", false, "prefix random labels to force cache misses")
	timeout := flag.Duration("timeout", 3*time.Second, "per-request client timeout")
	slowMs := flag.Int("slow-ms", 1137, "slow threshold in ms (Chromium DNS task budget)")
	flag.Parse()
	if *target == "" {
		fmt.Fprintln(os.Stderr, "loadgen: -target is required")
		os.Exit(2)
	}
	entries, err := parseMix(*mix)
	if err != nil {
		fmt.Fprintln(os.Stderr, "loadgen:", err)
		os.Exit(2)
	}
	baseNames := strings.Split(*names, ",")
	for i := range baseNames {
		baseNames[i] = strings.TrimSpace(baseNames[i])
	}

	client := &http.Client{
		Timeout: *timeout,
		Transport: &http.Transport{
			MaxIdleConns:        256,
			MaxIdleConnsPerHost: 256,
			IdleConnTimeout:     90 * time.Second,
		},
	}

	type task struct{ name string; t uint16 }
	tasks := make(chan task)
	var mu sync.Mutex
	var samples []sample
	var wg sync.WaitGroup

	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for tk := range tasks {
				s := runOne(client, *target, tk.name, tk.t, *slowMs)
				mu.Lock()
				samples = append(samples, s)
				mu.Unlock()
			}
		}()
	}

	// Pace the task stream: a ticker when -qps caps the rate, a tight loop
	// otherwise; both stop at the deadline.
	deadline := time.Now().Add(*duration)
	var pace <-chan time.Time
	if *qps > 0 {
		t := time.NewTicker(time.Duration(float64(time.Second) / *qps))
		defer t.Stop()
		pace = t.C
	}
Producing:
	for {
		if time.Now().After(deadline) {
			break
		}
		if pace != nil {
			select {
			case <-pace:
			case <-time.After(time.Until(deadline)):
				break Producing
			}
		}
		e := entries[mathrand.Intn(len(entries))]
		name := baseNames[mathrand.Intn(len(baseNames))]
		if *unique {
			name = randLabel() + "." + name
		}
		select {
		case tasks <- task{name: name, t: e.t}:
		case <-time.After(time.Until(deadline)):
			break Producing
		}
	}
	close(tasks)
	wg.Wait()

	report(samples, *concurrency, *qps, *duration, *slowMs)
}

// runOne performs one POST DoH exchange and classifies the outcome.
func runOne(client *http.Client, target, name string, qtype uint16, slowMs int) sample {
	q := &wire.Packet{
		Header:    wire.Header{ID: randomID(), Flags: 0x0100},
		Questions: []wire.Question{{Name: name, Type: qtype, Class: wire.ClassIN}},
	}
	body, err := q.Encode()
	if err != nil {
		return sample{qtype: typeName(qtype), err: "encode: " + err.Error()}
	}
	start := time.Now()
	req, err := http.NewRequest(http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return sample{qtype: typeName(qtype), err: "request: " + err.Error()}
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")
	resp, err := client.Do(req)
	dur := time.Since(start)
	s := sample{qtype: typeName(qtype), dur: dur, slow: dur > time.Duration(slowMs)*time.Millisecond}
	if err != nil {
		s.err = truncate(err.Error(), 120)
		return s
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	s.status = resp.StatusCode
	if resp.StatusCode != http.StatusOK {
		s.err = fmt.Sprintf("HTTP %d", resp.StatusCode)
	}
	return s
}

// report prints the per-type summary and the global line.
func report(samples []sample, concurrency int, qps float64, duration time.Duration, slowMs int) {
	byType := map[string][]sample{}
	for _, s := range samples {
		byType[s.qtype] = append(byType[s.qtype], s)
	}
	types := make([]string, 0, len(byType))
	for t := range byType {
		types = append(types, t)
	}
	sort.Strings(types)

	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	fmt.Fprintf(w, "samples=%d concurrency=%d qps_cap=%.1f duration=%s slow_ms=%d\n\n",
		len(samples), concurrency, qps, duration, slowMs)
	for _, t := range types {
		ss := byType[t]
		durs := make([]time.Duration, 0, len(ss))
		errs, slow := 0, 0
		for _, s := range ss {
			if s.err != "" {
				errs++
			} else {
				durs = append(durs, s.dur)
			}
			if s.slow {
				slow++
			}
		}
		fmt.Fprintf(w, "%-5s n=%-6d ok=%-6d err=%-4d slow(>%dms)=%-4d (%.1f%%)", t, len(ss), len(ss)-errs, errs, slowMs, slow, pct(slow, len(ss)))
		if len(durs) > 0 {
			sort.Slice(durs, func(i, j int) bool { return durs[i] < durs[j] })
			fmt.Fprintf(w, " p50=%s p90=%s p95=%s p99=%s max=%s",
				quantile(durs, 0.50), quantile(durs, 0.90), quantile(durs, 0.95), quantile(durs, 0.99), durs[len(durs)-1])
		}
		fmt.Fprintln(w)
	}
}

func quantile(sorted []time.Duration, q float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(math.Ceil(q*float64(len(sorted)))) - 1
	if idx < 0 {
		idx = 0
	}
	return sorted[idx]
}

func pct(n, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(n) / float64(total) * 100
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func randLabel() string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("l%x", binary.BigEndian.Uint32(b[:]))
}

func randomID() uint16 {
	var b [2]byte
	_, _ = rand.Read(b[:])
	return binary.BigEndian.Uint16(b[:])
}

func parseMix(s string) ([]mixEntry, error) {
	var entries []mixEntry
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, w, ok := strings.Cut(part, ":")
		if !ok {
			return nil, fmt.Errorf("bad mix entry %q (want type:weight)", part)
		}
		weight, err := strconv.Atoi(strings.TrimSpace(w))
		if err != nil || weight <= 0 {
			return nil, fmt.Errorf("bad weight in mix entry %q", part)
		}
		var t uint16
		switch strings.ToUpper(strings.TrimSpace(name)) {
		case "A":
			t = wire.TypeA
		case "AAAA":
			t = wire.TypeAAAA
		case "HTTPS":
			t = wire.TypeHTTPS
		default:
			return nil, fmt.Errorf("unsupported mix type %q (A, AAAA, HTTPS)", name)
		}
		// Expand the weight into the pick list so entry i is chosen with
		// probability weight/total under a uniform random index.
		for i := 0; i < weight; i++ {
			entries = append(entries, mixEntry{qtype: typeName(t), t: t})
		}
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("empty mix")
	}
	return entries, nil
}

func typeName(t uint16) string {
	switch t {
	case wire.TypeA:
		return "A"
	case wire.TypeAAAA:
		return "AAAA"
	case wire.TypeHTTPS:
		return "HTTPS"
	}
	return strconv.Itoa(int(t))
}
