package cfhost

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

// Probing: for each candidate, dial TCP to <ip>:443 and complete a TLS
// handshake with ServerName = first managed domain, InsecureSkipVerify=false
// (production path). Timing covers dial through handshake completion. Each
// address gets Rounds attempts (single-round budget = Timeout ms); the median
// of successful rounds decides; all-round failure eliminates the address.

// probeOptions parameterizes a probe sweep (port and TLS config construction
// are injectable so tests can target ephemeral local TLS servers).
type probeOptions struct {
	sni         string
	port        string
	concurrency int
	rounds      int
	timeoutMs   int
	httpVerify  bool
}

// newProbeTLSConfig is the production TLS configuration seam: standard
// certificate-chain verification. Tests swap it for an insecure variant
// against httptest.NewTLSServer.
var newProbeTLSConfig = func(serverName string) *tls.Config {
	return &tls.Config{ServerName: serverName}
}

// probeOutcome is the per-address result of one sweep.
type probeOutcome struct {
	addr   netip.Addr
	median time.Duration
	ok     bool
}

// probeAddress measures one target over several rounds; ok is false when
// every round failed or timed out.
func probeAddress(ctx context.Context, target, sni string, timeout time.Duration, rounds int) (time.Duration, bool) {
	var times []time.Duration
	dialer := &net.Dialer{}
	for i := 0; i < rounds; i++ {
		if ctx.Err() != nil {
			break
		}
		rctx, cancel := context.WithTimeout(ctx, timeout)
		start := time.Now()
		conn, err := dialer.DialContext(rctx, "tcp", target)
		if err != nil {
			cancel()
			continue
		}
		tc := tls.Client(conn, newProbeTLSConfig(sni))
		err = tc.HandshakeContext(rctx)
		cancel()
		if err != nil {
			tc.Close()
			continue
		}
		elapsed := time.Since(start)
		tc.Close()
		times = append(times, elapsed)
	}
	if len(times) == 0 {
		return 0, false
	}
	return medianOf(times), true
}

// probeCandidates probes all candidates concurrently (bounded by
// concurrency), optionally applying the HTTP end-to-end verification
// (/cdn-cgi/trace with SNI/Host = sni), preserving input order.
func probeCandidates(ctx context.Context, addrs []netip.Addr, opts probeOptions) []probeOutcome {
	outcomes := make([]probeOutcome, len(addrs))
	sem := make(chan struct{}, opts.concurrency)
	var wg sync.WaitGroup
	timeout := time.Duration(opts.timeoutMs) * time.Millisecond
	for i, a := range addrs {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, a netip.Addr) {
			defer wg.Done()
			defer func() { <-sem }()
			target := net.JoinHostPort(a.String(), opts.port)
			med, ok := probeAddress(ctx, target, opts.sni, timeout, opts.rounds)
			if ok && opts.httpVerify {
				ok = httpVerifyAddr(ctx, target, opts.sni, timeout)
			}
			outcomes[i] = probeOutcome{addr: a, median: med, ok: ok}
		}(i, a)
	}
	wg.Wait()
	return outcomes
}

// httpVerifyAddr performs the optional end-to-end check: GET
// https://<domain>/cdn-cgi/trace dialed manually to target, succeeding when
// the body contains "http=crypto" or the response is 2xx and readable.
func httpVerifyAddr(ctx context.Context, target, domain string, timeout time.Duration) bool {
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	transport := &http.Transport{
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d, err := (&net.Dialer{}).DialContext(ctx, "tcp", target)
			if err != nil {
				return nil, err
			}
			tc := tls.Client(d, newProbeTLSConfig(domain))
			if err := tc.HandshakeContext(ctx); err != nil {
				d.Close()
				return nil, err
			}
			return tc, nil
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: timeout}
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, "https://"+domain+"/cdn-cgi/trace", nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return false
	}
	return string(body) != "" && (strings.Contains(string(body), "http=crypto") ||
		(resp.StatusCode >= 200 && resp.StatusCode < 300))
}

// medianOf returns the lower median of ts.
func medianOf(ts []time.Duration) time.Duration {
	s := append([]time.Duration(nil), ts...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return s[(len(s)-1)/2]
}
