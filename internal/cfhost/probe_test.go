package cfhost

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// withInsecureTLS swaps the probe TLS config seam for the duration of a test
// so httptest.NewTLSServer endpoints can be probed.
func withInsecureTLS(t *testing.T) {
	t.Helper()
	old := newProbeTLSConfig
	newProbeTLSConfig = func(serverName string) *tls.Config {
		return &tls.Config{ServerName: serverName, InsecureSkipVerify: true}
	}
	t.Cleanup(func() { newProbeTLSConfig = old })
}

func TestMedianOf(t *testing.T) {
	cases := []struct {
		in   []time.Duration
		want time.Duration
	}{
		{[]time.Duration{100}, 100},
		{[]time.Duration{300, 100, 200}, 200},
		{[]time.Duration{100, 300}, 100}, // even -> lower median
		{[]time.Duration{50, 20, 90, 10}, 20},
	}
	for _, c := range cases {
		if got := medianOf(c.in); got != c.want {
			t.Errorf("medianOf(%v) = %v want %v", c.in, got, c.want)
		}
	}
}

func TestProbeAddressSuccessAndFailure(t *testing.T) {
	withInsecureTLS(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(srv.Close)

	target := srv.Listener.Addr().String()
	med, ok := probeAddress(context.Background(), target, "example.com", 3*time.Second, 2)
	if !ok {
		t.Fatal("local TLS endpoint should probe ok")
	}
	if med <= 0 {
		t.Fatalf("median should be positive, got %v", med)
	}

	// Unreachable port fails within the round budget.
	start := time.Now()
	_, ok = probeAddress(context.Background(), "127.0.0.1:1", "example.com", 500*time.Millisecond, 1)
	if ok {
		t.Fatal("dead target must fail")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("failure took too long: %v", elapsed)
	}
}

func TestProbeCandidatesOrderFilterVerify(t *testing.T) {
	withInsecureTLS(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/cdn-cgi/trace") {
			w.Write([]byte("fl=abc\nhttp=crypto\n"))
			return
		}
		w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)

	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	opts := probeOptions{
		sni:         "example.com",
		port:        port,
		concurrency: 4,
		rounds:      1,
		timeoutMs:   2000,
	}

	// Dead public address (TEST-NET-3) plus a live loopback endpoint; the
	// loopback is only reachable through the injected port.
	addrs := []netip.Addr{
		netip.MustParseAddr("203.0.113.200"),
		netip.MustParseAddr("127.0.0.1"),
	}
	outcomes := probeCandidates(context.Background(), addrs, opts)
	if len(outcomes) != 2 {
		t.Fatalf("outcome count wrong: %v", outcomes)
	}
	if outcomes[0].ok {
		t.Fatal("dead candidate must be eliminated")
	}
	if !outcomes[1].ok {
		t.Fatal("live candidate should pass")
	}
	// Input order preserved.
	if outcomes[0].addr != addrs[0] || outcomes[1].addr != addrs[1] {
		t.Fatalf("order not preserved: %v", outcomes)
	}

	// HTTP verification passes on the trace endpoint.
	opts.httpVerify = true
	outcomes = probeCandidates(context.Background(), addrs[:1], opts)
	if outcomes[0].ok {
		t.Fatal("dead candidate must fail even with verify")
	}
}

func TestHTTPVerifyAddr(t *testing.T) {
	withInsecureTLS(t)

	okSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("fl=1a\nhttp=crypto\nu=agent\n"))
	}))
	t.Cleanup(okSrv.Close)
	if !httpVerifyAddr(context.Background(), okSrv.Listener.Addr().String(), "example.com", 2*time.Second) {
		t.Fatal("http=crypto response should verify")
	}

	badSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("not found"))
	}))
	t.Cleanup(badSrv.Close)
	if httpVerifyAddr(context.Background(), badSrv.Listener.Addr().String(), "example.com", 2*time.Second) {
		t.Fatal("404 without http=crypto should fail verification")
	}

	if httpVerifyAddr(context.Background(), "127.0.0.1:1", "example.com", 500*time.Millisecond) {
		t.Fatal("unreachable endpoint should fail verification")
	}
}

func TestTopByFamily(t *testing.T) {
	outcomes := []probeOutcome{
		{addr: netip.MustParseAddr("203.0.113.1"), median: 50 * time.Millisecond, ok: true},
		{addr: netip.MustParseAddr("203.0.113.2"), median: 30 * time.Millisecond, ok: true},
		{addr: netip.MustParseAddr("203.0.113.3"), median: 10 * time.Millisecond, ok: false}, // dead, ignored
		{addr: netip.MustParseAddr("2606:4700::1"), median: 90 * time.Millisecond, ok: true},
		{addr: netip.MustParseAddr("2606:4700::2"), median: 40 * time.Millisecond, ok: true},
	}
	v4, v6 := topByFamily(outcomes)
	if v4 == nil || v4.addr.String() != "203.0.113.2" {
		t.Fatalf("v4 top wrong: %+v", v4)
	}
	if v6 == nil || v6.addr.String() != "2606:4700::2" {
		t.Fatalf("v6 top wrong: %+v", v6)
	}

	// Tie resolves to the earlier candidate.
	tie := []probeOutcome{
		{addr: netip.MustParseAddr("203.0.113.1"), median: 50 * time.Millisecond, ok: true},
		{addr: netip.MustParseAddr("203.0.113.2"), median: 50 * time.Millisecond, ok: true},
	}
	v4, _ = topByFamily(tie)
	if v4.addr.String() != "203.0.113.1" {
		t.Fatalf("tie should keep earlier candidate, got %v", v4.addr)
	}

	// All dead.
	v4, v6 = topByFamily([]probeOutcome{{addr: netip.MustParseAddr("203.0.113.1"), ok: false}})
	if v4 != nil || v6 != nil {
		t.Fatal("dead sweep should have no top")
	}
}
