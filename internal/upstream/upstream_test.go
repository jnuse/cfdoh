package upstream

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jnuse/cfdoh/internal/config"
	"github.com/jnuse/cfdoh/internal/wire"
)

var dnsContentType = "application/dns-message"

func testQuery(id uint16, name string) []byte {
	q := &wire.Packet{
		Header:    wire.Header{ID: id, Flags: 0x0100},
		Questions: []wire.Question{{Name: name, Type: wire.TypeA, Class: wire.ClassIN}},
	}
	b, _ := q.Encode()
	return b
}

func testAnswer(query []byte, ips ...string) []byte {
	parsed, err := wire.Parse(query)
	if err != nil {
		panic(err)
	}
	resp := &wire.Packet{Header: wire.Header{ID: parsed.Header.ID, Flags: 0x8180}, Questions: parsed.Questions}
	for _, ip := range ips {
		addr, _ := wire.ParseIPv4(ip)
		resp.Answers = append(resp.Answers, wire.Record{
			Name: parsed.Questions[0].Name, Type: wire.TypeA, Class: wire.ClassIN, TTL: 60, RData: wire.A{IP: addr},
		})
	}
	b, _ := resp.Encode()
	return b
}

func cfgOf(upstreams ...string) *config.Config {
	return &config.Config{
		Upstreams:         upstreams,
		EcsUpstreams:      upstreams,
		UpstreamTimeoutMs: 1000,
		UpstreamHedgeMs:   0,
		MaxDNSPacketSize:  4096,
	}
}

// dohServer returns a DoH upstream responding with answer after delay; hits
// counts the requests it received.
func dohServer(answer func(query []byte) []byte, delay time.Duration) (*httptest.Server, *atomic.Int64) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		body := make([]byte, r.ContentLength)
		if _, err := readFull(r, body); err != nil {
			http.Error(w, "read failed", http.StatusBadRequest)
			return
		}
		if delay > 0 {
			select {
			case <-time.After(delay):
			case <-r.Context().Done():
				return
			}
		}
		w.Header().Set("Content-Type", dnsContentType)
		w.Write(answer(body))
	}))
	return srv, &hits
}

func readFull(r *http.Request, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		m, err := r.Body.Read(buf[n:])
		n += m
		if err != nil {
			if n == len(buf) {
				return n, nil
			}
			return n, err
		}
	}
	return n, nil
}

func TestQueryFirstFastAnswerSkipsSecond(t *testing.T) {
	first, firstHits := dohServer(func(q []byte) []byte { return testAnswer(q, "192.0.2.1") }, 0)
	defer first.Close()
	second, secondHits := dohServer(func(q []byte) []byte { return testAnswer(q, "192.0.2.2") }, 0)
	defer second.Close()

	res, err := Query(context.Background(), testQuery(0x11, "example.com"), cfgOf(first.URL, second.URL), false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Upstream != first.URL {
		t.Fatalf("winner = %s", res.Upstream)
	}
	if firstHits.Load() != 1 || secondHits.Load() != 0 {
		t.Fatalf("hits first=%d second=%d, second must stay idle", firstHits.Load(), secondHits.Load())
	}
}

func TestQueryHedgesSlowUpstream(t *testing.T) {
	slow := 400 * time.Millisecond
	first, _ := dohServer(func(q []byte) []byte { return testAnswer(q, "192.0.2.1") }, slow)
	defer first.Close()
	second, secondHits := dohServer(func(q []byte) []byte { return testAnswer(q, "192.0.2.2") }, 0)
	defer second.Close()

	cfg := cfgOf(first.URL, second.URL)
	cfg.UpstreamHedgeMs = 50
	start := time.Now()
	res, err := Query(context.Background(), testQuery(0x22, "example.com"), cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Upstream != second.URL {
		t.Fatalf("winner = %s, hedge must pick the fast upstream", res.Upstream)
	}
	if elapsed := time.Since(start); elapsed > slow {
		t.Fatalf("query waited for the slow upstream: %s", elapsed)
	}
	if secondHits.Load() != 1 {
		t.Fatalf("second upstream hits = %d", secondHits.Load())
	}
}

func TestQueryFallsThroughFailures(t *testing.T) {
	var broken http.HandlerFunc = func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}
	srv1 := httptest.NewServer(broken)
	defer srv1.Close()
	srv2 := httptest.NewServer(broken)
	defer srv2.Close()
	good, _ := dohServer(func(q []byte) []byte { return testAnswer(q, "192.0.2.3") }, 0)
	defer good.Close()

	cfg := cfgOf(srv1.URL, srv2.URL, good.URL) // hedge disabled: serial fallback
	res, err := Query(context.Background(), testQuery(0x33, "example.com"), cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Upstream != good.URL {
		t.Fatalf("winner = %s", res.Upstream)
	}
}

func TestQueryRejectsInvalidResponses(t *testing.T) {
	query := testQuery(0x44, "example.com")
	cases := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{"wrong content type", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.Write(testAnswer(query, "192.0.2.1"))
		}},
		{"missing QR bit", func(w http.ResponseWriter, r *http.Request) {
			body := make([]byte, 100)
			if _, err := readFull(r, body); err != nil {
				return
			}
			w.Header().Set("Content-Type", dnsContentType)
			w.Write(body)
		}},
		{"transaction ID mismatch", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", dnsContentType)
			w.Write(testAnswer(query, "192.0.2.1")[2:])
		}},
		{"oversized body", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", dnsContentType)
			w.Write(make([]byte, 8192))
		}},
		{"garbage body", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", dnsContentType)
			w.Write([]byte("not dns"))
		}},
	}
	for _, tc := range cases {
		srv := httptest.NewServer(tc.handler)
		cfg := cfgOf(srv.URL)
		if _, err := Query(context.Background(), query, cfg, false); err == nil {
			t.Fatalf("%s: invalid response accepted", tc.name)
		}
		srv.Close()
	}
}

func TestQueryAllFail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusBadGateway)
	}))
	defer srv.Close()
	_, err := Query(context.Background(), testQuery(0x55, "example.com"), cfgOf(srv.URL), false)
	if err == nil || err.Error() == "" {
		t.Fatalf("want error, got %v", err)
	}
	if len(err.Error()) < len("all upstreams failed") {
		t.Fatalf("error must summarize the chain: %v", err)
	}
}

func TestQueryEmptyUpstreamList(t *testing.T) {
	if _, err := Query(context.Background(), testQuery(1, "example.com"), cfgOf(), false); err == nil {
		t.Fatal("empty upstream list must fail")
	}
}

func TestQueryEcsRouting(t *testing.T) {
	normal, normalHits := dohServer(func(q []byte) []byte { return testAnswer(q, "192.0.2.1") }, 0)
	defer normal.Close()
	ecs, ecsHits := dohServer(func(q []byte) []byte { return testAnswer(q, "192.0.2.2") }, 0)
	defer ecs.Close()

	cfg := cfgOf(normal.URL)
	cfg.EcsUpstreams = []string{ecs.URL}

	res, err := Query(context.Background(), testQuery(0x66, "example.cn"), cfg, true)
	if err != nil {
		t.Fatal(err)
	}
	if res.Upstream != ecs.URL || normalHits.Load() != 0 || ecsHits.Load() != 1 {
		t.Fatalf("ecs routing wrong: winner=%s normal=%d ecs=%d", res.Upstream, normalHits.Load(), ecsHits.Load())
	}
}

func TestQuerySingleflightMergesConcurrent(t *testing.T) {
	release := make(chan struct{})
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		body := make([]byte, r.ContentLength)
		if _, err := readFull(r, body); err != nil {
			return
		}
		<-release
		w.Header().Set("Content-Type", dnsContentType)
		w.Write(testAnswer(body, "192.0.2.1"))
	}))
	defer srv.Close()

	query := testQuery(0x77, "example.com") // identical bytes share one flight
	const callers = 50
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := Query(context.Background(), query, cfgOf(srv.URL), false); err != nil {
				t.Errorf("merged query failed: %v", err)
			}
		}()
	}
	// give the callers time to pile onto one flight, then let it finish
	time.Sleep(200 * time.Millisecond)
	close(release)
	wg.Wait()
	if hits.Load() != 1 {
		t.Fatalf("outbound queries = %d, want 1", hits.Load())
	}
}

func TestResolveAddresses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		if _, err := readFull(r, body); err != nil {
			return
		}
		parsed, err := wire.Parse(body)
		if err != nil || len(parsed.Questions) != 1 {
			http.Error(w, "bad query", http.StatusBadRequest)
			return
		}
		resp := &wire.Packet{Header: wire.Header{ID: parsed.Header.ID, Flags: 0x8180}, Questions: parsed.Questions}
		question := parsed.Questions[0]
		switch question.Type {
		case wire.TypeA:
			a1, _ := wire.ParseIPv4("203.0.113.1")
			a2, _ := wire.ParseIPv4("203.0.113.1") // duplicate on purpose
			a3, _ := wire.ParseIPv4("203.0.113.2")
			for _, ip := range [][4]byte{a1, a2, a3} {
				resp.Answers = append(resp.Answers, wire.Record{Name: question.Name, Type: wire.TypeA, Class: wire.ClassIN, TTL: 60, RData: wire.A{IP: ip}})
			}
		case wire.TypeAAAA:
			ip, _ := wire.ParseIPv6("2001:db8::1")
			resp.Answers = append(resp.Answers, wire.Record{Name: question.Name, Type: wire.TypeAAAA, Class: wire.ClassIN, TTL: 60, RData: wire.AAAA{IP: ip}})
		}
		out, _ := resp.Encode()
		w.Header().Set("Content-Type", dnsContentType)
		w.Write(out)
	}))
	defer srv.Close()

	v4, v6, err := ResolveAddresses(context.Background(), "preferred.example.com", cfgOf(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(v4) != fmt.Sprint([]string{"203.0.113.1", "203.0.113.2"}) {
		t.Fatalf("v4 = %v (want dedup)", v4)
	}
	if len(v6) != 1 || v6[0] != "2001:0db8:0000:0000:0000:0000:0000:0001" {
		t.Fatalf("v6 = %v", v6)
	}
}

func TestResolveAddressesDoubleFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	if _, _, err := ResolveAddresses(context.Background(), "down.example.com", cfgOf(srv.URL)); err == nil {
		t.Fatal("double family failure must surface an error")
	}
}
