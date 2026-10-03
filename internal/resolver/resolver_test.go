package resolver

import (
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jnuse/cfdoh/internal/cfrange"
	"github.com/jnuse/cfdoh/internal/config"
	"github.com/jnuse/cfdoh/internal/ech"
	"github.com/jnuse/cfdoh/internal/pool"
	"github.com/jnuse/cfdoh/internal/wire"
)

func TestMain(m *testing.M) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	m.Run()
}

// resetCache drops the shared answer cache between tests.
func resetCache() {
	sharedMu.Lock()
	shared = nil
	sharedMu.Unlock()
}

func baseCfg(upstreams ...string) *config.Config {
	return &config.Config{
		Upstreams:         upstreams,
		EcsUpstreams:      upstreams,
		UpstreamTimeoutMs: 1000,
		UpstreamHedgeMs:   0,
		MaxDNSPacketSize:  65535,
		CacheMinTTL:       30,
		CacheMaxTTL:       3600,
		NegativeCacheMaxTTL: 300,
		CacheStaleTTL:     86400,
		CachePrefetchPercent: 10,
		CacheMaxEntries:   4096,
		EcsMode:           "off",
		EcsIPv4Prefix:     24,
		EcsIPv6Prefix:     48,
	}
}

func loadRanges(t *testing.T) {
	t.Helper()
	v4 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("104.16.0.0/12\n172.64.0.0/13\n"))
	}))
	v6 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("2606:4700::/32\n"))
	}))
	t.Cleanup(v4.Close)
	t.Cleanup(v6.Close)
	cfg := &config.Config{CFIPv4URL: v4.URL, CFIPv6URL: v6.URL}
	if _, err := cfrange.Load(context.Background(), cfg); err != nil {
		t.Fatalf("cfrange.Load: %v", err)
	}
}

// newFakeUpstream starts a DoH upstream answering via respond; hits counts
// the received queries.
func newFakeUpstream(t *testing.T, respond func(q *wire.Packet) *wire.Packet) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read failed", http.StatusBadRequest)
			return
		}
		q, err := wire.Parse(body)
		if err != nil || len(q.Questions) != 1 {
			http.Error(w, "bad query", http.StatusBadRequest)
			return
		}
		resp := respond(q)
		out, err := resp.Encode()
		if err != nil {
			http.Error(w, "encode failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(out)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func buildQuery(id uint16, name string, qtype uint16) []byte {
	q := &wire.Packet{
		Header:    wire.Header{ID: id, Flags: 0x0100},
		Questions: []wire.Question{{Name: name, Type: qtype, Class: wire.ClassIN}},
	}
	b, _ := q.Encode()
	return b
}

func respondWith(f func(question wire.Question) []wire.Record) func(*wire.Packet) *wire.Packet {
	return func(q *wire.Packet) *wire.Packet {
		return &wire.Packet{
			Header:    wire.Header{ID: q.Header.ID, Flags: 0x8180},
			Questions: q.Questions,
			Answers:   f(q.Questions[0]),
		}
	}
}

func aRec(name, ip string, ttl uint32) wire.Record {
	v, err := wire.ParseIPv4(ip)
	if err != nil {
		panic(err)
	}
	return wire.Record{Name: name, Type: wire.TypeA, Class: wire.ClassIN, TTL: ttl, RData: wire.A{IP: v}}
}

func httpsHintRec(name string, v4 string, ttl uint32) wire.Record {
	ip, err := wire.ParseIPv4(v4)
	if err != nil {
		panic(err)
	}
	return wire.Record{Name: name, Type: wire.TypeHTTPS, Class: wire.ClassIN, TTL: ttl,
		RData: wire.SVCB{Priority: 1, Target: ".",
			Params: []wire.SvcParam{{Key: wire.ParamIPv4Hint, Value: ip[:]}}}}
}

// validECHList is structurally valid: declared length 8 == len-2 and the
// first ECHConfig (length 4) fits exactly.
func validECHList() []byte {
	return []byte{0x00, 0x08, 0xfe, 0x0d, 0x00, 0x04, 0x11, 0x22, 0x33, 0x44}
}

func answerIPs(pkt *wire.Packet, rtype uint16) []string {
	var out []string
	for _, r := range pkt.Answers {
		switch rd := r.RData.(type) {
		case wire.A:
			if r.Type == rtype {
				out = append(out, wire.IPv4String(rd.IP))
			}
		case wire.AAAA:
			if r.Type == rtype {
				out = append(out, wire.IPv6String(rd.IP))
			}
		}
	}
	return out
}

func findHTTPS(pkt *wire.Packet) *wire.Record {
	for i := range pkt.Answers {
		if pkt.Answers[i].Type == wire.TypeHTTPS {
			return &pkt.Answers[i]
		}
	}
	return nil
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := slices.Clone(a), slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(x, y)
}

func waitHits(t *testing.T, hits *atomic.Int64, want int64) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if hits.Load() >= want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("upstream hits = %d, want >= %d", hits.Load(), want)
}

const deadUpstream = "https://127.0.0.1:1/dns-query"

func TestResolveRewritesFromLearnedPool(t *testing.T) {
	resetCache()
	loadRanges(t)
	srv, hits := newFakeUpstream(t, respondWith(func(q wire.Question) []wire.Record {
		return []wire.Record{aRec(q.Name, "104.16.1.1", 60)}
	}))
	cfg := baseCfg(srv.URL)
	cfg.CFRewriteEnabled = true
	if err := pool.SetLearned([]string{"104.17.9.1", "104.17.9.2"}, nil, 3600, "probe-a", ""); err != nil {
		t.Fatal(err)
	}
	opts := &Options{CfDomainIsDefault: true}

	answer, err := Resolve(context.Background(), buildQuery(0x11, "www.cftest.example", wire.TypeA), opts, cfg)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := wire.Parse(answer)
	if err != nil {
		t.Fatal(err)
	}
	if got := answerIPs(parsed, wire.TypeA); !sameSet(got, []string{"104.17.9.1", "104.17.9.2"}) {
		t.Fatalf("A = %v, want learned pool addresses", got)
	}
	if hits.Load() != 1 {
		t.Fatalf("upstream hits = %d, want 1", hits.Load())
	}
}

func TestResolveCacheHitAndPatchID(t *testing.T) {
	resetCache()
	srv, hits := newFakeUpstream(t, respondWith(func(q wire.Question) []wire.Record {
		return []wire.Record{aRec(q.Name, "104.16.1.1", 60), aRec(q.Name, "104.16.1.2", 60)}
	}))
	cfg := baseCfg(srv.URL)
	query := buildQuery(0x2468, "www.cached.example", wire.TypeA)

	for i := 0; i < 2; i++ {
		answer, err := Resolve(context.Background(), query, &Options{}, cfg)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := wire.Parse(answer)
		if err != nil {
			t.Fatal(err)
		}
		if parsed.Header.ID != 0x2468 {
			t.Fatalf("run %d: answer ID = %#x, want 0x2468", i, parsed.Header.ID)
		}
		if got := answerIPs(parsed, wire.TypeA); !sameSet(got, []string{"104.16.1.1", "104.16.1.2"}) {
			t.Fatalf("run %d: A = %v", i, got)
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("upstream hits = %d, second identical query must come from cache", hits.Load())
	}
}

func TestResolveRefreshServesAndPrefetches(t *testing.T) {
	resetCache()
	srv, hits := newFakeUpstream(t, respondWith(func(q wire.Question) []wire.Record {
		return []wire.Record{aRec(q.Name, "104.16.1.1", 60)}
	}))
	cfg := baseCfg(srv.URL)
	cfg.CachePrefetchPercent = 100 // remaining TTL <= full TTL: refresh from the start

	query := buildQuery(1, "www.prefetch.example", wire.TypeA)
	if _, err := Resolve(context.Background(), query, &Options{}, cfg); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 1 {
		t.Fatalf("hits after first resolve = %d", hits.Load())
	}

	answer, err := Resolve(context.Background(), query, &Options{}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if parsed, err := wire.Parse(answer); err != nil || len(answerIPs(parsed, wire.TypeA)) != 1 {
		t.Fatalf("refresh state must answer immediately: %v", err)
	}
	waitHits(t, hits, 2) // background refresh reached the upstream
}

func TestResolveHTTPSServesStaleImmediately(t *testing.T) {
	resetCache()
	srv, hits := newFakeUpstream(t, respondWith(func(q wire.Question) []wire.Record {
		return []wire.Record{httpsHintRec(q.Name, "104.16.1.1", 1)}
	}))
	cfg := baseCfg(srv.URL)
	cfg.CacheMinTTL = 0
	cfg.CacheMaxTTL = 1
	cfg.CacheStaleTTL = 3600

	query := buildQuery(2, "www.stale-https.example", wire.TypeHTTPS)
	if _, err := Resolve(context.Background(), query, &Options{}, cfg); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond) // entry expires inside the stale window

	answer, err := Resolve(context.Background(), query, &Options{}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := wire.Parse(answer)
	if err != nil {
		t.Fatal(err)
	}
	https := findHTTPS(parsed)
	if https == nil {
		t.Fatalf("expired HTTPS cache must serve immediately, answers = %v", parsed.Answers)
	}
	if https.TTL != 30 {
		t.Fatalf("stale HTTPS TTL = %d, want 30", https.TTL)
	}
	if hits.Load() != 1 {
		t.Fatalf("hits = %d, the stale serve must not block on upstream", hits.Load())
	}
	waitHits(t, hits, 2) // background refresh
}

func TestResolveStaleFallbackWhenUpstreamDead(t *testing.T) {
	resetCache()
	srv, _ := newFakeUpstream(t, respondWith(func(q wire.Question) []wire.Record {
		return []wire.Record{aRec(q.Name, "104.16.1.7", 1)}
	}))
	cfg := baseCfg(srv.URL)
	cfg.CacheMinTTL = 0
	cfg.CacheMaxTTL = 1
	cfg.CacheStaleTTL = 3600

	query := buildQuery(3, "www.fallback.example", wire.TypeA)
	if _, err := Resolve(context.Background(), query, &Options{}, cfg); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)

	cfg.Upstreams = []string{deadUpstream}
	cfg.EcsUpstreams = []string{deadUpstream}
	answer, err := Resolve(context.Background(), query, &Options{}, cfg)
	if err != nil {
		t.Fatalf("stale fallback must answer, got error: %v", err)
	}
	parsed, err := wire.Parse(answer)
	if err != nil {
		t.Fatal(err)
	}
	if got := answerIPs(parsed, wire.TypeA); !sameSet(got, []string{"104.16.1.7"}) {
		t.Fatalf("A = %v, want the cached address", got)
	}
	if parsed.Answers[0].TTL != 30 {
		t.Fatalf("stale TTL = %d, want 30", parsed.Answers[0].TTL)
	}
}

func TestResolveServfailWithoutCache(t *testing.T) {
	resetCache()
	cfg := baseCfg(deadUpstream)
	query := buildQuery(0x1234, "www.dead.example", wire.TypeA)

	answer, err := Resolve(context.Background(), query, &Options{}, cfg)
	if err != nil {
		t.Fatalf("SERVFAIL is an answer, not an error: %v", err)
	}
	parsed, err := wire.Parse(answer)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Header.RCode() != 2 {
		t.Fatalf("rcode = %d, want 2", parsed.Header.RCode())
	}
	if !parsed.Header.QR() || !parsed.Header.RD() {
		t.Fatalf("flags = %#x, want QR|RD preserved", parsed.Header.Flags)
	}
	if parsed.Header.ID != 0x1234 {
		t.Fatalf("ID = %#x, want the request ID", parsed.Header.ID)
	}
	if len(parsed.Answers) != 0 {
		t.Fatalf("SERVFAIL must be empty, answers = %v", parsed.Answers)
	}
}

func TestResolveUpstreamServfailNotCached(t *testing.T) {
	resetCache()
	srv, hits := newFakeUpstream(t, func(q *wire.Packet) *wire.Packet {
		return &wire.Packet{Header: wire.Header{ID: q.Header.ID, Flags: 0x8182}, Questions: q.Questions}
	})
	cfg := baseCfg(srv.URL)
	query := buildQuery(4, "www.upstream-servfail.example", wire.TypeA)

	for i := 0; i < 2; i++ {
		answer, err := Resolve(context.Background(), query, &Options{}, cfg)
		if err != nil {
			t.Fatal(err)
		}
		if parsed, err := wire.Parse(answer); err != nil || parsed.Header.RCode() != 2 {
			t.Fatalf("run %d: upstream SERVFAIL must pass through", i)
		}
	}
	if hits.Load() != 2 {
		t.Fatalf("hits = %d, SERVFAIL must not be cached", hits.Load())
	}
}

func TestResolveBlockRuleRefused(t *testing.T) {
	resetCache()
	srv, hits := newFakeUpstream(t, respondWith(func(q wire.Question) []wire.Record {
		return []wire.Record{aRec(q.Name, "104.16.1.1", 60)}
	}))
	cfg := baseCfg(srv.URL)
	cfg.RulesJSON = `[{"match":{"domain_suffix":["blocked.test"]},"action":"block"}]`

	answer, err := Resolve(context.Background(), buildQuery(5, "www.blocked.test", wire.TypeA), &Options{}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := wire.Parse(answer)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Header.RCode() != 3 {
		t.Fatalf("rcode = %d, want 3 (REFUSED)", parsed.Header.RCode())
	}
	if !parsed.Header.QR() {
		t.Fatalf("QR not set: %#x", parsed.Header.Flags)
	}
	if len(parsed.Answers) != 0 {
		t.Fatalf("REFUSED must carry no answers: %v", parsed.Answers)
	}
	if hits.Load() != 0 {
		t.Fatalf("upstream hits = %d, blocked query must not be forwarded", hits.Load())
	}
}

func TestResolveECHInjectViaSourceDomain(t *testing.T) {
	resetCache()
	loadRanges(t)
	srv, _ := newFakeUpstream(t, func(q *wire.Packet) *wire.Packet {
		resp := &wire.Packet{Header: wire.Header{ID: q.Header.ID, Flags: 0x8180}, Questions: q.Questions}
		question := q.Questions[0]
		switch wire.CanonicalName(question.Name) {
		case "www.ech-site.example":
			if question.Type == wire.TypeHTTPS {
				resp.Answers = append(resp.Answers, aRec(question.Name, "104.16.1.1", 60))
				resp.Answers = append(resp.Answers, httpsHintRec(question.Name, "104.16.1.1", 60))
			}
		default: // the ECH publication domain
			resp.Answers = append(resp.Answers, wire.Record{
				Name: question.Name, Type: wire.TypeHTTPS, Class: wire.ClassIN, TTL: 300,
				RData: wire.SVCB{Priority: 1, Target: ".",
					Params: []wire.SvcParam{{Key: wire.ParamECH, Value: validECHList()}}},
			})
		}
		return resp
	})
	cfg := baseCfg(srv.URL)
	cfg.EchEnabled = true
	cfg.EchSourceDomain = "ech-source.test"

	answer, err := Resolve(context.Background(), buildQuery(6, "www.ech-site.example", wire.TypeHTTPS), &Options{}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := wire.Parse(answer)
	if err != nil {
		t.Fatal(err)
	}
	https := findHTTPS(parsed)
	if https == nil {
		t.Fatalf("HTTPS record missing from answer")
	}
	_, _, _, echBytes := wire.DescribeHTTPS(https)
	if !slices.Equal(echBytes, validECHList()) {
		t.Fatalf("ech = %v, want the published config list", echBytes)
	}
}

func TestResolveMetaECHOverride(t *testing.T) {
	resetCache()
	srv, _ := newFakeUpstream(t, respondWith(func(q wire.Question) []wire.Record {
		return []wire.Record{httpsHintRec(q.Name, "157.240.1.35", 60)}
	}))
	cfg := baseCfg(srv.URL)
	cfg.MetaDomains = []string{"meta.test"}

	ech.SetMeta(validECHList(), 3600, "probe", "rotated")
	t.Cleanup(ech.ClearMeta)

	answer, err := Resolve(context.Background(), buildQuery(7, "www.meta.test", wire.TypeHTTPS), &Options{}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := wire.Parse(answer)
	if err != nil {
		t.Fatal(err)
	}
	https := findHTTPS(parsed)
	if https == nil {
		t.Fatalf("HTTPS record missing from answer")
	}
	_, _, _, echBytes := wire.DescribeHTTPS(https)
	if !slices.Equal(echBytes, validECHList()) {
		t.Fatalf("ech = %v, want the learned Meta key", echBytes)
	}
}

func TestResolveMetaECHSeedFromConfig(t *testing.T) {
	resetCache()
	srv, _ := newFakeUpstream(t, respondWith(func(q wire.Question) []wire.Record {
		return []wire.Record{httpsHintRec(q.Name, "157.240.1.35", 60)}
	}))
	cfg := baseCfg(srv.URL)
	cfg.MetaDomains = []string{"meta.test"}
	cfg.MetaEchConfigBase64 = base64.StdEncoding.EncodeToString(validECHList())

	answer, err := Resolve(context.Background(), buildQuery(8, "seed.meta.test", wire.TypeHTTPS), &Options{}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := wire.Parse(answer)
	if err != nil {
		t.Fatal(err)
	}
	https := findHTTPS(parsed)
	if https == nil {
		t.Fatalf("HTTPS record missing from answer")
	}
	_, _, _, echBytes := wire.DescribeHTTPS(https)
	if !slices.Equal(echBytes, validECHList()) {
		t.Fatalf("ech = %v, want the seed config", echBytes)
	}
}

func TestResolveExplicitPoolFailureIsError(t *testing.T) {
	resetCache()
	cfg := baseCfg(deadUpstream)
	opts := &Options{CfDomains: []string{"dead.test"}, CfDomainIsDefault: false}
	if _, err := Resolve(context.Background(), buildQuery(9, "www.dead.example", wire.TypeA), opts, cfg); err == nil {
		t.Fatal("explicit preferred-pool failure must surface an error")
	}
}

func TestResolveNotesCollectDecisionChain(t *testing.T) {
	resetCache()
	loadRanges(t)
	srv, _ := newFakeUpstream(t, respondWith(func(q wire.Question) []wire.Record {
		return []wire.Record{aRec(q.Name, "104.16.1.1", 60)}
	}))
	cfg := baseCfg(srv.URL)
	var notes []string
	result, err := ResolveFresh(context.Background(), buildQuery(10, "www.notes.example", wire.TypeA), &Options{}, cfg, &notes)
	if err != nil {
		t.Fatal(err)
	}
	if result.Packet == nil || result.Upstream == "" {
		t.Fatalf("result incomplete: %+v", result)
	}
	joined := ""
	for _, n := range notes {
		joined += n + "\n"
	}
	for _, want := range []string{"ecs:", "upstream:", "cloudflare:", "pool:"} {
		if !slices.ContainsFunc(notes, func(n string) bool {
			return len(n) >= len(want) && n[:len(want)] == want
		}) {
			t.Fatalf("notes missing %q step: %v", want, notes)
		}
	}
	// explain must not touch the cache
	if c := sharedCache(cfg); c.Len() != 0 {
		t.Fatalf("ResolveFresh stored %d entries, explain must stay read-only", c.Len())
	}
}

func TestChromiumECHVerdict(t *testing.T) {
	qname := "www.example.com"
	aPacket := &wire.Packet{Answers: []wire.Record{aRec(qname, "104.16.1.1", 60)}}
	echRecord := wire.Record{
		Name: qname, Type: wire.TypeHTTPS, Class: wire.ClassIN, TTL: 60,
		RData: wire.SVCB{Priority: 1, Target: ".",
			Params: []wire.SvcParam{{Key: wire.ParamECH, Value: validECHList()}}},
	}
	noECHRecord := wire.Record{
		Name: qname, Type: wire.TypeHTTPS, Class: wire.ClassIN, TTL: 60,
		RData: wire.SVCB{Priority: 1, Target: "."},
	}

	tests := []struct {
		name       string
		a, aaaa    *wire.Packet
		https      *wire.Packet
		wantUsable bool
		wantReason string
	}{
		{
			name:       "usable with matching owner and ech",
			a:          aPacket,
			https:      &wire.Packet{Answers: []wire.Record{echRecord}},
			wantUsable: true,
		},
		{
			name:       "no address records",
			https:      &wire.Packet{Answers: []wire.Record{echRecord}},
			wantUsable: false,
			wantReason: "no address records in the A/AAAA answers",
		},
		{
			name: "multiple owners",
			a: &wire.Packet{Answers: []wire.Record{
				aRec(qname, "104.16.1.1", 60),
				aRec("edge.example.net", "104.16.1.2", 60),
			}},
			https:      &wire.Packet{Answers: []wire.Record{echRecord}},
			wantUsable: false,
			wantReason: "address records have multiple owners",
		},
		{
			name:       "no https answer",
			a:          aPacket,
			wantUsable: false,
			wantReason: "no HTTPS answer",
		},
		{
			name:       "https without ech",
			a:          aPacket,
			https:      &wire.Packet{Answers: []wire.Record{noECHRecord}},
			wantUsable: false,
			wantReason: "HTTPS record carries no ech parameter",
		},
		{
			name: "https target mismatch",
			a:    aPacket,
			https: &wire.Packet{Answers: []wire.Record{{
				Name: qname, Type: wire.TypeHTTPS, Class: wire.ClassIN, TTL: 60,
				RData: wire.SVCB{Priority: 1, Target: "other.example.net",
					Params: []wire.SvcParam{{Key: wire.ParamECH, Value: validECHList()}}},
			}}},
			wantUsable: false,
			wantReason: "HTTPS target does not match the address owner",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			usable, reason := ChromiumECHVerdict(tt.a, tt.aaaa, tt.https)
			if usable != tt.wantUsable {
				t.Fatalf("usable = %v, want %v (reason %q)", usable, tt.wantUsable, reason)
			}
			if !tt.wantUsable && reason == "" {
				t.Fatal("negative verdict must carry a reason")
			}
			if tt.wantUsable && reason != "" {
				t.Fatalf("positive verdict must not carry a reason, got %q", reason)
			}
		})
	}
}
