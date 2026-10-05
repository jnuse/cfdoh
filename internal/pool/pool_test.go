package pool

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jnuse/cfdoh/internal/config"
	"github.com/jnuse/cfdoh/internal/wire"
)

func resetPool(t *testing.T, base int64) {
	t.Helper()
	mu.Lock()
	defaults = newPoolTable(MaxDefaultSources)
	scoped = newPoolTable(MaxScopedPools)
	ispPools = newPoolTable(MaxIspPools)
	mu.Unlock()
	github = newHostPools(MaxHostSources)
	sites = newHostPools(MaxHostSources)
	tagMu.Lock()
	cachedValid = false
	tagMu.Unlock()
	original := now
	now = func() int64 { return base }
	t.Cleanup(func() { now = original })
}

func eq(t *testing.T, got []string, want ...string) {
	t.Helper()
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestCombineRankingsSingleOrEmpty(t *testing.T) {
	if got := CombineRankings(nil, 6); got != nil {
		t.Fatalf("no lists = %v", got)
	}
	if got := CombineRankings([][]string{{}}, 6); got != nil {
		t.Fatalf("empty lists = %v", got)
	}
	eq(t, CombineRankings([][]string{{"1.1.1.1", "2.2.2.2"}}, 6), "1.1.1.1", "2.2.2.2")
	eq(t, CombineRankings([][]string{{"1.1.1.1", "2.2.2.2"}, {}}, 6), "1.1.1.1", "2.2.2.2")
}

func TestCombineRankingsStrictMajority(t *testing.T) {
	// three probers: needed = 2
	lists := [][]string{
		{"10.0.1.1", "10.0.2.1", "10.0.3.1"}, // a b c
		{"10.0.1.1", "10.0.2.1", "10.0.4.1"}, // a b d
		{"10.0.1.1", "10.0.3.1"},             // a c
	}
	// votes: a=3, b=2, c=2, d=1; a first (3 votes), b/c tie at 2:
	// b avg pos = (1+1)/2 = 1, c avg = (2+2)/2 = 2 → b before c
	eq(t, CombineRankings(lists, 6), "10.0.1.1", "10.0.2.1", "10.0.3.1")
}

func TestCombineRankingsPerBlockCap(t *testing.T) {
	// seven addresses in one /24, two elsewhere, all majority-vouched
	var list []string
	for i := 1; i <= 7; i++ {
		list = append(list, fmt.Sprintf("10.0.1.%d", i))
	}
	list = append(list, "10.0.2.1", "10.0.3.1")
	lists := [][]string{list, list}
	eq(t, CombineRankings(lists, 6), "10.0.1.1", "10.0.1.2", "10.0.2.1", "10.0.3.1")
}

func TestCombineRankingsInterleaveWithoutConsensus(t *testing.T) {
	// two probers, disjoint lists: no majority IP → interleave
	lists := [][]string{
		{"1.1.1.1", "1.1.1.2"},
		{"2.2.2.1", "2.2.2.2"},
	}
	eq(t, CombineRankings(lists, 6), "1.1.1.1", "2.2.2.1", "1.1.1.2", "2.2.2.2")
	// consensus of exactly one is below minConsensus → interleave too
	lists = [][]string{{"1.1.1.1", "9.9.9.9"}, {"1.1.1.1", "8.8.8.8"}, {"1.1.1.1", "7.7.7.7"}}
	got := CombineRankings(lists, 6)
	if len(got) != 4 {
		t.Fatalf("interleave length = %d (%v)", len(got), got)
	}
	if got[0] != "1.1.1.1" {
		t.Fatalf("first interleaved = %s", got[0])
	}
}

func TestCombineRankingsIPv6Blocks(t *testing.T) {
	l1 := []string{"2001:db8:aaaa::1", "2001:db8:aaaa::2", "2001:db8:bbbb::1"}
	eq(t, CombineRankings([][]string{l1, l1}, 6),
		"2001:db8:aaaa::1", "2001:db8:aaaa::2", "2001:db8:bbbb::1")
}

func TestCombineRankingsInterleavePerBlockCap(t *testing.T) {
	// three disjoint lists: no majority anywhere, so the interleave path
	// runs; one prober's list holds six addresses in a single /24. The
	// interleaved merge must cap that block at two so a lone prober cannot
	// monopolize one /24 (F-007: 交错合并且每 /24 不超过 2 个).
	lists := [][]string{
		{"10.0.1.1", "10.0.1.2", "10.0.1.3", "10.0.1.4", "10.0.1.5", "10.0.1.6"},
		{"20.0.1.1"},
		{"30.0.1.1"},
	}
	got := CombineRankings(lists, 6)
	blocks := make(map[string]int)
	for _, ip := range got {
		blocks[addressBlock(ip)]++
	}
	if blocks["10.0.1"] != 2 {
		t.Fatalf("interleaved /24 count = %d (output %v)", blocks["10.0.1"], got)
	}
	// the two out-of-block addresses still contribute: 2 + 1 + 1
	if len(got) != 4 {
		t.Fatalf("interleaved output = %v", got)
	}
}

func TestSetLearnedRoutingAndValidation(t *testing.T) {
	resetPool(t, 1_000_000)
	if err := SetLearned([]string{"999.1.1.1"}, nil, 60, "p", ""); err == nil {
		t.Fatal("invalid v4 accepted")
	}
	if err := SetLearned(nil, []string{"bad::zz"}, 60, "p", ""); err == nil {
		t.Fatal("invalid v6 accepted")
	}
	if err := SetLearned([]string{"1.1.1.1", "1.1.1.1"}, nil, 60, "probe", ""); err != nil {
		t.Fatal(err)
	}
	if st := LearnedStatus(); st == nil || len(st.Sources) != 1 || len(st.Sources[0].IPv4) != 1 {
		t.Fatalf("learned = %+v", st)
	}
	// scoped + isp routing
	if err := SetLearned([]string{"58.247.22.1"}, nil, 60, "p", "58.247.22/24"); err != nil {
		t.Fatal(err)
	}
	if err := SetLearned([]string{"1.2.3.4"}, nil, 60, "hub", "isp:chinanet"); err != nil {
		t.Fatal(err)
	}
	if got := len(ScopedStatus()); got != 1 {
		t.Fatalf("scoped = %d", got)
	}
	if got := len(IspPoolStatus()); got != 1 {
		t.Fatalf("isp = %d", got)
	}
}

func TestSetLearnedCapacityEviction(t *testing.T) {
	resetPool(t, 1_000_000)
	for i := 0; i < MaxDefaultSources+2; i++ {
		if err := SetLearned([]string{fmt.Sprintf("10.1.%d.1", i)}, nil, 600, fmt.Sprintf("probe-%d", i), ""); err != nil {
			t.Fatal(err)
		}
	}
	if st := LearnedStatus(); len(st.Sources) > MaxDefaultSources {
		t.Fatalf("sources = %d", len(st.Sources))
	}
	oldest := LearnedStatus().Sources[0].Source
	if oldest == "probe-0" {
		t.Fatal("oldest source must be evicted first")
	}
}

func TestExpiryDropsPools(t *testing.T) {
	resetPool(t, 1_000_000)
	if err := SetLearned([]string{"1.1.1.1"}, nil, 100, "probe", ""); err != nil {
		t.Fatal(err)
	}
	now = func() int64 { return 1_000_000 + 101_000 }
	if st := LearnedStatus(); st != nil {
		t.Fatal("expired source must drop")
	}
}

func TestLearnedStatusOmitsExpiredSources(t *testing.T) {
	// one lapsed and one live prober: the merged pool stays alive from the
	// live source, but the Sources view must not list the expired one.
	resetPool(t, 1_000_000)
	if err := SetLearned([]string{"1.1.1.1"}, nil, 60, "stale-probe", ""); err != nil {
		t.Fatal(err)
	}
	if err := SetLearned([]string{"2.2.2.1"}, nil, 600, "live-probe", ""); err != nil {
		t.Fatal(err)
	}
	now = func() int64 { return 1_000_000 + 61_000 }
	st := LearnedStatus()
	if st == nil {
		t.Fatal("live source must keep the merged pool alive")
	}
	if len(st.Sources) != 1 || st.Sources[0].Source != "live-probe" {
		t.Fatalf("sources = %+v", st.Sources)
	}
}

func TestPreferredLayering(t *testing.T) {
	resetPool(t, 1_000_000)
	cfg := &config.Config{}
	clientScope := "58.247.22/24"
	ispScope := "isp:chinanet"

	// client > isp > national > learned; fill top-up per family
	mustSet(t, []string{"58.247.22.1", "58.247.22.2"}, []string{"2606:4700::1"}, 600, "probe-client", clientScope)
	mustSet(t, []string{"1.2.3.4"}, nil, 600, "hub-isp", ispScope)
	mustSet(t, []string{"5.6.7.8", "5.6.7.9", "5.6.7.10", "5.6.7.11", "5.6.7.12", "5.6.7.13", "5.6.7.14"}, nil, 600, "hub-national", ScopeNational)
	mustSet(t, []string{"9.9.9.9"}, nil, 600, "probe-default", "")

	pool, err := Preferred(context.Background(), nil, nil, nil, true, cfg, clientScope, ispScope)
	if err != nil {
		t.Fatal(err)
	}
	// v4: client 2 + isp 1 + national topped to 6
	eq(t, pool.IPv4, "58.247.22.1", "58.247.22.2", "1.2.3.4", "5.6.7.8", "5.6.7.9", "5.6.7.10")
	// v6: client only (national has none, learned has none)
	eq(t, pool.IPv6, "2606:4700::1")
	// scope tags the contributing narrow layers (national/learned contribute no scope)
	if pool.Scope != clientScope+","+ispScope {
		t.Fatalf("scope = %q", pool.Scope)
	}
}

func TestPreferredExplicitSkipsLayers(t *testing.T) {
	resetPool(t, 1_000_000)
	cfg := &config.Config{CFPreferredIPv4: []string{"203.0.113.1"}}
	mustSet(t, []string{"1.1.1.1"}, nil, 600, "probe", "")

	pool, err := Preferred(context.Background(), []string{"9.9.9.9"}, nil, nil, false, cfg, "", "")
	if err != nil {
		t.Fatal(err)
	}
	eq(t, pool.IPv4, "9.9.9.9")

	// static config applies when nothing else supplies the family
	pool, err = Preferred(context.Background(), nil, nil, nil, false, cfg, "", "")
	if err != nil {
		t.Fatal(err)
	}
	eq(t, pool.IPv4, "203.0.113.1")
}

func TestPreferredDropAAAA(t *testing.T) {
	resetPool(t, 1_000_000)
	cfg := &config.Config{CFDropAAAA: true, CFPreferredIPv6: []string{"2606:4700::1"}}
	pool, err := Preferred(context.Background(), nil, []string{"2606:4700::9"}, nil, false, cfg, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(pool.IPv6) != 0 {
		t.Fatalf("drop_aaaa must clear v6 even when explicit: %v", pool.IPv6)
	}
}

func TestPreferredDomainFallback(t *testing.T) {
	resetPool(t, 1_000_000)
	var v4hits, v6hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		if _, err := r.Body.Read(body); err != nil && len(body) == 0 {
			return
		}
		parsed, _ := wire.Parse(body)
		resp := &wire.Packet{Header: wire.Header{ID: parsed.Header.ID, Flags: 0x8180}, Questions: parsed.Questions}
		q := parsed.Questions[0]
		switch q.Name {
		case "cf.example.":
			if q.Type == wire.TypeA {
				v4hits.Add(1)
				ip, _ := wire.ParseIPv4("104.18.1.1")
				resp.Answers = append(resp.Answers, wire.Record{Name: q.Name, Type: wire.TypeA, Class: wire.ClassIN, TTL: 60, RData: wire.A{IP: ip}})
			} else {
				v6hits.Add(1)
				ip, _ := wire.ParseIPv6("2606:4700::1")
				resp.Answers = append(resp.Answers, wire.Record{Name: q.Name, Type: wire.TypeAAAA, Class: wire.ClassIN, TTL: 60, RData: wire.AAAA{IP: ip}})
			}
		default:
			// dead.example and friends: SERVFAIL-ish empty
			resp.Header.Flags = 0x8182
		}
		out, _ := resp.Encode()
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(out)
	}))
	defer srv.Close()
	cfg := &config.Config{Upstreams: []string{srv.URL}, EcsUpstreams: []string{srv.URL}, UpstreamTimeoutMs: 1000, MaxDNSPacketSize: 4096}

	// no learned layers: domains resolve; single dead domain tolerated
	pool, err := Preferred(context.Background(), nil, nil, []string{"cf.example", "dead.example"}, true, cfg, "", "")
	if err != nil {
		t.Fatal(err)
	}
	eq(t, pool.IPv4, "104.18.1.1")
	// upstream address rendering is the padded 8-group form
	if len(pool.IPv6) != 1 || pool.IPv6[0] != "2606:4700:0000:0000:0000:0000:0000:0001" {
		t.Fatalf("v6 = %v", pool.IPv6)
	}

	// all domains dead: error
	if _, err := Preferred(context.Background(), nil, nil, []string{"dead.example"}, true, cfg, "", ""); err == nil {
		t.Fatal("all domains failing must error")
	}
}

func TestHostPoolsMajorityAndWithdraw(t *testing.T) {
	resetPool(t, 1_000_000)
	SetGithub("p1", map[string][]string{"github.com": {"140.82.1.1", "140.82.1.2"}}, 600)
	SetGithub("p2", map[string][]string{"github.com": {"140.82.1.1", "140.82.2.2"}}, 600)
	// majority (both) vouches 140.82.1.1; the rest is one vote each → 1.1
	// first, then interleave picks per block cap… assert via combine of 2 lists
	eq(t, GithubPoolFor("github.com"), "140.82.1.1", "140.82.1.2", "140.82.2.2")

	// withdraw: p2 stops listing github.com
	SetGithub("p2", map[string][]string{}, 600)
	eq(t, GithubPoolFor("github.com"), "140.82.1.1", "140.82.1.2")

	// host casing and trailing dot
	eq(t, GithubPoolFor("GitHub.com."), "140.82.1.1", "140.82.1.2")

	// expiry drops everything
	now = func() int64 { return 1_000_000 + 601_000 }
	if got := GithubPoolFor("github.com"); got != nil {
		t.Fatalf("expired pools = %v", got)
	}
}

func TestSitePoolTag(t *testing.T) {
	resetPool(t, 1_000_000)
	if tag := SitePoolTag("linux.do"); tag != "" {
		t.Fatalf("empty tag = %q", tag)
	}
	SetSites("checker", map[string][]string{"linux.do": {"104.18.1.1", "104.18.1.2"}}, 600)
	first := SitePoolTag("linux.do")
	if len(first) < 5 || first[:4] != "site" {
		t.Fatalf("tag = %q", first)
	}
	// identical content: stable tag
	SetSites("checker2", map[string][]string{"linux.do": {"104.18.1.1", "104.18.1.2"}}, 600)
	if SitePoolTag("linux.do") != first {
		t.Fatal("same merged content must keep the tag")
	}
	// different content: different tag (both majority sources replaced)
	SetSites("checker", map[string][]string{"linux.do": {"104.18.9.9"}}, 600)
	SetSites("checker2", map[string][]string{"linux.do": {"104.18.9.9"}}, 600)
	if SitePoolTag("linux.do") == first {
		t.Fatal("content change must change the tag")
	}
	if st := SiteStatus(); st == nil || len(st.Hosts) != 1 {
		t.Fatalf("site status = %+v", st)
	}
}

func TestHostPoolStatusSources(t *testing.T) {
	resetPool(t, 1_000_000)
	SetSites("a", map[string][]string{"x.example": {"1.1.1.1"}}, 600)
	SetSites("b", map[string][]string{"y.example": {"2.2.2.2"}}, 600)
	st := SiteStatus()
	if st == nil || len(st.Sources) != 2 {
		t.Fatalf("sources = %+v", st)
	}
	if len(st.Hosts) != 2 {
		t.Fatalf("hosts = %v", st.Hosts)
	}
}

func mustSet(t *testing.T, ipv4, ipv6 []string, ttl int, source, scope string) {
	t.Helper()
	if err := SetLearned(ipv4, ipv6, ttl, source, scope); err != nil {
		t.Fatal(err)
	}
}

func TestPreferredConcurrentOnExpiredPools(t *testing.T) {
	resetPool(t, 1_000_000)
	cfg := &config.Config{}
	clientScope := "58.247.22/24"
	mustSet(t, []string{"58.247.22.1"}, nil, 50, "probe", clientScope)
	mustSet(t, []string{"1.2.3.4"}, nil, 50, "hub", "isp:chinanet")
	mustSet(t, []string{"5.6.7.8"}, nil, 5000, "hub", ScopeNational)

	// expire the narrow pools; concurrent Preferred calls all hit the
	// expired entries while collecting layers — this used to race (read
	// lock + lazy delete) and must stay clean under -race
	now = func() int64 { return 1_000_000 + 60_000 }
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pool, err := Preferred(context.Background(), nil, nil, nil, true, cfg, clientScope, "isp:chinanet")
			if err != nil {
				t.Errorf("Preferred: %v", err)
				return
			}
			eq(t, pool.IPv4, "5.6.7.8")
		}()
	}
	wg.Wait()
}
