package h3

import (
	"strings"
	"testing"
)

func resetH3(t *testing.T, base int64) {
	t.Helper()
	mu.Lock()
	sources = make(map[string]*report)
	sourceOrder.Init()
	generation = 0
	lastSnapshot = ""
	mu.Unlock()
	baseNow := func() int64 { return base }
	original := now
	now = baseNow
	t.Cleanup(func() { now = original })
}

func TestUnanimousApprovalRequired(t *testing.T) {
	resetH3(t, 1_000_000)
	SetVerdicts("probe-a", map[string]bool{"linux.do": true, "x.com": false}, 600)
	SetVerdicts("probe-b", map[string]bool{"linux.do": true, "x.com": true}, 600)

	// every source must confirm: linux.do ok from both → allowed
	v := VerdictFor("linux.do")
	if v == nil || !v.Allowed {
		t.Fatalf("linux.do verdict = %+v", v)
	}
	if len(v.Sources) != 2 {
		t.Fatalf("sources = %v", v.Sources)
	}
	// x.com: one fail veto
	v = VerdictFor("x.com")
	if v == nil || v.Allowed {
		t.Fatalf("x.com verdict = %+v, one fail must veto", v)
	}
	// suffix coverage + longest match: sub.linux.do inherits
	if v := VerdictFor("sub.linux.do"); v == nil || !v.Allowed || v.Host != "linux.do" {
		t.Fatalf("subdomain verdict = %+v", v)
	}
	// no data → nil
	if v := VerdictFor("unmeasured.example"); v != nil {
		t.Fatalf("unmeasured = %+v", v)
	}
}

func TestSuffixLongestMatch(t *testing.T) {
	resetH3(t, 1_000_000)
	SetVerdicts("probe", map[string]bool{
		"example.com":     true,
		"bad.example.com": false,
	}, 600)
	if v := VerdictFor("host.bad.example.com"); v == nil || v.Allowed || v.Host != "bad.example.com" {
		t.Fatalf("longest suffix must win: %+v", v)
	}
	if v := VerdictFor("good.example.com"); v == nil || !v.Allowed || v.Host != "example.com" {
		t.Fatalf("parent verdict: %+v", v)
	}
	// the reported host itself matches too
	if v := VerdictFor("example.com"); v == nil || !v.Allowed {
		t.Fatalf("host itself: %+v", v)
	}
}

func TestAlpnFor(t *testing.T) {
	resetH3(t, 1_000_000)
	SetVerdicts("probe", map[string]bool{"linux.do": true, "x.com": false}, 600)

	alpn, why := AlpnFor("linux.do", []string{"h2"})
	if len(alpn) != 2 || alpn[0] != "h3" || alpn[1] != "h2" {
		t.Fatalf("allowed alpn = %v", alpn)
	}
	if !strings.Contains(why, "works") {
		t.Fatalf("why = %q", why)
	}
	alpn, _ = AlpnFor("x.com", []string{"h2"})
	if len(alpn) != 1 || alpn[0] != "h2" {
		t.Fatalf("denied alpn = %v", alpn)
	}
	alpn, why = AlpnFor("plain.example", []string{"h2", "h3"})
	if len(alpn) != 2 || alpn[0] != "h2" {
		t.Fatalf("fallback alpn = %v", alpn)
	}
	if !strings.Contains(why, "default") {
		t.Fatalf("why = %q", why)
	}
}

func TestExpiryFallsBackToDefault(t *testing.T) {
	resetH3(t, 1_000_000)
	SetVerdicts("probe", map[string]bool{"linux.do": false}, 100)
	if v := VerdictFor("linux.do"); v == nil || v.Allowed {
		t.Fatalf("pre-expiry = %+v", v)
	}
	now = func() int64 { return 1_000_000 + 101_000 }
	if v := VerdictFor("linux.do"); v != nil {
		t.Fatalf("expired verdict = %+v", v)
	}
	if tag := CacheTag(); tag == "" {
		t.Fatal("tag must exist")
	}
}

func TestGenerationBumpsOnSnapshotChangeOnly(t *testing.T) {
	resetH3(t, 1_000_000)
	SetVerdicts("probe", map[string]bool{"linux.do": true}, 600)
	first := CacheTag()
	// identical re-report: no snapshot change, no bump
	SetVerdicts("probe", map[string]bool{"linux.do": true}, 600)
	if CacheTag() != first {
		t.Fatal("identical report must not bump the generation")
	}
	// verdict flip: bump
	SetVerdicts("probe", map[string]bool{"linux.do": false}, 600)
	second := CacheTag()
	if second == first {
		t.Fatal("flip must bump the generation")
	}
	// new source, same effective verdict: no change
	SetVerdicts("probe-2", map[string]bool{"linux.do": true, "other.example": true}, 600)
	// probe says fail, probe-2 says ok → linux.do flips to fail; other.example added → snapshot changed → bump
	if CacheTag() == second {
		t.Fatal("effective snapshot change must bump")
	}
	// expiry pruning changes the snapshot: bump
	now = func() int64 { return 1_000_000 + 601_000 }
	if CacheTag() == second {
		t.Fatal("pruning must bump when verdicts disappear")
	}
}

func TestCapacityLimits(t *testing.T) {
	resetH3(t, 1_000_000)
	verdicts := make(map[string]bool)
	for i := 0; i < 100; i++ {
		verdicts[string(rune('a'+i%26))+string(rune('a'+i/26))+".example"] = true
	}
	SetVerdicts("probe", verdicts, 600)
	st := Status()
	hostCount := 0
	for _, s := range st.Sources {
		if s.Source == "probe" {
			hostCount = len(s.Hosts)
		}
	}
	if hostCount != maxHosts {
		t.Fatalf("hosts per report = %d, want %d", hostCount, maxHosts)
	}

	for i := 0; i < maxSources+3; i++ {
		SetVerdicts(string(rune('A'+i)), map[string]bool{"x.example": true}, 600)
	}
	st = Status()
	if len(st.Sources) > maxSources {
		t.Fatalf("sources = %d, want <= %d", len(st.Sources), maxSources)
	}
}
