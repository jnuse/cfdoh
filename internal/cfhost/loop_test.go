package cfhost

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDecideHysteresis(t *testing.T) {
	const ms = time.Millisecond
	cases := []struct {
		name         string
		hasCur       bool
		curOK        bool
		curStreak    int
		failover     int
		curMedian    time.Duration
		newMedian    time.Duration
		hysteresis   float64
		wantKeep     bool
		wantStreak   int
		wantForced   bool
	}{
		{"no current adopts new", false, false, 0, 3, 0, 100 * ms, 0.2, false, 0, false},
		{"5 percent gain keeps current", true, true, 0, 3, 100 * ms, 95 * ms, 0.2, true, 0, false},
		{"25 percent gain switches", true, true, 0, 3, 100 * ms, 75 * ms, 0.2, false, 0, false},
		{"alive current resets streak", true, true, 2, 3, 100 * ms, 95 * ms, 0.2, true, 0, false},
		{"failed current increments streak", true, false, 0, 3, 0, 50 * ms, 0.2, true, 1, false},
		{"failed current keeps accumulating", true, false, 1, 3, 0, 50 * ms, 0.2, true, 2, false},
		{"streak reaches failover forces switch", true, false, 2, 3, 0, 500 * ms, 0.2, false, 0, true},
		{"zero hysteresis any gain switches", true, true, 0, 3, 100 * ms, 99 * ms, 0, false, 0, false},
		{"zero hysteresis equal median keeps", true, true, 0, 3, 100 * ms, 100 * ms, 0, true, 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			keep, streak, forced := decideHysteresis(c.hasCur, c.curOK, c.curStreak,
				c.failover, c.curMedian, c.newMedian, c.hysteresis)
			if keep != c.wantKeep || streak != c.wantStreak || forced != c.wantForced {
				t.Fatalf("got keep=%v streak=%d forced=%v, want keep=%v streak=%d forced=%v",
					keep, streak, forced, c.wantKeep, c.wantStreak, c.wantForced)
			}
		})
	}
}

func TestDecideV6(t *testing.T) {
	const ms = time.Millisecond
	cur := "2606:4700::1"
	curAddr := netip.MustParseAddr(cur)
	newAddr := netip.MustParseAddr("2606:4700::2")
	byAddr := map[netip.Addr]probeOutcome{
		curAddr: {addr: curAddr, median: 100 * ms, ok: true},
	}
	top := &probeOutcome{addr: newAddr, median: 95 * ms, ok: true}
	topBad := &probeOutcome{addr: newAddr, median: 0, ok: false}

	cases := []struct {
		name    string
		cur     string
		byAddr  map[netip.Addr]probeOutcome
		top     *probeOutcome
		wantNew bool
		wantHas bool
	}{
		{"no top keeps nothing", "", byAddr, nil, false, false},
		{"no top keeps current", cur, byAddr, nil, false, true},
		{"no current adopts top", "", byAddr, top, true, true},
		{"failed current adopts top", cur, map[netip.Addr]probeOutcome{}, top, true, true},
		{"insufficient gain keeps current", cur, byAddr, top, false, true},
		{"corrupt current adopts top", "not-an-addr", byAddr, top, true, true},
		{"dead top keeps nothing", "", byAddr, topBad, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			addr, has := decideV6(c.cur, c.byAddr, c.top, 0.2)
			if has != c.wantHas {
				t.Fatalf("has=%v want %v", has, c.wantHas)
			}
			if c.wantHas && c.wantNew && addr != c.top.addr {
				t.Fatalf("should adopt new top, got %v", addr)
			}
			if c.wantHas && !c.wantNew && c.cur != "" && addr.String() != c.cur {
				t.Fatalf("should keep current, got %v", addr)
			}
		})
	}
	// A top with a big gain switches.
	addr, has := decideV6(cur, byAddr, &probeOutcome{addr: newAddr, median: 20 * ms, ok: true}, 0.2)
	if !has || addr != newAddr {
		t.Fatalf("20%% of median should switch: %v has=%v", addr, has)
	}
}

func testConfig(t *testing.T, hosts, state string, sources ...string) *Config {
	t.Helper()
	return &Config{
		ManagedDomains: []string{"d.example.com"},
		Sources:        sources,
		Concurrency:    2,
		Timeout:        300,
		Rounds:         1,
		Hysteresis:     0.2,
		FailoverRounds: 3,
		Interval:       time.Minute,
		HostsPath:      hosts,
		StatePath:      state,
		CandidateLimit: 16,
	}
}

func TestRunOnceNoCandidatesNoHistory(t *testing.T) {
	dir := t.TempDir()
	hostsPath := filepath.Join(dir, "hosts")
	hostsContent := []byte("user mapping\r\n")
	if err := os.WriteFile(hostsPath, hostsContent, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := testConfig(t, hostsPath, filepath.Join(dir, "state.json"), "list:")

	err := RunOnce(context.Background(), cfg)
	if err == nil {
		t.Fatal("all sources failed with no history must error")
	}
	got, _ := os.ReadFile(hostsPath)
	if string(got) != string(hostsContent) {
		t.Fatalf("hosts must stay untouched:\n%q", got)
	}
}

func TestRunOnceProbeFailureKeepsHosts(t *testing.T) {
	dir := t.TempDir()
	hostsPath := filepath.Join(dir, "hosts")
	block := renderBlock([]string{"d.example.com"}, netip.MustParseAddr("9.9.9.9"), netip.Addr{}, false)
	if err := os.WriteFile(hostsPath, block, 0o644); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(dir, "state.json")

	// TEST-NET-3 address: public unicast (passes the filter) but unroutable.
	cfg := testConfig(t, hostsPath, statePath, "list:203.0.113.201")
	if err := RunOnce(context.Background(), cfg); err != nil {
		t.Fatalf("full probe failure should not error: %v", err)
	}

	got, _ := os.ReadFile(hostsPath)
	if string(got) != string(block) {
		t.Fatalf("hosts must stay untouched on full probe failure:\n%q", got)
	}
	st, found := loadState(statePath)
	if !found {
		t.Fatal("state should be written")
	}
	if !strings.Contains(st.LastSummary, "best_v4=none") {
		t.Fatalf("summary should record failure: %q", st.LastSummary)
	}
	if st.FailStreak != 1 {
		t.Fatalf("fail streak should be 1, got %d", st.FailStreak)
	}
	if st.NextRun <= 0 {
		t.Fatal("next_run should be scheduled")
	}
	if len(st.Candidates) != 1 || st.Candidates[0] != "203.0.113.201" {
		t.Fatalf("candidates should persist for fallback: %v", st.Candidates)
	}
}
