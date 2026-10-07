package cfhost

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDecideHysteresis(t *testing.T) {
	const ms = time.Millisecond
	cases := []struct {
		name       string
		hasCur     bool
		curOK      bool
		curStreak  int
		failover   int
		curMedian  time.Duration
		newMedian  time.Duration
		hysteresis float64
		wantKeep   bool
		wantStreak int
		wantForced bool
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

func TestNextDelayFallsBackToInterval(t *testing.T) {
	// Missing (zero) or stale next_run — e.g. when the state file could not
	// be saved — must fall back to a full interval instead of collapsing
	// the loop into a busy spin.
	interval := 10 * time.Minute
	if got := nextDelay(clientState{NextRun: 0}, interval); got != interval {
		t.Fatalf("zero next_run should sleep a full interval, got %v", got)
	}
	past := time.Now().Add(-time.Hour).Unix()
	if got := nextDelay(clientState{NextRun: past}, interval); got != interval {
		t.Fatalf("stale next_run should sleep a full interval, got %v", got)
	}
	future := time.Now().Add(90 * time.Second).Unix()
	got := nextDelay(clientState{NextRun: future}, interval)
	if got <= 0 || got > 90*time.Second {
		t.Fatalf("future next_run should sleep until it, got %v", got)
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

// withFakeProbes injects a deterministic successful probe sweep so RunOnce
// and RunLoop tests drive the hosts-update path without network access.
func withFakeProbes(t *testing.T, outcomes ...probeOutcome) {
	t.Helper()
	old := runProbes
	runProbes = func(ctx context.Context, addrs []netip.Addr, opts probeOptions) []probeOutcome {
		return outcomes
	}
	t.Cleanup(func() { runProbes = old })
}

func TestRunOnceHostsWriteFailureSkipsRound(t *testing.T) {
	// Persistent hosts write failure (rename retries exhausted): RunOnce
	// returns nil, hosts stays untouched, the current address and fail
	// streak survive unchanged and the state (next run, candidates) is
	// saved — the daemon retries next cycle.
	dir := t.TempDir()
	hostsPath := hostsFileWithBlock(t, dir)
	orig, _ := os.ReadFile(hostsPath)
	orig = append([]byte("user mapping\r\n"), orig...)
	if err := os.WriteFile(hostsPath, orig, 0o644); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(dir, "state.json")
	if err := saveState(statePath, clientState{CurrentV4: "9.9.9.9"}); err != nil {
		t.Fatal(err)
	}

	// Current 9.9.9.9 alive at 100ms, candidate 1.1.1.1 at 10ms: a >20%
	// gain forces a switch, so a write is attempted (and injected to fail).
	cur := netip.MustParseAddr("9.9.9.9")
	cand := netip.MustParseAddr("1.1.1.1")
	withFakeProbes(t,
		probeOutcome{addr: cand, median: 10 * time.Millisecond, ok: true},
		probeOutcome{addr: cur, median: 100 * time.Millisecond, ok: true})
	withHostsSeams(t,
		func() string { return "" },
		func(a, b string) bool { return false },
		func(oldpath, newpath string) error { return errFakeLock },
		func(err error) bool { return errors.Is(err, errFakeLock) },
		0)

	cfg := testConfig(t, hostsPath, statePath, "list:1.1.1.1")
	if err := RunOnce(context.Background(), cfg); err != nil {
		t.Fatalf("hosts write failure must skip the round, not fail RunOnce: %v", err)
	}

	got, _ := os.ReadFile(hostsPath)
	if !bytes.Equal(got, orig) {
		t.Fatalf("hosts must stay untouched on write failure:\n%q", got)
	}
	st, found := loadState(statePath)
	if !found {
		t.Fatal("state must be saved on skip")
	}
	if st.CurrentV4 != "9.9.9.9" {
		t.Fatalf("current v4 must survive the skip, got %q", st.CurrentV4)
	}
	if st.FailStreak != 0 {
		t.Fatalf("fail streak must stay unchanged, got %d", st.FailStreak)
	}
	if st.NextRun <= 0 {
		t.Fatal("next_run must be scheduled despite the skip")
	}
	if len(st.Candidates) != 1 || st.Candidates[0] != "1.1.1.1" {
		t.Fatalf("candidates must persist: %v", st.Candidates)
	}
}

func TestRunLoopSurvivesHostsWriteFailure(t *testing.T) {
	// The daemon loop must not exit while every hosts write fails: passes
	// keep running (each burning the full rename retry budget) until the
	// context is cancelled, and cancellation still returns nil.
	dir := t.TempDir()
	hostsPath := hostsFileWithBlock(t, dir)
	statePath := filepath.Join(dir, "state.json")

	var calls atomic.Int64
	withFakeProbes(t,
		probeOutcome{addr: netip.MustParseAddr("1.1.1.1"), median: 10 * time.Millisecond, ok: true})
	withHostsSeams(t,
		func() string { return "" },
		func(a, b string) bool { return false },
		func(oldpath, newpath string) error {
			calls.Add(1)
			return errFakeLock
		},
		func(err error) bool { return errors.Is(err, errFakeLock) },
		0)

	cfg := testConfig(t, hostsPath, statePath, "list:1.1.1.1")
	cfg.Interval = 20 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- RunLoop(ctx, cfg) }()

	// Two full passes = 2*(1 initial + renameRetryMax retries) calls. A
	// RunLoop that died on the first write failure would stall here.
	wantCalls := int64(2 * (1 + renameRetryMax))
	deadline := time.Now().Add(10 * time.Second)
	for calls.Load() < wantCalls && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RunLoop must survive hosts write failures and stop cleanly, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunLoop did not return after cancel")
	}
	if calls.Load() < wantCalls {
		t.Fatalf("expected >= %d rename calls (two full passes), got %d", wantCalls, calls.Load())
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

func TestRunOnceLockedRefusesWhileHeld(t *testing.T) {
	// run-once shares the single-instance lock with the daemon: while a
	// live holder keeps it, RunOnceLocked refuses without running a pass;
	// once free, the pass runs to completion and releases the lock again
	// (a stale lock from a dead holder is taken over by acquireLock).
	dir := t.TempDir()
	hostsPath := filepath.Join(dir, "hosts")
	statePath := filepath.Join(dir, "state.json")
	cfg := testConfig(t, hostsPath, statePath, "list:1.1.1.1")

	release, err := acquireLock(statePath)
	if err != nil {
		t.Fatalf("seed lock: %v", err)
	}
	if err := RunOnceLocked(context.Background(), cfg); err == nil ||
		!strings.Contains(err.Error(), "another cfhost instance") {
		t.Fatalf("run-once under a live lock must refuse, got %v", err)
	}
	release()

	cand := netip.MustParseAddr("1.1.1.1")
	withFakeProbes(t, probeOutcome{addr: cand, median: 10 * time.Millisecond, ok: true})
	if err := RunOnceLocked(context.Background(), cfg); err != nil {
		t.Fatalf("RunOnceLocked after release: %v", err)
	}
	st, found := loadState(statePath)
	if !found || st.CurrentV4 != "1.1.1.1" {
		t.Fatalf("pass must run under the lock, state=%+v found=%v", st, found)
	}
	if _, err := acquireLock(statePath); err != nil {
		t.Fatalf("lock must be free after RunOnceLocked: %v", err)
	}
}
