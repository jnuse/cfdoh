package pool

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// stateTestResetTables clears all five package tables (tests mutate state).
func stateTestResetTables() {
	mu.Lock()
	defaults = newPoolTable(MaxDefaultSources)
	scoped = newPoolTable(MaxScopedPools)
	ispPools = newPoolTable(MaxIspPools)
	mu.Unlock()
	github = newHostPools(MaxHostSources)
	sites = newHostPools(MaxHostSources)
}

// stateTestFreezeClock pins the package clock for one test.
func stateTestFreezeClock(t *testing.T, at int64) {
	t.Helper()
	previous := now
	now = func() int64 { return at }
	t.Cleanup(func() { now = previous })
}

// hostStatusEmpty matches the never-nil contract: an empty host-pool
// report is a non-nil object with no sources and no hosts.
func hostStatusEmpty(s *HostPoolStatus) bool {
	return s != nil && len(s.Sources) == 0 && len(s.Hosts) == 0
}

func TestPoolStateRoundTrip(t *testing.T) {
	stateTestResetTables()
	stateTestFreezeClock(t, 1_000_000)

	if err := SetLearned([]string{"104.16.1.1", "104.16.1.2"}, []string{"2606:4700::1111"}, 300, "probe-a", ""); err != nil {
		t.Fatalf("SetLearned: %v", err)
	}
	if err := SetLearned([]string{"104.16.2.1"}, nil, 600, "probe-b", ""); err != nil {
		t.Fatalf("SetLearned: %v", err)
	}
	if err := SetLearned([]string{"104.16.3.1"}, []string{"2606:4700::2222"}, 600, "probe-a", "2001:db8::/48"); err != nil {
		t.Fatalf("SetLearned: %v", err)
	}
	if err := SetLearned([]string{"104.16.4.1"}, nil, 900, "probe-isp", "isp:cmcc"); err != nil {
		t.Fatalf("SetLearned: %v", err)
	}
	SetGithub("hub-a", map[string][]string{"github.com": {"140.82.1.1", "140.82.1.2"}}, 300)
	SetSites("hub-b", map[string][]string{"example.com": {"93.184.1.1"}}, 300)

	learnedBefore := LearnedStatus()
	scopedBefore := ScopedStatus()
	ispBefore := IspPoolStatus()
	githubBefore := GithubStatus()
	sitesBefore := SiteStatus()

	path := filepath.Join(t.TempDir(), "pool-state.json")
	if err := SaveState(path); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	stateTestResetTables()
	if LearnedStatus() != nil || len(ScopedStatus()) != 0 || len(IspPoolStatus()) != 0 ||
		!hostStatusEmpty(GithubStatus()) || !hostStatusEmpty(SiteStatus()) {
		t.Fatal("tables not cleared before LoadState")
	}
	if err := LoadState(path); err != nil {
		t.Fatalf("LoadState: %v", err)
	}

	if got := LearnedStatus(); !reflect.DeepEqual(got, learnedBefore) {
		t.Errorf("learned table mismatch:\n got %+v\nwant %+v", got, learnedBefore)
	}
	if got := ScopedStatus(); !reflect.DeepEqual(got, scopedBefore) {
		t.Errorf("scoped table mismatch:\n got %+v\nwant %+v", got, scopedBefore)
	}
	if got := IspPoolStatus(); !reflect.DeepEqual(got, ispBefore) {
		t.Errorf("isp table mismatch:\n got %+v\nwant %+v", got, ispBefore)
	}
	if got := GithubStatus(); !reflect.DeepEqual(got, githubBefore) {
		t.Errorf("github table mismatch:\n got %+v\nwant %+v", got, githubBefore)
	}
	if got := SiteStatus(); !reflect.DeepEqual(got, sitesBefore) {
		t.Errorf("sites table mismatch:\n got %+v\nwant %+v", got, sitesBefore)
	}
}

func TestPoolStateSkipsExpiredEntries(t *testing.T) {
	stateTestResetTables()
	stateTestFreezeClock(t, 1_000_000)

	if err := SetLearned([]string{"104.16.1.1"}, nil, 1, "probe-old", ""); err != nil {
		t.Fatalf("SetLearned: %v", err)
	}
	if err := SetLearned([]string{"104.16.2.1"}, nil, 600, "probe-live", ""); err != nil {
		t.Fatalf("SetLearned: %v", err)
	}
	if err := SetLearned([]string{"104.16.3.1"}, nil, 1, "probe-old", "2001:db8::/48"); err != nil {
		t.Fatalf("SetLearned: %v", err)
	}
	SetGithub("hub-old", map[string][]string{"github.com": {"140.82.1.1"}}, 1)
	SetGithub("hub-live", map[string][]string{"github.com": {"140.82.2.2"}}, 600)

	now = func() int64 { return 1_002_000 } // past the ttl=1 entries

	path := filepath.Join(t.TempDir(), "pool-state.json")
	if err := SaveState(path); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	stateTestResetTables()
	if err := LoadState(path); err != nil {
		t.Fatalf("LoadState: %v", err)
	}

	learned := LearnedStatus()
	if learned == nil || len(learned.Sources) != 1 || learned.Sources[0].Source != "probe-live" {
		t.Errorf("expired self-learning entry survived: %+v", learned)
	}
	if got := ScopedStatus(); len(got) != 0 {
		t.Errorf("expired scoped entry survived: %+v", got)
	}
	githubStatus := GithubStatus()
	if githubStatus == nil || len(githubStatus.Sources) != 1 || githubStatus.Sources[0].Source != "hub-live" {
		t.Fatalf("expired github entry survived: %+v", githubStatus)
	}
	if len(githubStatus.Hosts) != 1 {
		t.Fatalf("github hosts = %v, want exactly one host", githubStatus.Hosts)
	}
	for host, pool := range githubStatus.Hosts {
		if !reflect.DeepEqual(pool, []string{"140.82.2.2"}) {
			t.Errorf("github pool for %s = %v, want [140.82.2.2]", host, pool)
		}
	}
}

func TestPoolStateCorruptFile(t *testing.T) {
	stateTestResetTables()
	path := filepath.Join(t.TempDir(), "pool-state.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := LoadState(path); err != nil {
		t.Fatalf("corrupt snapshot must not fail: %v", err)
	}
	if LearnedStatus() != nil || len(ScopedStatus()) != 0 || !hostStatusEmpty(GithubStatus()) || !hostStatusEmpty(SiteStatus()) {
		t.Error("state must stay empty after unreadable snapshot")
	}

	if err := os.WriteFile(path, []byte(`{"version":99}`), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := LoadState(path); err != nil {
		t.Fatalf("unknown version must not fail: %v", err)
	}
	if LearnedStatus() != nil || !hostStatusEmpty(GithubStatus()) {
		t.Error("state must stay empty after unknown version")
	}
}

func TestPoolStateMissingFile(t *testing.T) {
	stateTestResetTables()
	if err := LoadState(filepath.Join(t.TempDir(), "absent.json")); err != nil {
		t.Fatalf("missing snapshot must be a no-op: %v", err)
	}
	if LearnedStatus() != nil || len(ScopedStatus()) != 0 || !hostStatusEmpty(GithubStatus()) {
		t.Error("state must stay empty without a snapshot")
	}
}
