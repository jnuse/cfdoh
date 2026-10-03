package h3

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// stateTestReset clears the verdict source table and generation.
func stateTestReset() {
	mu.Lock()
	sources = make(map[string]*report)
	sourceOrder.Init()
	generation = 0
	lastSnapshot = ""
	mu.Unlock()
}

// stateTestFreezeClock pins the package clock for one test.
func stateTestFreezeClock(t *testing.T, at int64) {
	t.Helper()
	previous := now
	now = func() int64 { return at }
	t.Cleanup(func() { now = previous })
}

func TestH3StateRoundTrip(t *testing.T) {
	stateTestReset()
	stateTestFreezeClock(t, 1_000_000)

	SetVerdicts("probe-a", map[string]bool{"example.com": true, "api.example.com": false}, 300)
	SetVerdicts("probe-b", map[string]bool{"example.com": true, "other.test": true}, 600)

	before := Status()

	path := filepath.Join(t.TempDir(), "h3-state.json")
	if err := SaveState(path); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	stateTestReset()
	if got := Status(); len(got.Effective) != 0 || len(got.Sources) != 0 {
		t.Fatal("state not cleared before LoadState")
	}
	if err := LoadState(path); err != nil {
		t.Fatalf("LoadState: %v", err)
	}

	if after := Status(); !reflect.DeepEqual(after, before) {
		t.Errorf("verdict table mismatch:\n got %+v\nwant %+v", after, before)
	}
}

func TestH3StateSkipsExpiredSources(t *testing.T) {
	stateTestReset()
	stateTestFreezeClock(t, 1_000_000)

	SetVerdicts("probe-old", map[string]bool{"old.test": true}, 1)
	SetVerdicts("probe-live", map[string]bool{"live.test": false}, 600)

	now = func() int64 { return 1_002_000 } // past the ttl=1 report

	path := filepath.Join(t.TempDir(), "h3-state.json")
	if err := SaveState(path); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	stateTestReset()
	if err := LoadState(path); err != nil {
		t.Fatalf("LoadState: %v", err)
	}

	status := Status()
	if len(status.Sources) != 1 || status.Sources[0].Source != "probe-live" {
		t.Errorf("expired source survived: %+v", status.Sources)
	}
	if len(status.Effective) != 1 {
		t.Fatalf("effective = %+v, want exactly the live entry", status.Effective)
	}
	for host, allowed := range status.Effective {
		if allowed {
			t.Errorf("host %s must stay denied after restore", host)
		}
	}
}

func TestH3StateCorruptFile(t *testing.T) {
	stateTestReset()
	path := filepath.Join(t.TempDir(), "h3-state.json")
	if err := os.WriteFile(path, []byte("}}}"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := LoadState(path); err != nil {
		t.Fatalf("corrupt snapshot must not fail: %v", err)
	}
	if status := Status(); len(status.Effective) != 0 || len(status.Sources) != 0 {
		t.Error("state must stay empty after unreadable snapshot")
	}

	if err := os.WriteFile(path, []byte(`{"version":7}`), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := LoadState(path); err != nil {
		t.Fatalf("unknown version must not fail: %v", err)
	}
	if status := Status(); len(status.Sources) != 0 {
		t.Error("state must stay empty after unknown version")
	}
}

func TestH3StateMissingFile(t *testing.T) {
	stateTestReset()
	if err := LoadState(filepath.Join(t.TempDir(), "absent.json")); err != nil {
		t.Fatalf("missing snapshot must be a no-op: %v", err)
	}
	if status := Status(); len(status.Effective) != 0 || len(status.Sources) != 0 {
		t.Error("state must stay empty without a snapshot")
	}
}
