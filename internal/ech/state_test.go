package ech

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// stateTestReset clears the publish cache and the Meta override.
func stateTestReset() {
	mu.Lock()
	publish = make(map[string]*cachedConfig)
	meta = nil
	metaGen = 0
	mu.Unlock()
}

// stateTestFreezeClock pins the package clock for one test.
func stateTestFreezeClock(t *testing.T, at int64) {
	t.Helper()
	previous := now
	now = func() int64 { return at }
	t.Cleanup(func() { now = previous })
}

// stateTestConfig builds a minimal valid ECHConfigList.
func stateTestConfig() []byte {
	return []byte{0x00, 0x04, 0x00, 0x0d, 0x00, 0x00}
}

func TestEchStateRoundTrip(t *testing.T) {
	stateTestReset()
	stateTestFreezeClock(t, 1_000_000)

	mu.Lock()
	publish["cloudflare-ech.com."] = &cachedConfig{data: stateTestConfig(), expiresAt: 1_000_000 + 3_600_000}
	mu.Unlock()
	SetMeta(stateTestConfig(), 600, "probe-a", "learned key")

	before := Status()

	path := filepath.Join(t.TempDir(), "ech-state.json")
	if err := SaveState(path); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	stateTestReset()
	if Status() != nil {
		t.Fatal("meta not cleared before LoadState")
	}
	mu.Lock()
	empty := len(publish) == 0
	mu.Unlock()
	if !empty {
		t.Fatal("publish cache not cleared before LoadState")
	}
	if err := LoadState(path); err != nil {
		t.Fatalf("LoadState: %v", err)
	}

	if after := Status(); !reflect.DeepEqual(after, before) {
		t.Errorf("meta state mismatch:\n got %+v\nwant %+v", after, before)
	}
	cfg, state := MetaOverride()
	if state != MetaLearned || !sameBytes(cfg, stateTestConfig()) {
		t.Errorf("MetaOverride after load = %v (state %d), want the learned config", cfg, state)
	}
	mu.Lock()
	cached, ok := publish["cloudflare-ech.com."]
	restored := ok && sameBytes(cached.data, stateTestConfig()) && cached.expiresAt == 1_000_000+3_600_000
	mu.Unlock()
	if !restored {
		t.Errorf("publish cache after load = %+v (present=%v)", cached, ok)
	}
}

func TestEchStateSuspendedRoundTrip(t *testing.T) {
	stateTestReset()
	stateTestFreezeClock(t, 1_000_000)

	SetMetaSuspended(600, "probe-a", "quic broken")
	before := Status()

	path := filepath.Join(t.TempDir(), "ech-state.json")
	if err := SaveState(path); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	stateTestReset()
	if err := LoadState(path); err != nil {
		t.Fatalf("LoadState: %v", err)
	}

	cfg, state := MetaOverride()
	if state != MetaSuspended || cfg != nil {
		t.Errorf("MetaOverride after load = %v (state %d), want suspended without config", cfg, state)
	}
	if after := Status(); !reflect.DeepEqual(after, before) {
		t.Errorf("suspended meta mismatch:\n got %+v\nwant %+v", after, before)
	}
}

func TestEchStateSkipsExpiredEntries(t *testing.T) {
	stateTestReset()
	stateTestFreezeClock(t, 1_000_000)

	mu.Lock()
	publish["expired.example."] = &cachedConfig{data: stateTestConfig(), expiresAt: 1_000_500}
	mu.Unlock()
	SetMeta(stateTestConfig(), 1, "probe-a", "learned")

	now = func() int64 { return 1_001_000 } // past both entries

	path := filepath.Join(t.TempDir(), "ech-state.json")
	if err := SaveState(path); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	stateTestReset()
	if err := LoadState(path); err != nil {
		t.Fatalf("LoadState: %v", err)
	}

	mu.Lock()
	publishLen, metaLeft := len(publish), meta
	mu.Unlock()
	if publishLen != 0 {
		t.Errorf("expired publish entry survived: %d entries", publishLen)
	}
	if metaLeft != nil {
		t.Errorf("expired meta survived: %+v", metaLeft)
	}
	if _, state := MetaOverride(); state != MetaSeed {
		t.Errorf("MetaOverride state = %d, want MetaSeed", state)
	}
}

func TestEchStateCorruptFile(t *testing.T) {
	stateTestReset()
	path := filepath.Join(t.TempDir(), "ech-state.json")
	if err := os.WriteFile(path, []byte("}}}"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := LoadState(path); err != nil {
		t.Fatalf("corrupt snapshot must not fail: %v", err)
	}
	if Status() != nil {
		t.Error("meta must stay empty after unreadable snapshot")
	}

	if err := os.WriteFile(path, []byte(`{"version":7}`), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := LoadState(path); err != nil {
		t.Fatalf("unknown version must not fail: %v", err)
	}
	if Status() != nil {
		t.Error("meta must stay empty after unknown version")
	}

	// invalid publish payload: skipped, load still succeeds
	if err := os.WriteFile(path, []byte(`{"version":1,"publish":{"x.":{"config":"!!!","expiresAt":999999999999}}}`), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := LoadState(path); err != nil {
		t.Fatalf("invalid publish entry must not fail: %v", err)
	}
	mu.Lock()
	publishLen := len(publish)
	mu.Unlock()
	if publishLen != 0 {
		t.Errorf("invalid publish entry survived: %d entries", publishLen)
	}
}

func TestEchStateMissingFile(t *testing.T) {
	stateTestReset()
	if err := LoadState(filepath.Join(t.TempDir(), "absent.json")); err != nil {
		t.Fatalf("missing snapshot must be a no-op: %v", err)
	}
	if Status() != nil {
		t.Error("state must stay empty without a snapshot")
	}
}
