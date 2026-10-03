package cfhost

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestStateRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "state.json")
	st := clientState{
		CurrentV4:   "1.2.3.4",
		CurrentV6:   "2606:4700::1",
		LastSummary: "tested=10 ok=8 best_v4=1.2.3.4 42ms",
		NextRun:     1730000000,
		FailStreak:  2,
		Candidates:  []string{"1.2.3.4", "5.6.7.8"},
	}
	if err := saveState(path, st); err != nil {
		t.Fatal(err)
	}
	got, found := loadState(path)
	if !found {
		t.Fatal("state file should be found")
	}
	if got.CurrentV4 != st.CurrentV4 || got.CurrentV6 != st.CurrentV6 ||
		got.LastSummary != st.LastSummary || got.NextRun != st.NextRun ||
		got.FailStreak != st.FailStreak || len(got.Candidates) != 2 {
		t.Fatalf("round trip mismatch: %+v", got)
	}
}

func TestLoadStateMissingAndCorrupt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if _, found := loadState(path); found {
		t.Fatal("missing file must not be found")
	}
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, found := loadState(path)
	if !found {
		t.Fatal("corrupt file still counts as found")
	}
	if st.CurrentV4 != "" || st.Candidates != nil {
		t.Fatalf("corrupt file must decode to empty state: %+v", st)
	}
}

func TestLockRejectsLivePID(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	lock := lockPathFor(statePath)
	if err := os.WriteFile(lock, []byte(strconv.Itoa(os.Getpid())), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := acquireLock(statePath); err == nil {
		t.Fatal("live pid in lock must be rejected")
	}
}

func TestLockOverwritesDeadAndCorrupt(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	lock := lockPathFor(statePath)

	// Dead pid: overwritten.
	if err := os.WriteFile(lock, []byte("999999"), 0o644); err != nil {
		t.Fatal(err)
	}
	release, err := acquireLock(statePath)
	if err != nil {
		t.Fatalf("dead pid must be overwritten: %v", err)
	}
	if got, _ := os.ReadFile(lock); string(got) != strconv.Itoa(os.Getpid()) {
		t.Fatalf("lock content wrong: %s", got)
	}
	release()
	if _, err := os.Stat(lock); !os.IsNotExist(err) {
		t.Fatal("release must remove the lock file")
	}

	// Corrupt lock: overwritten.
	if err := os.WriteFile(lock, []byte("not-a-pid"), 0o644); err != nil {
		t.Fatal(err)
	}
	release, err = acquireLock(statePath)
	if err != nil {
		t.Fatalf("corrupt lock must be overwritten: %v", err)
	}
	release()
}

func TestReadLockPID(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	if pid := readLockPID(statePath); pid != 0 {
		t.Fatalf("missing lock should read 0, got %d", pid)
	}
	if err := os.WriteFile(lockPathFor(statePath), []byte(" 4242\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if pid := readLockPID(statePath); pid != 4242 {
		t.Fatalf("lock pid should be 4242, got %d", pid)
	}
}
