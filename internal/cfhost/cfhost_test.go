package cfhost

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStatusRendersStateWhenConfigInvalid(t *testing.T) {
	// A read-only status query must not be held hostage by unrelated config
	// validation: with CFHOST_STATE_PATH set and the config invalid, the
	// state file at the override path is still rendered.
	clearEnv(t)
	dir := t.TempDir()
	statePath := filepath.Join(dir, "cfhost-state.json")
	st := clientState{
		CurrentV4:   "203.0.113.7",
		LastSummary: "seeded",
		NextRun:     time.Now().Add(time.Hour).Unix(),
	}
	if err := saveState(statePath, st); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CFHOST_STATE_PATH", statePath)
	// No CFHOST_MANAGED_DOMAINS / CFHOST_SOURCES: LoadConfig fails.
	out := Status()
	if !strings.Contains(out, "current v4: 203.0.113.7") {
		t.Fatalf("status should render state despite config failure, got %q", out)
	}
	if !strings.Contains(out, "last summary: seeded") {
		t.Fatalf("status should render summary, got %q", out)
	}
	if !strings.Contains(out, "lock: free") {
		t.Fatalf("lock should be reported free, got %q", out)
	}
}

func TestStatusNoStateWhenNothingExists(t *testing.T) {
	clearEnv(t)
	t.Setenv("CFHOST_MANAGED_DOMAINS", "a.example.com")
	t.Setenv("CFHOST_SOURCES", "list:1.1.1.1")
	t.Setenv("CFHOST_STATE_PATH", filepath.Join(t.TempDir(), "absent-state.json"))
	if out := Status(); out != "no state" {
		t.Fatalf("expected \"no state\", got %q", out)
	}
}

func TestRotatingWriterRotatesOnWritePath(t *testing.T) {
	// Rotation must trigger on the write path, not only at startup: after
	// crossing the size threshold the current file becomes .1 and logging
	// continues in a fresh file.
	dir := t.TempDir()
	w, err := newRotatingWriter(filepath.Join(dir, "cfhost.log"))
	if err != nil {
		t.Fatal(err)
	}
	chunk := bytes.Repeat([]byte("x"), logRotateSize/4) // 256KiB
	for i := 0; i < 5; i++ {
		if _, err := w.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	rotated, err := os.Stat(filepath.Join(dir, "cfhost.log.1"))
	if err != nil {
		t.Fatal("expected rotated cfhost.log.1")
	}
	if rotated.Size() != int64(logRotateSize) {
		t.Fatalf("rotated file size = %d, want %d", rotated.Size(), logRotateSize)
	}
	current, err := os.Stat(filepath.Join(dir, "cfhost.log"))
	if err != nil {
		t.Fatal(err)
	}
	if current.Size() != int64(len(chunk)) {
		t.Fatalf("current file size = %d, want %d", current.Size(), len(chunk))
	}

	// Writing continues after rotation.
	if _, err := w.Write([]byte("tail\n")); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(dir, "cfhost.log"))
	if !bytes.HasSuffix(data, []byte("tail\n")) {
		t.Fatalf("post-rotation write lost: %q", data)
	}
}

func TestOpenRotatingLogRotatesOversizedStartupFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfhost.log")
	if err := os.WriteFile(path, bytes.Repeat([]byte("y"), logRotateSize+1), 0o644); err != nil {
		t.Fatal(err)
	}
	w, err := openRotatingLog(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("fresh\n")); err != nil {
		t.Fatal(err)
	}
	rotated, err := os.Stat(path + ".1")
	if err != nil {
		t.Fatal("startup rotation should move the oversized file to .1")
	}
	if rotated.Size() != int64(logRotateSize+1) {
		t.Fatalf(".1 size = %d, want %d", rotated.Size(), logRotateSize+1)
	}
	data, _ := os.ReadFile(path)
	if string(data) != "fresh\n" {
		t.Fatalf("fresh log wrong: %q", data)
	}
}
