package cfhost

import (
	"bytes"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var (
	td = []string{"d1.example.com", "d2.example.com"}
	v4 = netip.MustParseAddr("1.2.3.4")
	v6 = netip.MustParseAddr("2606:4700::1111")
)

// hostsFileWithBlock seeds a hosts file holding an outdated managed block.
func hostsFileWithBlock(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "hosts")
	old := renderBlock(td, netip.MustParseAddr("9.9.9.9"), netip.Addr{}, false)
	if err := os.WriteFile(path, old, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// snapshotPath returns the snapshot path for a hosts file in dir and asserts
// no snapshot tmp leftovers remain.
func snapshotPath(t *testing.T, dir string) string {
	t.Helper()
	return filepath.Join(dir, "hosts.snapshot")
}

func TestSpliceBlockPreservesOutsideBytes(t *testing.T) {
	prefix := "user entry\r\n# manual mapping\r\n"
	suffix := "tail without newline"
	old := renderBlock(td, netip.MustParseAddr("9.9.9.9"), netip.Addr{}, false)
	data := append([]byte(prefix), old...)
	data = append(data, suffix...)

	newBlock := renderBlock(td, v4, v6, true)
	out, changed := spliceBlock(data, newBlock)
	if !changed {
		t.Fatal("address change must alter content")
	}
	if !bytes.HasPrefix(out, []byte(prefix)) {
		t.Fatalf("prefix not preserved:\n%q", out)
	}
	if !bytes.HasSuffix(out, []byte(suffix)) {
		t.Fatalf("suffix not preserved:\n%q", out)
	}
	if !bytes.Contains(out, newBlock) {
		t.Fatalf("new block missing:\n%q", out)
	}
	if bytes.Contains(out, []byte("9.9.9.9")) {
		t.Fatalf("old address still present:\n%q", out)
	}
}

func TestSpliceBlockAppendsWithoutMarker(t *testing.T) {
	data := []byte("entry") // no trailing newline, no block
	out, changed := spliceBlock(data, renderBlock(td, v4, netip.Addr{}, false))
	if !changed {
		t.Fatal("append must change content")
	}
	if !bytes.HasPrefix(out, []byte("entry\n")) {
		t.Fatalf("missing newline inserted:\n%q", out)
	}
	if !bytes.HasSuffix(out, renderBlock(td, v4, netip.Addr{}, false)) {
		t.Fatalf("block not appended:\n%q", out)
	}

	// Empty file gets just the block.
	out, _ = spliceBlock(nil, renderBlock(td, v4, netip.Addr{}, false))
	if !bytes.Equal(out, renderBlock(td, v4, netip.Addr{}, false)) {
		t.Fatalf("empty file splice wrong:\n%q", out)
	}
}

func TestSpliceBlockMissingEndMarker(t *testing.T) {
	data := []byte("keep\n# BEGIN cfhost\n1.1.1.1 old\n") // no END marker
	out, _ := spliceBlock(data, renderBlock(td, v4, netip.Addr{}, false))
	if !bytes.HasPrefix(out, []byte("keep\n")) {
		t.Fatalf("prefix lost:\n%q", out)
	}
	if !bytes.Equal(out, append([]byte("keep\n"), renderBlock(td, v4, netip.Addr{}, false)...)) {
		t.Fatalf("unterminated block should be rebuilt:\n%q", out)
	}
}

func TestUpdateHostsRoundTripAndMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts")
	if err := os.WriteFile(path, []byte("user 127.0.0.1 mapping\r\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}

	written, err := updateHosts(path, snapshotPath(t, dir), td, v4, v6, true)
	if err != nil || !written {
		t.Fatalf("first update: written=%v err=%v", written, err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode not preserved: %v", st.Mode().Perm())
	}
	data, _ := os.ReadFile(path)
	if !bytes.HasPrefix(data, []byte("user 127.0.0.1 mapping\r\n")) {
		t.Fatalf("outside block lost:\n%q", data)
	}
	want := renderBlock(td, v4, v6, true)
	if !bytes.Contains(data, want) {
		t.Fatalf("block content wrong:\n%q", data)
	}

	// Second identical update must not rewrite.
	before, _ := os.Stat(path)
	time.Sleep(10 * time.Millisecond)
	written, err = updateHosts(path, snapshotPath(t, dir), td, v4, v6, true)
	if err != nil {
		t.Fatal(err)
	}
	if written {
		t.Fatal("unchanged content must not rewrite")
	}
	after, _ := os.Stat(path)
	if !after.ModTime().Equal(before.ModTime()) {
		t.Fatal("mtime changed despite no write")
	}

	// Address change rewrites and rebuilds the block.
	written, err = updateHosts(path, snapshotPath(t, dir), td, netip.MustParseAddr("5.6.7.8"), netip.Addr{}, false)
	if err != nil || !written {
		t.Fatalf("changed update: written=%v err=%v", written, err)
	}
	data, _ = os.ReadFile(path)
	if !bytes.HasPrefix(data, []byte("user 127.0.0.1 mapping\r\n")) {
		t.Fatalf("outside block lost on rewrite:\n%q", data)
	}
	if !bytes.Contains(data, renderBlock(td, netip.MustParseAddr("5.6.7.8"), netip.Addr{}, false)) {
		t.Fatalf("block not rebuilt:\n%q", data)
	}
}

func TestUpdateHostsMissingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts")
	written, err := updateHosts(path, snapshotPath(t, dir), td, v4, netip.Addr{}, false)
	if err != nil || !written {
		t.Fatalf("missing hosts file should be created: written=%v err=%v", written, err)
	}
	data, _ := os.ReadFile(path)
	if !bytes.Equal(data, renderBlock(td, v4, netip.Addr{}, false)) {
		t.Fatalf("created file wrong:\n%q", data)
	}
	// An empty pre-write state has nothing to lose: no snapshot may appear.
	if _, err := os.Stat(filepath.Join(dir, "hosts.snapshot")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("empty pre-write state must not snapshot, stat err=%v", err)
	}
}

func TestUpdateHostsTransientReadErrorSkips(t *testing.T) {
	// Reading a path we cannot open (a directory yields EISDIR, not
	// ErrNotExist) must produce the skip signal, not a fatal error: the
	// daemon survives transient hosts read failures (e.g. antivirus locks).
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts-as-dir")
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
	written, err := updateHosts(path, snapshotPath(t, dir), td, v4, netip.Addr{}, false)
	if !errors.Is(err, errHostsSkipped) {
		t.Fatalf("expected skip signal, got %v", err)
	}
	if written {
		t.Fatal("skip must not write anything")
	}
}

func TestUpdateHostsSnapshotKeepsPreWriteBytes(t *testing.T) {
	// Every actual write snapshots the exact pre-write bytes first; the
	// previous snapshot rolls into hosts.snapshot.1, so a crash-truncated
	// hosts still leaves a complete recovery generation behind.
	dir := t.TempDir()
	path := hostsFileWithBlock(t, dir)
	first, _ := os.ReadFile(path)

	if _, err := updateHosts(path, snapshotPath(t, dir), td, v4, netip.Addr{}, false); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "hosts.snapshot"))
	if err != nil {
		t.Fatalf("snapshot missing after write: %v", err)
	}
	if !bytes.Equal(got, first) {
		t.Fatalf("snapshot must hold exact pre-write bytes:\n%q", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "hosts.snapshot.tmp")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("snapshot tmp leftover: %v", err)
	}

	second, _ := os.ReadFile(path)
	if _, err := updateHosts(path, snapshotPath(t, dir), td, netip.MustParseAddr("5.6.7.8"), netip.Addr{}, false); err != nil {
		t.Fatal(err)
	}
	got, err = os.ReadFile(filepath.Join(dir, "hosts.snapshot"))
	if err != nil || !bytes.Equal(got, second) {
		t.Fatalf("second snapshot wrong (err=%v):\n%q", err, got)
	}
	got, err = os.ReadFile(filepath.Join(dir, "hosts.snapshot.1"))
	if err != nil || !bytes.Equal(got, first) {
		t.Fatalf("rotated generation must hold the first pre-write state (err=%v):\n%q", err, got)
	}
}

func TestUpdateHostsSnapshotFailureSkipsWrite(t *testing.T) {
	// No backup, no write: when the snapshot cannot be persisted (here: its
	// directory does not exist), the round is skipped and hosts stays
	// byte-for-byte intact.
	dir := t.TempDir()
	path := hostsFileWithBlock(t, dir)
	orig, _ := os.ReadFile(path)

	written, err := updateHosts(path, filepath.Join(dir, "no-such-dir", "hosts.snapshot"), td, v4, netip.Addr{}, false)
	if !errors.Is(err, errHostsSkipped) {
		t.Fatalf("snapshot failure must skip, got %v", err)
	}
	if written {
		t.Fatal("skip must not report a write")
	}
	got, _ := os.ReadFile(path)
	if !bytes.Equal(got, orig) {
		t.Fatalf("hosts must stay untouched after snapshot failure:\n%q", got)
	}
}

func TestUpdateHostsUnchangedLeavesSnapshotAlone(t *testing.T) {
	dir := t.TempDir()
	path := hostsFileWithBlock(t, dir)
	if _, err := updateHosts(path, snapshotPath(t, dir), td, v4, netip.Addr{}, false); err != nil {
		t.Fatal(err)
	}
	snap := filepath.Join(dir, "hosts.snapshot")
	before, _ := os.Stat(snap)
	time.Sleep(10 * time.Millisecond)

	// Same target address: unchanged short-circuits before the snapshot.
	if written, err := updateHosts(path, snapshotPath(t, dir), td, v4, netip.Addr{}, false); err != nil || written {
		t.Fatalf("unchanged update: written=%v err=%v", written, err)
	}
	after, _ := os.Stat(snap)
	if !after.ModTime().Equal(before.ModTime()) {
		t.Fatal("unchanged update must not touch the snapshot")
	}
}

func TestRenderBlockOrder(t *testing.T) {
	block := string(renderBlock(td, v4, v6, true))
	want := "# BEGIN cfhost\n1.2.3.4 d1.example.com\n1.2.3.4 d2.example.com\n" +
		"2606:4700::1111 d1.example.com\n2606:4700::1111 d2.example.com\n# END cfhost\n"
	if block != want {
		t.Fatalf("block render wrong:\n%q\nwant\n%q", block, want)
	}
	noV6 := string(renderBlock(td, v4, netip.Addr{}, false))
	if strings.Contains(noV6, "2606:") {
		t.Fatalf("v4-only block must not contain v6 lines:\n%q", noV6)
	}
}
