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

// errFakeLock stands in for a Windows access-denied / sharing-violation
// rename failure caused by an antivirus scan handle.
var errFakeLock = errors.New("fake antivirus lock")

// withHostsSeams overrides the hosts write seams (temp dir, same-volume
// decision, rename action, lock classification, retry delay) for one test
// and restores them on cleanup. Tests using it must not run in parallel.
func withHostsSeams(t *testing.T,
	tempDir func() string,
	sameVolume func(a, b string) bool,
	rename func(oldpath, newpath string) error,
	lockError func(error) bool,
	delay time.Duration) {
	t.Helper()
	oldTemp, oldVol, oldRename, oldLock, oldDelay :=
		hostsTempDir, hostsSameVolume, hostsRename, isRenameLockError, renameRetryDelay
	hostsTempDir, hostsSameVolume, hostsRename, isRenameLockError, renameRetryDelay =
		tempDir, sameVolume, rename, lockError, delay
	t.Cleanup(func() {
		hostsTempDir, hostsSameVolume, hostsRename, isRenameLockError, renameRetryDelay =
			oldTemp, oldVol, oldRename, oldLock, oldDelay
	})
}

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

// noStagingLeftover asserts no .cfhost-hosts-* temp file remains in dir.
func noStagingLeftover(t *testing.T, dir, what string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".cfhost-hosts-") {
			t.Fatalf("%s: staging leftover %s", what, e.Name())
		}
	}
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

	written, err := updateHosts(path, td, v4, v6, true)
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
	written, err = updateHosts(path, td, v4, v6, true)
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
	written, err = updateHosts(path, td, netip.MustParseAddr("5.6.7.8"), netip.Addr{}, false)
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
	path := filepath.Join(t.TempDir(), "hosts")
	written, err := updateHosts(path, td, v4, netip.Addr{}, false)
	if err != nil || !written {
		t.Fatalf("missing hosts file should be created: written=%v err=%v", written, err)
	}
	data, _ := os.ReadFile(path)
	if !bytes.Equal(data, renderBlock(td, v4, netip.Addr{}, false)) {
		t.Fatalf("created file wrong:\n%q", data)
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
	written, err := updateHosts(path, td, v4, netip.Addr{}, false)
	if !errors.Is(err, errHostsSkipped) {
		t.Fatalf("expected skip signal, got %v", err)
	}
	if written {
		t.Fatal("skip must not write anything")
	}
}

func TestUpdateHostsTempPreferredWhenSameVolume(t *testing.T) {
	// Same-volume TEMP (Windows layout): the temp file must be staged in
	// TEMP, not in the antivirus-watched hosts directory, and renamed into
	// place atomically.
	dir := t.TempDir()
	tempDir := t.TempDir()
	path := hostsFileWithBlock(t, dir)

	var renamedFrom string
	withHostsSeams(t,
		func() string { return tempDir },
		func(a, b string) bool { return true },
		func(oldpath, newpath string) error {
			renamedFrom = oldpath
			return os.Rename(oldpath, newpath)
		},
		func(err error) bool { return false },
		0)

	written, err := updateHosts(path, td, v4, netip.Addr{}, false)
	if err != nil || !written {
		t.Fatalf("update: written=%v err=%v", written, err)
	}
	if filepath.Dir(renamedFrom) != tempDir {
		t.Fatalf("temp file must be staged in TEMP %s, got %s", tempDir, renamedFrom)
	}
	noStagingLeftover(t, tempDir, "TEMP after rename")
	data, _ := os.ReadFile(path)
	if !bytes.Contains(data, renderBlock(td, v4, netip.Addr{}, false)) {
		t.Fatalf("hosts block not updated:\n%q", data)
	}
}

func TestUpdateHostsTempCrossVolumeFallsBackToHostsDir(t *testing.T) {
	// Cross-volume TEMP (rename would degrade to copy+delete): staging must
	// fall back to the hosts directory to keep the rename atomic.
	dir := t.TempDir()
	tempDir := t.TempDir()
	path := hostsFileWithBlock(t, dir)

	var renamedFrom string
	withHostsSeams(t,
		func() string { return tempDir },
		func(a, b string) bool { return false }, // simulated cross-volume TEMP
		func(oldpath, newpath string) error {
			renamedFrom = oldpath
			return os.Rename(oldpath, newpath)
		},
		func(err error) bool { return false },
		0)

	written, err := updateHosts(path, td, v4, netip.Addr{}, false)
	if err != nil || !written {
		t.Fatalf("update: written=%v err=%v", written, err)
	}
	if filepath.Dir(renamedFrom) != dir {
		t.Fatalf("cross-volume TEMP must stage next to hosts (%s), got %s", dir, renamedFrom)
	}
	entries, _ := os.ReadDir(tempDir)
	if len(entries) != 0 {
		t.Fatalf("nothing may be created in a cross-volume TEMP: %v", entries)
	}
}

func TestUpdateHostsTempUnusableFallsBackToHostsDir(t *testing.T) {
	// Same-volume but unusable TEMP (missing directory): staging retries in
	// the hosts directory instead of failing the round.
	dir := t.TempDir()
	tempDir := filepath.Join(dir, "no-such-temp")
	path := hostsFileWithBlock(t, dir)

	var renamedFrom string
	withHostsSeams(t,
		func() string { return tempDir },
		func(a, b string) bool { return true },
		func(oldpath, newpath string) error {
			renamedFrom = oldpath
			return os.Rename(oldpath, newpath)
		},
		func(err error) bool { return false },
		0)

	written, err := updateHosts(path, td, v4, netip.Addr{}, false)
	if err != nil || !written {
		t.Fatalf("update: written=%v err=%v", written, err)
	}
	if filepath.Dir(renamedFrom) != dir {
		t.Fatalf("unusable TEMP must stage next to hosts (%s), got %s", dir, renamedFrom)
	}
}

func TestUpdateHostsACLCarryOrderAndFailureSkips(t *testing.T) {
	// The ACL carry runs after staging, before the rename, with the staged
	// file and the original hosts as arguments; a carry failure skips the
	// round (old file intact, temp cleaned) without attempting the rename.
	for _, tc := range []struct {
		name      string
		carryErr  error
		wantWrite bool
	}{{"carry ok", nil, true}, {"carry fails", errFakeLock, false}} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := hostsFileWithBlock(t, dir)
			orig, _ := os.ReadFile(path)

			var events []string
			withHostsSeams(t,
				func() string { return "" },
				func(a, b string) bool { return false },
				func(oldpath, newpath string) error {
					events = append(events, "rename")
					return os.Rename(oldpath, newpath)
				},
				func(err error) bool { return false },
				0)
			oldCarry := hostsPreserveACL
			hostsPreserveACL = func(tmpName, origPath string) error {
				if origPath != path {
					t.Errorf("carry origPath = %q, want hosts path %q", origPath, path)
				}
				if _, err := os.Stat(tmpName); err != nil {
					t.Errorf("carry must see the staged file: %v", err)
				}
				events = append(events, "acl")
				return tc.carryErr
			}
			t.Cleanup(func() { hostsPreserveACL = oldCarry })

			written, err := updateHosts(path, td, v4, netip.Addr{}, false)
			if tc.wantWrite {
				if err != nil || !written {
					t.Fatalf("update: written=%v err=%v", written, err)
				}
				if len(events) != 2 || events[0] != "acl" || events[1] != "rename" {
					t.Fatalf("carry must precede rename, events=%v", events)
				}
				return
			}
			if !errors.Is(err, errHostsSkipped) {
				t.Fatalf("carry failure must skip, got %v", err)
			}
			if written || len(events) != 1 || events[0] != "acl" {
				t.Fatalf("carry failure must not rename, events=%v written=%v", events, written)
			}
			got, _ := os.ReadFile(path)
			if !bytes.Equal(got, orig) {
				t.Fatalf("hosts must stay untouched after carry failure:\n%q", got)
			}
			noStagingLeftover(t, dir, "hosts dir after carry failure")
		})
	}
}

func TestUpdateHostsRenameRetriesThenSucceeds(t *testing.T) {
	// A rename failure sequence classified as an antivirus lock is retried
	// with backoff and succeeds once the scan releases the file.
	dir := t.TempDir()
	path := hostsFileWithBlock(t, dir)
	orig, _ := os.ReadFile(path)

	failures := 3
	calls := 0
	withHostsSeams(t,
		func() string { return "" },
		func(a, b string) bool { return false },
		func(oldpath, newpath string) error {
			calls++
			if failures > 0 {
				failures--
				return errFakeLock
			}
			return os.Rename(oldpath, newpath)
		},
		func(err error) bool { return errors.Is(err, errFakeLock) },
		0)

	written, err := updateHosts(path, td, v4, netip.Addr{}, false)
	if err != nil || !written {
		t.Fatalf("update after retries: written=%v err=%v", written, err)
	}
	if calls != 1+3 {
		t.Fatalf("rename calls = %d, want 1 initial + 3 retries = 4", calls)
	}
	data, _ := os.ReadFile(path)
	if bytes.Equal(data, orig) || !bytes.Contains(data, renderBlock(td, v4, netip.Addr{}, false)) {
		t.Fatalf("hosts must hold the new block after retries:\n%q", data)
	}
	noStagingLeftover(t, dir, "hosts dir after retried rename")
}

func TestUpdateHostsRenameExhaustedSkips(t *testing.T) {
	// Retry budget exhausted: the round is skipped (errHostsSkipped), hosts
	// stays byte-for-byte identical and the staged temp file is cleaned up.
	dir := t.TempDir()
	path := hostsFileWithBlock(t, dir)
	orig, _ := os.ReadFile(path)

	calls := 0
	withHostsSeams(t,
		func() string { return "" },
		func(a, b string) bool { return false },
		func(oldpath, newpath string) error {
			calls++
			return errFakeLock
		},
		func(err error) bool { return errors.Is(err, errFakeLock) },
		0)

	written, err := updateHosts(path, td, v4, netip.Addr{}, false)
	if !errors.Is(err, errHostsSkipped) {
		t.Fatalf("exhausted retries must skip, got %v", err)
	}
	if written {
		t.Fatal("skip must not report a write")
	}
	if calls != 1+renameRetryMax {
		t.Fatalf("rename calls = %d, want 1 initial + %d retries", calls, renameRetryMax)
	}
	got, _ := os.ReadFile(path)
	if !bytes.Equal(got, orig) {
		t.Fatalf("hosts must stay untouched after exhausted retries:\n%q", got)
	}
	noStagingLeftover(t, dir, "hosts dir after exhausted retries")
}

func TestUpdateHostsRenameNonLockErrorSkipsWithoutRetry(t *testing.T) {
	// A rename failure that is not an antivirus-style lock returns
	// immediately: no retries, the round is skipped and the staged temp
	// file is cleaned up. The hour-long retry delay guarantees the test
	// budget blows up on any accidental retry.
	dir := t.TempDir()
	path := hostsFileWithBlock(t, dir)
	orig, _ := os.ReadFile(path)

	calls := 0
	withHostsSeams(t,
		func() string { return "" },
		func(a, b string) bool { return false },
		func(oldpath, newpath string) error {
			calls++
			return errors.New("not a lock")
		},
		func(err error) bool { return false },
		time.Hour)

	written, err := updateHosts(path, td, v4, netip.Addr{}, false)
	if !errors.Is(err, errHostsSkipped) {
		t.Fatalf("non-lock rename failure must skip, got %v", err)
	}
	if written {
		t.Fatal("skip must not report a write")
	}
	if calls != 1 {
		t.Fatalf("non-lock rename failure must not retry, calls = %d", calls)
	}
	got, _ := os.ReadFile(path)
	if !bytes.Equal(got, orig) {
		t.Fatalf("hosts must stay untouched after non-lock failure:\n%q", got)
	}
	noStagingLeftover(t, dir, "hosts dir after non-lock rename failure")
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
