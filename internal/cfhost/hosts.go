package cfhost

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// Hosts block management: only the marked block (# BEGIN cfhost .. # END
// cfhost) is owned by the daemon; everything outside is preserved byte for
// byte. Updates write the hosts file in place — the file object is never
// replaced, so its owner and ACL stay whatever Windows put there and a
// system update resetting hosts ownership (e.g. to TrustedInstaller) cannot
// freeze the daemon. Before each in-place write the exact pre-write bytes
// are snapshotted next to the config file (hosts.snapshot, with one older
// generation kept as hosts.snapshot.1): if a crash or power loss ever
// truncates hosts mid-write, the snapshot holds the last complete pre-write
// state — recovery is manual (copy the snapshot over hosts). Unchanged
// block content never triggers a write.

const (
	hostsBegin = "# BEGIN cfhost"
	hostsEnd   = "# END cfhost"
)

// errHostsSkipped signals a transient hosts read or write failure: this
// round skips the hosts update (nothing is written) instead of failing the
// daemon, which retries next cycle.
var errHostsSkipped = errors.New("cfhost: hosts read or write failed, update skipped")

// hostsSnapshotPath places the pre-write hosts snapshot in the state
// directory (the config file's folder), keeping every runtime file together.
func hostsSnapshotPath(statePath string) string {
	return filepath.Join(filepath.Dir(statePath), "hosts.snapshot")
}

// snapshotHosts preserves the exact pre-write bytes before an in-place
// hosts write. The snapshot is published atomically (write tmp, rename) and
// one previous generation is kept (hosts.snapshot.1): after a
// crash-truncated hosts the *next* round would otherwise snapshot the
// already-damaged bytes, so the older generation is the recovery point.
// Empty input (no hosts file yet) skips the snapshot — there is nothing to
// lose. A failure here must skip the round: no backup, no write.
func snapshotHosts(snapshotPath string, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	// Rolling the previous generation is best-effort: the fresh snapshot
	// published below is what gates the write.
	if err := os.Rename(snapshotPath, snapshotPath+".1"); err != nil && !errors.Is(err, fs.ErrNotExist) {
		slog.Warn("cfhost: hosts snapshot rotation failed", "error", err.Error())
	}
	tmp := snapshotPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, snapshotPath); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// renderBlock builds the managed block. Each family renders one line per
// (address, domain) pair, grouped by address in list order (the head first):
// the per-domain line order in the file is exactly the attempt order the
// OS resolver returns, so the head stays the primary and the spares follow.
// A one-element list renders byte-identically to the old single-address form.
func renderBlock(domains []string, v4s, v6s []netip.Addr, hasV6 bool) []byte {
	var b bytes.Buffer
	b.WriteString(hostsBegin)
	b.WriteByte('\n')
	for _, ip := range v4s {
		for _, d := range domains {
			fmt.Fprintf(&b, "%s %s\n", ip.String(), d)
		}
	}
	if hasV6 {
		for _, ip := range v6s {
			for _, d := range domains {
				fmt.Fprintf(&b, "%s %s\n", ip.String(), d)
			}
		}
	}
	b.WriteString(hostsEnd)
	b.WriteByte('\n')
	return b.Bytes()
}

// findMarkerLine locates a line equal to marker (ignoring a trailing \r),
// starting at byte offset from. It returns the line start and the offset just
// past the line terminator.
func findMarkerLine(data []byte, marker string, from int) (start, end int, found bool) {
	i := from
	for i < len(data) {
		lineEnd := bytes.IndexByte(data[i:], '\n')
		var ln []byte
		next := len(data)
		if lineEnd >= 0 {
			ln = data[i : i+lineEnd]
			next = i + lineEnd + 1
		} else {
			ln = data[i:]
		}
		if string(bytes.TrimSuffix(ln, []byte("\r"))) == marker {
			return i, next, true
		}
		if lineEnd < 0 {
			break
		}
		i = next
	}
	return 0, 0, false
}

// spliceBlock replaces the marked block (or appends one) in data with block.
// Bytes outside the block are preserved exactly. The second return value
// reports whether the result differs from the input.
func spliceBlock(data, block []byte) ([]byte, bool) {
	bs, bAfter, ok := findMarkerLine(data, hostsBegin, 0)
	var out []byte
	if !ok {
		out = append([]byte{}, data...)
		if len(out) > 0 && out[len(out)-1] != '\n' {
			out = append(out, '\n')
		}
		out = append(out, block...)
		return out, !bytes.Equal(out, data)
	}
	_, eAfter, eOk := findMarkerLine(data, hostsEnd, bAfter)
	out = append(out, data[:bs]...)
	out = append(out, block...)
	if eOk {
		out = append(out, data[eAfter:]...)
	}
	return out, !bytes.Equal(out, data)
}

// updateHosts rewrites the managed block if (and only if) the rendered
// content differs from the current file. Returns whether the file was
// written. Every transient failure — read, snapshot, or the in-place write
// (e.g. an antivirus briefly holding hosts) — returns errHostsSkipped so
// the caller treats the round as skipped and the daemon stays alive.
func updateHosts(path, snapshotPath string, domains []string, v4s, v6s []netip.Addr, hasV6 bool) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		// Transient read failure (e.g. antivirus briefly locking hosts on
		// Windows): skip this round; the daemon retries next cycle.
		slog.Warn("cfhost: hosts read failed, skipping hosts update this round", "error", err.Error())
		return false, errHostsSkipped
	}
	content, changed := spliceBlock(data, renderBlock(domains, v4s, v6s, hasV6))
	if !changed {
		return false, nil
	}
	// The pre-write snapshot gates the in-place write: without a backup on
	// disk, a crash mid-write could lose the user's own hosts entries with
	// no recovery point.
	if err := snapshotHosts(snapshotPath, data); err != nil {
		slog.Warn("cfhost: hosts snapshot failed, skipping hosts update this round", "error", err.Error())
		return false, errHostsSkipped
	}
	mode := fs.FileMode(0o644)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	if err := os.WriteFile(path, content, mode); err != nil {
		slog.Warn("cfhost: hosts write failed, skipping hosts update this round", "error", err.Error())
		return false, errHostsSkipped
	}
	return true, nil
}

// flushDNS refreshes the system DNS cache after a hosts update. Windows runs
// ipconfig /flushdns; other platforms have no equivalent action. Failures are
// logged only.
func flushDNS() {
	if runtime.GOOS != "windows" {
		return
	}
	if err := exec.Command("ipconfig", "/flushdns").Run(); err != nil {
		slog.Warn("cfhost: flushdns failed", "error", err.Error())
	}
}
