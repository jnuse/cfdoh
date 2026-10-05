package cfhost

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"net/netip"
)

// Hosts block management: only the marked block (# BEGIN cfhost .. # END
// cfhost) is owned by the daemon; everything outside is preserved byte for
// byte. Updates are atomic (full temp file + rename; the temp file prefers
// the system TEMP directory to dodge the antivirus gate on the etc
// directory) and keep the original file mode. Unchanged block content never
// triggers a write.

const (
	hostsBegin = "# BEGIN cfhost"
	hostsEnd   = "# END cfhost"
)

// errHostsSkipped signals a transient hosts read or write failure: this
// round skips the hosts update (nothing is written) instead of failing the
// daemon, which retries next cycle.
var errHostsSkipped = errors.New("cfhost: hosts read or write failed, update skipped")

// Injection seams (see the newProbeTLSConfig precedent): tests override the
// temp directory, the same-volume decision, the rename action and the
// lock-error classification to simulate Windows antivirus races without a
// real scanner.
var (
	hostsTempDir      = os.TempDir
	hostsSameVolume   = sameVolumeDefault
	hostsRename       = os.Rename
	isRenameLockError = isRenameLockErrorDefault
)

// renameRetryDelay is the backoff between rename retries; a variable so
// tests can shrink it.
var renameRetryDelay = 200 * time.Millisecond

// renameRetryMax bounds the rename retries after the first failure: five
// retries at 200ms absorb the usual antivirus scan window (a few hundred
// milliseconds) before the round is given up as skipped.
const renameRetryMax = 5

// renderBlock builds the managed block: one line per domain for IPv4, then
// one line per domain for IPv6 when available.
func renderBlock(domains []string, v4, v6 netip.Addr, hasV6 bool) []byte {
	var b bytes.Buffer
	b.WriteString(hostsBegin)
	b.WriteByte('\n')
	for _, d := range domains {
		fmt.Fprintf(&b, "%s %s\n", v4.String(), d)
	}
	if hasV6 {
		for _, d := range domains {
			fmt.Fprintf(&b, "%s %s\n", v6.String(), d)
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
// written. Every transient read or write failure — including rename
// retries exhausted under an antivirus lock — returns errHostsSkipped so
// the caller treats the round as skipped and the daemon stays alive.
func updateHosts(path string, domains []string, v4, v6 netip.Addr, hasV6 bool) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		// Transient read failure (e.g. antivirus briefly locking hosts on
		// Windows): skip this round; the daemon retries next cycle.
		slog.Warn("cfhost: hosts read failed, skipping hosts update this round", "error", err.Error())
		return false, errHostsSkipped
	}
	content, changed := spliceBlock(data, renderBlock(domains, v4, v6, hasV6))
	if !changed {
		return false, nil
	}
	mode := fs.FileMode(0o644)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	tmpName := writeHostsTemp(filepath.Dir(path), content, mode)
	if tmpName == "" {
		return false, errHostsSkipped
	}
	if err := renameHostsWithRetry(tmpName, path); err != nil {
		os.Remove(tmpName)
		return false, errHostsSkipped
	}
	return true, nil
}

// writeHostsTemp stages content in a closed temp file and returns its path,
// or "" when staging failed (already logged): the round is skipped. The
// temp file prefers the system TEMP directory — creating files inside
// System32\drivers\etc is far more likely to draw an antivirus scan than
// TEMP — and falls back to the hosts directory when TEMP sits on another
// volume (rename across volumes degrades to copy+delete and loses
// atomicity) or cannot be used. Both locations keep the write-then-rename
// replacement atomic and preserve the original file mode.
func writeHostsTemp(dir string, content []byte, mode fs.FileMode) string {
	tmpDir := dir
	if t := hostsTempDir(); t != "" && hostsSameVolume(t, dir) {
		tmpDir = t
	}
	tmp, err := os.CreateTemp(tmpDir, ".cfhost-hosts-*")
	if err != nil && tmpDir != dir {
		// Unusable TEMP (missing directory, access denied, ...): fall back
		// to the hosts directory and keep the rename atomic.
		tmpDir = dir
		tmp, err = os.CreateTemp(tmpDir, ".cfhost-hosts-*")
	}
	if err != nil {
		slog.Warn("cfhost: hosts temp file creation failed, skipping hosts update this round",
			"temp_dir", tmpDir, "error", err.Error())
		return ""
	}
	name := tmp.Name()
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		os.Remove(name)
		slog.Warn("cfhost: hosts temp write failed, skipping hosts update this round", "error", err.Error())
		return ""
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		os.Remove(name)
		slog.Warn("cfhost: hosts temp chmod failed, skipping hosts update this round", "error", err.Error())
		return ""
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		slog.Warn("cfhost: hosts temp close failed, skipping hosts update this round", "error", err.Error())
		return ""
	}
	return name
}

// renameHostsWithRetry replaces the hosts file with the staged temp file.
// Rename failures that look like a transient antivirus handle (access
// denied / sharing violation, Windows) are retried with backoff — the scan
// usually releases the file within a few hundred milliseconds. After
// renameRetryMax retries the error is returned and the caller skips this
// round; non-retryable failures return immediately.
func renameHostsWithRetry(tmpName, path string) error {
	for retry := 0; ; retry++ {
		err := hostsRename(tmpName, path)
		if err == nil {
			return nil
		}
		if !isRenameLockError(err) || retry >= renameRetryMax {
			slog.Warn("cfhost: hosts rename failed, skipping hosts update this round",
				"retries", retry, "error", err.Error())
			return err
		}
		slog.Warn("cfhost: hosts rename blocked (likely antivirus scan), retrying",
			"retry", retry+1, "of", renameRetryMax, "error", err.Error())
		time.Sleep(renameRetryDelay)
	}
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
