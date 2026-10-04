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

	"net/netip"
)

// Hosts block management: only the marked block (# BEGIN cfhost .. # END
// cfhost) is owned by the daemon; everything outside is preserved byte for
// byte. Updates are atomic (temp file + rename) and keep the original file
// mode. Unchanged block content never triggers a write.

const (
	hostsBegin = "# BEGIN cfhost"
	hostsEnd   = "# END cfhost"
)

// errHostsSkipped signals a transient hosts read failure: this round skips
// the hosts update (nothing is written) instead of failing the daemon.
var errHostsSkipped = errors.New("cfhost: hosts read failed, update skipped")

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
// written.
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
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".cfhost-hosts-*")
	if err != nil {
		return false, fmt.Errorf("temp hosts: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return false, fmt.Errorf("write temp hosts: %w", err)
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return false, fmt.Errorf("chmod temp hosts: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return false, fmt.Errorf("close temp hosts: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return false, fmt.Errorf("rename hosts: %w", err)
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
