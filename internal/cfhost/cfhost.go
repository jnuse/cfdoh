// Package cfhost implements the cfdoh client daemon: candidate discovery,
// local latency probing, hysteresis-driven best-address selection and hosts
// block maintenance.
//
// 契约: .trellis/spec/arch/cfhost.md. 只写带标记的 hosts 区块, 区块外逐字节
// 保留; 测速全部失败时保留 hosts 现状; 单实例锁防并发写入.
package cfhost

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// serviceControl abstracts the Windows service lifecycle so the entry point
// stays thin and non-Windows builds compile without the svc packages.
// Implemented per platform (service_windows.go / service_other.go).
type serviceControl interface {
	install() error
	uninstall() error
	start() error
	stop() error
}

// Install registers the Windows service (error on other platforms).
func Install() error { return servicePlatform().install() }

// Uninstall removes the Windows service.
func Uninstall() error { return servicePlatform().uninstall() }

// Start starts the registered Windows service.
func Start() error { return servicePlatform().start() }

// Stop stops the registered Windows service.
func Stop() error { return servicePlatform().stop() }

// Status renders the current state: addresses in use, last sweep summary,
// next refresh time and lock status. Returns "no state" when no state file
// exists yet. A failed config load must not sink this read-only query: the
// state path falls back to CFHOST_STATE_PATH or the default location.
func Status() string {
	cfg, err := LoadConfig()
	var statePath string
	if err == nil {
		statePath = cfg.StatePath
	} else {
		slog.Warn("cfhost: config load failed, falling back to default state path", "error", err.Error())
		statePath = resolveStatePath()
	}
	st, found := loadState(statePath)
	if !found {
		return "no state"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "current v4: %s\n", orNone(st.CurrentV4))
	fmt.Fprintf(&b, "current v6: %s\n", orNone(st.CurrentV6))
	fmt.Fprintf(&b, "last summary: %s\n", orNone(st.LastSummary))
	if st.NextRun > 0 {
		fmt.Fprintf(&b, "next run: %s\n", time.Unix(st.NextRun, 0).Format(time.RFC3339))
	} else {
		fmt.Fprintf(&b, "next run: unknown\n")
	}
	if pid := readLockPID(statePath); pid > 0 {
		fmt.Fprintf(&b, "lock: held by pid %d\n", pid)
	} else {
		fmt.Fprintf(&b, "lock: free\n")
	}
	if st.LogNote != "" {
		fmt.Fprintf(&b, "log: %s\n", st.LogNote)
	}
	return strings.TrimRight(b.String(), "\n")
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

// stateDirOf returns the directory used for the state file, lock file and
// log file.
func stateDirOf(statePath string) string {
	return filepath.Dir(statePath)
}

// Logging: slog writes to stderr and to cfhost.log next to the state file.
// The log rotates to .1 (one generation kept) past 1MiB, checked both at
// startup and on every write, so long-running daemons rotate without a
// restart. A file open failure falls back to stderr only.

var loggingOnce sync.Once

// logHealth records the file-log outcome of this process (path + ok or the
// failure); every pass copies it into the state file so status can show a
// daemon whose file logging died silently.
var logHealth string

// logRotateSize is the size past which cfhost.log rotates to cfhost.log.1.
const logRotateSize = 1 << 20

// initLogging wires the rotating file log (stateDir/cfhost.log) plus
// stderr through slog, once per process. The outcome — path plus ok or the
// failure — is recorded in logHealth and carried into the state file by
// every pass, so `cfhost status` can surface a daemon whose file logging
// silently died (a service process cannot show its stderr to anyone).
func initLogging(stateDir string) {
	loggingOnce.Do(func() {
		path := filepath.Join(stateDir, "cfhost.log")
		w := io.Writer(os.Stderr)
		if rw, err := openRotatingLog(stateDir); err != nil {
			logHealth = fmt.Sprintf("%s (unavailable: %v)", path, err)
			slog.Warn("cfhost: file logging unavailable", "error", err.Error())
		} else {
			logHealth = fmt.Sprintf("%s (ok)", path)
			w = io.MultiWriter(os.Stderr, rw)
		}
		slog.SetDefault(slog.New(slog.NewTextHandler(w, nil)))
	})
}

// openRotatingLog prepares the rotating log file in stateDir, rotating an
// already oversized file first.
func openRotatingLog(stateDir string) (*rotatingWriter, error) {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(stateDir, "cfhost.log")
	if st, err := os.Stat(path); err == nil && st.Size() > logRotateSize {
		os.Remove(path + ".1")
		if err := os.Rename(path, path+".1"); err != nil {
			return nil, err
		}
	}
	return newRotatingWriter(path)
}

// rotatingWriter wraps the log file and rotates it to .1 (one generation
// kept) once it grows past logRotateSize, so rotation keeps working for the
// lifetime of the process instead of only at startup.
type rotatingWriter struct {
	mu   sync.Mutex
	path string
	f    *os.File
	size int64
}

func newRotatingWriter(path string) (*rotatingWriter, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	size := int64(0)
	if st, err := f.Stat(); err == nil {
		size = st.Size()
	}
	return &rotatingWriter{path: path, f: f, size: size}, nil
}

func (w *rotatingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return 0, os.ErrClosed
	}
	if w.size+int64(len(p)) > logRotateSize {
		w.rotateLocked()
		if w.f == nil {
			return 0, os.ErrClosed
		}
	}
	n, err := w.f.Write(p)
	w.size += int64(n)
	return n, err
}

// rotateLocked renames the current log to .1 and reopens a fresh file. It
// must be called with w.mu held and never logs (the log path runs through
// this writer; logging here would deadlock).
func (w *rotatingWriter) rotateLocked() {
	w.f.Close()
	os.Remove(w.path + ".1")
	os.Rename(w.path, w.path+".1")
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		w.f = nil
		return
	}
	w.f = f
	w.size = 0
	if st, err := f.Stat(); err == nil {
		w.size = st.Size()
	}
}
