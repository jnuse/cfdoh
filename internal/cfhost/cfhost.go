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
// exists yet.
func Status() string {
	cfg, err := LoadConfig()
	if err != nil {
		return "no state"
	}
	st, found := loadState(cfg.StatePath)
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
	if pid := readLockPID(cfg.StatePath); pid > 0 {
		fmt.Fprintf(&b, "lock: held by pid %d\n", pid)
	} else {
		fmt.Fprintf(&b, "lock: free\n")
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
// The log rotates to .1 (one generation kept) past 1MiB. A file open failure
// falls back to stderr only.

var loggingOnce sync.Once

func initLogging(stateDir string) {
	loggingOnce.Do(func() {
		w := io.Writer(os.Stderr)
		if f, err := openLogWithRotate(stateDir); err != nil {
			slog.Warn("cfhost: file logging unavailable", "error", err.Error())
		} else {
			w = io.MultiWriter(os.Stderr, f)
		}
		slog.SetDefault(slog.New(slog.NewTextHandler(w, nil)))
	})
}

func openLogWithRotate(stateDir string) (*os.File, error) {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(stateDir, "cfhost.log")
	const rotateSize = 1 << 20
	if st, err := os.Stat(path); err == nil && st.Size() > rotateSize {
		os.Remove(path + ".1")
		if err := os.Rename(path, path+".1"); err != nil {
			return nil, err
		}
	}
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
}
