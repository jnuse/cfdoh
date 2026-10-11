//go:build windows

package cfhost

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	serviceName        = "cfhost"
	serviceDisplayName = "cfdoh cfhost"

	// serviceAccount is the per-service virtual account. Its SID
	// (NT SERVICE\<name>) comes into existence with the service and vanishes
	// with it: the daemon runs with no LocalSystem powers, holding only the
	// ACEs install grants below. Account-name resolution works only while
	// the service exists, so grants must happen after CreateService and
	// revocations before Delete.
	serviceAccount = `NT SERVICE\` + serviceName
)

// stopWaitHintMs matches the 30s the stop command waits for Stopped.
const stopWaitHintMs = 30000

// icacls runs the system ACL tool and folds its output into the error.
// Install/uninstall are rare elevated management commands; delegating the
// ACL edit to icacls avoids hand-building ACL binaries in-process, where a
// single malformed field corrupts a system object's security descriptor.
func icacls(args ...string) error {
	out, err := exec.Command("icacls", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("cfhost: icacls %s: %w: %s",
			strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// hostsGrantPath resolves the hosts file the installed daemon will
// maintain: the configured one when a config is loadable, the default
// otherwise. The install-time write grant must match the runtime path or
// the service would start unable to write its hosts file.
func hostsGrantPath() string {
	if cfg, err := LoadConfig(); err == nil && cfg.HostsPath != "" {
		return cfg.HostsPath
	}
	return defaultHostsPath()
}

type windowsService struct{}

func servicePlatform() serviceControl { return windowsService{} }

// install registers the service: automatic (delayed) start, binpath =
// current executable + "run", running under the per-service virtual account
// with least privilege. Grants the account exactly what the daemon needs:
// a write ACE on the hosts file and modify on the executable's directory
// (config, state, log, lock, snapshots — renames need delete). Failure at
// any step after creation rolls the service back. /grant:r replaces any
// previous grant for the account, keeping repeated installs idempotent.
func (windowsService) install() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cfhost: executable path: %w", err)
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("cfhost: connect service manager: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err == nil {
		s.Close()
		return fmt.Errorf("cfhost: service %s already exists", serviceName)
	}
	s, err = m.CreateService(serviceName, exe, mgr.Config{
		DisplayName:      serviceDisplayName,
		Description:      "cfdoh client daemon: latency probing and hosts maintenance",
		StartType:        mgr.StartAutomatic,
		DelayedAutoStart: true,
		ServiceStartName: serviceAccount,
	}, "run")
	if err != nil {
		return fmt.Errorf("cfhost: create service: %w", err)
	}
	// From here on the service exists; any failure below must not leave a
	// half-installed service behind.
	installed := false
	defer func() {
		if !installed {
			s.Delete()
			s.Close()
		}
	}()
	// Crash recovery: the SCM restarts the service 60s after any failure;
	// Windows repeats the last action for further consecutive failures, and
	// the failure count resets after one clean day.
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: time.Minute},
	}, 86400); err != nil {
		return fmt.Errorf("cfhost: set recovery actions: %w", err)
	}
	// The per-service SID resolves only after CreateService, so grants come
	// last. (W) is generic write on the file — enough for the in-place hosts
	// rewrite, no delete and no DACL/owner writes.
	if err := icacls(hostsGrantPath(), "/grant:r", serviceAccount+":(W)"); err != nil {
		return fmt.Errorf("cfhost: grant hosts write: %w", err)
	}
	// (OI)(CI)M lets new files inherit and propagates to existing ones
	// (log, state, lock, snapshot and its renames).
	if err := icacls(filepath.Dir(exe), "/grant:r", serviceAccount+":(OI)(CI)M"); err != nil {
		return fmt.Errorf("cfhost: grant program directory modify: %w", err)
	}
	installed = true
	s.Close()
	return nil
}

func (windowsService) uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("cfhost: connect service manager: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("cfhost: open service: %w", err)
	}
	defer s.Close()
	// Revoke the install-time grants while the service still exists — the
	// account name stops resolving once it is gone, which would strand the
	// ACEs as orphan SIDs on the hosts file and the program directory.
	// Best-effort: a missing ACE or file must not block service removal.
	if exe, err := os.Executable(); err == nil {
		if err := icacls(filepath.Dir(exe), "/remove", serviceAccount); err != nil {
			slog.Warn("cfhost: program directory grant not revoked", "error", err.Error())
		}
	}
	if err := icacls(hostsGrantPath(), "/remove", serviceAccount); err != nil {
		slog.Warn("cfhost: hosts grant not revoked", "error", err.Error())
	}
	if err := s.Delete(); err != nil {
		return fmt.Errorf("cfhost: delete service: %w", err)
	}
	return nil
}

func (windowsService) start() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("cfhost: connect service manager: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("cfhost: open service: %w", err)
	}
	defer s.Close()
	return s.Start()
}

func (windowsService) stop() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("cfhost: connect service manager: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("cfhost: open service: %w", err)
	}
	defer s.Close()
	status, err := s.Control(svc.Stop)
	if err != nil {
		return fmt.Errorf("cfhost: stop service: %w", err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for status.State != svc.Stopped && time.Now().Before(deadline) {
		time.Sleep(300 * time.Millisecond)
		if status, err = s.Query(); err != nil {
			return fmt.Errorf("cfhost: query service: %w", err)
		}
	}
	if status.State != svc.Stopped {
		return fmt.Errorf("cfhost: service did not stop within 30s (state %d)", status.State)
	}
	return nil
}

// isWindowsService reports whether the process runs under the service
// control manager.
func isWindowsService() bool {
	inService, err := svc.IsWindowsService()
	return err == nil && inService
}

// runAsWindowsService runs loopWithLock inside the SCM handshake.
func runAsWindowsService(ctx context.Context, cfg *Config) error {
	return svc.Run(serviceName, &serviceHandler{ctx: ctx, cfg: cfg})
}

type serviceHandler struct {
	ctx context.Context
	cfg *Config
}

func (h *serviceHandler) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(h.ctx)
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- loopWithLock(ctx, h.cfg)
	}()
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Stop, svc.Shutdown:
				// The pass in flight may be mid-probe; tell the SCM how long a
				// clean stop may take instead of letting it assume a hang.
				changes <- svc.Status{State: svc.StopPending, WaitHint: stopWaitHintMs}
				cancel()
			case svc.Interrogate:
				changes <- c.CurrentStatus
			default:
				slog.Warn("cfhost: unexpected service control request", "cmd", c.Cmd)
			}
		case err := <-errCh:
			changes <- svc.Status{State: svc.Stopped}
			if err != nil {
				slog.Error("cfhost: service loop exited", "error", err.Error())
				return false, 1
			}
			return false, 0
		}
	}
}

// pidAlive reports whether a process with the given PID exists.
func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		// Access denied still proves the process exists.
		return errors.Is(err, windows.ERROR_ACCESS_DENIED)
	}
	windows.CloseHandle(h)
	return true
}

// runSupervised routes RunLoop into the service handler when started by SCM.
func runSupervised(ctx context.Context, cfg *Config) error {
	if isWindowsService() {
		return runAsWindowsService(ctx, cfg)
	}
	return loopWithLock(ctx, cfg)
}
