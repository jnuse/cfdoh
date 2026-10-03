//go:build windows

package cfhost

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	serviceName        = "cfhost"
	serviceDisplayName = "cfdoh cfhost"
)

type windowsService struct{}

func servicePlatform() serviceControl { return windowsService{} }

// install registers the service: automatic start, binpath = current
// executable + " run".
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
		DisplayName: serviceDisplayName,
		StartType:   mgr.StartAutomatic,
		Description: "cfdoh client daemon: latency probing and hosts maintenance",
	}, "run")
	if err != nil {
		return fmt.Errorf("cfhost: create service: %w", err)
	}
	defer s.Close()
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
				changes <- svc.Status{State: svc.StopPending}
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
