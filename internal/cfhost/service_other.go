//go:build !windows

package cfhost

import (
	"context"
	"errors"
	"syscall"
)

var errServiceRequiresWindows = errors.New("service management requires Windows")

type stubService struct{}

func servicePlatform() serviceControl { return stubService{} }

func (stubService) install() error   { return errServiceRequiresWindows }
func (stubService) uninstall() error { return errServiceRequiresWindows }
func (stubService) start() error     { return errServiceRequiresWindows }
func (stubService) stop() error      { return errServiceRequiresWindows }

// isWindowsService is always false off Windows.
func isWindowsService() bool { return false }

// runSupervised runs the plain locked loop.
func runSupervised(ctx context.Context, cfg *Config) error {
	return loopWithLock(ctx, cfg)
}

// pidAlive reports whether a process with the given PID exists: kill(pid, 0)
// succeeds or fails with EPERM (process exists, owned by another user).
func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}
