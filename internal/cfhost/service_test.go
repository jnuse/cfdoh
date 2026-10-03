package cfhost

import (
	"runtime"
	"testing"
)

func TestServiceStubsOnNonWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("non-Windows only")
	}
	fns := map[string]func() error{
		"Install":   Install,
		"Uninstall": Uninstall,
		"Start":     Start,
		"Stop":      Stop,
	}
	for name, fn := range fns {
		err := fn()
		if err == nil {
			t.Fatalf("%s should fail on non-Windows", name)
		}
		if err.Error() != "service management requires Windows" {
			t.Fatalf("%s error = %q", name, err.Error())
		}
	}
	if isWindowsService() {
		t.Fatal("isWindowsService must be false off Windows")
	}
}
