package main

import "testing"

// H2 regression: the installed Windows service starts the binary with the
// "run" argument, which must land in the daemon loop, not the
// unknown-subcommand exit path.
func TestDaemonInvocation(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"run"},
	} {
		if !daemonInvocation(args) {
			t.Fatalf("daemonInvocation(%q) = false, want true", args)
		}
	}
	for _, args := range [][]string{
		{"install"},
		{"uninstall"},
		{"start"},
		{"stop"},
		{"run-once"},
		{"status"},
		{"--version"},
		{"unknown"},
	} {
		if daemonInvocation(args) {
			t.Fatalf("daemonInvocation(%q) = true, want false", args)
		}
	}
}
