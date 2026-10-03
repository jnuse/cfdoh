package cfhost

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// State persistence and the single-instance lock. The state file records the
// addresses in use, the last sweep summary and the fallback candidate list.
// A corrupt state file is treated as an empty state (never blocks startup).

// clientState is the JSON shape of the state file.
type clientState struct {
	CurrentV4   string   `json:"current_v4"`
	CurrentV6   string   `json:"current_v6"`
	LastSummary string   `json:"last_summary"`
	NextRun     int64    `json:"next_run"`
	FailStreak  int      `json:"fail_streak"`
	Candidates  []string `json:"candidates"`
}

// loadState reads the state file; found is false only when the file does not
// exist. Corrupt JSON decodes to an empty state.
func loadState(path string) (clientState, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return clientState{}, false
		}
		return clientState{}, true
	}
	var st clientState
	if err := json.Unmarshal(data, &st); err != nil {
		return clientState{}, true
	}
	return st, true
}

// saveState writes the state atomically (temp file + rename), creating the
// parent directory when needed.
func saveState(path string, st clientState) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("state dir: %w", err)
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("encode state: %w", err)
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(dir, ".cfhost-state-*")
	if err != nil {
		return fmt.Errorf("temp state: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("write state: %w", err)
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("chmod state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("close state: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("rename state: %w", err)
	}
	return nil
}

// acquireLock takes the single-instance lock next to the state file. A live
// PID in the lock file is a hard error; a stale or corrupt lock is
// overwritten. The returned release func removes the lock file.
func acquireLock(statePath string) (func(), error) {
	lockPath := lockPathFor(statePath)
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		return nil, fmt.Errorf("lock dir: %w", err)
	}
	if data, err := os.ReadFile(lockPath); err == nil {
		if pid, perr := strconv.Atoi(strings.TrimSpace(string(data))); perr == nil && pidAlive(pid) {
			return nil, fmt.Errorf("another cfhost instance is running (pid %d)", pid)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("read lock: %w", err)
	}
	if err := os.WriteFile(lockPath, []byte(strconv.Itoa(os.Getpid())), 0o644); err != nil {
		return nil, fmt.Errorf("write lock: %w", err)
	}
	return func() { os.Remove(lockPath) }, nil
}

// readLockPID reports the PID held in the lock file, or 0 when free.
func readLockPID(statePath string) int {
	data, err := os.ReadFile(lockPathFor(statePath))
	if err != nil {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return 0
	}
	return pid
}

func lockPathFor(statePath string) string {
	return filepath.Join(filepath.Dir(statePath), "cfhost.lock")
}
