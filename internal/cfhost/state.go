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
	"time"
)

// State persistence and the single-instance lock. The state file records the
// addresses in use, the last sweep summary and the fallback candidate list.
// A corrupt state file is treated as an empty state (never blocks startup).

// lockGracePeriod is how long a contender waits for a concurrently starting
// creator to write its PID before treating an empty lock file as abandoned.
const lockGracePeriod = 200 * time.Millisecond

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

// acquireLock takes the single-instance lock next to the state file. The
// lock file is created exclusively (O_EXCL) and the PID written right after,
// so two simultaneous starts can never both win. A live PID in the lock
// file is a hard error; a stale or corrupt lock is removed and creation
// retried once. The returned release func removes the lock file.
func acquireLock(statePath string) (func(), error) {
	lockPath := lockPathFor(statePath)
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		return nil, fmt.Errorf("lock dir: %w", err)
	}
	release, err := createLockFile(lockPath)
	if err == nil {
		return release, nil
	}
	if !errors.Is(err, fs.ErrExist) {
		return nil, fmt.Errorf("create lock: %w", err)
	}
	// The lock exists: a live holder is a hard error; a stale, corrupt or
	// just-vanished lock is cleared and creation retried once.
	if pid, ok := lockHolderPID(lockPath); ok && pidAlive(pid) {
		return nil, fmt.Errorf("another cfhost instance is running (pid %d)", pid)
	}
	if err := os.Remove(lockPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("remove stale lock: %w", err)
	}
	release, err = createLockFile(lockPath)
	if err != nil {
		return nil, fmt.Errorf("another cfhost instance is running (create lock: %w)", err)
	}
	return release, nil
}

// createLockFile creates the lock file exclusively and writes the current
// PID into it.
func createLockFile(lockPath string) (func(), error) {
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	if _, err := f.Write([]byte(strconv.Itoa(os.Getpid()))); err != nil {
		f.Close()
		os.Remove(lockPath)
		return nil, fmt.Errorf("write lock: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(lockPath)
		return nil, fmt.Errorf("close lock: %w", err)
	}
	return func() { os.Remove(lockPath) }, nil
}

// lockHolderPID reads the holder PID from the lock file. A just-created
// empty file may belong to a concurrently starting creator that has not
// written its PID yet; it gets a short grace period before being treated as
// abandoned. Corrupt content resolves to (0, true) — no live holder. A
// missing or unreadable file resolves to ok=false (undecidable).
func lockHolderPID(lockPath string) (pid int, decided bool) {
	deadline := time.Now().Add(lockGracePeriod)
	for {
		data, err := os.ReadFile(lockPath)
		if err != nil {
			return 0, false
		}
		if pid, perr := strconv.Atoi(strings.TrimSpace(string(data))); perr == nil && pid > 0 {
			return pid, true
		}
		if len(data) > 0 || time.Now().After(deadline) {
			return 0, true // corrupt or abandoned: no live holder
		}
		time.Sleep(2 * time.Millisecond)
	}
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
