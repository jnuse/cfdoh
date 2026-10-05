//go:build windows

package cfhost

import (
	"errors"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// sameVolumeDefault reports whether two paths live on the same volume, so a
// rename between them stays atomic. On Windows this compares drive (or UNC)
// prefixes; incomparable paths (empty volume names) count as different.
func sameVolumeDefault(a, b string) bool {
	va, vb := filepath.VolumeName(a), filepath.VolumeName(b)
	return va != "" && va == vb
}

// isRenameLockErrorDefault reports whether a rename failure looks like a
// transient antivirus scan handle on the file: access denied (5) or sharing
// violation (32).
func isRenameLockErrorDefault(err error) bool {
	var errno windows.Errno
	if !errors.As(err, &errno) {
		return false
	}
	return errno == windows.ERROR_ACCESS_DENIED || errno == windows.ERROR_SHARING_VIOLATION
}
