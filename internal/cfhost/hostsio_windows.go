//go:build windows

package cfhost

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
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

// hostsPreserveACLDefault carries the original hosts file's security
// descriptor (owner, group, DACL) onto the staged temp file before the
// rename. A same-volume rename keeps the temp file's ACL, which inherits
// from the user profile TEMP directory (current user full control, no
// BUILTIN\Users read) — after the swap the DNS Client service (NETWORK
// SERVICE, granted read through Users) cannot open hosts and silently
// bypasses it. Copying the original's descriptor restores the expected
// inheritance chain. A missing original (first run, or the operator removed
// a polluted file) gets the standard protected DACL instead — SYSTEM and
// Administrators full control, Users read+execute — via well-known SIDs so
// non-English installs match too.
func hostsPreserveACLDefault(tmpName, origPath string) error {
	const sections = windows.OWNER_SECURITY_INFORMATION |
		windows.GROUP_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION
	if _, statErr := os.Stat(origPath); statErr == nil {
		orig, err := windows.GetNamedSecurityInfo(origPath, windows.SE_FILE_OBJECT, sections)
		if err != nil {
			return fmt.Errorf("read original hosts acl: %w", err)
		}
		owner, _, err := orig.Owner()
		if err != nil {
			return fmt.Errorf("read original hosts owner: %w", err)
		}
		group, _, err := orig.Group()
		if err != nil {
			return fmt.Errorf("read original hosts group: %w", err)
		}
		dacl, _, err := orig.DACL()
		if err != nil {
			return fmt.Errorf("read original hosts dacl: %w", err)
		}
		err = windows.SetNamedSecurityInfo(tmpName, windows.SE_FILE_OBJECT, sections, owner, group, dacl, nil)
		if errors.Is(err, windows.ERROR_INVALID_OWNER) || errors.Is(err, windows.ERROR_INVALID_PRIMARY_GROUP) {
			// The original owner (or group) cannot be assigned by this process
			// — e.g. a Windows update reset hosts ownership to TrustedInstaller
			// and the service token lacks SeRestorePrivilege/SeTakeOwnership.
			// The owner is cosmetic here: the mechanism exists for the DACL
			// (Users read for the DNS Client). Degrade to DACL-only instead of
			// skipping the round; after the rename the file owns SYSTEM and
			// subsequent rounds take the full path again (self-healing).
			slog.Info("cfhost: hosts owner carry unavailable, applying DACL only", "error", err.Error())
			return windows.SetNamedSecurityInfo(tmpName, windows.SE_FILE_OBJECT,
				windows.DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
		}
		return err
	}
	// No original to inherit from: apply the standard hosts DACL explicitly.
	sd, err := windows.SecurityDescriptorFromString(
		"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;RX;;;BU)")
	if err != nil {
		return fmt.Errorf("build standard hosts acl: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("read standard hosts dacl: %w", err)
	}
	return windows.SetNamedSecurityInfo(tmpName, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}
