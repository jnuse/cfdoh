//go:build !windows

package cfhost

// sameVolumeDefault: off Windows the temp file always stays in the hosts
// directory (existing behavior) — /tmp may be a different filesystem (e.g.
// tmpfs) and volume names cannot tell, so preferring it would risk
// non-atomic cross-filesystem renames.
func sameVolumeDefault(a, b string) bool { return false }

// isRenameLockErrorDefault: off Windows no rename failure is classified as
// an antivirus scan lock, so backoff retries never trigger.
func isRenameLockErrorDefault(err error) bool { return false }

// hostsPreserveACLDefault is a no-op off Windows: POSIX permission bits
// flow through Chmod and rename carries no ACL to preserve.
func hostsPreserveACLDefault(tmpName, origPath string) error { return nil }
