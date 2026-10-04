package pool

// ResetHostPoolsForTesting clears the GitHub and site pool tables and the
// content-tag cache. Test support for cross-package tests that need a
// deterministic empty host-pool state; never call from production paths.
func ResetHostPoolsForTesting() {
	github = newHostPools(MaxHostSources)
	sites = newHostPools(MaxHostSources)
	tagMu.Lock()
	cachedValid = false
	tagMu.Unlock()
}
