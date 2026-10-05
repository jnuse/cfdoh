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

// ResetLearnedPoolsForTesting clears the three learned pool tables and the
// content-tag cache. Test support so cross-package tests (resolver) start
// from a deterministic learned state instead of inheriting whatever earlier
// tests uploaded; never call from production paths.
func ResetLearnedPoolsForTesting() {
	mu.Lock()
	defaults = newPoolTable(MaxDefaultSources)
	scoped = newPoolTable(MaxScopedPools)
	ispPools = newPoolTable(MaxIspPools)
	mu.Unlock()
	tagMu.Lock()
	cachedValid = false
	tagMu.Unlock()
}
