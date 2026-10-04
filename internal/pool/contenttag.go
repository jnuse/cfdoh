package pool

import (
	"fmt"
	"hash/fnv"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// The content tag hashes the effective (unexpired) content of all five pool
// tables into one stable value. The resolver folds it into the cache
// variant so any pool flip — a learned, GitHub or site pool write, or the
// lazy expiry of the last active entry — changes cache keys immediately
// instead of after the answer TTL (F-004/F-007/F-028).
//
// Hashing content rather than counting writes matches the reference tags
// (site content hash; h3 and Meta generations bump only on effective
// change): a prober re-reporting an identical list keeps the tag, so
// periodic no-op reports do not flush the answer cache. The tag is also
// stable across restarts — same content, same tag — so reloading the pool
// and cache snapshots keeps previously cached entries valid instead of
// invalidating every key once per boot.

// tagMu serializes pool-table mutations with tag computation. It is always
// acquired before any table lock and never after (mutate and ContentTag
// both take it first), so it cannot deadlock with mu or the host-pool
// mutexes.
var tagMu sync.Mutex

var (
	cachedTag     string
	cachedValid   bool
	cachedHorizon int64 // earliest expiresAt folded into cachedTag
)

// mutate runs one table mutation under tagMu, dropping the cached tag.
// Every writer to the five tables goes through here (SetLearned,
// SetGithub, SetSites, LoadState) so the tag can never go stale on a flip.
func mutate(fn func()) {
	tagMu.Lock()
	defer tagMu.Unlock()
	cachedValid = false
	fn()
}

// ContentTag returns the content hash over every pool table's active
// content; the resolver folds it into the cache variant.
func ContentTag() string {
	tagMu.Lock()
	if cachedValid && now() < cachedHorizon {
		tag := cachedTag
		tagMu.Unlock()
		return tag
	}
	tagMu.Unlock()

	tagMu.Lock()
	defer tagMu.Unlock()
	// re-check: another call may have computed while we waited
	if cachedValid && now() < cachedHorizon {
		return cachedTag
	}
	tag, horizon := snapshotContentLocked()
	cachedTag, cachedValid, cachedHorizon = tag, true, horizon
	return tag
}

// snapshotContentLocked builds the canonical content string of the five
// tables and hashes it; the caller holds tagMu. Table locks are taken in
// the fixed order mu → github → sites. Only active entries are folded;
// their earliest expiresAt becomes the horizon at which the tag must be
// recomputed (lazy expiry is a content change: the nationwide pool layer
// disappearing falls answers back to the domain/static pools, and the
// served answers must follow at the next query, F-007).
func snapshotContentLocked() (string, int64) {
	current := now()
	var b strings.Builder
	horizon := int64(math.MaxInt64)

	mu.RLock()
	appendLearnedLocked(&b, &horizon, current, 'D', defaults)
	appendLearnedLocked(&b, &horizon, current, 'C', scoped)
	appendLearnedLocked(&b, &horizon, current, 'I', ispPools)
	mu.RUnlock()

	appendHostsLocked(&b, &horizon, current, 'G', github)
	appendHostsLocked(&b, &horizon, current, 'S', sites)

	if b.Len() == 0 {
		return "0", horizon // all tables empty (or fully expired): constant
	}
	h := fnv.New64a()
	h.Write([]byte(b.String()))
	return strconv.FormatUint(h.Sum64(), 16), horizon
}

// appendLearnedLocked folds one learned table. Keys are sorted so the
// hash is independent of write and map iteration order: a periodic
// multi-scope refresh rewrites identical content through a randomly
// iterated map (hubfeed) and re-setting each key moves it in the table's
// insertion list — identical content must keep the tag either way. The
// insertion order still governs capacity eviction; the caller holds mu.
func appendLearnedLocked(b *strings.Builder, horizon *int64, current int64, kind rune, t *poolTable) {
	keys := make([]string, 0, len(t.entries))
	for key, pool := range t.entries {
		if pool.expiresAt > current {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		pool := t.entries[key]
		fmt.Fprintf(b, "%c|%q|%s|%s\n", kind, key, strings.Join(pool.ipv4, ","), strings.Join(pool.ipv6, ","))
		*horizon = min(*horizon, pool.expiresAt)
	}
}

// appendHostsLocked folds one per-host pool; hosts are sorted so the map
// iteration order cannot shake the hash.
func appendHostsLocked(b *strings.Builder, horizon *int64, current int64, kind rune, h *hostPools) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for el := h.order.Front(); el != nil; el = el.Next() {
		source := el.Value.(string)
		report := h.sources[source]
		if report.expiresAt <= current {
			continue
		}
		hosts := make([]string, 0, len(report.hosts))
		for host := range report.hosts {
			hosts = append(hosts, host)
		}
		sort.Strings(hosts)
		for _, host := range hosts {
			fmt.Fprintf(b, "%c|%q|%q|%s\n", kind, source, host, strings.Join(report.hosts[host], ","))
		}
		*horizon = min(*horizon, report.expiresAt)
	}
}
