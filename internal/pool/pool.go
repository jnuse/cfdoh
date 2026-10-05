// Package pool holds the layered preferred-IP pools: three learned tables
// (self-learning, client-prefix scoped, operator), the per-host pools
// (GitHub, sites) and the layering logic that picks a pool for a request.
//
// 契约: .trellis/spec/arch/pool.md. 取池窄优先, 每地址族独立补足; 投票与限段
// 规则是防污染核心; 容量常量集中 rank.go; Meta ECH 状态不入本模块.
package pool

import (
	"container/list"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/jnuse/cfdoh/internal/config"
	"github.com/jnuse/cfdoh/internal/upstream"
	"github.com/jnuse/cfdoh/internal/wire"
)

// now is the clock hook for tests (unix milliseconds).
var now = func() int64 { return time.Now().UnixMilli() }

// Pool is the resolved preferred pool for one request.
type Pool struct {
	IPv4  []string
	IPv6  []string
	Scope string // narrower scopes that contributed, comma-joined
}

// SourceStatus is one self-learning source's report.
type SourceStatus struct {
	Source    string
	IPv4      []string
	IPv6      []string
	ExpiresAt int64
}

// LearnedReport is the merged nationwide self-learning pool.
type LearnedReport struct {
	IPv4      []string
	IPv6      []string
	ExpiresAt int64
	Sources   []SourceStatus
}

// ScopedReport is one client-prefix pool snapshot.
type ScopedReport struct {
	Scope     string
	IPv4      []string
	IPv6      []string
	ExpiresAt int64
	Active    bool
}

// IspPoolReport is one operator pool snapshot.
type IspPoolReport struct {
	Scope     string
	IPv4      []string
	IPv6      []string
	ExpiresAt int64
	Active    bool
}

type learnedPool struct {
	ipv4      []string
	ipv6      []string
	expiresAt int64
	source    string
}

// poolTable is an insertion-ordered table with capacity eviction (oldest
// first); re-setting a key refreshes its position.
type poolTable struct {
	entries map[string]*learnedPool
	order   *list.List
	cap     int
}

func newPoolTable(capacity int) *poolTable {
	return &poolTable{entries: make(map[string]*learnedPool), order: list.New(), cap: capacity}
}

func (t *poolTable) set(key string, pool *learnedPool) {
	if _, ok := t.entries[key]; ok {
		delete(t.entries, key)
		for el := t.order.Front(); el != nil; el = el.Next() {
			if el.Value.(string) == key {
				t.order.Remove(el)
				break
			}
		}
	}
	t.entries[key] = pool
	t.order.PushBack(key)
	for t.order.Len() > t.cap {
		oldest := t.order.Front()
		delete(t.entries, oldest.Value.(string))
		t.order.Remove(oldest)
	}
}

// get returns the pool when present and unexpired, deleting it otherwise.
func (t *poolTable) get(key string) *learnedPool {
	if key == "" {
		return nil
	}
	pool, ok := t.entries[key]
	if !ok {
		return nil
	}
	if pool.expiresAt <= now() {
		delete(t.entries, key)
		for el := t.order.Front(); el != nil; el = el.Next() {
			if el.Value.(string) == key {
				t.order.Remove(el)
				break
			}
		}
		return nil
	}
	return pool
}

// snapshot lists entries oldest-first with expiry kept verbatim.
func (t *poolTable) snapshot() []*learnedPool {
	out := make([]*learnedPool, 0, len(t.entries))
	for el := t.order.Front(); el != nil; el = el.Next() {
		out = append(out, t.entries[el.Value.(string)])
	}
	return out
}

var (
	mu       sync.RWMutex
	defaults = newPoolTable(MaxDefaultSources) // keyed by source
	scoped   = newPoolTable(MaxScopedPools)    // keyed by client scope
	ispPools = newPoolTable(MaxIspPools)       // keyed by "isp:<name>"
)

// SetLearned records one prober report. scope "" targets the nationwide
// self-learning table (keyed by source); "isp:<name>" targets operator
// pools; anything else is a client-prefix pool. Every address is strictly
// validated; lists are deduplicated.
func SetLearned(ipv4, ipv6 []string, ttl int, source, scope string) error {
	for _, addr := range ipv4 {
		if _, err := wire.ParseIPv4(addr); err != nil {
			return fmt.Errorf("invalid ipv4 address %q", addr)
		}
	}
	for _, addr := range ipv6 {
		if _, err := wire.ParseIPv6(addr); err != nil {
			return fmt.Errorf("invalid ipv6 address %q", addr)
		}
	}
	pool := &learnedPool{
		ipv4:      dedupe(ipv4),
		ipv6:      dedupe(ipv6),
		expiresAt: now() + int64(ttl)*1000,
		source:    source,
	}
	mutate(func() {
		mu.Lock()
		defer mu.Unlock()
		if scope == "" {
			defaults.set(source, pool)
		} else if strings.HasPrefix(scope, "isp:") {
			ispPools.set(scope, pool)
		} else {
			scoped.set(scope, pool)
		}
	})
	slog.Info("event", "event", "preferred_pool_updated", "detail",
		fmt.Sprintf("source=%s scope=%s ipv4=%d ipv6=%d ttl=%d", source, scope, len(pool.ipv4), len(pool.ipv6), ttl))
	return nil
}

// activeLearned merges the nationwide self-learning sources at read time.
func activeLearned() *learnedPool {
	var pools []*learnedPool
	for _, pool := range defaults.snapshot() {
		if pool.expiresAt > now() {
			pools = append(pools, pool)
		}
	}
	if len(pools) == 0 {
		return nil
	}
	merged := &learnedPool{source: strings.Join(poolSources(pools), "+")}
	lists4 := make([][]string, len(pools))
	lists6 := make([][]string, len(pools))
	for i, pool := range pools {
		lists4[i] = pool.ipv4
		lists6[i] = pool.ipv6
		merged.expiresAt = maxInt64(merged.expiresAt, pool.expiresAt)
	}
	merged.ipv4 = CombineRankings(lists4, PoolSize)
	merged.ipv6 = CombineRankings(lists6, PoolSize)
	return merged
}

func poolSources(pools []*learnedPool) []string {
	out := make([]string, 0, len(pools))
	for _, pool := range pools {
		out = append(out, pool.source)
	}
	return out
}

type poolLayer struct {
	pool  *learnedPool
	scope string // "" when the layer needs no cache scope of its own
}

// Preferred resolves the preferred pool for one request. Layer order
// (narrow first): client-prefix pool → operator pool → hub nationwide pool
// → self-learning pool; explicit request parameters skip all four. Each
// family fills independently to PoolSize; when no learned layer is active
// the preferred domains (or the static config) provide the pool.
func Preferred(ctx context.Context, explicitV4, explicitV6, domains []string, usingDefault bool, cfg *config.Config, clientScope, ispScope string) (*Pool, error) {
	ipv4 := explicitV4
	if ipv4 == nil {
		ipv4 = cfg.CFPreferredIPv4
	}
	ipv6 := explicitV6
	if ipv6 == nil {
		ipv6 = cfg.CFPreferredIPv6
	}

	// Write lock: layer collection may lazily evict expired entries, which
	// mutates the shared tables — a read lock would race on concurrent
	// Preferred calls hitting the same expired key.
	mu.Lock()
	var layers []poolLayer
	if usingDefault {
		if pool := scoped.get(clientScope); pool != nil {
			layers = append(layers, poolLayer{pool, clientScope})
		}
		if pool := ispPools.get(ispScope); pool != nil {
			layers = append(layers, poolLayer{pool, ispScope})
		}
		if ispScope != ScopeNational {
			if pool := ispPools.get(ScopeNational); pool != nil {
				layers = append(layers, poolLayer{pool, ""})
			}
		}
		if nationwide := activeLearned(); nationwide != nil {
			layers = append(layers, poolLayer{nationwide, ""})
		}
	}
	mu.Unlock()

	var used []string
	usedSet := make(map[string]bool)
	if len(layers) > 0 {
		if explicitV4 == nil {
			if filled := fillFamily(layers, false, &used, usedSet); filled != nil {
				ipv4 = filled
			}
		}
		if explicitV6 == nil && !cfg.CFDropAAAA {
			if filled := fillFamily(layers, true, &used, usedSet); filled != nil {
				ipv6 = filled
			}
		}
	} else if len(domains) > 0 && (explicitV4 == nil || explicitV6 == nil) {
		resolved, err := mergedDomainPool(ctx, domains, cfg)
		if err != nil {
			return nil, err
		}
		if explicitV4 == nil {
			ipv4 = resolved.v4
		}
		if explicitV6 == nil {
			ipv6 = resolved.v6
		}
	}
	if cfg.CFDropAAAA {
		ipv6 = []string{}
	}
	return &Pool{IPv4: ipv4, IPv6: ipv6, Scope: strings.Join(used, ",")}, nil
}

// fillFamily walks the layers narrow→wide, topping the family up to
// PoolSize with addresses the wider layers add.
func fillFamily(layers []poolLayer, v6 bool, used *[]string, usedSet map[string]bool) []string {
	var out []string
	included := make(map[string]bool)
	for _, layer := range layers {
		family := layer.pool.ipv4
		if v6 {
			family = layer.pool.ipv6
		}
		added := 0
		for _, addr := range family {
			if included[addr] || len(out) >= PoolSize {
				continue
			}
			included[addr] = true
			out = append(out, addr)
			added++
		}
		if added > 0 && layer.scope != "" && !usedSet[layer.scope] {
			usedSet[layer.scope] = true
			*used = append(*used, layer.scope)
		}
		if len(out) >= PoolSize {
			break
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

type domainAddresses struct {
	v4, v6 []string
}

// mergedDomainPool resolves every preferred domain, tolerating single
// failures; all failing is an error. Union deduplicated, 16 per family.
func mergedDomainPool(ctx context.Context, domains []string, cfg *config.Config) (*domainAddresses, error) {
	results := make([]domainAddresses, len(domains))
	failures := 0
	var wg sync.WaitGroup
	for i, domain := range domains {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v4, v6, err := upstream.ResolveAddresses(ctx, domain, cfg)
			if err != nil {
				return
			}
			results[i] = domainAddresses{v4: v4, v6: v6}
		}()
	}
	wg.Wait()
	seen4 := make(map[string]bool)
	seen6 := make(map[string]bool)
	out := &domainAddresses{}
	for _, result := range results {
		if result.v4 == nil && result.v6 == nil {
			failures++
			continue
		}
		for _, addr := range result.v4 {
			if !seen4[addr] && len(out.v4) < 16 {
				seen4[addr] = true
				out.v4 = append(out.v4, addr)
			}
		}
		for _, addr := range result.v6 {
			if !seen6[addr] && len(out.v6) < 16 {
				seen6[addr] = true
				out.v6 = append(out.v6, addr)
			}
		}
	}
	if failures == len(domains) {
		return nil, fmt.Errorf("unable to resolve any preferred domain (%s)", strings.Join(domains, ", "))
	}
	return out, nil
}

// LearnedStatus renders the merged nationwide self-learning pool. Only
// sources whose reports are still valid are listed (aligns the baseline:
// lapsed probers must not linger in the status view).
func LearnedStatus() *LearnedReport {
	mu.RLock()
	defer mu.RUnlock()
	pools := activeLearned()
	if pools == nil {
		return nil
	}
	report := &LearnedReport{IPv4: pools.ipv4, IPv6: pools.ipv6, ExpiresAt: pools.expiresAt}
	current := now()
	for _, pool := range defaults.snapshot() {
		if pool.expiresAt <= current {
			continue
		}
		report.Sources = append(report.Sources, SourceStatus{
			Source: pool.source, IPv4: pool.ipv4, IPv6: pool.ipv6, ExpiresAt: pool.expiresAt,
		})
	}
	return report
}

// ScopedStatus lists the client-prefix pools.
func ScopedStatus() []ScopedReport {
	mu.RLock()
	defer mu.RUnlock()
	return scopedReports(scoped)
}

// IspPoolStatus lists the operator pools (national included).
func IspPoolStatus() []IspPoolReport {
	mu.RLock()
	defer mu.RUnlock()
	reports := scopedReports(ispPools)
	out := make([]IspPoolReport, len(reports))
	for i, r := range reports {
		out[i] = IspPoolReport(r)
	}
	return out
}

func scopedReports(t *poolTable) []ScopedReport {
	var out []ScopedReport
	for _, pool := range t.snapshot() {
		scope := scopeOfTable(t, pool)
		if scope == "" {
			continue
		}
		out = append(out, ScopedReport{
			Scope: scope, IPv4: pool.ipv4, IPv6: pool.ipv6,
			ExpiresAt: pool.expiresAt, Active: pool.expiresAt > now(),
		})
	}
	return out
}

func scopeOfTable(t *poolTable, pool *learnedPool) string {
	for el := t.order.Front(); el != nil; el = el.Next() {
		key := el.Value.(string)
		if t.entries[key] == pool {
			return key
		}
	}
	return ""
}

func dedupe(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
