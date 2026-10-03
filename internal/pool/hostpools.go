package pool

import (
	"container/list"
	"fmt"
	"hash/fnv"
	"log/slog"
	"sync"

	"github.com/jnuse/cfdoh/internal/wire"
)

// HostSourceStatus is one reporting source of a per-host pool.
type HostSourceStatus struct {
	Source    string
	Hosts     int
	ExpiresAt int64
}

// HostPoolStatus is the merged per-host pool state.
type HostPoolStatus struct {
	Sources []HostSourceStatus
	Hosts   map[string][]string
}

type hostReport struct {
	hosts     map[string][]string // host → ranked IPv4 list
	expiresAt int64
}

// hostPools keeps per-host IPv4 pools reported by several sources: each
// source's latest report replaces its previous one and a host's pool is
// merged at read time over the sources listing it.
type hostPools struct {
	mu      sync.Mutex
	sources map[string]*hostReport
	order   *list.List
	cap     int
}

func newHostPools(capacity int) *hostPools {
	return &hostPools{sources: make(map[string]*hostReport), order: list.New(), cap: capacity}
}

func (h *hostPools) set(source string, hosts map[string][]string, ttl int) {
	clean := make(map[string][]string, len(hosts))
	for host, ips := range hosts {
		name := wire.CanonicalName(host)
		var valid []string
		seen := make(map[string]bool)
		for _, ip := range ips {
			if _, err := wire.ParseIPv4(ip); err != nil || seen[ip] {
				continue // defensive: httpapi validates before calling
			}
			seen[ip] = true
			valid = append(valid, ip)
		}
		if name != "" && name != "." && len(valid) > 0 {
			clean[name] = valid
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.sources[source]; ok {
		delete(h.sources, source)
		for el := h.order.Front(); el != nil; el = el.Next() {
			if el.Value.(string) == source {
				h.order.Remove(el)
				break
			}
		}
	}
	h.sources[source] = &hostReport{hosts: clean, expiresAt: now() + int64(ttl)*1000}
	h.order.PushBack(source)
	for h.order.Len() > h.cap {
		oldest := h.order.Front()
		delete(h.sources, oldest.Value.(string))
		h.order.Remove(oldest)
	}
}

// active returns the unexpired reports oldest-first.
func (h *hostPools) active() []*hostReport {
	current := now()
	var out []*hostReport
	for el := h.order.Front(); el != nil; el = el.Next() {
		source := el.Value.(string)
		report := h.sources[source]
		if report.expiresAt <= current {
			// lazy expiry: drop and keep walking with the list intact here;
			// deletion happens on the next mutation or read of that source.
			continue
		}
		out = append(out, report)
	}
	return out
}

func (h *hostPools) poolFor(host string) []string {
	name := wire.CanonicalName(host)
	h.mu.Lock()
	defer h.mu.Unlock()
	var lists [][]string
	for _, report := range h.active() {
		if list, ok := report.hosts[name]; ok {
			lists = append(lists, list)
		}
	}
	if len(lists) == 0 {
		return nil
	}
	return CombineRankings(lists, PoolSize)
}

func (h *hostPools) status() *HostPoolStatus {
	h.mu.Lock()
	defer h.mu.Unlock()
	active := h.active()
	if len(active) == 0 {
		return nil
	}
	// rebuild order-indexed source list
	out := &HostPoolStatus{Hosts: make(map[string][]string)}
	index := make(map[*hostReport]string)
	for el := h.order.Front(); el != nil; el = el.Next() {
		source := el.Value.(string)
		if report, ok := h.sources[source]; ok && report.expiresAt > now() {
			index[report] = source
			out.Sources = append(out.Sources, HostSourceStatus{
				Source: source, Hosts: len(report.hosts), ExpiresAt: report.expiresAt,
			})
		}
	}
	for _, report := range active {
		for host := range report.hosts {
			if _, done := out.Hosts[host]; !done {
				out.Hosts[host] = h.poolForLocked(host)
			}
		}
	}
	return out
}

// poolForLocked is poolFor without re-locking.
func (h *hostPools) poolForLocked(host string) []string {
	var lists [][]string
	for _, report := range h.active() {
		if list, ok := report.hosts[host]; ok {
			lists = append(lists, list)
		}
	}
	if len(lists) == 0 {
		return nil
	}
	return CombineRankings(lists, PoolSize)
}

var (
	github = newHostPools(MaxHostSources)
	sites  = newHostPools(MaxHostSources)
)

// SetGithub replaces one source's GitHub host pools.
func SetGithub(source string, hosts map[string][]string, ttl int) {
	github.set(source, hosts, ttl)
	slog.Info("event", "event", "github_pools_updated", "detail",
		fmt.Sprintf("source=%s hosts=%d ttl=%d", source, len(hosts), ttl))
}

// SetSites replaces one source's site pools. A report without a host
// withdraws that source's override for it.
func SetSites(source string, hosts map[string][]string, ttl int) {
	sites.set(source, hosts, ttl)
	slog.Info("event", "event", "site_pools_updated", "detail",
		fmt.Sprintf("source=%s hosts=%v ttl=%d", source, hostKeys(hosts), ttl))
}

// GithubPoolFor returns the merged IPv4 pool a GitHub host is pinned to.
func GithubPoolFor(host string) []string { return github.poolFor(host) }

// SitePoolFor returns the merged IPv4 pool a site host is pinned to.
func SitePoolFor(host string) []string { return sites.poolFor(host) }

// SitePoolTag is the cache-key tag of a host's active site pool (content
// hash, stable across restarts); empty without an active pool.
func SitePoolTag(host string) string {
	pool := sites.poolFor(host)
	if len(pool) == 0 {
		return ""
	}
	h := fnv.New32a()
	h.Write([]byte(joinComma(pool)))
	return fmt.Sprintf("site%x", h.Sum32())
}

// GithubStatus renders the GitHub pools state.
func GithubStatus() *HostPoolStatus { return github.status() }

// SiteStatus renders the site pools state.
func SiteStatus() *HostPoolStatus { return sites.status() }

func joinComma(values []string) string {
	out := ""
	for i, value := range values {
		if i > 0 {
			out += ","
		}
		out += value
	}
	return out
}

func hostKeys(hosts map[string][]string) []string {
	out := make([]string, 0, len(hosts))
	for host := range hosts {
		out = append(out, host)
	}
	return out
}
