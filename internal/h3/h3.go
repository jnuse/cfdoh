// Package h3 gates HTTP/3 advertisement on measured QUIC+ECH verdicts.
//
// 契约: .trellis/spec/arch/h3.md. 同一主机全部来源都确认才允许 h3, 任一否认
// 即否决; 主机按后缀最长匹配, verdict 作用于该主机及其子域; 有效快照变化递增
// 代数, 代数折入 HTTPS 应答缓存键.
package h3

import (
	"container/list"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/jnuse/cfdoh/internal/wire"
)

// Capacity constants (spec: 集中一处定义).
const (
	maxSources = 8
	maxHosts   = 64
)

// Verdict is the effective judgment for a name.
type Verdict struct {
	Host    string
	Allowed bool
	Sources []string
}

// SourceStatus is one prober's report snapshot.
type SourceStatus struct {
	Source    string
	Hosts     map[string]bool
	ExpiresAt int64
}

// StatusReport is the full module state for /admin endpoints.
type StatusReport struct {
	Effective map[string]bool
	Sources   []SourceStatus
}

type report struct {
	hosts     map[string]bool
	expiresAt int64
}

// now is the clock hook for tests (unix milliseconds).
var now = func() int64 { return time.Now().UnixMilli() }

var (
	mu           sync.Mutex
	sources      = make(map[string]*report)
	sourceOrder  list.List // source names, oldest first
	generation   int
	lastSnapshot string
)

// SetVerdicts replaces one source's verdict report. Host names are
// canonicalized; each report carries at most maxHosts entries and at most
// maxSources reports are kept (oldest evicted).
func SetVerdicts(source string, verdicts map[string]bool, ttl int) {
	hosts := make(map[string]bool, len(verdicts))
	names := make([]string, 0, len(verdicts))
	for host := range verdicts {
		names = append(names, host)
	}
	sort.Strings(names) // deterministic cap
	if len(names) > maxHosts {
		names = names[:maxHosts]
	}
	for _, host := range names {
		hosts[wire.CanonicalName(host)] = verdicts[host]
	}
	mu.Lock()
	defer mu.Unlock()
	rep := &report{hosts: hosts, expiresAt: now() + int64(ttl)*1000}
	delete(sources, source) // re-reporting moves the source to freshest
	for el := sourceOrder.Front(); el != nil; el = el.Next() {
		if el.Value.(string) == source {
			sourceOrder.Remove(el)
			break
		}
	}
	sources[source] = rep
	sourceOrder.PushBack(source)
	for sourceOrder.Len() > maxSources {
		oldest := sourceOrder.Front()
		delete(sources, oldest.Value.(string))
		sourceOrder.Remove(oldest)
	}
	refreshGenerationLocked()
	slog.Info("event", "event", "h3_verdicts_updated", "detail", fmt.Sprintf("source=%s verdicts=%d ttl=%d", source, len(hosts), ttl))
}

// VerdictFor returns the verdict of the most specific reported host covering
// name, or nil without data.
func VerdictFor(name string) *Verdict {
	mu.Lock()
	defer mu.Unlock()
	effective := pruneAndEffectiveLocked()
	var best *Verdict
	for host, entry := range effective {
		if !wire.MatchDomain(name, []string{"*." + host}) {
			continue
		}
		if best == nil || len(host) > len(best.Host) {
			v := Verdict{Host: host, Allowed: entry.allowed, Sources: append([]string(nil), entry.sources...)}
			best = &v
		}
	}
	return best
}

// AlpnFor returns the ALPN list for an ECH-carrying HTTPS answer: h3+h2 when
// probers confirm QUIC+ECH, h2 when they found it failing, otherwise the
// caller's fallback (upstream ALPN preserved).
func AlpnFor(name string, fallback []string) (alpn []string, why string) {
	verdict := VerdictFor(name)
	if verdict == nil {
		return fallback, "no QUIC+ECH measurement; default"
	}
	detail := fmt.Sprintf("%s: %v", verdict.Host, verdict.Sources)
	if verdict.Allowed {
		return []string{"h3", "h2"}, "QUIC+ECH works per probers (" + detail + ")"
	}
	return []string{"h2"}, "QUIC+ECH fails per probers (" + detail + ")"
}

// CacheTag is the generation tag folded into HTTPS cache keys; it changes
// exactly when the effective verdict snapshot changes.
func CacheTag() string {
	mu.Lock()
	defer mu.Unlock()
	refreshGenerationLocked()
	return fmt.Sprintf("h3g%d", generation)
}

type effectiveEntry struct {
	allowed bool
	sources []string
}

// pruneAndEffectiveLocked drops expired reports and merges the rest.
func pruneAndEffectiveLocked() map[string]*effectiveEntry {
	current := now()
	for source, rep := range sources {
		if rep.expiresAt <= current {
			delete(sources, source)
			for el := sourceOrder.Front(); el != nil; el = el.Next() {
				if el.Value.(string) == source {
					sourceOrder.Remove(el)
					break
				}
			}
		}
	}
	result := make(map[string]*effectiveEntry)
	for source, rep := range sources {
		for host, ok := range rep.hosts {
			entry := result[host]
			if entry == nil {
				entry = &effectiveEntry{allowed: true}
				result[host] = entry
			}
			if !ok {
				entry.allowed = false
			}
			entry.sources = append(entry.sources, fmt.Sprintf("%s:%s", source, okWord(ok)))
		}
	}
	return result
}

func okWord(ok bool) string {
	if ok {
		return "ok"
	}
	return "fail"
}

// refreshGenerationLocked bumps the generation when the effective snapshot
// (sorted host→allowed pairs) changed since the last observation.
func refreshGenerationLocked() {
	effective := pruneAndEffectiveLocked()
	pairs := make([]string, 0, len(effective))
	for host, entry := range effective {
		pairs = append(pairs, fmt.Sprintf("%s=%v", host, entry.allowed))
	}
	sort.Strings(pairs)
	snapshot := fmt.Sprintf("%v", pairs)
	if snapshot != lastSnapshot {
		lastSnapshot = snapshot
		generation++
	}
}

// Status renders the full state for /admin/h3.
func Status() *StatusReport {
	mu.Lock()
	defer mu.Unlock()
	effective := pruneAndEffectiveLocked()
	out := &StatusReport{Effective: make(map[string]bool, len(effective)), Sources: nil}
	for host, entry := range effective {
		out.Effective[host] = entry.allowed
	}
	for el := sourceOrder.Front(); el != nil; el = el.Next() {
		source := el.Value.(string)
		rep := sources[source]
		hosts := make(map[string]bool, len(rep.hosts))
		expires := int64(0)
		for host, ok := range rep.hosts {
			hosts[host] = ok
			if rep.expiresAt > expires {
				expires = rep.expiresAt
			}
		}
		out.Sources = append(out.Sources, SourceStatus{Source: source, Hosts: hosts, ExpiresAt: expires})
	}
	return out
}
