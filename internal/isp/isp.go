// Package isp maps client addresses to operator scopes ("isp:<name>") using
// a remotely fetched "<operator> <CIDR>" table.
//
// 契约: .trellis/spec/arch/isp.md. 表行解析集中一处; 保留名 national 禁用;
// 同地址命中多网段取最长前缀 (区间表 + 单调栈 parent 指针); 识别永不阻塞查询,
// 未配置/未命中/加载失败一律回落 (调用方走全国层).
package isp

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jnuse/cfdoh/internal/config"
)

const (
	maxTableBytes = 4 << 20 // 4MiB
	refreshEvery  = 10 * time.Minute
	retryEvery    = 60 * time.Second
	fetchTimeout  = 5 * time.Second
)

// ispName matches [a-z][a-z0-9-]{1,23}: 2..24 chars, lowercase.
var ispName = regexp.MustCompile(`^[a-z][a-z0-9-]{1,23}$`)

// ScopeNationalPrefix is the scope prefix shared with pool ("isp:<name>").
const scopePrefix = "isp:"

// entry is one closed interval [start, end] per CIDR.
type entry struct {
	start netip.Addr
	end   netip.Addr
	isp   int
}

// rangeSet is a sorted interval table with a parent pointer to the nearest
// enclosing range: CIDRs nest or are disjoint, so the most specific range
// covering an address is found by walking up from the last range that starts
// at or before it.
type rangeSet struct {
	entries []entry
	parent  []int
}

type table struct {
	names []string
	v4    *rangeSet
	v6    *rangeSet
}

var (
	mu         sync.Mutex
	current    *table
	loadedAt   time.Time
	failedAt   time.Time
	refreshing bool
	tableText  string
)

// now is the clock hook for tests.
var now = time.Now

// Reset forgets all loaded state (test hook).
func Reset() {
	mu.Lock()
	defer mu.Unlock()
	current = nil
	tableText = ""
	loadedAt = time.Time{}
	failedAt = time.Time{}
	refreshing = false
}

// ScopeOf returns the operator scope of clientIP. It never blocks: the
// first load runs in the background, and until it lands every lookup misses
// and the caller falls back to the nationwide pool.
func ScopeOf(ctx context.Context, clientIP string, cfg *config.Config) (string, bool) {
	if strings.TrimSpace(clientIP) == "" || cfg == nil || cfg.IspTableURL == "" {
		return "", false
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(clientIP))
	if err != nil {
		return "", false
	}
	addr = addr.Unmap()

	if needRefresh() {
		go refresh(context.WithoutCancel(ctx), cfg)
	}

	mu.Lock()
	t := current
	mu.Unlock()
	if t == nil {
		return "", false
	}
	name := lookup(t, addr)
	if name == "" {
		return "", false
	}
	return scopePrefix + name, true
}

// needRefresh reports whether a refresh should start now: the failed-load
// backoff applies both before the first successful load and while a stale
// table keeps serving, so a dead source is retried at most once per window.
func needRefresh() bool {
	mu.Lock()
	defer mu.Unlock()
	if refreshing {
		return false
	}
	n := now()
	if !failedAt.IsZero() && n.Sub(failedAt) < retryEvery {
		return false
	}
	if current == nil {
		return true
	}
	return n.Sub(loadedAt) >= refreshEvery
}

// refresh fetches and installs the table; unchanged content is not rebuilt.
func refresh(ctx context.Context, cfg *config.Config) {
	mu.Lock()
	if refreshing {
		mu.Unlock()
		return
	}
	refreshing = true
	mu.Unlock()

	err := func() error {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), fetchTimeout)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.IspTableURL, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Cache-Control", "no-cache")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			return fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxTableBytes+1))
		if err != nil {
			return err
		}
		if len(body) > maxTableBytes {
			return fmt.Errorf("table exceeds %d bytes", maxTableBytes)
		}
		text := string(body)
		parsed, err := parseTable(text)
		if err != nil {
			return err
		}
		mu.Lock()
		defer mu.Unlock()
		if text != tableText {
			current = parsed
			tableText = text
		}
		loadedAt = now()
		return nil
	}()

	mu.Lock()
	refreshing = false
	if err != nil {
		failedAt = now()
	} else {
		failedAt = time.Time{}
	}
	mu.Unlock()
}

// parseTable parses "<isp> <cidr>" lines. Malformed lines are skipped
// silently; a table with zero usable entries is an error.
func parseTable(text string) (*table, error) {
	var names []string
	index := make(map[string]int)
	var v4, v6 []entry
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name, cidr := fields[0], fields[1]
		// "national" names the nationwide pool, never an operator.
		if name == "national" || !ispName.MatchString(name) {
			continue
		}
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil || prefix.Addr().Zone() != "" {
			continue
		}
		prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()).Masked()
		start := prefix.Addr()
		end := lastAddress(prefix)
		id, ok := index[name]
		if !ok {
			id = len(names)
			index[name] = id
			names = append(names, name)
		}
		if start.Is4() {
			v4 = append(v4, entry{start: start, end: end, isp: id})
		} else {
			v6 = append(v6, entry{start: start, end: end, isp: id})
		}
	}
	if len(v4) == 0 && len(v6) == 0 {
		return nil, fmt.Errorf("isp table has no usable entries")
	}
	return &table{names: names, v4: buildRanges(v4), v6: buildRanges(v6)}, nil
}

// buildRanges sorts entries by start ascending (equal starts: broader first)
// and links each range to its nearest enclosing one via a monotonic stack.
func buildRanges(entries []entry) *rangeSet {
	sorted := make([]entry, len(entries))
	copy(sorted, entries)
	sort.Slice(sorted, func(i, j int) bool {
		if c := sorted[i].start.Compare(sorted[j].start); c != 0 {
			return c < 0
		}
		// equal starts: broader (larger end) first
		return sorted[i].end.Compare(sorted[j].end) > 0
	})
	parent := make([]int, len(sorted))
	var stack []int
	for i := range sorted {
		for len(stack) > 0 && sorted[stack[len(stack)-1]].end.Compare(sorted[i].start) < 0 {
			stack = stack[:len(stack)-1]
		}
		if len(stack) > 0 {
			parent[i] = stack[len(stack)-1]
		} else {
			parent[i] = -1
		}
		stack = append(stack, i)
	}
	return &rangeSet{entries: sorted, parent: parent}
}

// lookup returns the operator of the most specific range containing addr.
func lookup(t *table, addr netip.Addr) string {
	set := t.v6
	if addr.Is4() {
		set = t.v4
	}
	// binary search: last entry whose start is <= addr
	lo, hi, found := 0, len(set.entries)-1, -1
	for lo <= hi {
		mid := (lo + hi) / 2
		if set.entries[mid].start.Compare(addr) <= 0 {
			found = mid
			lo = mid + 1
		} else {
			hi = mid - 1
		}
	}
	for at := found; at >= 0; at = set.parent[at] {
		if set.entries[at].end.Compare(addr) >= 0 {
			return t.names[set.entries[at].isp]
		}
	}
	return ""
}

func lastAddress(p netip.Prefix) netip.Addr {
	addr := p.Addr()
	bits := p.Bits()
	if addr.Is4() {
		var out [4]byte
		b := addr.As4()
		copy(out[:], b[:])
		hostBits := 32 - bits
		for i := 3; i >= 0 && hostBits > 0; i-- {
			out[i] |= byte((1 << min(hostBits, 8)) - 1)
			hostBits -= 8
		}
		return netip.AddrFrom4(out)
	}
	var out [16]byte
	b := addr.As16()
	copy(out[:], b[:])
	hostBits := 128 - bits
	for i := 15; i >= 0 && hostBits > 0; i-- {
		out[i] |= byte((1 << min(hostBits, 8)) - 1)
		hostBits -= 8
	}
	return netip.AddrFrom16(out)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
