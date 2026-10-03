// Package cfrange fetches Cloudflare's published IP ranges and answers
// membership queries.
//
// 契约: .trellis/spec/arch/cfrange.md. 判定语义保持纯函数; Load 成功后换入
// 包级当前表 (数据所有权: 当前网段表与拉取时刻), 失败时调用方沿用旧表.
package cfrange

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jnuse/cfdoh/internal/config"
)

// fetch limits: the published lists are a few hundred bytes each.
const (
	maxListBytes = 1 << 20
	fetchTimeout = 10 * time.Second
)

// Ranges is an immutable snapshot of Cloudflare's published prefixes.
type Ranges struct {
	V4 []netip.Prefix
	V6 []netip.Prefix
}

// current holds the latest successful snapshot; nil until the first load.
var current atomic.Pointer[Ranges]

// Load fetches both official lists, deduplicates the prefixes and swaps them
// in as the package's current table. On failure it returns an error and
// leaves the previous table untouched.
func Load(ctx context.Context, cfg *config.Config) (*Ranges, error) {
	if cfg == nil {
		return nil, fmt.Errorf("cfrange: nil config")
	}
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	v4, err := fetchPrefixes(ctx, cfg.CFIPv4URL)
	if err != nil {
		return nil, fmt.Errorf("cfrange ipv4 list: %w", err)
	}
	v6, err := fetchPrefixes(ctx, cfg.CFIPv6URL)
	if err != nil {
		return nil, fmt.Errorf("cfrange ipv6 list: %w", err)
	}
	r := &Ranges{V4: dedupe(v4), V6: dedupe(v6)}
	current.Store(r)
	return r, nil
}

// Current returns the table the rest of the server shares (hubfeed's pool
// validation, rewrite's Cloudflare checks). Nil-safe: Contains on a nil
// table answers false.
func Current() *Ranges { return current.Load() }

// Contains reports whether ip falls inside any published prefix of its
// address family.
func (r *Ranges) Contains(ip string) bool {
	if r == nil {
		return false
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	if addr.Is4() {
		for _, p := range r.V4 {
			if p.Contains(addr) {
				return true
			}
		}
		return false
	}
	for _, p := range r.V6 {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func fetchPrefixes(ctx context.Context, url string) ([]netip.Prefix, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxListBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxListBytes {
		return nil, fmt.Errorf("list exceeds %d bytes", maxListBytes)
	}
	var out []netip.Prefix
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		prefix, err := netip.ParsePrefix(line)
		if err != nil {
			continue // malformed lines are skipped, not fatal
		}
		out = append(out, prefix.Masked())
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no usable prefixes")
	}
	return out, nil
}

func dedupe(in []netip.Prefix) []netip.Prefix {
	seen := make(map[netip.Prefix]bool, len(in))
	out := make([]netip.Prefix, 0, len(in))
	for _, p := range in {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}
