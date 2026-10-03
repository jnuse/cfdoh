// Package hubfeed pulls the public pool API (cfhub) into the operator and
// nationwide pools.
//
// 契约: .trellis/spec/arch/hubfeed.md. 仅采用 published 为真的池; 逐池校验任一
// 地址不在 Cloudflare 公布网段内则整池不采用, 其余池不受影响; 拉取在后台执行,
// 不阻塞查询路径.
package hubfeed

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/jnuse/cfdoh/internal/cfrange"
	"github.com/jnuse/cfdoh/internal/config"
	"github.com/jnuse/cfdoh/internal/pool"
	"github.com/jnuse/cfdoh/internal/wire"
)

const (
	fetchTimeout = 10 * time.Second
	maxFeedBytes = 2 << 20 // 2MiB
	perFamilyCap = 6       // addresses adopted per pool family
)

// ispFeedName validates feed isp fields (same alphabet as the isp table).
var ispFeedName = regexp.MustCompile(`^[a-z][a-z0-9-]{1,23}$`)

// feedDoc mirrors the public pool API JSON.
type feedDoc struct {
	Pools []feedPool `json:"pools"`
}

type feedPool struct {
	ISP       string      `json:"isp"`
	Family    int         `json:"family"`
	IPs       []feedEntry `json:"ips"`
	Probers   int         `json:"probers"`
	Users     int         `json:"users"`
	Published bool        `json:"published"`
}

type feedEntry struct {
	IP string `json:"ip"`
}

// httpClient never follows redirects: a moved feed is a failure, not a chase.
var httpClient = &http.Client{
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// Start launches the background refresh loop: one immediate pull, then one
// every PoolFeedIntervalSec. An empty POOL_FEED_URL disables the feature.
func Start(ctx context.Context, cfg *config.Config) error {
	if cfg == nil || cfg.PoolFeedDisabled || cfg.PoolFeedURL == "" {
		slog.Info("pool feed disabled")
		return nil
	}
	go func() {
		if err := RefreshOnce(ctx, cfg); err != nil {
			slog.Warn("pool feed initial refresh failed", "error", err.Error())
		}
		interval := cfg.PoolFeedIntervalSec
		if interval <= 0 {
			interval = 60
		}
		ticker := time.NewTicker(time.Duration(interval) * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := RefreshOnce(ctx, cfg); err != nil {
					slog.Warn("pool feed refresh failed", "error", err.Error())
				}
			}
		}
	}()
	return nil
}

// RefreshOnce pulls, validates and installs the public pools in one pass.
func RefreshOnce(ctx context.Context, cfg *config.Config) error {
	started := time.Now()
	doc, err := fetch(ctx, cfg.PoolFeedURL)
	if err != nil {
		slog.Warn("event", "event", "pool_feed_refresh", "detail",
			fmt.Sprintf("ok=false error=%s elapsed_ms=%d", err.Error(), time.Since(started).Milliseconds()))
		return err
	}

	// scope → {v4, v6} addresses in feed order
	adopted := map[string][2][]string{}
	var summary []string
	for i := range doc.Pools {
		entry := &doc.Pools[i]
		if !entry.Published {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(entry.ISP))
		if name != "national" && !ispFeedName.MatchString(name) {
			reject(entry, "invalid isp name %q", entry.ISP)
			continue
		}
		if entry.Family != 4 && entry.Family != 6 {
			reject(entry, "invalid family %d", entry.Family)
			continue
		}
		addresses, err := validateAddresses(entry)
		if err != nil {
			reject(entry, "%v", err)
			continue
		}
		scope := "isp:" + name
		merged := adopted[scope]
		if entry.Family == 4 {
			merged[0] = addresses
		} else {
			merged[1] = addresses
		}
		adopted[scope] = merged
	}

	for scope, families := range adopted {
		if len(families[0]) == 0 && len(families[1]) == 0 {
			continue
		}
		if err := pool.SetLearned(families[0], families[1], cfg.PoolFeedTTLSec, "pool-feed", scope); err != nil {
			slog.Warn("pool feed install failed", "scope", scope, "error", err.Error())
			continue
		}
		summary = append(summary, fmt.Sprintf("%s:v4=%d,v6=%d", scope, len(families[0]), len(families[1])))
	}
	slog.Info("event", "event", "pool_feed_refresh", "detail",
		fmt.Sprintf("ok=true %s elapsed_ms=%d", strings.Join(summary, " "), time.Since(started).Milliseconds()))
	return nil
}

// validateAddresses strictly parses and Cloudflare-checks every address of
// the pool (pollution anywhere rejects the whole pool, F-028); the adopted
// list keeps feed order, deduplicated, capped after full validation.
func validateAddresses(entry *feedPool) ([]string, error) {
	ranges := cfrange.Current()
	if ranges == nil {
		return nil, fmt.Errorf("cloudflare ranges not loaded yet")
	}
	var out []string
	seen := make(map[string]bool)
	for _, item := range entry.IPs {
		ip := strings.TrimSpace(item.IP)
		if ip == "" {
			return nil, fmt.Errorf("empty address")
		}
		var err error
		if entry.Family == 4 {
			_, err = wire.ParseIPv4(ip)
		} else {
			_, err = wire.ParseIPv6(ip)
		}
		if err != nil {
			return nil, fmt.Errorf("invalid address %q", ip)
		}
		if !ranges.Contains(ip) {
			return nil, fmt.Errorf("address %q outside cloudflare ranges", ip)
		}
		if seen[ip] {
			continue
		}
		seen[ip] = true
		if len(out) < perFamilyCap {
			out = append(out, ip)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("pool has no addresses")
	}
	return out, nil
}

func reject(entry *feedPool, format string, args ...any) {
	slog.Warn("event", "event", "pool_feed_rejected", "detail",
		fmt.Sprintf("pool isp=%s family=%d rejected: %s", entry.ISP, entry.Family, fmt.Sprintf(format, args...)))
}

func fetch(ctx context.Context, url string) (*feedDoc, error) {
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFeedBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxFeedBytes {
		return nil, fmt.Errorf("feed exceeds %d bytes", maxFeedBytes)
	}
	var doc feedDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("invalid feed JSON: %w", err)
	}
	return &doc, nil
}
