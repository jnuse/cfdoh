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
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/jnuse/cfdoh/internal/cfrange"
	"github.com/jnuse/cfdoh/internal/config"
	"github.com/jnuse/cfdoh/internal/pool"
	"github.com/jnuse/cfdoh/internal/wire"
)

const (
	fetchTimeout  = 10 * time.Second
	maxFeedBytes  = 2 << 20 // 2MiB
	ipv4FamilyCap = 10
	ipv6FamilyCap = 8
	stateVersion  = 1
)

var errStaticallyDisabled = errors.New("pool feed is statically disabled")

type stateFile struct {
	Version int   `json:"version"`
	Enabled *bool `json:"enabled"`
}

// Controller owns the live feed switch and serializes pool installation
// against state transitions. Fetching stays outside mu; generation checks
// prevent a stale in-flight response from being installed after a toggle.
type Controller struct {
	cfg       *config.Config
	statePath string
	available bool

	mu         sync.Mutex
	enabled    bool
	generation uint64
	started    bool
	wake       chan struct{}
}

// NewController creates a feed controller. A configured feed defaults to
// enabled; a statically disabled or empty URL remains unavailable.
func NewController(cfg *config.Config, statePath string) *Controller {
	available := cfg != nil && !cfg.PoolFeedDisabled && strings.TrimSpace(cfg.PoolFeedURL) != ""
	return &Controller{
		cfg: cfg, statePath: statePath, available: available,
		enabled: available, wake: make(chan struct{}, 1),
	}
}

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

// LoadState restores the optional persisted feed selection. Missing or
// unreadable snapshots use the configured default and never block startup.
func (c *Controller) LoadState() error {
	if c == nil {
		return nil
	}
	if c.statePath == "" {
		c.useDefaultState()
		return nil
	}
	data, err := os.ReadFile(c.statePath)
	if err != nil {
		if os.IsNotExist(err) {
			c.useDefaultState()
			return nil
		}
		c.useDefaultState()
		return err
	}
	var state stateFile
	if err := json.Unmarshal(data, &state); err != nil {
		slog.Warn("pool feed state unreadable; using default", "path", c.statePath, "error", err)
		c.useDefaultState()
		return nil
	}
	if state.Version != stateVersion || state.Enabled == nil {
		slog.Warn("pool feed state invalid; using default", "path", c.statePath, "version", state.Version)
		c.useDefaultState()
		return nil
	}

	c.mu.Lock()
	c.enabled = *state.Enabled && c.available
	c.generation++
	if !c.enabled {
		pool.RemoveIspSource("pool-feed")
	}
	c.mu.Unlock()
	return nil
}

// useDefaultState applies the configured startup default and removes restored
// feed pools only when the feed is statically unavailable.
func (c *Controller) useDefaultState() {
	c.mu.Lock()
	c.enabled = c.available
	c.generation++
	if !c.enabled {
		pool.RemoveIspSource("pool-feed")
	}
	c.mu.Unlock()
}

// SaveState snapshots the current selection when persistence is configured.
func (c *Controller) SaveState() error {
	if c == nil || c.statePath == "" {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writeStateLocked(c.enabled)
}

// Enabled reports the current runtime selection.
func (c *Controller) Enabled() bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.enabled
}

// SetEnabled persists a requested selection before applying it. Repeated
// values are idempotent; enabling a statically unavailable feed is rejected.
func (c *Controller) SetEnabled(enabled bool) error {
	if c == nil {
		return errors.New("pool feed controller is unavailable")
	}
	if enabled && !c.available {
		return errStaticallyDisabled
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.statePath != "" {
		if err := c.writeStateLocked(enabled); err != nil {
			return fmt.Errorf("persist pool feed state: %w", err)
		}
	}
	if c.enabled == enabled {
		if !enabled {
			pool.RemoveIspSource("pool-feed")
		}
		return nil
	}
	c.enabled = enabled
	c.generation++
	if !enabled {
		pool.RemoveIspSource("pool-feed")
	} else if c.started {
		select {
		case c.wake <- struct{}{}:
		default:
		}
	}
	return nil
}

func (c *Controller) writeStateLocked(enabled bool) error {
	selection := enabled
	data, err := json.Marshal(stateFile{Version: stateVersion, Enabled: &selection})
	if err != nil {
		return err
	}
	return writeStateFile(c.statePath, data)
}

// Start launches one worker that performs an immediate refresh when enabled,
// then refreshes on the configured interval or when a disabled feed is enabled.
func (c *Controller) Start(ctx context.Context) error {
	if c == nil || c.cfg == nil {
		return errors.New("pool feed configuration is unavailable")
	}
	c.mu.Lock()
	if c.started {
		c.mu.Unlock()
		return nil
	}
	c.started = true
	available := c.available
	c.mu.Unlock()
	if !available {
		slog.Info("pool feed disabled")
		return nil
	}
	go c.run(ctx)
	return nil
}

func (c *Controller) run(ctx context.Context) {
	interval := c.cfg.PoolFeedIntervalSec
	if interval <= 0 {
		interval = 60
	}
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()
	c.refreshAndLog(ctx, "initial")
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.refreshAndLog(ctx, "scheduled")
		case <-c.wake:
			c.refreshAndLog(ctx, "enabled")
		}
	}
}

func (c *Controller) refreshAndLog(ctx context.Context, reason string) {
	if err := c.RefreshOnce(ctx); err != nil {
		slog.Warn("pool feed "+reason+" refresh failed", "error", err.Error())
	}
}

// RefreshOnce fetches and validates the public pools, then installs them only
// if the enabled state and generation have not changed during the request.
func (c *Controller) RefreshOnce(ctx context.Context) error {
	if c == nil || c.cfg == nil {
		return errors.New("pool feed configuration is unavailable")
	}
	c.mu.Lock()
	if !c.enabled {
		c.mu.Unlock()
		return nil
	}
	generation := c.generation
	cfg := c.cfg
	c.mu.Unlock()

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

	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.enabled || c.generation != generation {
		slog.Info("event", "event", "pool_feed_refresh", "detail",
			fmt.Sprintf("ok=false discarded=state_changed elapsed_ms=%d", time.Since(started).Milliseconds()))
		return nil
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
	limit := ipv4FamilyCap
	if entry.Family == 6 {
		limit = ipv6FamilyCap
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
		if len(out) < limit {
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

func writeStateFile(path string, data []byte) error {
	tmp := path + ".tmp"
	file, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		os.Remove(tmp)
		return err
	}
	if err := file.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
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
