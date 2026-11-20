// Package cfpush uploads the pools described by pools.json to a cfdoh
// server's preferred-pool report endpoint — the same self-report path the
// probers use — as a manual fallback when the cfhub feed is unavailable.
//
// 契约: .trellis/spec/arch/cfpush.md. 单次执行: 读文件, 校验, 逐池上报,
// 汇总退出; 不重试, 不常驻, 不落状态.
package cfpush

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultSource  = "cfpush"
	defaultTTL     = 86400
	minTTL         = 60
	maxTTL         = 86400
	RequestTimeout = 10 * time.Second
	maxPools       = 64
	maxAddrs       = 64 // matches the server's per-family cap
	maxBodyPreview = 512
)

// Config mirrors pools.json: the upload target and credentials plus the
// pools themselves, so one file carries everything the tool needs.
type Config struct {
	URL    string `json:"url"`
	Token  string `json:"token"`
	Source string `json:"source"`
	TTL    int    `json:"ttl"`
	CFHub  *bool  `json:"cfhub,omitempty"`
	Pools  []Pool `json:"pools"`
}

// Pool is one reported scope with its address families.
type Pool struct {
	Scope string   `json:"scope"`
	IPv4  []string `json:"ipv4"`
	IPv6  []string `json:"ipv6"`
}

// httpClient bounds one upload request.
var httpClient = &http.Client{Timeout: RequestTimeout}

// Run loads pools.json next to the executable and uploads every pool.
func Run() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("executable path: %w", err)
	}
	return RunFile(filepath.Join(filepath.Dir(exe), "pools.json"))
}

// RunFile loads, validates and uploads one pools.json. A failed pool does
// not stop the rest; any failure makes the overall result an error.
func RunFile(path string) error {
	cfg, err := LoadConfig(path)
	if err != nil {
		return err
	}
	failed := 0
	for i := range cfg.Pools {
		p := &cfg.Pools[i]
		if err := Upload(cfg, p); err != nil {
			failed++
			fmt.Fprintf(os.Stderr, "cfpush: %s: %v\n", p.Scope, err)
			continue
		}
		fmt.Printf("cfpush: %s: ok (v4=%d v6=%d ttl=%d)\n",
			p.Scope, len(p.IPv4), len(p.IPv6), cfg.TTL)
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d pools failed", failed, len(cfg.Pools))
	}
	return nil
}

// LoadConfig reads and validates one pools.json file.
func LoadConfig(path string) (*Config, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var cfg Config
	if err := json.Unmarshal(body, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	cfg.URL = strings.TrimSpace(cfg.URL)
	if cfg.URL == "" {
		return nil, errors.New("url is required")
	}
	if !strings.HasPrefix(cfg.URL, "http://") && !strings.HasPrefix(cfg.URL, "https://") {
		return nil, errors.New("url must be http(s)")
	}
	cfg.Token = strings.TrimSpace(cfg.Token)
	if cfg.Token == "" {
		return nil, errors.New("token is required")
	}
	if strings.TrimSpace(cfg.Source) == "" {
		cfg.Source = defaultSource
	}
	cfg.TTL = clampTTL(cfg.TTL)
	if len(cfg.Pools) == 0 {
		return nil, errors.New("no pools")
	}
	if len(cfg.Pools) > maxPools {
		return nil, fmt.Errorf("too many pools (%d > %d)", len(cfg.Pools), maxPools)
	}
	for i := range cfg.Pools {
		p := &cfg.Pools[i]
		p.Scope = strings.TrimSpace(p.Scope)
		if p.Scope == "" {
			return nil, fmt.Errorf("pools[%d]: scope is required", i)
		}
		if len(p.IPv4) > maxAddrs || len(p.IPv6) > maxAddrs {
			return nil, fmt.Errorf("pools[%d] (%s): too many addresses (max %d per family)",
				i, p.Scope, maxAddrs)
		}
		// Both families empty is a legal report: the server installs an
		// empty pool, which supersedes (clears) whatever that scope held.
	}
	return &cfg, nil
}

func clampTTL(ttl int) int {
	switch {
	case ttl == 0:
		return defaultTTL
	case ttl < minTTL:
		return minTTL
	case ttl > maxTTL:
		return maxTTL
	}
	return ttl
}

// Upload reports one pool. A non-2xx reply or an unexpected body fails
// the entry; the server's error text is surfaced verbatim (e.g. the
// outside-the-Cloudflare-ranges rejection for isp scopes).
func Upload(cfg *Config, p *Pool) error {
	report := map[string]any{
		"ipv4":   p.IPv4,
		"ipv6":   p.IPv6,
		"ttl":    cfg.TTL,
		"source": cfg.Source,
		"scope":  p.Scope,
	}
	if cfg.CFHub != nil {
		report["cfhub"] = *cfg.CFHub
	}
	payload, err := json.Marshal(report)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, cfg.URL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyPreview+1))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out struct {
		OK bool `json:"ok"`
	}
	if err := json.Unmarshal(body, &out); err != nil || !out.OK {
		return fmt.Errorf("unexpected response: %s", strings.TrimSpace(string(body)))
	}
	return nil
}
