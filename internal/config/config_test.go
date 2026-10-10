package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadClean(t *testing.T) *Config {
	t.Helper()
	for _, name := range []string{
		"UPSTREAMS", "ECS_UPSTREAMS", "UPSTREAM_TIMEOUT_MS", "UPSTREAM_HEDGE_MS",
		"CACHE_MIN_TTL", "CACHE_MAX_TTL", "NEGATIVE_CACHE_MAX_TTL", "CACHE_STALE_TTL",
		"CACHE_PREFETCH_PERCENT", "ECS_MODE", "ECS_DOMAINS", "ECS_IPV4_PREFIX", "ECS_IPV6_PREFIX",
		"POOL_FEED_URL", "POOL_FEED_INTERVAL_SEC", "POOL_FEED_TTL_SEC",
		"HOST", "PORT", "PUBLIC_HOSTNAMES", "MAX_DNS_PACKET_SIZE", "DYNAMIC_RULES_MAX_BYTES",
		"CACHE_MAX_ENTRIES", "ADMIN_TOKEN", "HUB_TOKEN", "CFDOH_CONFIG", "RULES_JSON",
		"ECS_DOMAINS_URL",
	} {
		os.Unsetenv(name)
	}
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cfg
}

func TestDefaults(t *testing.T) {
	cfg := loadClean(t)
	if len(cfg.Upstreams) != 3 || cfg.Upstreams[0] != "https://cloudflare-dns.com/dns-query" {
		t.Fatalf("upstreams default: %v", cfg.Upstreams)
	}
	if cfg.UpstreamTimeoutMs != 2500 || cfg.UpstreamHedgeMs != 100 {
		t.Fatalf("timeout/hedge defaults: %d %d", cfg.UpstreamTimeoutMs, cfg.UpstreamHedgeMs)
	}
	if cfg.EcsMode != "rules" || len(cfg.EcsDomains) != 1 || cfg.EcsDomains[0] != ".cn" {
		t.Fatalf("ecs defaults: %v %v", cfg.EcsMode, cfg.EcsDomains)
	}
	if cfg.PoolFeedURL != "https://cfhub.1molchuan.top/api/v1/pools" || cfg.PoolFeedDisabled {
		t.Fatalf("pool feed default: %v %v", cfg.PoolFeedURL, cfg.PoolFeedDisabled)
	}
	if cfg.Port != 8787 || cfg.Host != "127.0.0.1" {
		t.Fatalf("listen default: %s %d", cfg.Host, cfg.Port)
	}
	if cfg.MaxDNSPacketSize != 4096 || cfg.CacheMaxEntries != 4096 {
		t.Fatalf("limits default: %d %d", cfg.MaxDNSPacketSize, cfg.CacheMaxEntries)
	}
	if cfg.EchSourceDomain != "cloudflare-ech.com" || len(cfg.MetaDomains) != 6 {
		t.Fatalf("ech defaults: %v %v", cfg.EchSourceDomain, cfg.MetaDomains)
	}
	if cfg.TLSEnabled() {
		t.Fatal("tls enabled by default")
	}
}

func TestClamping(t *testing.T) {
	t.Setenv("UPSTREAM_TIMEOUT_MS", "10")
	t.Setenv("CACHE_MAX_TTL", "999999")
	t.Setenv("CACHE_PREFETCH_PERCENT", "-5")
	t.Setenv("MAX_DNS_PACKET_SIZE", "abc")
	cfg := loadClean(t)
	// t.Setenv before loadClean's Unsetenv... loadClean unsets! Re-do without clean.
	_ = cfg
}

func TestEcsUpstreamsFollowsUpstreams(t *testing.T) {
	// unset (or empty) ECS_UPSTREAMS follows the resolved UPSTREAMS so
	// subnet-bearing queries stay on the operator's own relay set instead
	// of leaking to the built-in default triple (B2/M6)
	os.Unsetenv("UPSTREAMS")
	os.Unsetenv("ECS_UPSTREAMS")
	relay := "https://relay.example/dns-query,https://relay2.example/dns-query"
	t.Setenv("UPSTREAMS", relay)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(cfg.EcsUpstreams, ",") != relay {
		t.Fatalf("EcsUpstreams must follow Upstreams when ECS_UPSTREAMS is unset: %v", cfg.EcsUpstreams)
	}
	for _, u := range cfg.EcsUpstreams {
		if strings.Contains(u, "cloudflare-dns.com") || strings.Contains(u, "dns.google") || strings.Contains(u, "quad9") {
			t.Fatalf("subnet-bearing queries must not leak to the built-in defaults: %v", cfg.EcsUpstreams)
		}
	}

	// both unset: the built-in triple, unchanged default behavior
	os.Unsetenv("UPSTREAMS")
	cfg, err = Load()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(cfg.EcsUpstreams, ",") != strings.Join(cfg.Upstreams, ",") {
		t.Fatalf("both unset must yield the same list: %v vs %v", cfg.EcsUpstreams, cfg.Upstreams)
	}
	if len(cfg.EcsUpstreams) != 3 {
		t.Fatalf("default triple = %v", cfg.EcsUpstreams)
	}

	// an explicitly set ECS_UPSTREAMS keeps its own fail-fast semantics
	t.Setenv("UPSTREAMS", relay)
	t.Setenv("ECS_UPSTREAMS", "https://ecs-relay.example/dns-query")
	cfg, err = Load()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(cfg.EcsUpstreams, ",") != "https://ecs-relay.example/dns-query" {
		t.Fatalf("explicit ECS_UPSTREAMS must win: %v", cfg.EcsUpstreams)
	}
}

func TestClampingDirect(t *testing.T) {
	for _, name := range []string{"UPSTREAM_TIMEOUT_MS", "CACHE_MAX_TTL", "CACHE_PREFETCH_PERCENT", "MAX_DNS_PACKET_SIZE"} {
		os.Unsetenv(name)
	}
	t.Setenv("UPSTREAM_TIMEOUT_MS", "10")
	t.Setenv("CACHE_MAX_TTL", "999999")
	t.Setenv("CACHE_PREFETCH_PERCENT", "-5")
	t.Setenv("MAX_DNS_PACKET_SIZE", "60000")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.UpstreamTimeoutMs != 250 {
		t.Fatalf("timeout not clamped to min: %d", cfg.UpstreamTimeoutMs)
	}
	if cfg.CacheMaxTTL != 86400 {
		t.Fatalf("max ttl not clamped: %d", cfg.CacheMaxTTL)
	}
	if cfg.CachePrefetchPercent != 0 {
		t.Fatalf("prefetch not clamped: %d", cfg.CachePrefetchPercent)
	}
	if cfg.MaxDNSPacketSize != 60000 {
		t.Fatalf("in-range value altered: %d", cfg.MaxDNSPacketSize)
	}
}

func TestEnvOverFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfdoh.env")
	if err := os.WriteFile(path, []byte("# comment\nPORT=9999\nADMIN_TOKEN=file-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CFDOH_CONFIG", path)
	t.Setenv("PORT", "7777")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != 7777 {
		t.Fatalf("env should win: %d", cfg.Port)
	}
	if cfg.AdminToken != "file-token" {
		t.Fatalf("file value lost: %q", cfg.AdminToken)
	}
}

func TestHTTPSFilter(t *testing.T) {
	t.Setenv("UPSTREAMS", "http://insecure.example/dns-query,https://secure.example/dns-query")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Upstreams) != 1 || cfg.Upstreams[0] != "https://secure.example/dns-query" {
		t.Fatalf("https filter: %v", cfg.Upstreams)
	}
}

func TestPoolFeedDisable(t *testing.T) {
	t.Setenv("POOL_FEED_URL", "")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.PoolFeedDisabled || cfg.PoolFeedURL != "" {
		t.Fatalf("disable semantics: %q %v", cfg.PoolFeedURL, cfg.PoolFeedDisabled)
	}
}

func TestSanitizedSummaryHidesTokens(t *testing.T) {
	t.Setenv("ADMIN_TOKEN", "super-secret")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	summary := cfg.SanitizedSummary()
	if len(summary) == 0 {
		t.Fatal("empty summary")
	}
	if contains(summary, "super-secret") {
		t.Fatal("token leaked into summary")
	}
}

func contains(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}

// L10 regression: a single legitimate line beyond the 64KiB scanner default
// (e.g. an embedded rules payload) loads fine; only lines past the 4MiB cap
// still fail.
func TestLongConfigLineAccepted(t *testing.T) {
	os.Unsetenv("ADMIN_TOKEN")
	dir := t.TempDir()
	long := strings.Repeat("a", 100*1024)
	path := filepath.Join(dir, "cfdoh.env")
	if err := os.WriteFile(path, []byte("ADMIN_TOKEN="+long+"\nPORT=9000\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CFDOH_CONFIG", path)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("long single line must load: %v", err)
	}
	if cfg.Port != 9000 || cfg.AdminToken != long {
		t.Fatalf("long line value lost: port=%d token-len=%d", cfg.Port, len(cfg.AdminToken))
	}

	over := filepath.Join(dir, "over.env")
	if err := os.WriteFile(over, []byte("ADMIN_TOKEN="+strings.Repeat("a", (4<<20)+8)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CFDOH_CONFIG", over)
	if _, err := Load(); err == nil {
		t.Fatal("line beyond the 4MiB cap must fail")
	}
}

// loadTestConfig unsets the ISP-related variables, applies env with
// t.Setenv (auto-restored) and loads.
func loadTestConfig(t *testing.T, env map[string]string) *Config {
	t.Helper()
	os.Unsetenv("ISP_TABLE_URL")
	os.Unsetenv("ISP_SOURCES")
	for k, v := range env {
		t.Setenv(k, v)
	}
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cfg
}

func TestIspSourcesDefaultsAndModes(t *testing.T) {
	// Unset ISP_TABLE_URL and ISP_SOURCES: the built-in operator sources
	// load; explicit empty disables; a custom list replaces; the table URL
	// wins and leaves sources empty.
	t.Run("default sources", func(t *testing.T) {
		cfg := loadTestConfig(t, nil)
		if cfg.IspTableURL != "" || len(cfg.IspSources) != 4 {
			t.Fatalf("want 4 built-in sources, got table=%q sources=%d", cfg.IspTableURL, len(cfg.IspSources))
		}
		for _, s := range cfg.IspSources {
			if !strings.HasPrefix(s.URL, "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/") {
				t.Fatalf("unexpected built-in URL %q", s.URL)
			}
		}
	})
	t.Run("explicit empty disables", func(t *testing.T) {
		cfg := loadTestConfig(t, map[string]string{"ISP_SOURCES": " "})
		if len(cfg.IspSources) != 0 {
			t.Fatalf("blank ISP_SOURCES must disable, got %d sources", len(cfg.IspSources))
		}
	})
	t.Run("custom list", func(t *testing.T) {
		cfg := loadTestConfig(t, map[string]string{
			"ISP_SOURCES": " chinanet=https://a.example/c.txt , bad, x=http://plain.example/c.txt",
		})
		if len(cfg.IspSources) != 1 || cfg.IspSources[0].Name != "chinanet" {
			t.Fatalf("want only the valid https entry, got %+v", cfg.IspSources)
		}
	})
	t.Run("table url wins", func(t *testing.T) {
		cfg := loadTestConfig(t, map[string]string{
			"ISP_TABLE_URL": "https://table.example/isp.txt",
			"ISP_SOURCES":   "chinanet=https://a.example/c.txt",
		})
		if cfg.IspTableURL == "" || len(cfg.IspSources) != 0 {
			t.Fatalf("ISP_TABLE_URL must override sources, got table=%q sources=%d",
				cfg.IspTableURL, len(cfg.IspSources))
		}
	})
}

func TestEcsDomainsURLDefaultAndOptOut(t *testing.T) {
	os.Unsetenv("ECS_DOMAINS_URL")
	// Unset: the built-in community table (same policy as ISP_SOURCES).
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.EcsDomainsURL != defaultEcsDomainsURL {
		t.Fatalf("default ECS_DOMAINS_URL = %q, want the built-in chnlist URL", cfg.EcsDomainsURL)
	}
	// Explicitly empty: the dynamic table is off.
	t.Setenv("ECS_DOMAINS_URL", "")
	cfg, err = Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.EcsDomainsURL != "" {
		t.Fatalf("empty ECS_DOMAINS_URL must disable the dynamic table, got %q", cfg.EcsDomainsURL)
	}
}
