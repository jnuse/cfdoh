// Package config loads server configuration from environment variables and an
// optional KEY=VALUE file (path in CFDOH_CONFIG). Environment wins; numeric
// values are clamped into their documented ranges with a warning.
package config

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
)

// Config mirrors the environment surface one field per variable.
type Config struct {
	Upstreams            []string
	EcsUpstreams         []string
	UpstreamTimeoutMs    int
	UpstreamHedgeMs      int
	CacheMinTTL          int
	CacheMaxTTL          int
	NegativeCacheMaxTTL  int
	CacheStaleTTL        int
	CachePrefetchPercent int
	EcsMode              string
	EcsDomains           []string
	EcsIPv4Prefix        int
	EcsIPv6Prefix        int
	CFRewriteEnabled     bool
	CFPreferredDomain    []string
	CFPreferredIPv4      []string
	CFPreferredIPv6      []string
	CFDropAAAA           bool
	AdminToken           string
	HubToken             string
	DohOriginToken       string
	IspTableURL          string
	CFIPv4URL            string
	CFIPv6URL            string
	RulesJSON            string
	RulesURL             string
	EchEnabled           bool
	EchConfigBase64      string
	EchDomains           []string
	EchSourceDomain      string
	MetaEchConfigBase64  string
	MetaDomains          []string
	XDomains             []string
	GithubDomains        []string
	DynamicRuleHosts     []string
	DynamicRulesMaxBytes int
	MaxDNSPacketSize     int
	PoolFeedURL          string
	PoolFeedDisabled     bool
	PoolFeedIntervalSec  int
	PoolFeedTTLSec       int
	Host                 string
	Port                 int
	PublicHostnames      []string
	TLSCertFile          string
	TLSKeyFile           string
	CacheMaxEntries      int
	CachePersistPath     string
	PathAliases          []string
	Debug                bool
	LogQueries           bool
	PprofAddr            string
}

var defaultUpstreams = "https://cloudflare-dns.com/dns-query,https://dns.google/dns-query,https://dns.quad9.net/dns-query"

type source struct {
	file map[string]string
}

func (s *source) lookup(name string) (string, bool) {
	if v, ok := os.LookupEnv(name); ok {
		return v, true
	}
	if s.file != nil {
		if v, ok := s.file[name]; ok {
			return v, true
		}
	}
	return "", false
}

func (s *source) str(name, def string) string {
	if v, ok := s.lookup(name); ok {
		return v
	}
	return def
}

func (s *source) strList(name, def string) []string {
	raw := s.str(name, def)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func (s *source) intClamp(name string, def, min, max int) int {
	raw, ok := s.lookup(name)
	if !ok {
		return def
	}
	v, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		slog.Warn("config: non-numeric value, using default", "key", name, "value", raw, "default", def)
		return def
	}
	if v < min {
		slog.Warn("config: clamped to minimum", "key", name, "value", v, "min", min)
		return min
	}
	if v > max {
		slog.Warn("config: clamped to maximum", "key", name, "value", v, "max", max)
		return max
	}
	return v
}

func (s *source) boolValue(name string, def bool) bool {
	raw, ok := s.lookup(name)
	if !ok {
		return def
	}
	return strings.EqualFold(strings.TrimSpace(raw), "true")
}

// Load reads the configuration. POOL_FEED_URL is special: unset keeps the
// default endpoint; explicitly set to the empty string disables pool feeding.
func Load() (*Config, error) {
	fileMap, err := readFileConfig(os.Getenv("CFDOH_CONFIG"))
	if err != nil {
		return nil, err
	}
	src := &source{file: fileMap}

	cfg := &Config{}
	httpsOnly := func(urls []string) []string {
		out := make([]string, 0, len(urls))
		for _, u := range urls {
			if strings.HasPrefix(u, "https://") {
				out = append(out, u)
			}
		}
		return out
	}
	cfg.Upstreams = httpsOnly(src.strList("UPSTREAMS", defaultUpstreams))
	cfg.EcsUpstreams = httpsOnly(src.strList("ECS_UPSTREAMS", defaultUpstreams))
	cfg.UpstreamTimeoutMs = src.intClamp("UPSTREAM_TIMEOUT_MS", 2500, 250, 15000)
	cfg.UpstreamHedgeMs = src.intClamp("UPSTREAM_HEDGE_MS", 100, 0, 5000)
	cfg.CacheMinTTL = src.intClamp("CACHE_MIN_TTL", 30, 0, 3600)
	cfg.CacheMaxTTL = src.intClamp("CACHE_MAX_TTL", 3600, 1, 86400)
	cfg.NegativeCacheMaxTTL = src.intClamp("NEGATIVE_CACHE_MAX_TTL", 300, 0, 3600)
	cfg.CacheStaleTTL = src.intClamp("CACHE_STALE_TTL", 86400, 0, 604800)
	cfg.CachePrefetchPercent = src.intClamp("CACHE_PREFETCH_PERCENT", 10, 0, 90)
	cfg.EcsMode = strings.ToLower(strings.TrimSpace(src.str("ECS_MODE", "rules")))
	if cfg.EcsMode != "off" && cfg.EcsMode != "always" && cfg.EcsMode != "rules" {
		slog.Warn("config: invalid ECS_MODE, falling back to rules", "value", cfg.EcsMode)
		cfg.EcsMode = "rules"
	}
	cfg.EcsDomains = lowerList(src.strList("ECS_DOMAINS", ".cn"))
	cfg.EcsIPv4Prefix = src.intClamp("ECS_IPV4_PREFIX", 24, 0, 32)
	cfg.EcsIPv6Prefix = src.intClamp("ECS_IPV6_PREFIX", 48, 0, 128)
	cfg.CFRewriteEnabled = src.boolValue("CF_REWRITE_ENABLED", false)
	cfg.CFPreferredDomain = canonicalDomains(src.strList("CF_PREFERRED_DOMAIN", ""))
	cfg.CFPreferredIPv4 = src.strList("CF_PREFERRED_IPV4", "")
	cfg.CFPreferredIPv6 = src.strList("CF_PREFERRED_IPV6", "")
	cfg.CFDropAAAA = src.boolValue("CF_DROP_AAAA", false)
	cfg.AdminToken = src.str("ADMIN_TOKEN", "")
	cfg.HubToken = src.str("HUB_TOKEN", "")
	cfg.DohOriginToken = src.str("DOH_ORIGIN_TOKEN", "")
	cfg.IspTableURL = src.str("ISP_TABLE_URL", "")
	cfg.CFIPv4URL = src.str("CF_IPV4_URL", "https://www.cloudflare.com/ips-v4")
	cfg.CFIPv6URL = src.str("CF_IPV6_URL", "https://www.cloudflare.com/ips-v6")
	cfg.RulesJSON = src.str("RULES_JSON", "[]")
	cfg.RulesURL = src.str("RULES_URL", "")
	cfg.EchEnabled = src.boolValue("ECH_ENABLED", false)
	cfg.EchConfigBase64 = src.str("ECH_CONFIG_BASE64", "")
	cfg.EchDomains = lowerList(src.strList("ECH_DOMAINS", ""))
	cfg.EchSourceDomain = strings.ToLower(src.str("ECH_SOURCE_DOMAIN", "cloudflare-ech.com"))
	cfg.MetaEchConfigBase64 = src.str("META_ECH_CONFIG_BASE64", "")
	cfg.MetaDomains = lowerList(src.strList("META_DOMAINS", "facebook.com,instagram.com,whatsapp.net,fbcdn.net,messenger.com,threads.net"))
	cfg.XDomains = lowerList(src.strList("X_DOMAINS", "x.com,twitter.com,twimg.com,t.co"))
	cfg.GithubDomains = lowerList(src.strList("GITHUB_DOMAINS", ""))
	cfg.DynamicRuleHosts = lowerList(src.strList("DYNAMIC_RULE_HOSTS", "paste.rs,raw.githubusercontent.com,gist.githubusercontent.com"))
	cfg.DynamicRulesMaxBytes = src.intClamp("DYNAMIC_RULES_MAX_BYTES", 262144, 1024, 1048576)
	cfg.MaxDNSPacketSize = src.intClamp("MAX_DNS_PACKET_SIZE", 4096, 512, 65535)
	if v, ok := src.lookup("POOL_FEED_URL"); ok && strings.TrimSpace(v) == "" {
		cfg.PoolFeedURL = ""
		cfg.PoolFeedDisabled = true
	} else {
		cfg.PoolFeedURL = src.str("POOL_FEED_URL", "https://cfhub.1molchuan.top/api/v1/pools")
		if !strings.HasPrefix(cfg.PoolFeedURL, "https://") {
			slog.Warn("config: POOL_FEED_URL must use https, pool feeding disabled", "value", cfg.PoolFeedURL)
			cfg.PoolFeedURL = ""
			cfg.PoolFeedDisabled = true
		}
	}
	cfg.PoolFeedIntervalSec = src.intClamp("POOL_FEED_INTERVAL_SEC", 300, 60, 3600)
	cfg.PoolFeedTTLSec = src.intClamp("POOL_FEED_TTL_SEC", 1800, 300, 86400)
	cfg.Host = src.str("HOST", "127.0.0.1")
	cfg.Port = src.intClamp("PORT", 8787, 1, 65535)
	cfg.PublicHostnames = lowerList(src.strList("PUBLIC_HOSTNAMES", ""))
	cfg.TLSCertFile = src.str("TLS_CERT_FILE", "")
	cfg.TLSKeyFile = src.str("TLS_KEY_FILE", "")
	cfg.CacheMaxEntries = src.intClamp("CACHE_MAX_ENTRIES", 4096, 128, 65536)
	cfg.CachePersistPath = src.str("CACHE_PERSIST_PATH", "")
	cfg.PathAliases = src.strList("PATH_ALIASES", "")
	cfg.Debug = src.boolValue("DEBUG", false)
	cfg.LogQueries = src.boolValue("LOG_QUERIES", false)
	cfg.PprofAddr = src.str("PPROF_ADDR", "")
	return cfg, nil
}

// TLSEnabled reports whether direct-TLS listening is fully configured.
func (c *Config) TLSEnabled() bool { return c.TLSCertFile != "" && c.TLSKeyFile != "" }

// SanitizedSummary renders a redacted multi-line summary; tokens show only
// whether they are configured.
func (c *Config) SanitizedSummary() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "upstreams=%s (ecs: %d)\n", strings.Join(c.Upstreams, ","), len(c.EcsUpstreams))
	fmt.Fprintf(&sb, "timeout=%dms hedge=%dms\n", c.UpstreamTimeoutMs, c.UpstreamHedgeMs)
	fmt.Fprintf(&sb, "cache ttl=%d..%d neg=%d stale=%d prefetch=%d%% entries=%d\n",
		c.CacheMinTTL, c.CacheMaxTTL, c.NegativeCacheMaxTTL, c.CacheStaleTTL, c.CachePrefetchPercent, c.CacheMaxEntries)
	fmt.Fprintf(&sb, "ecs mode=%s domains=%s v4/%d v6/%d\n", c.EcsMode, strings.Join(c.EcsDomains, ","), c.EcsIPv4Prefix, c.EcsIPv6Prefix)
	fmt.Fprintf(&sb, "rewrite=%v preferred_domain=%s drop_aaaa=%v\n", c.CFRewriteEnabled, strings.Join(c.CFPreferredDomain, ","), c.CFDropAAAA)
	fmt.Fprintf(&sb, "admin_token=%s hub_token=%s doh_origin_token=%s\n", configuredWord(c.AdminToken), configuredWord(c.HubToken), configuredWord(c.DohOriginToken))
	fmt.Fprintf(&sb, "isp_table=%s\n", configuredWord(c.IspTableURL))
	fmt.Fprintf(&sb, "ech enabled=%v source=%s meta=%s\n", c.EchEnabled, c.EchSourceDomain, configuredWord(c.MetaEchConfigBase64))
	fmt.Fprintf(&sb, "pool_feed url=%s interval=%ds ttl=%ds\n", configuredWord(c.PoolFeedURL), c.PoolFeedIntervalSec, c.PoolFeedTTLSec)
	fmt.Fprintf(&sb, "listen=%s:%d tls=%v aliases=%s\n", c.Host, c.Port, c.TLSEnabled(), strings.Join(c.PathAliases, ","))
	fmt.Fprintf(&sb, "persist=%s pprof=%s debug=%v\n", configuredWord(c.CachePersistPath), configuredWord(c.PprofAddr), c.Debug)
	return sb.String()
}

func configuredWord(v string) string {
	if v == "" {
		return "off"
	}
	return "on"
}

func lowerList(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		out = append(out, strings.ToLower(v))
	}
	return out
}

func canonicalDomains(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		out = append(out, strings.ToLower(strings.TrimSuffix(v, ".")))
	}
	return out
}

func readFileConfig(path string) (map[string]string, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("config file: %w", err)
	}
	defer f.Close()
	out := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			slog.Warn("config: ignoring malformed line", "file", path, "line", line)
			continue
		}
		out[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	return out, scanner.Err()
}
