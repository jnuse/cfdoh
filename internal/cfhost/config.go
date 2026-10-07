package cfhost

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Config mirrors the client configuration surface. Timeout is stored in
// milliseconds; Interval is a time.Duration.
type Config struct {
	ManagedDomains []string
	Sources        []string
	Concurrency    int
	Timeout        int // milliseconds per probe round
	Rounds         int
	Hysteresis     float64
	FailoverRounds int
	Interval       time.Duration
	HostsPath      string

	// Auxiliary exported fields (allowed additions).
	StatePath      string
	CandidateLimit int
	HTTPVerify     bool
}

// Default values and clamp ranges are pinned by the task spec.
const (
	defaultConcurrency    = 8
	defaultTimeoutMs      = 2000
	defaultRounds         = 3
	defaultHysteresis     = 0.2
	defaultFailoverRounds = 3
	defaultInterval       = 60 * time.Minute
	defaultCandidateLimit = 256
	defaultHTTPVerify     = true

	minConcurrency = 1
	maxConcurrency = 64
	minTimeoutMs   = 250
	maxTimeoutMs   = 10000
	minRounds      = 1
	maxRounds      = 10
	minHysteresis  = 0.0
	maxHysteresis  = 0.9
	minFailover    = 1
	maxFailover    = 100
	minInterval    = time.Minute
	maxInterval    = 24 * time.Hour
)

// fileConfig is the on-disk JSON shape (snake_case keys). Zero values mean
// "not set, keep default"; Hysteresis and HTTPVerify are pointers because
// 0 / false are legal explicit values.
type fileConfig struct {
	ManagedDomains []string `json:"managed_domains"`
	Sources        []string `json:"sources"`
	Concurrency    int      `json:"concurrency"`
	TimeoutMs      int      `json:"timeout_ms"`
	Rounds         int      `json:"rounds"`
	Hysteresis     *float64 `json:"hysteresis"`
	FailoverRounds int      `json:"failover_rounds"`
	IntervalMin    int      `json:"interval_min"`
	HostsPath      string   `json:"hosts_path"`
	StatePath      string   `json:"state_path"`
	CandidateLimit int      `json:"candidate_limit"`
	HTTPVerify     *bool    `json:"http_verify"`
}

func (fc *fileConfig) applyTo(cfg *Config) {
	if len(fc.ManagedDomains) > 0 {
		cfg.ManagedDomains = fc.ManagedDomains
	}
	if len(fc.Sources) > 0 {
		cfg.Sources = fc.Sources
	}
	if fc.Concurrency != 0 {
		cfg.Concurrency = fc.Concurrency
	}
	if fc.TimeoutMs != 0 {
		cfg.Timeout = fc.TimeoutMs
	}
	if fc.Rounds != 0 {
		cfg.Rounds = fc.Rounds
	}
	if fc.Hysteresis != nil {
		cfg.Hysteresis = *fc.Hysteresis
	}
	if fc.FailoverRounds != 0 {
		cfg.FailoverRounds = fc.FailoverRounds
	}
	if fc.IntervalMin != 0 {
		cfg.Interval = time.Duration(fc.IntervalMin) * time.Minute
	}
	if fc.HostsPath != "" {
		cfg.HostsPath = fc.HostsPath
	}
	if fc.StatePath != "" {
		cfg.StatePath = fc.StatePath
	}
	if fc.CandidateLimit != 0 {
		cfg.CandidateLimit = fc.CandidateLimit
	}
	if fc.HTTPVerify != nil {
		cfg.HTTPVerify = *fc.HTTPVerify
	}
}

// configPath resolves the config file location: CFHOST_CONFIG when set,
// otherwise cfhost.json next to the executable (portable layout). The
// second return reports whether CFHOST_CONFIG was explicitly set.
func configPath() (path string, explicit bool) {
	if p := strings.TrimSpace(os.Getenv("CFHOST_CONFIG")); p != "" {
		return p, true
	}
	return defaultConfigPath(), false
}

// resolveStatePath resolves the state file location without a fully valid
// config: CFHOST_STATE_PATH when set, otherwise the default next to the
// config file. Used by Status when config loading fails.
func resolveStatePath() string {
	if p := strings.TrimSpace(os.Getenv("CFHOST_STATE_PATH")); p != "" {
		return p
	}
	path, _ := configPath()
	return defaultStatePath(path)
}

// LoadConfig loads the client configuration: defaults, then the JSON file
// (CFHOST_CONFIG or the platform default path), then environment variables
// (CFHOST_*). Environment wins over the file. The default state path
// follows the config file's directory, so state, lock and log live wherever
// the config lives (portable layout: binary and its runtime files in one
// folder).
func LoadConfig() (*Config, error) {
	path, explicit := configPath()
	cfg := &Config{
		Concurrency:    defaultConcurrency,
		Timeout:        defaultTimeoutMs,
		Rounds:         defaultRounds,
		Hysteresis:     defaultHysteresis,
		FailoverRounds: defaultFailoverRounds,
		Interval:       defaultInterval,
		HostsPath:      defaultHostsPath(),
		StatePath:      defaultStatePath(path),
		CandidateLimit: defaultCandidateLimit,
		HTTPVerify:     defaultHTTPVerify,
	}
	if data, err := os.ReadFile(path); err == nil {
		var fc fileConfig
		if err := json.Unmarshal(data, &fc); err != nil {
			return nil, fmt.Errorf("cfhost: parse config %s: %w", path, err)
		}
		fc.applyTo(cfg)
	} else if explicit || !os.IsNotExist(err) {
		return nil, fmt.Errorf("cfhost: read config %s: %w", path, err)
	}

	if err := applyEnv(cfg); err != nil {
		return nil, err
	}
	if err := cfg.normalize(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// applyEnv overrides config fields from CFHOST_* environment variables.
func applyEnv(cfg *Config) error {
	if v, ok := os.LookupEnv("CFHOST_MANAGED_DOMAINS"); ok && strings.TrimSpace(v) != "" {
		cfg.ManagedDomains = splitCSV(v)
	}
	if v, ok := os.LookupEnv("CFHOST_SOURCES"); ok && strings.TrimSpace(v) != "" {
		cfg.Sources = splitSourceList(v)
	}
	for _, o := range []struct {
		name string
		set  func(int)
	}{
		{"CFHOST_CONCURRENCY", func(n int) { cfg.Concurrency = n }},
		{"CFHOST_TIMEOUT_MS", func(n int) { cfg.Timeout = n }},
		{"CFHOST_ROUNDS", func(n int) { cfg.Rounds = n }},
		{"CFHOST_FAILOVER_ROUNDS", func(n int) { cfg.FailoverRounds = n }},
		{"CFHOST_INTERVAL_MIN", func(n int) { cfg.Interval = time.Duration(n) * time.Minute }},
		{"CFHOST_CANDIDATE_LIMIT", func(n int) { cfg.CandidateLimit = n }},
	} {
		if err := envInt(o.name, o.set); err != nil {
			return err
		}
	}
	if v, ok := os.LookupEnv("CFHOST_HYSTERESIS"); ok && v != "" {
		f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		if err != nil {
			return fmt.Errorf("cfhost: CFHOST_HYSTERESIS: %w", err)
		}
		cfg.Hysteresis = f
	}
	if v, ok := os.LookupEnv("CFHOST_HOSTS_PATH"); ok && v != "" {
		cfg.HostsPath = strings.TrimSpace(v)
	}
	if v, ok := os.LookupEnv("CFHOST_STATE_PATH"); ok && v != "" {
		cfg.StatePath = strings.TrimSpace(v)
	}
	if v, ok := os.LookupEnv("CFHOST_HTTP_VERIFY"); ok && v != "" {
		b, err := parseLooseBool(v)
		if err != nil {
			return fmt.Errorf("cfhost: CFHOST_HTTP_VERIFY: %w", err)
		}
		cfg.HTTPVerify = b
	}
	return nil
}

// envInt applies an integer CFHOST_* override; unset or empty keeps the
// current value.
func envInt(name string, set func(int)) error {
	v, ok := os.LookupEnv(name)
	if !ok || v == "" {
		return nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return fmt.Errorf("cfhost: %s: %w", name, err)
	}
	set(n)
	return nil
}

// normalize validates required fields and clamps numerics into range.
func (cfg *Config) normalize() error {
	if len(cfg.ManagedDomains) < 1 {
		return fmt.Errorf("cfhost: managed_domains is required (at least one domain)")
	}
	for i, d := range cfg.ManagedDomains {
		// Store the normalized form (trimmed, no trailing dot): consumers
		// (probe SNI, hosts rendering) must never see the raw input.
		d = strings.TrimSuffix(strings.TrimSpace(d), ".")
		if !validDomain(d) {
			return fmt.Errorf("cfhost: invalid managed domain %q", d)
		}
		cfg.ManagedDomains[i] = d
	}
	if len(cfg.Sources) < 1 {
		return fmt.Errorf("cfhost: sources is required (at least one source)")
	}
	for _, s := range cfg.Sources {
		if strings.TrimSpace(s) == "" {
			return fmt.Errorf("cfhost: empty source entry")
		}
	}
	cfg.Concurrency = clampInt(cfg.Concurrency, minConcurrency, maxConcurrency, "concurrency")
	cfg.Timeout = clampInt(cfg.Timeout, minTimeoutMs, maxTimeoutMs, "timeout_ms")
	cfg.Rounds = clampInt(cfg.Rounds, minRounds, maxRounds, "rounds")
	cfg.FailoverRounds = clampInt(cfg.FailoverRounds, minFailover, maxFailover, "failover_rounds")
	if cfg.Hysteresis < minHysteresis {
		slog.Warn("cfhost: hysteresis below minimum, clamped", "value", cfg.Hysteresis, "min", minHysteresis)
		cfg.Hysteresis = minHysteresis
	} else if cfg.Hysteresis > maxHysteresis {
		slog.Warn("cfhost: hysteresis above maximum, clamped", "value", cfg.Hysteresis, "max", maxHysteresis)
		cfg.Hysteresis = maxHysteresis
	}
	if cfg.Interval < minInterval {
		slog.Warn("cfhost: interval below minimum, clamped", "value", cfg.Interval.String(), "min", minInterval.String())
		cfg.Interval = minInterval
	} else if cfg.Interval > maxInterval {
		slog.Warn("cfhost: interval above maximum, clamped", "value", cfg.Interval.String(), "max", maxInterval.String())
		cfg.Interval = maxInterval
	}
	if cfg.CandidateLimit <= 0 {
		cfg.CandidateLimit = defaultCandidateLimit
	}
	if cfg.HostsPath == "" {
		cfg.HostsPath = defaultHostsPath()
	}
	return nil
}

func clampInt(v, lo, hi int, name string) int {
	if v < lo {
		slog.Warn("cfhost: config value below minimum, clamped", "key", name, "value", v, "min", lo)
		return lo
	}
	if v > hi {
		slog.Warn("cfhost: config value above maximum, clamped", "key", name, "value", v, "max", hi)
		return hi
	}
	return v
}

func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// splitSourceList splits CFHOST_SOURCES on semicolons or newlines.
func splitSourceList(s string) []string {
	var out []string
	for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == ';' || r == '\n' || r == '\r' }) {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseLooseBool(s string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true, nil
	case "0", "false", "no", "off":
		return false, nil
	}
	return false, fmt.Errorf("invalid boolean %q", strings.TrimSpace(s))
}

func defaultHostsPath() string {
	if runtime.GOOS == "windows" {
		return `C:\Windows\System32\drivers\etc\hosts`
	}
	return "/etc/hosts"
}

// defaultStatePath places the state file next to the config file; the lock
// file and cfhost.log follow the state directory, so all runtime files
// share the config's folder.
func defaultStatePath(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), "cfhost-state.json")
}

// defaultConfigPath returns cfhost.json next to the running executable
// (portable layout). Falls back to the user config dir if the executable
// path cannot be determined.
func defaultConfigPath() string {
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), "cfhost.json")
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = "."
	}
	return filepath.Join(dir, "cfdoh", "cfhost.json")
}

// domainLabelRe matches a single DNS label: alphanumeric, hyphens inside,
// 1..63 bytes.
var domainLabelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// validDomain accepts a plain ASCII domain name (case-insensitive), each
// label 1..63 bytes, total length <= 253.
func validDomain(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if name == "" {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if !domainLabelRe.MatchString(label) {
			return false
		}
	}
	return true
}
