package cfhost

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var allEnvKeys = []string{
	"CFHOST_CONFIG", "CFHOST_MANAGED_DOMAINS", "CFHOST_SOURCES",
	"CFHOST_CONCURRENCY", "CFHOST_TIMEOUT_MS", "CFHOST_ROUNDS",
	"CFHOST_HYSTERESIS", "CFHOST_FAILOVER_ROUNDS", "CFHOST_INTERVAL_MIN",
	"CFHOST_HOSTS_PATH", "CFHOST_STATE_PATH", "CFHOST_CANDIDATE_LIMIT",
	"CFHOST_HTTP_VERIFY",
}

// clearEnv neutralizes every CFHOST_* variable and points the default config
// search at an empty XDG dir so tests never pick up real user config.
func clearEnv(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, k := range allEnvKeys {
		t.Setenv(k, "")
	}
	t.Setenv("XDG_CONFIG_HOME", dir)
	return dir
}

func writeConfigFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cfhost.json")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadConfigFileAndEnvPrecedence(t *testing.T) {
	clearEnv(t)
	path := writeConfigFile(t, `{
		"managed_domains": ["a.example.com"],
		"sources": ["list:1.1.1.1"],
		"concurrency": 4,
		"timeout_ms": 1500,
		"hysteresis": 0.3,
		"interval_min": 15
	}`)
	t.Setenv("CFHOST_CONFIG", path)
	t.Setenv("CFHOST_CONCURRENCY", "16")
	t.Setenv("CFHOST_MANAGED_DOMAINS", "b.example.com,c.example.com")
	t.Setenv("CFHOST_SOURCES", "list:1.0.0.1;pool:https://x.invalid\ndomain:d.example.com")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	// File values load.
	if cfg.Timeout != 1500 || cfg.Hysteresis != 0.3 || cfg.Interval != 15*time.Minute {
		t.Fatalf("file values not applied: %+v", cfg)
	}
	// Env wins over file.
	if cfg.Concurrency != 16 {
		t.Fatalf("env concurrency should win, got %d", cfg.Concurrency)
	}
	if strings.Join(cfg.ManagedDomains, ",") != "b.example.com,c.example.com" {
		t.Fatalf("env managed domains wrong: %v", cfg.ManagedDomains)
	}
	if len(cfg.Sources) != 3 {
		t.Fatalf("env sources (semicolon/newline separated) wrong: %v", cfg.Sources)
	}
}

func TestLoadConfigExplicitPathMissing(t *testing.T) {
	clearEnv(t)
	t.Setenv("CFHOST_CONFIG", filepath.Join(t.TempDir(), "absent.json"))
	if _, err := LoadConfig(); err == nil {
		t.Fatal("explicit missing config path should error")
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	clearEnv(t)
	t.Setenv("CFHOST_MANAGED_DOMAINS", "a.example.com")
	t.Setenv("CFHOST_SOURCES", "list:1.1.1.1")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Concurrency != 8 || cfg.Timeout != 2000 || cfg.Rounds != 3 ||
		cfg.Hysteresis != 0.2 || cfg.FailoverRounds != 3 || cfg.Interval != 10*time.Minute ||
		cfg.CandidateLimit != 256 || cfg.HTTPVerify {
		t.Fatalf("defaults wrong: %+v", cfg)
	}
	if cfg.HostsPath != "/etc/hosts" {
		t.Fatalf("linux default hosts path wrong: %s", cfg.HostsPath)
	}
	if !strings.HasSuffix(cfg.StatePath, "cfhost-state.json") {
		t.Fatalf("default state path wrong: %s", cfg.StatePath)
	}
}

func TestLoadConfigRequiredFields(t *testing.T) {
	clearEnv(t)
	if _, err := LoadConfig(); err == nil {
		t.Fatal("missing managed_domains and sources should error")
	}
	t.Setenv("CFHOST_MANAGED_DOMAINS", "a.example.com")
	if _, err := LoadConfig(); err == nil {
		t.Fatal("missing sources should error")
	}
	t.Setenv("CFHOST_SOURCES", "list:1.1.1.1")
	if _, err := LoadConfig(); err != nil {
		t.Fatalf("minimal config should load: %v", err)
	}
	t.Setenv("CFHOST_MANAGED_DOMAINS", "bad..domain")
	if _, err := LoadConfig(); err == nil {
		t.Fatal("invalid domain syntax should error")
	}
}

func TestLoadConfigClamps(t *testing.T) {
	clearEnv(t)
	t.Setenv("CFHOST_MANAGED_DOMAINS", "a.example.com")
	t.Setenv("CFHOST_SOURCES", "list:1.1.1.1")

	cases := []struct {
		key  string
		val  string
		want int
	}{
		{"CFHOST_CONCURRENCY", "0", 1},
		{"CFHOST_CONCURRENCY", "100", 64},
		{"CFHOST_TIMEOUT_MS", "10", 250},
		{"CFHOST_TIMEOUT_MS", "99999", 10000},
		{"CFHOST_ROUNDS", "0", 1},
		{"CFHOST_ROUNDS", "99", 10},
		{"CFHOST_FAILOVER_ROUNDS", "0", 1},
		{"CFHOST_FAILOVER_ROUNDS", "1000", 100},
		{"CFHOST_CANDIDATE_LIMIT", "-5", 256},
	}
	for _, c := range cases {
		clearEnv(t)
		t.Setenv("CFHOST_MANAGED_DOMAINS", "a.example.com")
		t.Setenv("CFHOST_SOURCES", "list:1.1.1.1")
		t.Setenv(c.key, c.val)
		cfg, err := LoadConfig()
		if err != nil {
			t.Fatalf("%s=%s: %v", c.key, c.val, err)
		}
		var got int
		switch c.key {
		case "CFHOST_CONCURRENCY":
			got = cfg.Concurrency
		case "CFHOST_TIMEOUT_MS":
			got = cfg.Timeout
		case "CFHOST_ROUNDS":
			got = cfg.Rounds
		case "CFHOST_FAILOVER_ROUNDS":
			got = cfg.FailoverRounds
		case "CFHOST_CANDIDATE_LIMIT":
			got = cfg.CandidateLimit
		}
		if got != c.want {
			t.Errorf("%s=%s: got %d want %d", c.key, c.val, got, c.want)
		}
	}

	// Hysteresis and interval clamps.
	clearEnv(t)
	t.Setenv("CFHOST_MANAGED_DOMAINS", "a.example.com")
	t.Setenv("CFHOST_SOURCES", "list:1.1.1.1")
	t.Setenv("CFHOST_HYSTERESIS", "0.95")
	t.Setenv("CFHOST_INTERVAL_MIN", "0")
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Hysteresis != 0.9 {
		t.Errorf("hysteresis clamp: got %v want 0.9", cfg.Hysteresis)
	}
	if cfg.Interval != time.Minute {
		t.Errorf("interval clamp: got %v want 1m", cfg.Interval)
	}

	clearEnv(t)
	t.Setenv("CFHOST_MANAGED_DOMAINS", "a.example.com")
	t.Setenv("CFHOST_SOURCES", "list:1.1.1.1")
	t.Setenv("CFHOST_INTERVAL_MIN", "99999")
	cfg, err = LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Interval != 24*time.Hour {
		t.Errorf("interval clamp: got %v want 24h", cfg.Interval)
	}
}

func TestValidDomain(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"a.example.com", true},
		{"A.EXAMPLE.COM", true},
		{"example.com.", true},
		{"x-y.example.com", true},
		{"localhost", true},
		{"", false},
		{"..", false},
		{"a..b.com", false},
		{"-a.com", false},
		{"a-.com", false},
		{"a_b.com", false},
		{strings.Repeat("a", 64) + ".com", false},
		{strings.Repeat("a", 250) + ".com", false},
	}
	for _, c := range cases {
		if got := validDomain(c.in); got != c.want {
			t.Errorf("validDomain(%q) = %v want %v", c.in, got, c.want)
		}
	}
}
