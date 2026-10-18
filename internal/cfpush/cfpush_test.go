package cfpush

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeConfig seeds one pools.json and returns its path.
func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pools.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadConfigValidation(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{{
		name: "url required",
		body: `{"token":"t","pools":[{"scope":"isp:national","ipv4":["1.2.3.4"]}]}`,
		want: "url is required",
	}, {
		name: "url scheme",
		body: `{"url":"ftp://x","token":"t","pools":[{"scope":"isp:national"}]}`,
		want: "url must be http(s)",
	}, {
		name: "token required",
		body: `{"url":"https://x","pools":[{"scope":"isp:national"}]}`,
		want: "token is required",
	}, {
		name: "pools required",
		body: `{"url":"https://x","token":"t"}`,
		want: "no pools",
	}, {
		name: "scope required",
		body: `{"url":"https://x","token":"t","pools":[{"ipv4":["1.2.3.4"]}]}`,
		want: "scope is required",
	}, {
		name: "broken json",
		body: `{`,
		want: "parse",
	}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadConfig(writeConfig(t, tc.body))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestLoadConfigDefaultsAndClamp(t *testing.T) {
	path := writeConfig(t, `{
		"url": " https://example.com/admin/preferred ",
		"token": " t ",
		"ttl": 10,
		"pools": [{"scope": " isp:unicom ", "ipv4": ["1.2.3.4"]}]
	}`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.URL != "https://example.com/admin/preferred" || cfg.Token != "t" {
		t.Fatalf("trim failed: %+v", cfg)
	}
	if cfg.Source != "cfpush" {
		t.Fatalf("source default = %q", cfg.Source)
	}
	if cfg.TTL != 60 {
		t.Fatalf("ttl must clamp to 60, got %d", cfg.TTL)
	}
	if cfg.Pools[0].Scope != "isp:unicom" {
		t.Fatalf("scope trim failed: %q", cfg.Pools[0].Scope)
	}
}

func TestRunFileUploadsEveryPool(t *testing.T) {
	type report struct {
		Authorization string
		Body          map[string]any
	}
	reports := make(chan report, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		reports <- report{Authorization: r.Header.Get("Authorization"), Body: body}
		if body["scope"] == "isp:bad" {
			http.Error(w, "address 9.9.9.9 outside the Cloudflare ranges", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	}))
	defer srv.Close()

	path := writeConfig(t, `{
		"url": "`+srv.URL+`",
		"token": "secret",
		"source": "manual",
		"pools": [
			{"scope": "isp:national", "ipv6": ["2606:4700::1"]},
			{"scope": "isp:bad", "ipv4": ["9.9.9.9"]}
		]
	}`)
	err := RunFile(path)
	if err == nil || err.Error() != "1 of 2 pools failed" {
		t.Fatalf("want 1 of 2 failed, got %v", err)
	}
	close(reports)
	seen := 0
	for rep := range reports {
		seen++
		if rep.Authorization != "Bearer secret" {
			t.Fatalf("bearer missing on report %d: %q", seen, rep.Authorization)
		}
		if rep.Body["source"] != "manual" {
			t.Fatalf("source not sent: %v", rep.Body["source"])
		}
	}
	if seen != 2 {
		t.Fatalf("both pools must be attempted, got %d", seen)
	}
}

func TestUploadRejectsUnexpectedBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ok":false}`))
	}))
	defer srv.Close()
	cfg := &Config{URL: srv.URL, Token: "t", Source: "cfpush", TTL: 60}
	err := Upload(cfg, &Pool{Scope: "isp:national", IPv4: []string{"1.2.3.4"}})
	if err == nil || !strings.Contains(err.Error(), "unexpected response") {
		t.Fatalf("want unexpected-response failure, got %v", err)
	}
}

func TestRunFileAggregatesFailures(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ok":false}`))
	}))
	defer srv.Close()
	path := writeConfig(t, `{"url":"`+srv.URL+`","token":"t",
		"pools":[{"scope":"isp:national","ipv4":["1.2.3.4"]}]}`)
	if err := RunFile(path); err == nil || err.Error() != "1 of 1 pools failed" {
		t.Fatalf("want aggregated failure, got %v", err)
	}
}
