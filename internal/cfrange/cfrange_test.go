package cfrange

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jnuse/cfdoh/internal/config"
)

func rangeConfig(v4URL, v6URL string) *config.Config {
	return &config.Config{CFIPv4URL: v4URL, CFIPv6URL: v6URL}
}

func TestLoadAndContains(t *testing.T) {
	v4 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("173.245.48.0/20\n103.21.244.0/22\n# comment\n\nnot-a-prefix\n188.114.96.0/22"))
	}))
	defer v4.Close()
	v6 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("2606:4700::/32"))
	}))
	defer v6.Close()

	r, err := Load(context.Background(), rangeConfig(v4.URL, v6.URL))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.V4) != 3 || len(r.V6) != 1 {
		t.Fatalf("v4=%d v6=%d", len(r.V4), len(r.V6))
	}
	cases := map[string]bool{
		"173.245.48.1":      true,
		"188.114.97.5":      true,
		"1.2.3.4":           false,
		"2606:4700::1":      true,
		"2606:4700:ffff::1": true,
		"2001:db8::1":       false,
		"garbage":           false,
	}
	for ip, want := range cases {
		if got := r.Contains(ip); got != want {
			t.Fatalf("Contains(%q) = %v", ip, got)
		}
	}
	if got := Current(); got != r {
		t.Fatal("Load must swap in the package current table")
	}
	if !Current().Contains("173.245.48.1") {
		t.Fatal("Current().Contains failed")
	}
}

func TestNilRangesSafe(t *testing.T) {
	var r *Ranges
	if r.Contains("173.245.48.1") {
		t.Fatal("nil table must answer false")
	}
}

func TestLoadFailureKeepsOldTable(t *testing.T) {
	v4 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("192.0.2.0/24"))
	}))
	defer v4.Close()
	v6 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("2001:db8::/32"))
	}))
	defer v6.Close()
	if _, err := Load(context.Background(), rangeConfig(v4.URL, v6.URL)); err != nil {
		t.Fatal(err)
	}

	// second load fails (empty list) — the old table must survive
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("nothing usable"))
	}))
	defer broken.Close()
	if _, err := Load(context.Background(), rangeConfig(broken.URL, broken.URL)); err == nil {
		t.Fatal("empty list must error")
	}
	if !Current().Contains("192.0.2.1") {
		t.Fatal("failed load must not clear the current table")
	}
}
