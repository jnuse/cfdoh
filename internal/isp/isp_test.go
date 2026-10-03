package isp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jnuse/cfdoh/internal/config"
)

func withTable(t *testing.T, text string) {
	t.Helper()
	Reset()
	parsed, err := parseTable(text)
	if err != nil {
		t.Fatalf("parseTable: %v", err)
	}
	mu.Lock()
	current = parsed
	tableText = text
	loadedAt = now()
	mu.Unlock()
	t.Cleanup(Reset)
}

// waitFor polls cond until true or the deadline passes.
func waitFor(cond func() bool, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return cond()
}

func stateObserved() bool {
	mu.Lock()
	defer mu.Unlock()
	return current != nil || !failedAt.IsZero()
}

func TestParseTableValidation(t *testing.T) {
	text := `
# comment
chinanet 1.2.0.0/16
Chinanet 1.3.0.0/16
national 1.4.0.0/16
bad_name 1.5.0.0/16
x 1.6.0.0/16
chinanet not-a-cidr
unicom 2400:da00::/32
chinanet 1.2.128.0/17
`
	parsed, err := parseTable(text)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.names) != 2 {
		t.Fatalf("names = %v (want chinanet+unicom, uppercase/national/short names skipped)", parsed.names)
	}
}

func TestParseTableRejectsEmpty(t *testing.T) {
	if _, err := parseTable("# nothing\nnope\n"); err == nil {
		t.Fatal("zero usable entries must error")
	}
}

func TestLookupNestedMostSpecific(t *testing.T) {
	withTable(t, strings.Join([]string{
		"chinanet 1.2.0.0/16",
		"unicom 1.2.128.0/17", // nested inside chinanet
		"cmcc 1.2.130.0/24",   // nested inside unicom
		"telecom 2606:4700::/32",
		"cernet 2606:4700:8000::/33",
	}, "\n"))

	cases := []struct {
		ip   string
		want string
	}{
		{"1.2.0.1", "chinanet"},
		{"1.2.127.1", "chinanet"},
		{"1.2.129.1", "unicom"},
		{"1.2.130.1", "cmcc"},
		{"1.2.131.1", "unicom"},
		{"9.9.9.9", ""},
		{"2606:4700::1", "telecom"},
		{"2606:4700:8000::1", "cernet"},
		{"2606:4701::1", ""},
	}
	for _, tc := range cases {
		addr, err := netip.ParseAddr(tc.ip)
		if err != nil {
			t.Fatal(err)
		}
		addr = addr.Unmap()
		if got := lookup(current, addr); got != tc.want {
			t.Fatalf("lookup(%s) = %q, want %q", tc.ip, got, tc.want)
		}
	}
}

func TestScopeOfDisabled(t *testing.T) {
	Reset()
	defer Reset()
	if _, ok := ScopeOf(context.Background(), "1.2.3.4", &config.Config{}); ok {
		t.Fatal("no IspTableURL configured: must miss")
	}
}

func TestScopeOfAsyncFirstLoadNeverBlocks(t *testing.T) {
	var hits atomic.Int64
	block := make(chan struct{})
	entered := make(chan struct{})
	var enterOnce sync.Once
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		enterOnce.Do(func() { close(entered) })
		<-block // slow first load
		w.Write([]byte("chinanet 58.247.0.0/16\n"))
	}))
	defer srv.Close()
	Reset()
	defer Reset()
	cfg := &config.Config{IspTableURL: srv.URL}

	start := time.Now()
	if _, ok := ScopeOf(context.Background(), "58.247.22.1", cfg); ok {
		t.Fatal("slow first load must miss, not block")
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("ScopeOf blocked %s on the first load", elapsed)
	}
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("background load never started")
	}
	close(block) // let the first load land
	if !waitFor(stateObserved, 2*time.Second) {
		t.Fatal("background load never finished")
	}
	if !waitFor(func() bool {
		scope, ok := ScopeOf(context.Background(), "58.247.22.1", cfg)
		return ok && scope == "isp:chinanet"
	}, 2*time.Second) {
		t.Fatal("table never became active")
	}
}

func TestScopeOfFailedLoadBackoff(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	Reset()
	defer Reset()
	cfg := &config.Config{IspTableURL: srv.URL}

	if _, ok := ScopeOf(context.Background(), "58.247.22.1", cfg); ok {
		t.Fatal("must miss on failure")
	}
	if !waitFor(stateObserved, 2*time.Second) {
		t.Fatal("failed load never recorded")
	}
	time.Sleep(50 * time.Millisecond)
	if _, ok := ScopeOf(context.Background(), "58.247.22.1", cfg); ok {
		t.Fatal("must still miss within the backoff window")
	}
	time.Sleep(50 * time.Millisecond)
	if hits.Load() != 1 {
		t.Fatalf("backoff violated: %d fetches", hits.Load())
	}
}

func TestStaleTableBackoffAfterFailedRefresh(t *testing.T) {
	var hits atomic.Int64
	var failing atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) == 1 {
			w.Write([]byte("chinanet 58.247.0.0/16\n"))
			return
		}
		if failing.Load() {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		w.Write([]byte("chinanet 58.247.0.0/16\n"))
	}))
	defer srv.Close()
	Reset()
	defer Reset()
	cfg := &config.Config{IspTableURL: srv.URL}

	ScopeOf(context.Background(), "58.247.22.1", cfg)
	if !waitFor(func() bool {
		scope, ok := ScopeOf(context.Background(), "58.247.22.1", cfg)
		return ok && scope == "isp:chinanet"
	}, 2*time.Second) {
		t.Fatal("first load never landed")
	}
	if hits.Load() != 1 {
		t.Fatalf("unexpected fetch count %d", hits.Load())
	}

	// open the refresh window and fail the source
	failing.Store(true)
	mu.Lock()
	loadedAt = now().Add(-2 * refreshEvery)
	failedAt = time.Time{}
	mu.Unlock()
	ScopeOf(context.Background(), "58.247.22.1", cfg)
	if !waitFor(func() bool {
		mu.Lock()
		defer mu.Unlock()
		return !failedAt.IsZero()
	}, 2*time.Second) {
		t.Fatal("failed refresh never recorded")
	}
	// inside the 60s backoff: no further fetch, stale table keeps serving
	time.Sleep(100 * time.Millisecond)
	scope, ok := ScopeOf(context.Background(), "58.247.22.1", cfg)
	if !ok || scope != "isp:chinanet" {
		t.Fatalf("stale table must keep serving: %q %v", scope, ok)
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("backoff violated while table stale: %d fetches", got)
	}
}

func TestRefreshKeepsOldTableOnFailure(t *testing.T) {
	content := "chinanet 58.247.0.0/16\n"
	var serve string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serve == "" {
			w.Write([]byte(content))
			return
		}
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	Reset()
	defer Reset()
	cfg := &config.Config{IspTableURL: srv.URL}
	ScopeOf(context.Background(), "58.247.22.1", cfg)
	if !waitFor(func() bool {
		mu.Lock()
		defer mu.Unlock()
		return current != nil
	}, 2*time.Second) {
		t.Fatal("first load never landed")
	}
	serve = "fail"
	mu.Lock()
	loadedAt = now().Add(-2 * refreshEvery)
	failedAt = time.Time{}
	mu.Unlock()
	// synchronous refresh path (as the background goroutine would run it)
	refresh(context.Background(), cfg)
	mu.Lock()
	failed := !failedAt.IsZero()
	tableAlive := current != nil
	mu.Unlock()
	if !failed || !tableAlive {
		t.Fatalf("refresh failure state wrong: failed=%v table=%v", failed, tableAlive)
	}
	if scope, ok := ScopeOf(context.Background(), "58.247.22.1", cfg); !ok || scope != "isp:chinanet" {
		t.Fatalf("stale table must keep serving: %q %v", scope, ok)
	}
}

func TestUnchangedContentNotRebuilt(t *testing.T) {
	same := "chinanet 58.247.0.0/16\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(same))
	}))
	defer srv.Close()
	Reset()
	defer Reset()
	cfg := &config.Config{IspTableURL: srv.URL}
	ScopeOf(context.Background(), "58.247.22.1", cfg)
	if !waitFor(func() bool {
		mu.Lock()
		defer mu.Unlock()
		return current != nil
	}, 2*time.Second) {
		t.Fatal("first load never landed")
	}
	first := current
	refresh(context.Background(), cfg)
	mu.Lock()
	rebuilt := current != first
	mu.Unlock()
	if rebuilt {
		t.Fatal("identical content must not rebuild the table")
	}
}
