package hubfeed

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jnuse/cfdoh/internal/cfrange"
	"github.com/jnuse/cfdoh/internal/config"
	"github.com/jnuse/cfdoh/internal/pool"
)

func feedServer(t *testing.T, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(body))
	}))
}

func loadRanges(t *testing.T) {
	t.Helper()
	v4 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("104.16.0.0/13"))
	}))
	defer v4.Close()
	v6 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("2606:4700::/32"))
	}))
	defer v6.Close()
	if _, err := cfrange.Load(context.Background(), &config.Config{CFIPv4URL: v4.URL, CFIPv6URL: v6.URL}); err != nil {
		t.Fatal(err)
	}
}

func TestRefreshOnceAdoptsValidPools(t *testing.T) {
	loadRanges(t)
	feed := `{"pools":[
		{"isp":"chinanet","family":4,"ips":[{"ip":"104.16.1.1"},{"ip":"104.16.1.2"},{"ip":"104.16.1.3"},{"ip":"104.16.1.4"},{"ip":"104.16.1.5"},{"ip":"104.16.1.6"},{"ip":"104.16.1.7"},{"ip":"104.16.1.8"},{"ip":"104.16.1.9"},{"ip":"104.16.1.10"},{"ip":"104.16.1.11"},{"ip":"104.16.1.12"}],"published":true},
		{"isp":"chinanet","family":6,"ips":[{"ip":"2606:4700::1"},{"ip":"2606:4700::2"},{"ip":"2606:4700::3"},{"ip":"2606:4700::4"},{"ip":"2606:4700::5"},{"ip":"2606:4700::6"},{"ip":"2606:4700::7"},{"ip":"2606:4700::8"},{"ip":"2606:4700::9"},{"ip":"2606:4700::10"}],"published":true},
		{"isp":"unicom","family":4,"ips":[{"ip":"104.16.9.9"}],"published":false},
		{"isp":"national","family":4,"ips":[{"ip":"104.16.2.1"},{"ip":"104.16.2.2"}],"published":true}
	]}`
	srv := feedServer(t, feed)
	defer srv.Close()
	cfg := &config.Config{PoolFeedURL: srv.URL, PoolFeedTTLSec: 1800}
	controller := NewController(cfg, "")

	if err := controller.RefreshOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	isp := pool.IspPoolStatus()
	var chinanet, national *pool.IspPoolReport
	for i := range isp {
		switch isp[i].Scope {
		case "isp:chinanet":
			chinanet = &isp[i]
		case "isp:national":
			national = &isp[i]
		}
	}
	if chinanet == nil || national == nil {
		t.Fatalf("isp pools = %+v", isp)
	}
	if len(chinanet.IPv4) != ipv4FamilyCap || len(chinanet.IPv6) != ipv6FamilyCap {
		t.Fatalf("chinanet lengths = %d/%d, want %d/%d", len(chinanet.IPv4), len(chinanet.IPv6), ipv4FamilyCap, ipv6FamilyCap)
	}
	if chinanet.IPv4[0] != "104.16.1.1" || chinanet.IPv4[ipv4FamilyCap-1] != "104.16.1.10" || chinanet.IPv6[ipv6FamilyCap-1] != "2606:4700::8" {
		t.Fatalf("feed order/caps not preserved: %v %v", chinanet.IPv4, chinanet.IPv6)
	}
	if len(national.IPv4) != 2 {
		t.Fatalf("national = %v", national.IPv4)
	}
	for _, report := range isp {
		if report.Scope == "isp:unicom" {
			t.Fatal("unpublished pool must not be adopted")
		}
	}
}

func TestRefreshOnceRejectsPollutedPool(t *testing.T) {
	loadRanges(t)
	feed := `{"pools":[
		{"isp":"cmcc","family":4,"ips":[{"ip":"104.16.3.1"},{"ip":"93.184.216.34"}],"published":true},
		{"isp":"cernet","family":4,"ips":[{"ip":"104.16.4.1"}],"published":true},
		{"isp":"cloud","family":4,"ips":[{"ip":"not-an-ip"}],"published":true}
	]}`
	srv := feedServer(t, feed)
	defer srv.Close()
	cfg := &config.Config{PoolFeedURL: srv.URL, PoolFeedTTLSec: 1800}

	if err := NewController(cfg, "").RefreshOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	isp := pool.IspPoolStatus()
	scopes := map[string]bool{}
	for _, report := range isp {
		scopes[report.Scope] = true
	}
	if scopes["isp:cmcc"] {
		t.Fatal("pool with a non-Cloudflare address must be rejected entirely")
	}
	if scopes["isp:cloud"] {
		t.Fatal("pool with an invalid address must be rejected entirely")
	}
	found := false
	for _, report := range isp {
		if report.Scope == "isp:cernet" && len(report.IPv4) == 1 && report.IPv4[0] == "104.16.4.1" {
			found = true
		}
	}
	if !found {
		t.Fatal("clean pools must still be adopted after a sibling rejection")
	}
}

func TestRefreshOnceFailures(t *testing.T) {
	loadRanges(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusBadGateway)
	}))
	defer srv.Close()
	if err := NewController(&config.Config{PoolFeedURL: srv.URL}, "").RefreshOnce(context.Background()); err == nil {
		t.Fatal("HTTP failure must error")
	}

	garbage := feedServer(t, "not json")
	defer garbage.Close()
	if err := NewController(&config.Config{PoolFeedURL: garbage.URL}, "").RefreshOnce(context.Background()); err == nil {
		t.Fatal("invalid JSON must error")
	}

}

func TestStartDisabled(t *testing.T) {
	if err := NewController(&config.Config{PoolFeedDisabled: true}, "").Start(context.Background()); err != nil {
		t.Fatalf("disabled feed must be a no-op: %v", err)
	}
	if err := NewController(&config.Config{PoolFeedURL: ""}, "").Start(context.Background()); err != nil {
		t.Fatalf("empty feed URL must be a no-op: %v", err)
	}
}

func TestStartRefreshesInBackground(t *testing.T) {
	loadRanges(t)
	var pulls atomic.Int64
	feed := `{"pools":[{"isp":"unicom","family":4,"ips":[{"ip":"104.16.5.1"}],"published":true}]}`
	pulled := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(feed))
		pulls.Add(1)
		pulled <- struct{}{}
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg := &config.Config{PoolFeedURL: srv.URL, PoolFeedIntervalSec: 60, PoolFeedTTLSec: 300}
	if err := NewController(cfg, "").Start(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-pulled:
	case <-time.After(2 * time.Second):
		t.Fatalf("start loop did not refresh, pulls=%d", pulls.Load())
	}
}

func TestPollutionBeyondCapStillRejectsWholePool(t *testing.T) {
	loadRanges(t)
	// All retained IPv4 slots are clean; pollution after the cap still rejects the pool.
	ips := make([]string, 0, ipv4FamilyCap+1)
	for i := 1; i <= ipv4FamilyCap; i++ {
		ips = append(ips, fmt.Sprintf(`{"ip":"104.16.6.%d"}`, i))
	}
	ips = append(ips, `{"ip":"93.184.216.34"}`)
	feed := fmt.Sprintf(`{"pools":[{"isp":"cmcc","family":4,"ips":[%s],"published":true}]}`, strings.Join(ips, ","))
	srv := feedServer(t, feed)
	defer srv.Close()

	if err := NewController(&config.Config{PoolFeedURL: srv.URL, PoolFeedTTLSec: 1800}, "").RefreshOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, report := range pool.IspPoolStatus() {
		if report.Scope == "isp:cmcc" {
			t.Fatal("pollution past the adoption cap must still reject the whole pool")
		}
	}
}

func TestDisableDiscardsInflightRefreshAndPreservesManualPool(t *testing.T) {
	loadRanges(t)
	pool.RemoveIspSource("pool-feed")
	t.Cleanup(func() { pool.RemoveIspSource("pool-feed") })
	mustSetPool := func(scope, source, ip string) {
		t.Helper()
		if err := pool.SetLearned([]string{ip}, nil, 1800, source, scope); err != nil {
			t.Fatal(err)
		}
	}
	mustSetPool("isp:old-feed", "pool-feed", "104.16.7.1")
	mustSetPool("isp:manual", "cfpush", "104.16.7.2")

	entered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	finishFetch := func() { releaseOnce.Do(func() { close(release) }) }
	defer finishFetch()
	feed := `{"pools":[{"isp":"late","family":4,"ips":[{"ip":"104.16.8.1"}],"published":true}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(feed))
	}))
	defer srv.Close()

	controller := NewController(&config.Config{PoolFeedURL: srv.URL, PoolFeedTTLSec: 1800}, "")
	refreshDone := make(chan error, 1)
	go func() { refreshDone <- controller.RefreshOnce(context.Background()) }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("refresh did not reach the feed")
	}
	if err := controller.SetEnabled(false); err != nil {
		t.Fatal(err)
	}
	if controller.Enabled() {
		t.Fatal("feed must be disabled")
	}
	finishFetch()
	if err := <-refreshDone; err != nil {
		t.Fatal(err)
	}

	remaining := map[string]bool{}
	for _, report := range pool.IspPoolStatus() {
		remaining[report.Scope] = true
	}
	if remaining["isp:old-feed"] || remaining["isp:late"] || !remaining["isp:manual"] {
		t.Fatalf("remaining scopes = %v", remaining)
	}
}

func TestFeedStateRestoresAndClearsFeedPools(t *testing.T) {
	pool.RemoveIspSource("pool-feed")
	t.Cleanup(func() { pool.RemoveIspSource("pool-feed") })
	path := filepath.Join(t.TempDir(), "pool-feed-state.json")
	cfg := &config.Config{PoolFeedURL: "https://feed.example/pools"}
	controller := NewController(cfg, path)
	if err := controller.SetEnabled(false); err != nil {
		t.Fatal(err)
	}
	if err := pool.SetLearned([]string{"104.16.9.1"}, nil, 1800, "pool-feed", "isp:restored"); err != nil {
		t.Fatal(err)
	}
	if err := pool.SetLearned([]string{"104.16.9.2"}, nil, 1800, "cfpush", "isp:manual-restored"); err != nil {
		t.Fatal(err)
	}

	restored := NewController(cfg, path)
	if err := restored.LoadState(); err != nil {
		t.Fatal(err)
	}
	if restored.Enabled() {
		t.Fatal("disabled state was not restored")
	}
	remaining := map[string]bool{}
	for _, report := range pool.IspPoolStatus() {
		remaining[report.Scope] = true
	}
	if remaining["isp:restored"] || !remaining["isp:manual-restored"] {
		t.Fatalf("restored scopes = %v", remaining)
	}
	if err := restored.SetEnabled(true); err != nil {
		t.Fatal(err)
	}
	reenabled := NewController(cfg, path)
	if err := reenabled.LoadState(); err != nil {
		t.Fatal(err)
	}
	if !reenabled.Enabled() {
		t.Fatal("enabled state was not persisted")
	}

	fresh := NewController(cfg, filepath.Join(t.TempDir(), "missing.json"))
	if err := fresh.LoadState(); err != nil || !fresh.Enabled() {
		t.Fatalf("missing snapshot default: enabled=%v err=%v", fresh.Enabled(), err)
	}
}

func TestFeedStateMissingSelectionDefaultsEnabled(t *testing.T) {
	pool.RemoveIspSource("pool-feed")
	t.Cleanup(func() { pool.RemoveIspSource("pool-feed") })
	if err := pool.SetLearned([]string{"104.16.9.10"}, nil, 1800, "pool-feed", "isp:restored-default"); err != nil {
		t.Fatal(err)
	}
	for _, contents := range []string{`{"version":1}`, `{"version":1,"enabled":null}`} {
		path := filepath.Join(t.TempDir(), "pool-feed-state.json")
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
		controller := NewController(&config.Config{PoolFeedURL: "https://feed.example/pools"}, path)
		if err := controller.LoadState(); err != nil {
			t.Fatal(err)
		}
		if !controller.Enabled() {
			t.Fatalf("invalid selection %s must use enabled default", contents)
		}
		found := false
		for _, report := range pool.IspPoolStatus() {
			if report.Scope == "isp:restored-default" {
				found = true
			}
		}
		if !found {
			t.Fatalf("invalid selection %s cleared feed-owned pools", contents)
		}
	}
}

func TestFeedSelectionWithoutPersistenceIsNotDurable(t *testing.T) {
	cfg := &config.Config{PoolFeedURL: "https://feed.example/pools"}
	controller := NewController(cfg, "")
	if err := controller.SetEnabled(false); err != nil {
		t.Fatal(err)
	}
	if err := controller.SaveState(); err != nil {
		t.Fatal(err)
	}

	restarted := NewController(cfg, "")
	if err := restarted.LoadState(); err != nil {
		t.Fatal(err)
	}
	if !restarted.Enabled() {
		t.Fatal("without persistence path, restart must use enabled default")
	}
}

func TestFeedStatePersistenceFailureDoesNotDisable(t *testing.T) {
	pool.RemoveIspSource("pool-feed")
	t.Cleanup(func() { pool.RemoveIspSource("pool-feed") })
	if err := pool.SetLearned([]string{"104.16.10.1"}, nil, 1800, "pool-feed", "isp:keep"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "missing", "state.json")
	controller := NewController(&config.Config{PoolFeedURL: "https://feed.example/pools"}, path)
	if err := controller.SetEnabled(false); err == nil {
		t.Fatal("expected persistence error")
	}
	if !controller.Enabled() {
		t.Fatal("failed persistence must leave runtime enabled")
	}
	found := false
	for _, report := range pool.IspPoolStatus() {
		if report.Scope == "isp:keep" {
			found = true
		}
	}
	if !found {
		t.Fatal("failed persistence must not clear feed pools")
	}
}

func TestEnablingTriggersImmediateRefresh(t *testing.T) {
	loadRanges(t)
	var pulls atomic.Int64
	pulled := make(chan struct{}, 4)
	feed := `{"pools":[{"isp":"enabled","family":4,"ips":[{"ip":"104.16.11.1"}],"published":true}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(feed))
		pulls.Add(1)
		pulled <- struct{}{}
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	controller := NewController(&config.Config{PoolFeedURL: srv.URL, PoolFeedIntervalSec: 60, PoolFeedTTLSec: 300}, "")
	if err := controller.SetEnabled(false); err != nil {
		t.Fatal(err)
	}
	if err := controller.Start(ctx); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if got := pulls.Load(); got != 0 {
		t.Fatalf("disabled startup fetched %d times", got)
	}
	if err := controller.SetEnabled(true); err != nil {
		t.Fatal(err)
	}
	select {
	case <-pulled:
	case <-time.After(2 * time.Second):
		t.Fatalf("enabling did not trigger refresh, pulls=%d", pulls.Load())
	}
}

func TestStaticDisableOverridesPersistedEnableAndClearsFeedPool(t *testing.T) {
	pool.RemoveIspSource("pool-feed")
	t.Cleanup(func() { pool.RemoveIspSource("pool-feed") })
	path := filepath.Join(t.TempDir(), "pool-feed-state.json")
	persisted := NewController(&config.Config{PoolFeedURL: "https://feed.example/pools"}, path)
	if err := persisted.SaveState(); err != nil {
		t.Fatal(err)
	}
	if err := pool.SetLearned([]string{"104.16.12.1"}, nil, 1800, "pool-feed", "isp:stale-feed"); err != nil {
		t.Fatal(err)
	}

	controller := NewController(&config.Config{PoolFeedURL: ""}, path)
	if err := controller.LoadState(); err != nil {
		t.Fatal(err)
	}
	if controller.Enabled() {
		t.Fatal("empty feed URL must override persisted enablement")
	}
	if err := controller.SetEnabled(true); err == nil {
		t.Fatal("statically disabled feed must not be re-enabled at runtime")
	}
	for _, report := range pool.IspPoolStatus() {
		if report.Scope == "isp:stale-feed" {
			t.Fatal("statically disabled startup must clear restored feed pools")
		}
	}
}
