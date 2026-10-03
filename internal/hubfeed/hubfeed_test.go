package hubfeed

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
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
		{"isp":"chinanet","family":4,"ips":[{"ip":"104.16.1.1"},{"ip":"104.16.1.2"},{"ip":"104.16.1.3"},{"ip":"104.16.1.4"},{"ip":"104.16.1.5"},{"ip":"104.16.1.6"},{"ip":"104.16.1.7"},{"ip":"104.16.1.8"}],"published":true},
		{"isp":"chinanet","family":6,"ips":[{"ip":"2606:4700::1"},{"ip":"2606:4700::2"}],"published":true},
		{"isp":"unicom","family":4,"ips":[{"ip":"104.16.9.9"}],"published":false},
		{"isp":"national","family":4,"ips":[{"ip":"104.16.2.1"},{"ip":"104.16.2.2"}],"published":true}
	]}`
	srv := feedServer(t, feed)
	defer srv.Close()
	cfg := &config.Config{PoolFeedURL: srv.URL, PoolFeedTTLSec: 1800}

	if err := RefreshOnce(context.Background(), cfg); err != nil {
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
	// per-family cap of 6 even though the feed listed 8
	if len(chinanet.IPv4) != 6 || len(chinanet.IPv6) != 2 {
		t.Fatalf("chinanet = %v %v", chinanet.IPv4, chinanet.IPv6)
	}
	if chinanet.IPv4[0] != "104.16.1.1" {
		t.Fatalf("feed order must be kept: %v", chinanet.IPv4)
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

	if err := RefreshOnce(context.Background(), cfg); err != nil {
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
	if err := RefreshOnce(context.Background(), &config.Config{PoolFeedURL: srv.URL}); err == nil {
		t.Fatal("HTTP failure must error")
	}

	garbage := feedServer(t, "not json")
	defer garbage.Close()
	if err := RefreshOnce(context.Background(), &config.Config{PoolFeedURL: garbage.URL}); err == nil {
		t.Fatal("invalid JSON must error")
	}

}

func TestStartDisabled(t *testing.T) {
	if err := Start(context.Background(), &config.Config{PoolFeedDisabled: true}); err != nil {
		t.Fatalf("disabled feed must be a no-op: %v", err)
	}
	if err := Start(context.Background(), &config.Config{PoolFeedURL: ""}); err != nil {
		t.Fatalf("empty feed URL must be a no-op: %v", err)
	}
}

func TestStartRefreshesInBackground(t *testing.T) {
	loadRanges(t)
	var pulls atomic.Int64
	feed := `{"pools":[{"isp":"unicom","family":4,"ips":[{"ip":"104.16.5.1"}],"published":true}]}`
	done := make(chan struct{})
	var closeOnce sync.Once
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(feed))
		if pulls.Add(1) >= 2 {
			closeOnce.Do(func() { close(done) })
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg := &config.Config{PoolFeedURL: srv.URL, PoolFeedIntervalSec: 60, PoolFeedTTLSec: 300}
	if err := Start(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	// force a quick second pull by calling RefreshOnce directly
	if err := RefreshOnce(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("start loop did not pull, pulls=%d", pulls.Load())
	}
}

func TestPollutionBeyondCapStillRejectsWholePool(t *testing.T) {
	loadRanges(t)
	// 6 clean addresses fill the cap, pollution sits at position 7
	ips := make([]string, 0, 7)
	for i := 1; i <= 6; i++ {
		ips = append(ips, fmt.Sprintf(`{"ip":"104.16.6.%d"}`, i))
	}
	ips = append(ips, `{"ip":"93.184.216.34"}`)
	feed := fmt.Sprintf(`{"pools":[{"isp":"cmcc","family":4,"ips":[%s],"published":true}]}`, strings.Join(ips, ","))
	srv := feedServer(t, feed)
	defer srv.Close()

	if err := RefreshOnce(context.Background(), &config.Config{PoolFeedURL: srv.URL, PoolFeedTTLSec: 1800}); err != nil {
		t.Fatal(err)
	}
	for _, report := range pool.IspPoolStatus() {
		if report.Scope == "isp:cmcc" {
			t.Fatal("pollution past the adoption cap must still reject the whole pool")
		}
	}
}
