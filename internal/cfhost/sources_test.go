package cfhost

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// insecureFetcher trusts the httptest self-signed certificate (scheme stays
// https so the source validation path is exercised end to end) and keeps the
// production redirect policy.
func insecureFetcher() *fetcher {
	return &fetcher{
		client: &http.Client{
			Timeout:       10 * time.Second,
			CheckRedirect: refuseDowngradeRedirect,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
		resolver: net.DefaultResolver,
	}
}

func tlsServer(t *testing.T, body string, status int) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if status != 0 {
			w.WriteHeader(status)
		}
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestParseSource(t *testing.T) {
	cases := []struct {
		in   string
		ok   bool
		kind string
		isp  string
		url  string
		rest string
	}{
		{"pool:https://x.invalid", true, "pool", "", "https://x.invalid", ""},
		{"pool:https://x.invalid#chinanet", true, "pool", "chinanet", "https://x.invalid", ""},
		{"pool:  ", false, "", "", "", ""},
		{"domain:example.com", true, "domain", "", "", "example.com"},
		{"domain:not a domain", false, "", "", "", ""},
		{"list:1.1.1.1,8.8.8.8", true, "list", "", "", "1.1.1.1,8.8.8.8"},
		{"https://api.invalid/ips", true, "api", "", "", "https://api.invalid/ips"},
		{"http://api.invalid/ips", false, "", "", "", ""},
		{"ftp://x", false, "", "", "", ""},
		{"", false, "", "", "", ""},
	}
	for _, c := range cases {
		spec, ok := parseSource(c.in)
		if ok != c.ok {
			t.Errorf("parseSource(%q) ok = %v want %v", c.in, ok, c.ok)
			continue
		}
		if !ok {
			continue
		}
		if spec.kind != c.kind || spec.isp != c.isp || spec.url != c.url || spec.rest != c.rest {
			t.Errorf("parseSource(%q) = %+v", c.in, spec)
		}
	}
}

func TestFetchFromPool(t *testing.T) {
	feed := `[
		{"published":true,"isp":"national","ipv4":["1.1.1.1","1.0.0.1"],"ipv6":["2606:4700:4700::1111"]},
		{"published":true,"isp":"chinanet","ipv4":["104.16.1.1"],"ipv6":[]},
		{"published":false,"isp":"national","ipv4":["2.2.2.2"]},
		{"published":true,"isp":"unicom","ipv4":["3.3.3.3"]}
	]`
	srv := tlsServer(t, feed, 0)
	f := insecureFetcher()
	ctx := context.Background()

	// Default isp filter is national: v4 + v6 merged.
	got, err := fetchFromPool(ctx, f, srv.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].String() != "1.1.1.1" || got[1].String() != "1.0.0.1" ||
		got[2].String() != "2606:4700:4700::1111" {
		t.Fatalf("national pool wrong: %v", got)
	}

	// Explicit isp filter.
	got, err = fetchFromPool(ctx, f, srv.URL, "chinanet")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].String() != "104.16.1.1" {
		t.Fatalf("chinanet pool wrong: %v", got)
	}

	// http scheme rejected.
	if _, err := fetchFromPool(ctx, f, "http://"+stripScheme(t, srv.URL), ""); err == nil {
		t.Fatal("http pool url must be rejected")
	}

	// Non-2xx is a failure.
	bad := tlsServer(t, "boom", http.StatusInternalServerError)
	if _, err := fetchFromPool(ctx, f, bad.URL, ""); err == nil {
		t.Fatal("non-2xx pool response must fail")
	}
}

func stripScheme(t *testing.T, url string) string {
	t.Helper()
	if len(url) > 8 && url[:8] == "https://" {
		return url[8:]
	}
	t.Fatalf("not https url: %s", url)
	return ""
}

func TestFetchFromAPI(t *testing.T) {
	f := insecureFetcher()
	ctx := context.Background()

	// Plain text lines.
	srv := tlsServer(t, "1.1.1.1\n8.8.8.8\r\n\n1.0.0.1\n", 0)
	got, err := fetchFromAPI(ctx, f, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].String() != "1.1.1.1" || got[2].String() != "1.0.0.1" {
		t.Fatalf("text list wrong: %v", got)
	}

	// JSON string array.
	srv2 := tlsServer(t, `["1.1.1.1","2606:4700:4700::1111","not-an-ip"]`, 0)
	got, err = fetchFromAPI(ctx, f, srv2.URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("json list wrong: %v", got)
	}
}

func TestFetchCandidatesMergeFilterDedupLimit(t *testing.T) {
	pool := tlsServer(t, `[
		{"published":true,"isp":"national","ipv4":["1.1.1.1","104.16.3.3"],"ipv6":["2606:4700::1"]}
	]`, 0)
	sources := []string{
		"pool:" + pool.URL,
		"list:1.1.1.1,10.0.0.7,127.0.0.1,192.168.1.4,169.254.1.1,::1,fe80::1,0.0.0.0,224.0.0.1,104.16.3.3",
	}
	cands, allFailed := fetchCandidates(context.Background(), sources, insecureFetcher(), 0)
	if allFailed {
		t.Fatal("should not be all-failed")
	}
	var got []string
	for _, a := range cands {
		got = append(got, a.String())
	}
	// Order: pool first (1.1.1.1, 104.16.3.3, 2606:4700::1), then only the
	// public entries from list (dedup drops repeats).
	want := []string{"1.1.1.1", "104.16.3.3", "2606:4700::1"}
	if len(got) != len(want) {
		t.Fatalf("candidates = %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("candidates = %v want %v", got, want)
		}
	}

	// Limit truncation keeps first-seen order.
	cands, _ = fetchCandidates(context.Background(), sources, insecureFetcher(), 2)
	if len(cands) != 2 || cands[0].String() != "1.1.1.1" || cands[1].String() != "104.16.3.3" {
		t.Fatalf("limit truncation wrong: %v", cands)
	}
}

func TestFetchCandidatesToleratesFailingSources(t *testing.T) {
	pool := tlsServer(t, `[{"published":true,"isp":"national","ipv4":["1.1.1.1"]}]`, 0)
	sources := []string{
		"pool:" + pool.URL,                           // good
		"list:not-an-ip,alsonotip",                   // parses but zero valid -> failed
		"https://127.0.0.1:1/ips",                    // connection refused -> failed
		"garbage-source",                             // unparsable -> failed
		"pool:http://insecure.invalid/feed#national", // http rejected
	}
	cands, allFailed := fetchCandidates(context.Background(), sources, insecureFetcher(), 0)
	if allFailed {
		t.Fatal("one good source must prevent all-failed")
	}
	if len(cands) != 1 || cands[0].String() != "1.1.1.1" {
		t.Fatalf("candidates wrong: %v", cands)
	}
}

func TestFetcherRefusesDowngradeRedirect(t *testing.T) {
	// An https source redirecting to a plain-http target must be refused:
	// fetching never moves off TLS (PRD F-023 https-only sources).
	downgradedHit := false
	downgraded := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		downgradedHit = true
		w.Write([]byte("1.1.1.1"))
	}))
	defer downgraded.Close()
	entry := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, downgraded.URL+"/ips", http.StatusFound)
	}))
	defer entry.Close()

	_, err := fetchFromAPI(context.Background(), insecureFetcher(), entry.URL)
	if err == nil {
		t.Fatal("https-to-http redirect must be refused")
	}
	if !strings.Contains(err.Error(), "non-https") {
		t.Fatalf("error should name the refused non-https target: %v", err)
	}
	if downgradedHit {
		t.Fatal("the downgraded http target must never be fetched")
	}

	// Same policy on the pool source.
	_, err = fetchFromPool(context.Background(), insecureFetcher(), entry.URL, "")
	if err == nil || !strings.Contains(err.Error(), "non-https") {
		t.Fatalf("pool source downgrade must be refused too: %v", err)
	}
}

func TestFetcherFollowsHTTPSRedirect(t *testing.T) {
	// https-to-https redirects are still followed.
	target := tlsServer(t, "1.1.1.1\n", 0)
	entry := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/ips", http.StatusFound)
	}))
	defer entry.Close()

	got, err := fetchFromAPI(context.Background(), insecureFetcher(), entry.URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].String() != "1.1.1.1" {
		t.Fatalf("https redirect should be followed, got %v", got)
	}
}

func TestFetchCandidatesAllFailed(t *testing.T) {
	sources := []string{
		"list:127.0.0.1,10.1.2.3", // valid parse, all filtered -> failed
		"https://127.0.0.1:1/ips", // refused
	}
	cands, allFailed := fetchCandidates(context.Background(), sources, insecureFetcher(), 0)
	if !allFailed || len(cands) != 0 {
		t.Fatalf("expected all-failed, got %v allFailed=%v", cands, allFailed)
	}
}
