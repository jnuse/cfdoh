package cfhost

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// Candidate source forms (pinned by the task spec):
//
//	pool:<url>[#<isp>]  public pool API (cfhub-shaped JSON: top-level
//	                     {"pools":[{isp,family,ips:[{ip}],published}]})
//	domain:<name>       system DNS A lookup for <name>
//	list:<ip,ip,...>    static list
//	https://...         generic remote API: one IP per line, or a JSON string array
//
// Remote sources only accept https and verify system roots. A failing source
// is logged and skipped; when every source fails callers fall back to the
// previous candidate set from the state file.

const (
	fetchTimeout   = 10 * time.Second
	fetchLimitByte = 2 << 20 // 2MiB response cap per source
)

// refuseDowngradeRedirect is the http.Client redirect policy for remote
// sources: https-to-https redirects are followed (bounded like the default
// client at 10 hops), but any redirect that would leave https — e.g. a
// downgraded http target — is refused so fetching never moves off TLS.
func refuseDowngradeRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	if req.URL.Scheme != "https" {
		return fmt.Errorf("refusing redirect to non-https %s", req.URL)
	}
	return nil
}

// fetcher bundles the injectable dependencies of candidate fetching.
type fetcher struct {
	client   *http.Client
	resolver *net.Resolver
}

var defaultFetcher = &fetcher{
	client:   &http.Client{Timeout: fetchTimeout, CheckRedirect: refuseDowngradeRedirect},
	resolver: net.DefaultResolver,
}

type sourceSpec struct {
	kind string // "pool" | "domain" | "list" | "api"
	rest string // raw remainder (domain, list body, full URL)
	url  string // pool URL only
	isp  string // pool isp filter ("" -> national)
}

// parseSource recognizes the four source forms. Unknown or malformed sources
// are rejected (the caller skips them).
func parseSource(s string) (sourceSpec, bool) {
	s = strings.TrimSpace(s)
	switch {
	case strings.HasPrefix(s, "pool:"):
		rest := strings.TrimPrefix(s, "pool:")
		rawURL, isp, _ := strings.Cut(rest, "#")
		rawURL = strings.TrimSpace(rawURL)
		isp = strings.TrimSpace(isp)
		if rawURL == "" {
			return sourceSpec{}, false
		}
		return sourceSpec{kind: "pool", url: rawURL, isp: isp}, true
	case strings.HasPrefix(s, "domain:"):
		d := strings.TrimSpace(strings.TrimPrefix(s, "domain:"))
		if !validDomain(d) {
			return sourceSpec{}, false
		}
		return sourceSpec{kind: "domain", rest: d}, true
	case strings.HasPrefix(s, "list:"):
		return sourceSpec{kind: "list", rest: strings.TrimPrefix(s, "list:")}, true
	case strings.HasPrefix(s, "https://"):
		return sourceSpec{kind: "api", rest: s}, true
	}
	return sourceSpec{}, false
}

// poolFeedDoc mirrors the public pool API JSON (cfhub shape): a top-level
// object wrapping pools; each pool carries its addresses nested in
// ips[].ip. Same shape as hubfeed's feedDoc (the server-side consumer of
// the same endpoint).
type poolFeedDoc struct {
	Pools []poolFeedEntry `json:"pools"`
}

type poolFeedEntry struct {
	ISP       string   `json:"isp"`
	Family    int      `json:"family"`
	IPs       []feedIP `json:"ips"`
	Published bool     `json:"published"`
}

type feedIP struct {
	IP string `json:"ip"`
}

// fetchCandidates pulls all sources, keeps only public unicast addresses,
// deduplicates in first-seen order and truncates to limit. The second return
// value reports whether every source failed (no valid addresses at all).
func fetchCandidates(ctx context.Context, sources []string, f *fetcher, limit int) ([]netip.Addr, bool) {
	var cands []netip.Addr
	seen := map[string]bool{}
	anyOK := false
	for _, s := range sources {
		spec, ok := parseSource(s)
		if !ok {
			slog.Warn("cfhost: skipping malformed source", "source", s)
			continue
		}
		addrs, err := fetchSource(ctx, spec, f)
		if err != nil {
			slog.Warn("cfhost: source failed", "source", s, "error", err.Error())
			continue
		}
		kept := 0
		for _, a := range addrs {
			a = a.Unmap()
			if !publicUnicast(a) {
				continue
			}
			k := a.String()
			if seen[k] {
				continue
			}
			seen[k] = true
			cands = append(cands, a)
			kept++
		}
		if kept == 0 {
			slog.Warn("cfhost: source yielded no usable addresses", "source", s)
			continue
		}
		anyOK = true
	}
	if limit > 0 && len(cands) > limit {
		cands = cands[:limit]
	}
	return cands, !anyOK
}

// publicUnicast filters loopback, private, link-local, multicast and
// unspecified addresses.
func publicUnicast(a netip.Addr) bool {
	return !(a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() ||
		a.IsMulticast() || a.IsUnspecified())
}

func fetchSource(ctx context.Context, spec sourceSpec, f *fetcher) ([]netip.Addr, error) {
	switch spec.kind {
	case "pool":
		return fetchFromPool(ctx, f, spec.url, spec.isp)
	case "domain":
		return fetchFromDomain(ctx, f, spec.rest)
	case "list":
		return parseIPList(spec.rest), nil
	case "api":
		return fetchFromAPI(ctx, f, spec.rest)
	}
	return nil, fmt.Errorf("unknown source kind %q", spec.kind)
}

// fetchFromPool pulls the cfhub-shaped pool feed and returns addresses from
// published pools whose isp matches (default "national").
func fetchFromPool(ctx context.Context, f *fetcher, rawURL, wantISP string) ([]netip.Addr, error) {
	if err := requireHTTPS(rawURL); err != nil {
		return nil, err
	}
	body, err := httpGetBody(ctx, f.client, rawURL)
	if err != nil {
		return nil, err
	}
	var feed poolFeedDoc
	if err := json.Unmarshal(body, &feed); err != nil {
		return nil, fmt.Errorf("pool feed: %w", err)
	}
	if wantISP == "" {
		wantISP = "national"
	}
	var out []netip.Addr
	for _, e := range feed.Pools {
		if !e.Published || e.ISP != wantISP {
			continue
		}
		// Family is classified per address (a pool's ips array may mix
		// families); the pool-level family field is not trusted.
		for _, item := range e.IPs {
			if a, err := netip.ParseAddr(strings.TrimSpace(item.IP)); err == nil {
				out = append(out, a)
			}
		}
	}
	return out, nil
}

// fetchFromDomain resolves A records through the system resolver (default
// net.Resolver, never the daemon itself).
func fetchFromDomain(ctx context.Context, f *fetcher, domain string) ([]netip.Addr, error) {
	return f.resolver.LookupNetIP(ctx, "ip4", strings.TrimSuffix(domain, "."))
}

// fetchFromAPI pulls a generic remote list: one IP per text line, or a JSON
// array of strings.
func fetchFromAPI(ctx context.Context, f *fetcher, rawURL string) ([]netip.Addr, error) {
	if err := requireHTTPS(rawURL); err != nil {
		return nil, err
	}
	body, err := httpGetBody(ctx, f.client, rawURL)
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimSpace(string(body))
	if strings.HasPrefix(trimmed, "[") {
		var items []string
		if err := json.Unmarshal([]byte(trimmed), &items); err != nil {
			return nil, fmt.Errorf("ip list json: %w", err)
		}
		var out []netip.Addr
		for _, s := range items {
			if a, err := netip.ParseAddr(strings.TrimSpace(s)); err == nil {
				out = append(out, a)
			}
		}
		return out, nil
	}
	return parseIPList(string(body)), nil
}

func httpGetBody(ctx context.Context, client *http.Client, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("http status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, fetchLimitByte))
}

func requireHTTPS(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid url: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("remote source must be https, got %q", u.Scheme)
	}
	return nil
}

// parseIPList parses comma/whitespace/newline separated addresses.
func parseIPList(s string) []netip.Addr {
	var out []netip.Addr
	for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' || r == ' ' || r == '\t' }) {
		if a, err := netip.ParseAddr(strings.TrimSpace(part)); err == nil {
			out = append(out, a)
		}
	}
	return out
}
