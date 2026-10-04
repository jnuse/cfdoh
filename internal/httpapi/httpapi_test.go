package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jnuse/cfdoh/internal/cfrange"
	"github.com/jnuse/cfdoh/internal/config"
	"github.com/jnuse/cfdoh/internal/ech"
	"github.com/jnuse/cfdoh/internal/pool"
	"github.com/jnuse/cfdoh/internal/wire"
)

func TestMain(m *testing.M) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	m.Run()
}

func baseCfg(upstreams ...string) *config.Config {
	return &config.Config{
		Upstreams:            upstreams,
		EcsUpstreams:         upstreams,
		UpstreamTimeoutMs:    1000,
		UpstreamHedgeMs:      0,
		MaxDNSPacketSize:     65535,
		CacheMinTTL:          30,
		CacheMaxTTL:          3600,
		NegativeCacheMaxTTL:  300,
		CacheStaleTTL:        86400,
		CachePrefetchPercent: 10,
		CacheMaxEntries:      4096,
		EcsMode:              "off",
		EcsIPv4Prefix:        24,
		EcsIPv6Prefix:        48,
	}
}

func loadRanges(t *testing.T) {
	t.Helper()
	v4 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("104.16.0.0/12\n172.64.0.0/13\n"))
	}))
	v6 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("2606:4700::/32\n"))
	}))
	t.Cleanup(v4.Close)
	t.Cleanup(v6.Close)
	cfg := &config.Config{CFIPv4URL: v4.URL, CFIPv6URL: v6.URL}
	if _, err := cfrange.Load(context.Background(), cfg); err != nil {
		t.Fatalf("cfrange.Load: %v", err)
	}
}

// newFakeUpstream starts a DoH upstream answering via respond.
func newFakeUpstream(t *testing.T, respond func(q *wire.Packet) *wire.Packet) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read failed", http.StatusBadRequest)
			return
		}
		q, err := wire.Parse(body)
		if err != nil || len(q.Questions) != 1 {
			http.Error(w, "bad query", http.StatusBadRequest)
			return
		}
		out, err := respond(q).Encode()
		if err != nil {
			http.Error(w, "encode failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(out)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func answerA(q *wire.Packet) *wire.Packet {
	return &wire.Packet{
		Header:    wire.Header{ID: q.Header.ID, Flags: 0x8180},
		Questions: q.Questions,
		Answers:   []wire.Record{aRec(q.Questions[0].Name, "104.16.1.1", 60)},
	}
}

func answerByType(q *wire.Packet) *wire.Packet {
	resp := &wire.Packet{Header: wire.Header{ID: q.Header.ID, Flags: 0x8180}, Questions: q.Questions}
	question := q.Questions[0]
	switch question.Type {
	case wire.TypeA:
		resp.Answers = append(resp.Answers, aRec(question.Name, "104.16.1.1", 60))
	case wire.TypeAAAA:
		resp.Answers = append(resp.Answers, aaaaRec(question.Name, "2606:4700:1111::1", 60))
	default:
		resp.Answers = append(resp.Answers, httpsRec(question.Name, "104.16.1.1", 60))
	}
	return resp
}

func buildQuery(id uint16, name string, qtype uint16) []byte {
	q := &wire.Packet{
		Header:    wire.Header{ID: id, Flags: 0x0100},
		Questions: []wire.Question{{Name: name, Type: qtype, Class: wire.ClassIN}},
	}
	b, _ := q.Encode()
	return b
}

func buildRawQuery(flags uint16, questions ...wire.Question) []byte {
	q := &wire.Packet{Header: wire.Header{ID: 0x0102, Flags: flags}, Questions: questions}
	b, _ := q.Encode()
	return b
}

func aRec(name, ip string, ttl uint32) wire.Record {
	v, err := wire.ParseIPv4(ip)
	if err != nil {
		panic(err)
	}
	return wire.Record{Name: name, Type: wire.TypeA, Class: wire.ClassIN, TTL: ttl, RData: wire.A{IP: v}}
}

// answerIPsOf renders the A-record addresses of a packet comma-joined.
func answerIPsOf(pkt *wire.Packet) string {
	var ips []string
	for _, r := range pkt.Answers {
		if a, ok := r.RData.(wire.A); ok {
			ips = append(ips, wire.IPv4String(a.IP))
		}
	}
	return strings.Join(ips, ",")
}

func aaaaRec(name, ip string, ttl uint32) wire.Record {
	v, err := wire.ParseIPv6(ip)
	if err != nil {
		panic(err)
	}
	return wire.Record{Name: name, Type: wire.TypeAAAA, Class: wire.ClassIN, TTL: ttl, RData: wire.AAAA{IP: v}}
}

func httpsRec(name, v4 string, ttl uint32) wire.Record {
	ip, err := wire.ParseIPv4(v4)
	if err != nil {
		panic(err)
	}
	return wire.Record{Name: name, Type: wire.TypeHTTPS, Class: wire.ClassIN, TTL: ttl,
		RData: wire.SVCB{Priority: 1, Target: ".",
			Params: []wire.SvcParam{{Key: wire.ParamIPv4Hint, Value: ip[:]}}}}
}

func newTS(t *testing.T, cfg *config.Config) (*httptest.Server, *Server) {
	t.Helper()
	s := New(cfg)
	ts := httptest.NewServer(s.handler())
	t.Cleanup(ts.Close)
	return ts, s
}

func decodeJSON(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode json: %v", err)
	}
	return out
}

// opaqueReader hides the body length so the client sends chunked framing.
type opaqueReader struct{ r io.Reader }

func (o opaqueReader) Read(p []byte) (int, error) { return o.r.Read(p) }

func TestRoutingBasics(t *testing.T) {
	ts, _ := newTS(t, baseCfg())

	tests := []struct {
		name   string
		method string
		path   string
		want   int
	}{
		{"unknown path", http.MethodGet, "/nope", 404},
		{"health non-GET", http.MethodPost, "/health", 405},
		{"probe non-GET", http.MethodPost, "/probe", 405},
		{"doh non-GET/POST", http.MethodPut, "/dns-query", 405},
		{"explain non-GET", http.MethodPost, "/explain", 405},
		{"unknown admin path", http.MethodGet, "/admin/unknown", 404},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest(tt.method, ts.URL+tt.path, nil)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != tt.want {
				t.Fatalf("%s %s = %d, want %d", tt.method, tt.path, resp.StatusCode, tt.want)
			}
		})
	}
}

func TestHostCheck421(t *testing.T) {
	cfg := baseCfg()
	cfg.PublicHostnames = []string{"doh.example.com"}
	ts, _ := newTS(t, cfg)

	get := func(host string) int {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/health", nil)
		req.Host = host
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := get("evil.example.com"); code != 421 {
		t.Fatalf("foreign host = %d, want 421", code)
	}
	if code := get("doh.example.com:8443"); code != 200 {
		t.Fatalf("allowed host with port = %d, want 200", code)
	}
	if code := get("localhost"); code != 200 {
		t.Fatalf("localhost = %d, want 200", code)
	}
}

func TestDoHValidationMatrix(t *testing.T) {
	ts, _ := newTS(t, baseCfg())
	valid := base64.RawURLEncoding.EncodeToString(buildQuery(1, "www.example.com", wire.TypeA))
	qrSet := base64.RawURLEncoding.EncodeToString(buildRawQuery(0x8100,
		wire.Question{Name: "www.example.com", Type: wire.TypeA, Class: wire.ClassIN}))
	twoQuestions := base64.RawURLEncoding.EncodeToString(buildRawQuery(0x0100,
		wire.Question{Name: "a.example.com", Type: wire.TypeA, Class: wire.ClassIN},
		wire.Question{Name: "b.example.com", Type: wire.TypeA, Class: wire.ClassIN}))

	tests := []struct {
		name string
		req  func() (*http.Request, error)
		want int
	}{
		{
			name: "unacceptable accept header",
			req: func() (*http.Request, error) {
				req, _ := http.NewRequest(http.MethodGet, ts.URL+"/dns-query?dns="+valid, nil)
				req.Header.Set("Accept", "text/html")
				return req, nil
			},
			want: 406,
		},
		{
			name: "wrong content type",
			req: func() (*http.Request, error) {
				req, _ := http.NewRequest(http.MethodPost, ts.URL+"/dns-query", strings.NewReader("x"))
				req.Header.Set("Content-Type", "application/json")
				return req, nil
			},
			want: 415,
		},
		{
			name: "missing dns parameter",
			req: func() (*http.Request, error) {
				return http.NewRequest(http.MethodGet, ts.URL+"/dns-query", nil)
			},
			want: 400,
		},
		{
			name: "invalid base64url",
			req: func() (*http.Request, error) {
				return http.NewRequest(http.MethodGet, ts.URL+"/dns-query?dns=not+valid!!!", nil)
			},
			want: 400,
		},
		{
			name: "QR bit set",
			req: func() (*http.Request, error) {
				return http.NewRequest(http.MethodGet, ts.URL+"/dns-query?dns="+qrSet, nil)
			},
			want: 400,
		},
		{
			name: "two questions",
			req: func() (*http.Request, error) {
				return http.NewRequest(http.MethodGet, ts.URL+"/dns-query?dns="+twoQuestions, nil)
			},
			want: 400,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := tt.req()
			if err != nil {
				t.Fatal(err)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != tt.want {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tt.want)
			}
		})
	}
}

func TestDoH413(t *testing.T) {
	cfg := baseCfg()
	cfg.MaxDNSPacketSize = 32
	ts, _ := newTS(t, cfg)
	big := bytes.Repeat([]byte{0}, 100)

	// GET: decoded size over the cap
	oversized := base64.RawURLEncoding.EncodeToString(buildQuery(2, "www.oversize.example.com", wire.TypeA))
	resp, err := http.Get(ts.URL + "/dns-query?dns=" + oversized)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 413 {
		t.Fatalf("GET oversized = %d, want 413", resp.StatusCode)
	}

	// POST: Content-Length precheck
	resp, err = http.Post(ts.URL+"/dns-query", "application/dns-message", bytes.NewReader(big))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 413 {
		t.Fatalf("POST content-length precheck = %d, want 413", resp.StatusCode)
	}

	// POST: actual read over the cap (chunked, unknown length)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/dns-query",
		io.NopCloser(opaqueReader{bytes.NewReader(big)}))
	req.Header.Set("Content-Type", "application/dns-message")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 413 {
		t.Fatalf("POST actual-read = %d, want 413", resp.StatusCode)
	}
}

func TestDoHSuccess(t *testing.T) {
	upstream := newFakeUpstream(t, answerA)
	ts, _ := newTS(t, baseCfg(upstream.URL))

	// GET
	query := buildQuery(0x1234, "www.get-ok.doh.test", wire.TypeA)
	resp, err := http.Get(ts.URL + "/dns-query?dns=" + base64.RawURLEncoding.EncodeToString(query))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("GET = %d, want 200", resp.StatusCode)
	}
	for header, want := range map[string]string{
		"Content-Type":           "application/dns-message",
		"Cache-Control":          "no-store",
		"X-Content-Type-Options": "nosniff",
	} {
		if got := resp.Header.Get(header); got != want {
			t.Fatalf("%s = %q, want %q", header, got, want)
		}
	}
	parsed, err := wire.Parse(body)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Header.ID != 0x1234 {
		t.Fatalf("GET answer ID = %#x, want 0x1234", parsed.Header.ID)
	}

	// GET with base64url padding (RFC 8484 clients may keep the '=' pad)
	padded := base64.RawURLEncoding.EncodeToString(query)
	padded += strings.Repeat("=", (4-len(padded)%4)%4)
	resp, err = http.Get(ts.URL + "/dns-query?dns=" + padded)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("GET padded = %d, want 200", resp.StatusCode)
	}

	// POST
	query = buildQuery(0x4321, "www.post-ok.doh.test", wire.TypeA)
	resp, err = http.Post(ts.URL+"/dns-query", "application/dns-message", bytes.NewReader(query))
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("POST = %d, want 200", resp.StatusCode)
	}
	if parsed, err = wire.Parse(body); err != nil || parsed.Header.ID != 0x4321 {
		t.Fatalf("POST answer ID = %#x (err %v), want 0x4321", parsed.Header.ID, err)
	}
}

func TestPathAlias(t *testing.T) {
	upstream := newFakeUpstream(t, answerA)
	cfg := baseCfg(upstream.URL)
	cfg.PathAliases = []string{"/linuxdo"}
	ts, _ := newTS(t, cfg)

	query := buildQuery(7, "www.alias.doh.test", wire.TypeA)
	resp, err := http.Get(ts.URL + "/linuxdo?dns=" + base64.RawURLEncoding.EncodeToString(query))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("alias = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/dns-message" {
		t.Fatalf("alias content type = %q", ct)
	}
	if parsed, err := wire.Parse(body); err != nil || parsed.Header.ID != 7 {
		t.Fatalf("alias answer ID = %#x (err %v)", parsed.Header.ID, err)
	}
}

func TestDoHParams(t *testing.T) {
	upstream := newFakeUpstream(t, answerA)
	cfg := baseCfg(upstream.URL)
	cfg.DynamicRuleHosts = []string{"good.example.com"}
	ts, _ := newTS(t, cfg)

	tests := []struct {
		name string
		url  string
	}{
		{"invalid ip4", "/dns-query?ip4=999.1.1.1"},
		{"too many ip4", "/dns-query?ip4=" + strings.Repeat("1.1.1.1,", 16) + "1.1.1.1"},
		{"invalid cf domain", "/dns-query?cf=bad_name"},
		{"invalid ech domain", "/dns-query?ech=-bad-"},
		{"rules host not whitelisted", "/dns-query?rules=https://bad.example.com/r.json"},
		{"rules not https", "/dns-query?rules=http://good.example.com/r.json"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := http.Get(ts.URL + tt.url + "&dns=" +
				base64.RawURLEncoding.EncodeToString(buildQuery(9, "www.params.doh.test", wire.TypeA)))
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != 400 {
				t.Fatalf("%s = %d, want 400", tt.url, resp.StatusCode)
			}
		})
	}

	// a valid explicit pool pins the answer addresses end to end
	loadRanges(t)
	resp, err := http.Get(ts.URL + "/dns-query?ip4=104.16.9.9,104.16.9.8&dns=" +
		base64.RawURLEncoding.EncodeToString(buildQuery(11, "www.pin.doh.test", wire.TypeA)))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("ip4 pin = %d, want 200", resp.StatusCode)
	}
	parsed, err := wire.Parse(body)
	if err != nil {
		t.Fatal(err)
	}
	if got := answerIPsOf(parsed); got != "104.16.9.9,104.16.9.8" && got != "104.16.9.8,104.16.9.9" {
		t.Fatalf("pinned addresses = %q, want the two explicit IPs", got)
	}
}

func TestProbeClientIP(t *testing.T) {
	ts, _ := newTS(t, baseCfg())
	probeIP := func(headers map[string]string) string {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/probe", nil)
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		out := decodeJSON(t, resp)
		ip, _ := out["client_ip"].(string)
		return ip
	}

	if ip := probeIP(map[string]string{
		"X-Real-IP":       "1.2.3.4",
		"X-Forwarded-For": "5.6.7.8",
	}); ip != "1.2.3.4" {
		t.Fatalf("X-Real-IP must win, got %q", ip)
	}
	if ip := probeIP(map[string]string{
		"X-Forwarded-For": "5.6.7.8, 10.0.0.1",
	}); ip != "5.6.7.8" {
		t.Fatalf("XFF first value expected, got %q", ip)
	}
	if ip := probeIP(map[string]string{
		"X-Real-IP": "not-an-ip",
	}); ip != "127.0.0.1" {
		t.Fatalf("unparseable header must fall through to RemoteAddr, got %q", ip)
	}
	if ip := probeIP(nil); ip != "127.0.0.1" {
		t.Fatalf("no headers must use RemoteAddr, got %q", ip)
	}

	gated, _ := newTS(t, func() *config.Config {
		cfg := baseCfg()
		cfg.DohOriginToken = "origin-secret"
		return cfg
	}())
	gatedIP := func(headers map[string]string) string {
		req, _ := http.NewRequest(http.MethodGet, gated.URL+"/probe", nil)
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		out := decodeJSON(t, resp)
		ip, _ := out["client_ip"].(string)
		return ip
	}
	if ip := gatedIP(map[string]string{
		"X-DoH-Origin-Token": "origin-secret",
		"X-DoH-Client-IP":    "9.9.9.9, 8.8.8.8",
		"X-Real-IP":          "1.2.3.4",
	}); ip != "9.9.9.9" {
		t.Fatalf("origin-token gated header must win, got %q", ip)
	}
	if ip := gatedIP(map[string]string{
		"X-DoH-Origin-Token": "wrong-token",
		"X-DoH-Client-IP":    "9.9.9.9",
		"X-Real-IP":          "1.2.3.4",
	}); ip != "1.2.3.4" {
		t.Fatalf("wrong origin token must fall through, got %q", ip)
	}
}

func TestAdminWithoutTokenIs404(t *testing.T) {
	ts, _ := newTS(t, baseCfg())
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		var body io.Reader
		if method == http.MethodPost {
			body = strings.NewReader(`{}`)
		}
		req, _ := http.NewRequest(method, ts.URL+"/admin/preferred", body)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 404 {
			t.Fatalf("%s /admin/preferred = %d, want 404", method, resp.StatusCode)
		}
	}
}

func TestAdminAuthMatrix(t *testing.T) {
	upstream := newFakeUpstream(t, answerA)
	cfg := baseCfg(upstream.URL)
	cfg.AdminToken = "admin-tok"
	cfg.HubToken = "hub-tok"
	ts, _ := newTS(t, cfg)

	do := func(method, path, token, body string) *http.Response {
		var reader io.Reader
		if body != "" {
			reader = strings.NewReader(body)
		}
		req, _ := http.NewRequest(method, ts.URL+path, reader)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	resp := do(http.MethodGet, "/admin/preferred", "", "")
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("no auth = %d, want 401", resp.StatusCode)
	}
	resp = do(http.MethodGet, "/admin/preferred", "wrong", "")
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("wrong token = %d, want 401", resp.StatusCode)
	}
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/admin/preferred", nil)
	req.Header.Set("Authorization", "Basic admin-tok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("basic scheme = %d, want 401", resp.StatusCode)
	}

	resp = do(http.MethodGet, "/admin/preferred", "hub-tok", "")
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("hub GET = %d, want 403", resp.StatusCode)
	}
	resp = do(http.MethodPost, "/admin/preferred", "hub-tok",
		`{"ipv4":["104.16.1.9"],"ttl":600,"source":"hub","scope":"default"}`)
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("hub default scope = %d, want 403", resp.StatusCode)
	}
	resp = do(http.MethodPost, "/admin/site", "hub-tok", `{}`)
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("hub site report = %d, want 403", resp.StatusCode)
	}
	resp = do(http.MethodPost, "/admin/github", "hub-tok", `{}`)
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("hub github report = %d, want 403", resp.StatusCode)
	}
	resp = do(http.MethodPost, "/admin/h3", "hub-tok", `{}`)
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("hub h3 report = %d, want 403", resp.StatusCode)
	}

	resp = do(http.MethodGet, "/admin/preferred", "admin-tok", "")
	out := decodeJSON(t, resp)
	if resp.StatusCode != 200 {
		t.Fatalf("admin GET = %d, want 200", resp.StatusCode)
	}
	for _, key := range []string{"learned", "isp", "github", "site", "ech", "h3", "selfcheck"} {
		if _, ok := out[key]; !ok {
			t.Fatalf("admin GET missing key %q", key)
		}
	}

	resp = do(http.MethodPost, "/admin/preferred", "admin-tok",
		`{"ipv4":["104.16.1.9"],"ttl":600,"source":"matrix","scope":"default"}`)
	if resp.StatusCode != 200 {
		t.Fatalf("admin POST = %d, want 200", resp.StatusCode)
	}
	body := decodeJSON(t, resp)
	if ok, _ := body["ok"].(bool); !ok {
		t.Fatalf("admin POST body = %v, want ok", body)
	}

	resp = do(http.MethodPost, "/admin/preferred", "admin-tok",
		`{"ipv4":["`+strings.Repeat("1.1.1.1,", 60)+`1.1.1.1"],"scope":"default"}`)
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("65 addresses = %d, want 400", resp.StatusCode)
	}

	// body over the 1 MiB admin cap
	big := `{"pad":"` + strings.Repeat("a", adminBodyLimit+64) + `"}`
	resp = do(http.MethodPost, "/admin/preferred", "admin-tok", big)
	resp.Body.Close()
	if resp.StatusCode != 413 {
		t.Fatalf("oversized admin body = %d, want 413", resp.StatusCode)
	}
}

func TestAdminPreferredValidation(t *testing.T) {
	upstream := newFakeUpstream(t, answerA)
	cfg := baseCfg(upstream.URL)
	cfg.AdminToken = "admin-tok"
	cfg.HubToken = "hub-tok"
	ts, _ := newTS(t, cfg)

	post := func(token, body string) int {
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/admin/preferred", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	for _, body := range []string{
		`{"ipv4":["1.2.3.999"],"scope":"default"}`,                                     // invalid address
		`{"ipv4":["1.2.3.4"],"scope":"bogus"}`,                                         // unknown scope
		`{"ipv4":["1.2.3.4"],"scope":"isp:national"}`,                                  // reserved name
		`{"ipv4":["1.2.3.4"],"scope":"isp:UPPER"}`,                                     // invalid operator name
		`{"ipv4":["` + strings.Repeat("1.1.1.1,", 64) + `1.1.1.1"],"scope":"default"}`, // 65 addresses
	} {
		if code := post("admin-tok", body); code != 400 {
			t.Fatalf("POST %s = %d, want 400", body, code)
		}
	}

	// ttl below the floor is clamped (200), not rejected
	if code := post("admin-tok", `{"ipv4":["104.16.1.10"],"ttl":5,"source":"clamp-src","scope":"default"}`); code != 200 {
		t.Fatalf("clamped ttl = %d, want 200", code)
	}
	found := false
	for _, src := range pool.LearnedStatus().Sources {
		if src.Source == "clamp-src" {
			found = true
			delta := src.ExpiresAt - time.Now().UnixMilli()
			if delta < 59*time.Second.Milliseconds() || delta > 61*time.Second.Milliseconds() {
				t.Fatalf("clamped ttl delta = %dms, want ~60000ms", delta)
			}
		}
	}
	if !found {
		t.Fatal("clamp-src missing from the learned pool")
	}

	// scope "client" resolves to the reporter's own /24
	if code := post("admin-tok", `{"ipv4":["104.16.1.11"],"ttl":600,"source":"client-src","scope":"client"}`); code != 200 {
		t.Fatalf("client scope = %d, want 200", code)
	}
	scopedFound := false
	for _, sc := range pool.ScopedStatus() {
		if sc.Scope == "127.0.0/24" {
			scopedFound = true
		}
	}
	if !scopedFound {
		t.Fatal("client scope pool 127.0.0/24 missing")
	}

	// isp pools: CF addresses accepted, outsiders reject the whole batch
	loadRanges(t)
	if code := post("hub-tok", `{"ipv4":["104.16.0.1"],"ttl":600,"source":"hub-isp","scope":"isp:chinanet"}`); code != 200 {
		t.Fatalf("hub isp CF address = %d, want 200", code)
	}
	ispFound := false
	for _, p := range pool.IspPoolStatus() {
		if p.Scope == "isp:chinanet" {
			ispFound = true
			if len(p.IPv4) != 1 || p.IPv4[0] != "104.16.0.1" {
				t.Fatalf("isp pool content = %v", p.IPv4)
			}
		}
	}
	if !ispFound {
		t.Fatal("isp:chinanet pool missing")
	}
	if code := post("hub-tok", `{"ipv4":["1.2.3.4"],"ttl":600,"source":"hub-isp","scope":"isp:chinanet"}`); code != 400 {
		t.Fatalf("hub isp non-CF address = %d, want 400", code)
	}
}

func TestAdminSiteGithubH3(t *testing.T) {
	cfg := baseCfg()
	cfg.AdminToken = "admin-tok"
	ts, _ := newTS(t, cfg)

	post := func(path, body string) int {
		req, _ := http.NewRequest(http.MethodPost, ts.URL+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer admin-tok")
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	if code := post("/admin/site", `{"source":"sc","ttl":600,"hosts":{"site.example.com":["104.16.0.5"]}}`); code != 200 {
		t.Fatalf("site POST = %d, want 200", code)
	}
	siteStatus := pool.SiteStatus()
	if ips, ok := siteStatus.Hosts["site.example.com"]; !ok || len(ips) != 1 {
		t.Fatalf("site pool hosts = %v", siteStatus.Hosts)
	}

	if code := post("/admin/github", `{"source":"gh","ttl":600,"hosts":{"github.com":["2606:4700::1"]}}`); code != 400 {
		t.Fatalf("github v6 address = %d, want 400", code)
	}
	if code := post("/admin/github", `{"source":"gh","ttl":600,"hosts":{"bad_host":["104.16.0.7"]}}`); code != 400 {
		t.Fatalf("github invalid host = %d, want 400", code)
	}
	if code := post("/admin/github", `{"source":"gh","ttl":600,"hosts":{"github.com":["104.16.0.7"]}}`); code != 200 {
		t.Fatalf("github POST = %d, want 200", code)
	}

	if code := post("/admin/h3", `{"source":"p1","ttl":600,"verdicts":{"a.example.com":true}}`); code != 200 {
		t.Fatalf("h3 POST = %d, want 200", code)
	}
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/admin/h3", nil)
	req.Header.Set("Authorization", "Bearer admin-tok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	out := decodeJSON(t, resp)
	if resp.StatusCode != 200 {
		t.Fatalf("h3 GET = %d, want 200", resp.StatusCode)
	}
	effective, _ := out["Effective"].(map[string]any)
	if v, ok := effective["a.example.com"]; !ok || v != true {
		t.Fatalf("h3 effective verdicts = %v", effective)
	}
}

func TestAdminSelfcheck(t *testing.T) {
	cfg := baseCfg()
	cfg.AdminToken = "admin-tok"
	ts, _ := newTS(t, cfg)

	post := func(body string) int {
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/admin/selfcheck", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer admin-tok")
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	problems := make([]string, 60)
	for i := range problems {
		problems[i] = fmt.Sprintf("problem-%02d-%s", i, strings.Repeat("x", 400))
	}
	body, _ := json.Marshal(map[string]any{
		"source": "sc-A", "ok": false, "problems": problems, "hosts": []string{"a.example.com"},
	})
	if code := post(string(body)); code != 200 {
		t.Fatalf("selfcheck POST = %d, want 200", code)
	}

	// fill the table to and past the 8-source cap
	for i := 0; i < 8; i++ {
		payload, _ := json.Marshal(map[string]any{"source": fmt.Sprintf("fill-%d", i), "ok": true})
		if code := post(string(payload)); code != 200 {
			t.Fatalf("fill POST = %d, want 200", code)
		}
	}

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/admin/selfcheck", nil)
	req.Header.Set("Authorization", "Bearer admin-tok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var reports []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&reports); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("selfcheck GET = %d, want 200", resp.StatusCode)
	}
	if len(reports) != 8 {
		t.Fatalf("report count = %d, want 8 (oldest evicted)", len(reports))
	}
	for _, r := range reports {
		if src, _ := r["source"].(string); src == "sc-A" {
			t.Fatal("sc-A (oldest) must have been evicted")
		}
	}

	// one fresh report: problems truncated to 50 entries / 300 bytes each
	truncProblems := append([]string{strings.Repeat("y", 400)}, problems...)
	truncBody, _ := json.Marshal(map[string]any{
		"source": "sc-trunc", "ok": true, "problems": truncProblems,
	})
	if code := post(string(truncBody)); code != 200 {
		t.Fatalf("truncate POST = %d, want 200", code)
	}
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/admin/selfcheck", nil)
	req.Header.Set("Authorization", "Bearer admin-tok")
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	reports = nil
	if err := json.NewDecoder(resp2.Body).Decode(&reports); err != nil {
		t.Fatal(err)
	}
	for _, r := range reports {
		if src, _ := r["source"].(string); src != "sc-trunc" {
			continue
		}
		list, _ := r["problems"].([]any)
		if len(list) != 50 {
			t.Fatalf("problems kept = %d, want 50", len(list))
		}
		for _, p := range list {
			if s, _ := p.(string); len(s) > 300 {
				t.Fatalf("problem entry len = %d, want <= 300", len(s))
			}
		}
		return
	}
	t.Fatal("sc-trunc report missing")
}

func TestAdminHealth(t *testing.T) {
	loadRanges(t)
	cfg := baseCfg()
	cfg.AdminToken = "admin-tok"
	ts, _ := newTS(t, cfg)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/admin/health", nil)
	req.Header.Set("Authorization", "Bearer admin-tok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	out := decodeJSON(t, resp)
	if resp.StatusCode != 200 {
		t.Fatalf("admin health = %d, want 200", resp.StatusCode)
	}
	if ok, _ := out["ok"].(bool); !ok {
		t.Fatalf("ok field = %v", out["ok"])
	}
	if loaded, _ := out["cfrange_loaded"].(bool); !loaded {
		t.Fatalf("cfrange_loaded = %v, want true", out["cfrange_loaded"])
	}
}

func TestExplain(t *testing.T) {
	upstream := newFakeUpstream(t, answerByType)
	cfg := baseCfg(upstream.URL)
	ts, _ := newTS(t, cfg)

	// invalid name / type / params
	for _, suffix := range []string{
		"",
		"?name=bad+name",
		"?name=www.example.com&type=MX",
		"?name=www.example.com&ip4=999.1.1.1",
	} {
		resp, err := http.Get(ts.URL + "/explain" + suffix)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 400 {
			t.Fatalf("/explain%s = %d, want 400", suffix, resp.StatusCode)
		}
	}

	resp, err := http.Get(ts.URL + "/explain?name=www.explain-ok.test&type=A")
	if err != nil {
		t.Fatal(err)
	}
	out := decodeJSON(t, resp)
	if resp.StatusCode != 200 {
		t.Fatalf("explain = %d, want 200", resp.StatusCode)
	}
	if ip, _ := out["client_ip"].(string); ip != "127.0.0.1" {
		t.Fatalf("client_ip = %q", ip)
	}
	answers, _ := out["answers"].(map[string]any)
	if len(answers) != 1 {
		t.Fatalf("type=A filter: want only A, got %d keys", len(answers))
	}
	if _, ok := answers["A"]; !ok {
		t.Fatal("answers missing A")
	}
	if _, ok := out["chromium_ech"].(map[string]any); ok {
		t.Fatal("filtered explain must leave chromium_ech null")
	}

	// unfiltered: all three types plus the Chromium verdict
	resp, err = http.Get(ts.URL + "/explain?name=www.explain-ok.test")
	if err != nil {
		t.Fatal(err)
	}
	out = decodeJSON(t, resp)
	if resp.StatusCode != 200 {
		t.Fatalf("explain = %d, want 200", resp.StatusCode)
	}
	answers, _ = out["answers"].(map[string]any)
	for _, key := range []string{"A", "AAAA", "HTTPS"} {
		if _, ok := answers[key]; !ok {
			t.Fatalf("answers missing %q", key)
		}
		if a, _ := answers[key].(map[string]any); a != nil {
			if cache, _ := a["cache"].(string); cache == "" {
				t.Fatalf("answers[%s] missing cache state", key)
			}
		}
	}
	if _, ok := out["chromium_ech"].(map[string]any); !ok {
		t.Fatal("chromium_ech missing")
	}
	if _, ok := out["selfcheck"]; !ok {
		t.Fatal("selfcheck missing")
	}
	if _, ok := out["pool"]; !ok {
		t.Fatal("pool missing")
	}
}

func TestRunGracefulShutdown(t *testing.T) {
	port := freePort(t)
	srv := New(&config.Config{Host: "127.0.0.1", Port: port})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()

	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	deadline := time.Now().Add(3 * time.Second)
	up := false
	for time.Now().Before(deadline) {
		resp, err := http.Get(base + "/health")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				up = true
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !up {
		t.Fatal("server did not come up")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after ctx cancel")
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func TestAdminSelfcheckMetaEch(t *testing.T) {
	ech.ClearMeta()
	t.Cleanup(ech.ClearMeta)
	cfg := baseCfg()
	cfg.AdminToken = "admin-tok"
	ts, _ := newTS(t, cfg)

	listA := []byte{0, 6, 1, 2, 0, 2, 3, 4} // valid ECHConfigList, fits exactly
	b64A := base64.StdEncoding.EncodeToString(listA)

	post := func(payload map[string]any) int {
		body, _ := json.Marshal(payload)
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/admin/selfcheck", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer admin-tok")
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	// rotated with a valid config: learned override installed, generation bumped
	if code := post(map[string]any{"source": "meta-probe", "ok": true,
		"metaEch": map[string]any{"state": "rotated", "echConfig": b64A}}); code != 200 {
		t.Fatalf("rotated POST = %d, want 200", code)
	}
	if cfgList, state := ech.MetaOverride(); state != ech.MetaLearned || string(cfgList) != string(listA) {
		t.Fatalf("override after rotated = %d %v, want learned %v", state, cfgList, listA)
	}
	learnedTag := ech.MetaCacheTag()

	// the plain selfcheck part rode along in the same POST
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/admin/selfcheck", nil)
	req.Header.Set("Authorization", "Bearer admin-tok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var reports []map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&reports)
	resp.Body.Close()
	if len(reports) != 1 {
		t.Fatalf("selfcheck reports = %d, want 1 (metaEch must coexist)", len(reports))
	}

	// ok with a byte-identical verified: renews the learned key, no generation bump
	if code := post(map[string]any{"source": "meta-probe", "ok": true,
		"metaEch": map[string]any{"state": "ok", "verified": b64A}}); code != 200 {
		t.Fatalf("ok/verified POST = %d, want 200", code)
	}
	if _, state := ech.MetaOverride(); state != ech.MetaLearned {
		t.Fatalf("state after verified ok = %d, want learned (renewed, not seed)", state)
	}
	if ech.MetaCacheTag() != learnedTag {
		t.Fatal("renewal with identical bytes must not bump the generation")
	}

	// broken: suspension, injection stops
	if code := post(map[string]any{"source": "meta-probe", "ok": true,
		"metaEch": map[string]any{"state": "broken", "reason": "edge rejects"}}); code != 200 {
		t.Fatalf("broken POST = %d, want 200", code)
	}
	if _, state := ech.MetaOverride(); state != ech.MetaSuspended {
		t.Fatalf("state after broken = %d, want suspended", state)
	}

	// ok without verified: clears the override back to the seed
	if code := post(map[string]any{"source": "meta-probe", "ok": true,
		"metaEch": map[string]any{"state": "ok"}}); code != 200 {
		t.Fatalf("ok POST = %d, want 200", code)
	}
	if _, state := ech.MetaOverride(); state != ech.MetaSeed {
		t.Fatalf("state after ok = %d, want seed", state)
	}

	// rotated with invalid base64: 400 and the prior learned state kept
	// (matches refer: a malformed report must not migrate state)
	if code := post(map[string]any{"source": "meta-probe", "ok": true,
		"metaEch": map[string]any{"state": "rotated", "echConfig": b64A}}); code != 200 {
		t.Fatalf("rotated POST (setup) = %d, want 200", code)
	}
	if code := post(map[string]any{"source": "meta-probe", "ok": true,
		"metaEch": map[string]any{"state": "rotated", "echConfig": "!!not-base64!!"}}); code != 400 {
		t.Fatalf("invalid rotated POST = %d, want 400", code)
	}
	if cfgList, state := ech.MetaOverride(); state != ech.MetaLearned || string(cfgList) != string(listA) {
		t.Fatalf("state after invalid rotated = %d %v, want learned %v (kept, not cleared)",
			state, cfgList, listA)
	}

	// unknown state: 400, state untouched
	if code := post(map[string]any{"source": "meta-probe", "ok": true,
		"metaEch": map[string]any{"state": "rotated", "echConfig": b64A}}); code != 200 {
		t.Fatalf("rotated POST (setup 2) = %d, want 200", code)
	}
	if code := post(map[string]any{"source": "meta-probe", "ok": true,
		"metaEch": map[string]any{"state": "wat"}}); code != 400 {
		t.Fatalf("unknown state POST = %d, want 400", code)
	}
	if _, state := ech.MetaOverride(); state != ech.MetaLearned {
		t.Fatalf("state after unknown state = %d, want learned (untouched)", state)
	}
}
