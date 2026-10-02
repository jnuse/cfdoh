package rules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jnuse/cfdoh/internal/config"
	"github.com/jnuse/cfdoh/internal/wire"
)

func queryPacket(name string, qtype uint16) *wire.Packet {
	return &wire.Packet{
		Header:    wire.Header{ID: 1, Flags: 0x0100},
		Questions: []wire.Question{{Name: name, Type: qtype, Class: wire.ClassIN}},
	}
}

func aRecord(name string, ttl uint32, ip string) wire.Record {
	addr, _ := wire.ParseIPv4(ip)
	return wire.Record{Name: name, Type: wire.TypeA, Class: wire.ClassIN, TTL: ttl, RData: wire.A{IP: addr}}
}

func aaaaRecord(name string, ttl uint32, ip string) wire.Record {
	addr, _ := wire.ParseIPv6(ip)
	return wire.Record{Name: name, Type: wire.TypeAAAA, Class: wire.ClassIN, TTL: ttl, RData: wire.AAAA{IP: addr}}
}

func cnameRecord(name string, ttl uint32, target string) wire.Record {
	return wire.Record{Name: name, Type: wire.TypeCNAME, Class: wire.ClassIN, TTL: ttl, RData: wire.Name{Name: target}}
}

func httpsRecord(name string, ttl uint32, params ...wire.SvcParam) wire.Record {
	return wire.Record{Name: name, Type: wire.TypeHTTPS, Class: wire.ClassIN, TTL: ttl,
		RData: wire.SVCB{Priority: 1, Target: ".", Params: params}}
}

func responseOf(q *wire.Packet, answers ...wire.Record) *wire.Packet {
	return &wire.Packet{Header: wire.Header{ID: q.Header.ID, Flags: 0x8180}, Questions: q.Questions, Answers: answers}
}

func mustParse(t *testing.T, data string) *RuleSet {
	t.Helper()
	rs, err := Parse([]byte(data))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return rs
}

func TestParseThreeShapes(t *testing.T) {
	arrayForm := mustParse(t, `[{"match":{"domain_exact":["example.com"]},"action":"block"}]`)
	wrapped := mustParse(t, `{"rules":[{"match":{"domain_exact":["example.com"]},"action":"block"}]}`)
	if len(arrayForm.Rules) != 1 || len(wrapped.Rules) != 1 {
		t.Fatalf("array=%d wrapped=%d", len(arrayForm.Rules), len(wrapped.Rules))
	}
	if !arrayForm.ShouldBlock(queryPacket("example.com", wire.TypeA)) {
		t.Fatal("array form block failed")
	}
	if !wrapped.ShouldBlock(queryPacket("example.com", wire.TypeA)) {
		t.Fatal("wrapped form block failed")
	}

	hostMap := mustParse(t, `{"*.example.com":{"ipv4":["203.0.113.10","203.0.113.10","bad"],"ipv6":["2001:db8::10"]}}`)
	if len(hostMap.Rules) != 2 {
		t.Fatalf("host-map rules = %d, want 2 (dedup + invalid filtered)", len(hostMap.Rules))
	}
	resp := responseOf(queryPacket("sub.example.com", wire.TypeA), aRecord("sub.example.com", 60, "192.0.2.1"))
	out := hostMap.Apply(queryPacket("sub.example.com", wire.TypeA), resp)
	if len(out.Answers) != 1 || out.Answers[0].Type != wire.TypeA {
		t.Fatalf("host-map ipv4 rewrite failed: %+v", out.Answers)
	}
	if got := wire.IPv4String(out.Answers[0].RData.(wire.A).IP); got != "203.0.113.10" {
		t.Fatalf("rewritten address = %s", got)
	}
	resp6 := responseOf(queryPacket("sub.example.com", wire.TypeAAAA), aaaaRecord("sub.example.com", 60, "2001:db8::1"))
	out6 := hostMap.Apply(queryPacket("sub.example.com", wire.TypeAAAA), resp6)
	if got := wire.IPv6String(out6.Answers[0].RData.(wire.AAAA).IP); got != "2001:0db8:0000:0000:0000:0000:0000:0010" {
		t.Fatalf("rewritten v6 = %s", got)
	}
}

func TestParseHostMapExactVsWildcard(t *testing.T) {
	rs := mustParse(t, `{"example.com":{"ipv4":["203.0.113.1"]},"*.wild.com":{"ipv4":["203.0.113.2"]}}`)
	// exact form only matches the domain itself
	resp := responseOf(queryPacket("sub.example.com", wire.TypeA), aRecord("sub.example.com", 60, "192.0.2.1"))
	if out := rs.Apply(queryPacket("sub.example.com", wire.TypeA), resp); out != resp {
		t.Fatal("exact host-map matched a subdomain")
	}
	// wildcard form matches subdomains
	resp2 := responseOf(queryPacket("a.wild.com", wire.TypeA), aRecord("a.wild.com", 60, "192.0.2.1"))
	out2 := rs.Apply(queryPacket("a.wild.com", wire.TypeA), resp2)
	if got := wire.IPv4String(out2.Answers[0].RData.(wire.A).IP); got != "203.0.113.2" {
		t.Fatalf("wildcard rewrite = %s", got)
	}
}

func TestParseRejectsInvalidJSON(t *testing.T) {
	if _, err := Parse([]byte(`{not json`)); err == nil {
		t.Fatal("invalid JSON accepted")
	}
	if _, err := Parse([]byte(``)); err == nil {
		t.Fatal("empty payload accepted")
	}
	if _, err := Parse([]byte(`"text"`)); err == nil {
		t.Fatal("scalar payload accepted")
	}
}

func TestParseCapsAndSkips(t *testing.T) {
	items := make([]string, 1200)
	for i := range items {
		items[i] = `{"action":"passthrough"}`
	}
	rs := mustParse(t, "["+strings.Join(items, ",")+"]")
	if len(rs.Rules) != maxRules {
		t.Fatalf("rules = %d, want cap %d", len(rs.Rules), maxRules)
	}
	rs2 := mustParse(t, `[1,"x",null,{"action":"block"}]`)
	if len(rs2.Rules) != 1 {
		t.Fatalf("non-object items skipped = %d", len(rs2.Rules))
	}
}

func TestShouldBlockConditions(t *testing.T) {
	rs := mustParse(t, `[
		{"match":{"domain_suffix":["ads.example"],"qtype":[1,28]},"action":"block"},
		{"match":{"domain_exact":["blocked.example.com"],"response_ip_cidr":["10.0.0.0/8"]},"action":{"block":true}},
		{"match":{"domain_exact":["never.example.com"]},"action":{"block":true}}
	]`)
	if !rs.ShouldBlock(queryPacket("ads.example", wire.TypeA)) {
		t.Fatal("suffix+qtype block failed")
	}
	if rs.ShouldBlock(queryPacket("ads.example", wire.TypeHTTPS)) {
		t.Fatal("qtype condition ignored")
	}
	if rs.ShouldBlock(queryPacket("blocked.example.com", wire.TypeA)) {
		t.Fatal("response_ip_cidr rule matched without a response")
	}
	if rs.ShouldBlock(queryPacket("clean.example.com", wire.TypeA)) {
		t.Fatal("unrelated domain blocked")
	}
}

func TestEcsOverride(t *testing.T) {
	rs := mustParse(t, `[
		{"match":{"domain_suffix":["a.example"]},"action":{"disable_ecs":true}},
		{"match":{"domain_suffix":["b.example"]},"action":"enable-ecs"}
	]`)
	if value, present := rs.EcsOverride(queryPacket("x.a.example", wire.TypeA)); !present || value {
		t.Fatalf("a.example override = %v/%v", value, present)
	}
	if value, present := rs.EcsOverride(queryPacket("x.b.example", wire.TypeA)); !present || !value {
		t.Fatalf("b.example override = %v/%v", value, present)
	}
	if _, present := rs.EcsOverride(queryPacket("x.c.example", wire.TypeA)); present {
		t.Fatal("no override expected")
	}
}

func TestApplyReplaceInheritsTTLAndOwner(t *testing.T) {
	rs := mustParse(t, `[
		{"match":{"domain_suffix":["example.com"]},"action":{"type":"replace-a","replace_a":["203.0.113.7","203.0.113.8"]}}
	]`)
	q := queryPacket("sub.example.com", wire.TypeA)
	resp := responseOf(q,
		cnameRecord("sub.example.com", 300, "edge.example.net"),
		aRecord("sub.example.com", 120, "192.0.2.1"),
		aRecord("sub.example.com", 90, "192.0.2.2"),
	)
	out := rs.Apply(q, resp)
	if len(out.Answers) != 3 {
		t.Fatalf("answers = %d", len(out.Answers))
	}
	if out.Answers[0].Type != wire.TypeCNAME {
		t.Fatal("cname must keep its position ahead of addresses")
	}
	var as []wire.Record
	for _, r := range out.Answers {
		if r.Type == wire.TypeA {
			as = append(as, r)
		}
	}
	if len(as) != 2 {
		t.Fatalf("replaced A records = %d", len(as))
	}
	for _, r := range as {
		if r.TTL != 90 || r.Name != "sub.example.com" {
			t.Fatalf("inherited ttl/owner wrong: %d/%s", r.TTL, r.Name)
		}
	}
	if got := wire.IPv4String(as[0].RData.(wire.A).IP); got != "203.0.113.7" {
		t.Fatalf("first replaced = %s", got)
	}
}

func TestApplyReplaceSkipsAbsentType(t *testing.T) {
	rs := mustParse(t, `[{"match":{"domain_suffix":["example.com"]},"action":{"replace_a":["203.0.113.7"]}}]`)
	q := queryPacket("sub.example.com", wire.TypeA)
	resp := responseOf(q, cnameRecord("sub.example.com", 60, "edge.example.net"))
	if out := rs.Apply(q, resp); out != resp {
		t.Fatal("replace must not create records of an absent type")
	}
}

func TestApplyValuesFallback(t *testing.T) {
	rs := mustParse(t, `[{"match":{"domain_suffix":["example.com"]},"action":{"type":"replace-a","values":["203.0.113.9"]}}]`)
	q := queryPacket("sub.example.com", wire.TypeA)
	out := rs.Apply(q, responseOf(q, aRecord("sub.example.com", 60, "192.0.2.1")))
	if got := wire.IPv4String(out.Answers[0].RData.(wire.A).IP); got != "203.0.113.9" {
		t.Fatalf("values fallback failed: %s", got)
	}
}

func TestApplyReplaceCNAME(t *testing.T) {
	rs := mustParse(t, `[{"match":{"domain_suffix":["example.com"]},"action":{"replace_cname":"fixed.example.net"}}]`)
	q := queryPacket("sub.example.com", wire.TypeA)
	out := rs.Apply(q, responseOf(q,
		cnameRecord("sub.example.com", 77, "old.example.net"),
		aRecord("edge.example.net", 60, "192.0.2.1"),
	))
	if got := out.Answers[0].RData.(wire.Name).Name; got != "fixed.example.net" {
		t.Fatalf("cname = %s", got)
	}
	if out.Answers[0].TTL != 77 || out.Answers[0].Name != "sub.example.com" {
		t.Fatal("cname ttl/owner not inherited")
	}
}

func TestApplyRewriteHTTPS(t *testing.T) {
	rs := mustParse(t, `[{"match":{"domain_suffix":["example.com"]},"action":{"rewrite_https":{"ipv4hint":["203.0.113.3","203.0.113.4"],"ipv6hint":["2001:db8::1"]}}}]`)
	q := queryPacket("sub.example.com", wire.TypeHTTPS)
	existing := wire.SvcParam{Key: wire.ParamIPv4Hint, Value: []byte{1, 2, 3, 4}}
	resp := responseOf(q, httpsRecord("sub.example.com", 60, existing))
	out := rs.Apply(q, resp)
	hint4 := wire.SvcParam{Key: wire.ParamIPv4Hint}
	for _, p := range out.Answers[0].RData.(wire.SVCB).Params {
		if p.Key == wire.ParamIPv4Hint {
			hint4 = p
		}
	}
	if len(hint4.Value) != 8 || hint4.Value[0] != 203 {
		t.Fatalf("ipv4hint = %v", hint4.Value)
	}
	_, ipv4, ipv6, _ := wire.DescribeHTTPS(&out.Answers[0])
	if len(ipv4) != 2 || ipv4[0] != "203.0.113.3" {
		t.Fatalf("describe ipv4 = %v", ipv4)
	}
	if len(ipv6) != 1 || ipv6[0] != "2001:0db8:0000:0000:0000:0000:0000:0001" {
		t.Fatalf("describe ipv6 = %v", ipv6)
	}
}

func TestApplyResponseIPCIDR(t *testing.T) {
	rs := mustParse(t, `[
		{"match":{"domain_suffix":["example.com"],"response_ip_cidr":["192.0.2.0/25","2001:db8:abcd::/48"]},"action":{"replace_a":["203.0.113.7"]}}
	]`)
	q := queryPacket("sub.example.com", wire.TypeA)
	// 192.0.2.200 is outside /25, 192.0.2.10 inside
	out := rs.Apply(q, responseOf(q, aRecord("sub.example.com", 60, "192.0.2.200")))
	if out.Answers[0].RData.(wire.A).IP != [4]byte{192, 0, 2, 200} {
		t.Fatal("outside cidr must not rewrite")
	}
	out = rs.Apply(q, responseOf(q, aRecord("sub.example.com", 60, "192.0.2.10")))
	if got := wire.IPv4String(out.Answers[0].RData.(wire.A).IP); got != "203.0.113.7" {
		t.Fatalf("inside cidr rewrite = %s", got)
	}
	// v6 cidr matches a AAAA answer (rule has both families)
	resp6 := responseOf(q, aaaaRecord("sub.example.com", 60, "2001:db8:abce::1"))
	out6 := rs.Apply(q, resp6)
	if out6 != resp6 {
		t.Fatal("v6 outside /48 must not rewrite")
	}
	// v6 cidr gates the rule; the replace-a action itself no-ops without A records
	resp6b := responseOf(q, aaaaRecord("sub.example.com", 60, "2001:db8:abcd:1::1"))
	if out6b := rs.Apply(q, resp6b); out6b != resp6b {
		t.Fatal("replace-a must no-op on A-less responses")
	}
	rs6 := mustParse(t, `[{"match":{"response_ip_cidr":["2001:db8:abcd::/48"]},"action":{"replace_aaaa":["2001:db8::99"]}}]`)
	rewritten := rs6.Apply(q, resp6b)
	if got := wire.IPv6String(rewritten.Answers[0].RData.(wire.AAAA).IP); got != "2001:0db8:0000:0000:0000:0000:0000:0099" {
		t.Fatalf("v6 inside /48 rewrite = %s", got)
	}
}

func TestApplyRunsEveryMatchingRuleInOrder(t *testing.T) {
	rs := mustParse(t, `[
		{"match":{"domain_suffix":["example.com"]},"action":{"replace_a":["203.0.113.1"]}},
		{"match":{"qtype":1},"action":{"replace_a":["203.0.113.2"]}}
	]`)
	q := queryPacket("sub.example.com", wire.TypeA)
	out := rs.Apply(q, responseOf(q, aRecord("sub.example.com", 60, "192.0.2.1")))
	if got := wire.IPv4String(out.Answers[0].RData.(wire.A).IP); got != "203.0.113.2" {
		t.Fatalf("later rule must win on same field: %s", got)
	}
}

func testConfig(rulesJSON, rulesURL string) *config.Config {
	return &config.Config{
		RulesJSON:            rulesJSON,
		RulesURL:             rulesURL,
		DynamicRuleHosts:     []string{"paste.rs", "raw.githubusercontent.com"},
		DynamicRulesMaxBytes: 4096,
		UpstreamTimeoutMs:    2500,
	}
}

func TestValidateDynamicURL(t *testing.T) {
	cfg := testConfig("", "")
	cases := []struct {
		raw string
		ok  bool
	}{
		{"https://paste.rs/abc", true},
		{"https://Raw.GitHubusercontent.com/x/y", true},
		{"http://paste.rs/abc", false},
		{"https://evil.example.com/abc", false},
		{"https://user:pass@paste.rs/abc", false},
		{"https://paste.rs:8443/abc", false},
		{"https://paste.rs:443/abc", true},
		{"https://paste.rs/abc?x=1", true},
		{"https://paste.rs/abc#frag", false},
		{"https://paste.rs/" + strings.Repeat("a", 2100), false},
	}
	for _, tc := range cases {
		if _, err := ValidateDynamicURL(tc.raw, cfg); (err == nil) != tc.ok {
			t.Fatalf("ValidateDynamicURL(%q) err = %v, want ok=%v", tc.raw, err, tc.ok)
		}
	}
}

func TestLoadEmbeddedAndRejectedRemote(t *testing.T) {
	embedded := `[{"match":{"domain_exact":["embedded.example"]},"action":"block"}]`
	cfg := testConfig(embedded, "")
	rs, err := Load(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !rs.ShouldBlock(queryPacket("embedded.example", wire.TypeA)) {
		t.Fatal("embedded rules not loaded")
	}

	cfg = testConfig(embedded, "http://paste.rs/rules") // non-https: embedded
	rs, _ = Load(context.Background(), cfg)
	if !rs.ShouldBlock(queryPacket("embedded.example", wire.TypeA)) {
		t.Fatal("non-https URL must fall back to embedded")
	}

	cfg = testConfig(embedded, "https://evil.example.com/rules") // host not whitelisted
	rs, _ = Load(context.Background(), cfg)
	if !rs.ShouldBlock(queryPacket("embedded.example", wire.TypeA)) {
		t.Fatal("non-whitelisted host must fall back to embedded")
	}
}

func TestFetchRemoteDefenseChain(t *testing.T) {
	remote := `[{"match":{"domain_exact":["remote.example"]},"action":"block"}]`

	t.Run("success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(remote))
		}))
		defer srv.Close()
		rs, ok := fetchRemote(context.Background(), srv.URL, testConfig("", ""))
		if !ok || !rs.ShouldBlock(queryPacket("remote.example", wire.TypeA)) {
			t.Fatal("remote rules not loaded")
		}
	})

	t.Run("http error status falls back", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "boom", http.StatusInternalServerError)
		}))
		defer srv.Close()
		if _, ok := fetchRemote(context.Background(), srv.URL, testConfig("", "")); ok {
			t.Fatal("5xx must be rejected")
		}
	})

	t.Run("redirect falls back", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
		}))
		defer srv.Close()
		if _, ok := fetchRemote(context.Background(), srv.URL, testConfig("", "")); ok {
			t.Fatal("redirect must be rejected")
		}
	})

	t.Run("oversized body falls back", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("[" + strings.Repeat(`{"action":"passthrough"},`, 400) + `"x"]`))
		}))
		defer srv.Close()
		if _, ok := fetchRemote(context.Background(), srv.URL, testConfig("", "")); ok {
			t.Fatal("oversized body must be rejected")
		}
	})

	t.Run("invalid json falls back", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("not json at all"))
		}))
		defer srv.Close()
		if _, ok := fetchRemote(context.Background(), srv.URL, testConfig("", "")); ok {
			t.Fatal("invalid json must be rejected")
		}
	})

	t.Run("zero rules from unexpected shape falls back", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"error":"quota exceeded"}`))
		}))
		defer srv.Close()
		if _, ok := fetchRemote(context.Background(), srv.URL, testConfig("", "")); ok {
			t.Fatal("error object yielding zero rules must be rejected")
		}
	})

	t.Run("trivially empty remote accepted", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("[]"))
		}))
		defer srv.Close()
		rs, ok := fetchRemote(context.Background(), srv.URL, testConfig("", ""))
		if !ok || len(rs.Rules) != 0 {
			t.Fatal("trivially empty remote must be accepted as an empty set")
		}
	})
}

func TestParseWrongTypedFieldsTolerated(t *testing.T) {
	rs := mustParse(t, `[
		{"match":{"domain_exact":"example.com","qtype":"1"},"action":{"replace_a":"203.0.113.1"}},
		{"match":{"domain_exact":["example.com"]},"action":42}
	]`)
	q := queryPacket("example.com", wire.TypeA)
	if rs.ShouldBlock(q) {
		t.Fatal("malformed actions must not block")
	}
	resp := responseOf(q, aRecord("example.com", 60, "192.0.2.1"))
	if out := rs.Apply(q, resp); out != resp {
		t.Fatal("wrong-typed fields must behave as absent")
	}
}
