package ecs

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jnuse/cfdoh/internal/config"
)

func TestDomainSetMatchSemantics(t *testing.T) {
	set := parseDomainList([]byte("example.com\ntaobao.com\n"))
	if set == nil {
		t.Fatal("expected a parsed set")
	}
	domains.Store(set)
	t.Cleanup(resetDomains)

	cases := []struct {
		name string
		want bool
	}{
		{"example.com", true},           // the domain itself
		{"www.example.com", true},       // a subdomain
		{"a.b.example.com.", true},      // deep subdomain, trailing dot
		{"WWW.TAOBAO.COM", true},        // case-insensitive
		{"notexample.com", false},       // dot boundary: not a suffix hit
		{"example.com.evil.net", false}, // the listed name must be an ancestor
		{"example.org", false},
		{"com", false}, // the public suffix alone is not listed
	}
	for _, c := range cases {
		if got := MatchDynamic(c.name); got != c.want {
			t.Errorf("MatchDynamic(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestParseDomainListDnsmasqShape(t *testing.T) {
	// dnsmasq-china-list lines are server=/domain/ directives; comments and
	// garbage must be skipped, not stored.
	body := []byte(strings.Join([]string{
		"# comment",
		"",
		"server=/baidu.com/",
		"server=/jd.com/",
		"plain.qq.com",
		"not a domain",
		"???",
	}, "\n"))
	set := parseDomainList(body)
	if set == nil {
		t.Fatal("expected a parsed set")
	}
	for _, want := range []string{"baidu.com", "jd.com", "plain.qq.com"} {
		if _, ok := set.names[want]; !ok {
			t.Errorf("entry %q missing from the parsed set", want)
		}
	}
	if got := len(set.names); got != 3 {
		t.Errorf("parsed %d entries, want 3 (garbage skipped)", got)
	}
	if parseDomainList([]byte("# only comments\n\n")) != nil {
		t.Error("an all-garbage body must parse to nil (kept-out-of-table)")
	}
}

func TestShouldUseDynamicTable(t *testing.T) {
	resetDomains()
	t.Cleanup(resetDomains)
	cfg := &config.Config{EcsMode: "rules", EcsDomains: []string{".cn"}}

	if ShouldUse(queryPacket(1, "www.example.com"), cfg, false, false) {
		t.Fatal("no dynamic table, non-.cn name must not attach ECS")
	}
	if n := SetDomainList([]byte("example.com")); n != 1 {
		t.Fatalf("SetDomainList = %d entries, want 1", n)
	}
	if !ShouldUse(queryPacket(1, "www.example.com"), cfg, false, false) {
		t.Fatal("dynamic table hit must attach ECS in rules mode")
	}
	if ShouldUse(queryPacket(1, "www.other.net"), cfg, false, false) {
		t.Fatal("dynamic miss, static miss must not attach ECS")
	}
	// off/always and the rule override stay untouched by the table.
	off := &config.Config{EcsMode: "off"}
	if ShouldUse(queryPacket(1, "www.example.com"), off, false, false) {
		t.Fatal("off mode must never attach")
	}
	always := &config.Config{EcsMode: "always"}
	if !ShouldUse(queryPacket(1, "www.other.net"), always, false, false) {
		t.Fatal("always mode must always attach")
	}
	if ShouldUse(queryPacket(1, "www.example.com"), cfg, false, true) {
		t.Fatal("present override (false) wins over a dynamic hit")
	}
}

func TestLoadDomainsKeepsOldTableOnFailure(t *testing.T) {
	resetDomains()
	t.Cleanup(resetDomains)
	cfg := &config.Config{UpstreamTimeoutMs: 500}

	if _, err := LoadDomains(context.Background(), "http://plain.example/list", cfg); err == nil {
		t.Fatal("non-https URL must be rejected")
	}
	if DomainCount() != 0 {
		t.Fatal("a rejected load must not install anything")
	}

	// httptest TLS servers are self-signed; trust them for the duration.
	oldTransport := domainsClient.Transport
	domainsClient.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	t.Cleanup(func() { domainsClient.Transport = oldTransport })

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			_, _ = w.Write([]byte("server=/first.com/\n"))
		case "/500":
			w.WriteHeader(http.StatusInternalServerError)
		case "/empty":
			_, _ = w.Write([]byte("# nothing usable\n"))
		}
	}))
	defer srv.Close()

	if n, err := LoadDomains(context.Background(), srv.URL+"/ok", cfg); err != nil || n != 1 {
		t.Fatalf("good load = (%d, %v), want (1, nil)", n, err)
	}
	if !MatchDynamic("a.first.com") {
		t.Fatal("good load must install the table")
	}
	for _, path := range []string{"/500", "/empty"} {
		if _, err := LoadDomains(context.Background(), srv.URL+path, cfg); err == nil {
			t.Fatalf("%s must fail", path)
		}
		if !MatchDynamic("a.first.com") {
			t.Fatalf("a failed load (%s) must keep the previous table", path)
		}
	}
}

// BenchmarkDomainSetMatch pins the hot-path cost at chnlist scale: ~80k
// entries must stay a few map lookups, not a linear scan.
func BenchmarkDomainSetMatch(b *testing.B) {
	var sb strings.Builder
	for i := 0; i < 80000; i++ {
		sb.WriteString("server=/site")
		sb.WriteString(itoa(i))
		sb.WriteString(".cn/\n")
	}
	if n := SetDomainList([]byte(sb.String())); n != 80000 {
		b.Fatalf("installed %d entries, want 80000", n)
	}
	b.Cleanup(resetDomains)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !MatchDynamic("deep.www.site12345.cn") {
			b.Fatal("expected hit")
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[pos:])
}
