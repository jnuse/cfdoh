package rewrite

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"testing"

	"github.com/jnuse/cfdoh/internal/cfrange"
	"github.com/jnuse/cfdoh/internal/config"
	"github.com/jnuse/cfdoh/internal/pool"
	"github.com/jnuse/cfdoh/internal/wire"
)

func testRanges() *cfrange.Ranges {
	return &cfrange.Ranges{
		V4: []netip.Prefix{netip.MustParsePrefix("104.16.0.0/12"), netip.MustParsePrefix("172.64.0.0/13")},
		V6: []netip.Prefix{netip.MustParsePrefix("2606:4700::/32")},
	}
}

// v6 renders an IPv6 literal the way wire does: eight full hex groups.
func v6(s string) string {
	ip, err := wire.ParseIPv6(s)
	if err != nil {
		panic(err)
	}
	return wire.IPv6String(ip)
}

func aRec(name, ip string, ttl uint32) wire.Record {
	v, err := wire.ParseIPv4(ip)
	if err != nil {
		panic(err)
	}
	return wire.Record{Name: name, Type: wire.TypeA, Class: wire.ClassIN, TTL: ttl, RData: wire.A{IP: v}}
}

func aaaaRec(name, ip string, ttl uint32) wire.Record {
	v, err := wire.ParseIPv6(ip)
	if err != nil {
		panic(err)
	}
	return wire.Record{Name: name, Type: wire.TypeAAAA, Class: wire.ClassIN, TTL: ttl, RData: wire.AAAA{IP: v}}
}

func cnameRec(name, target string, ttl uint32) wire.Record {
	return wire.Record{Name: name, Type: wire.TypeCNAME, Class: wire.ClassIN, TTL: ttl, RData: wire.Name{Name: target}}
}

func httpsRec(name string, v4, v6 []string, ttl uint32) wire.Record {
	var params []wire.SvcParam
	if len(v4) > 0 {
		params = append(params, wire.SvcParam{Key: wire.ParamIPv4Hint, Value: packHints(v4, 4)})
	}
	if len(v6) > 0 {
		params = append(params, wire.SvcParam{Key: wire.ParamIPv6Hint, Value: packHints(v6, 16)})
	}
	return wire.Record{Name: name, Type: wire.TypeHTTPS, Class: wire.ClassIN, TTL: ttl,
		RData: wire.SVCB{Priority: 1, Target: ".", Params: params}}
}

func query(name string, qtype uint16) *wire.Packet {
	return &wire.Packet{Header: wire.Header{ID: 1, Flags: 0x0100},
		Questions: []wire.Question{{Name: name, Type: qtype, Class: wire.ClassIN}}}
}

func answerIPs(resp *wire.Packet, rtype uint16) []string {
	var out []string
	for _, r := range resp.Answers {
		switch rd := r.RData.(type) {
		case wire.A:
			if r.Type == rtype {
				out = append(out, wire.IPv4String(rd.IP))
			}
		case wire.AAAA:
			if r.Type == rtype {
				out = append(out, wire.IPv6String(rd.IP))
			}
		}
	}
	return out
}

// validECHList is structurally valid: declared length 8 == len-2 and the
// first ECHConfig (length 4) fits exactly.
func validECHList() []byte {
	return []byte{0x00, 0x08, 0xfe, 0x0d, 0x00, 0x04, 0x11, 0x22, 0x33, 0x44}
}

// fakeDoH answers every A question with answerIP and leaves AAAA questions
// empty, mimicking an upstream DoH server.
func fakeDoH(t *testing.T, answerIP string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		pkt, err := wire.Parse(body)
		if err != nil || len(pkt.Questions) == 0 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		resp := &wire.Packet{Header: wire.Header{ID: pkt.Header.ID, Flags: 0x8180}}
		resp.Questions = pkt.Questions
		if pkt.Questions[0].Type == wire.TypeA && answerIP != "" {
			resp.Answers = append(resp.Answers, aRec(pkt.Questions[0].Name, answerIP, 60))
		}
		out, err := resp.Encode()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(out)
	}))
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

func TestUsesCloudflare(t *testing.T) {
	ranges := testRanges()
	tests := []struct {
		name string
		resp *wire.Packet
		want bool
	}{
		{
			name: "a record in range",
			resp: &wire.Packet{Answers: []wire.Record{aRec("example.com", "104.16.132.229", 60)}},
			want: true,
		},
		{
			name: "aaaa record in range",
			resp: &wire.Packet{Answers: []wire.Record{aaaaRec("example.com", "2606:4700:4700::1111", 60)}},
			want: true,
		},
		{
			name: "no address in range",
			resp: &wire.Packet{Answers: []wire.Record{
				aRec("example.com", "93.184.216.34", 60),
				aaaaRec("example.com", "2001:db8::1", 60),
			}},
			want: false,
		},
		{
			name: "https ipv4hint in range",
			resp: &wire.Packet{Answers: []wire.Record{
				httpsRec("example.com", []string{"104.16.132.229"}, nil, 60),
			}},
			want: true,
		},
		{
			name: "https ipv6hint in range",
			resp: &wire.Packet{Answers: []wire.Record{
				httpsRec("example.com", nil, []string{"2606:4700:4700::1111"}, 60),
			}},
			want: true,
		},
		{
			name: "https hints outside range",
			resp: &wire.Packet{Answers: []wire.Record{
				httpsRec("example.com", []string{"93.184.216.34"}, []string{"2001:db8::1"}, 60),
			}},
			want: false,
		},
		{name: "nil response", resp: nil, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := UsesCloudflare(tt.resp, ranges); got != tt.want {
				t.Fatalf("UsesCloudflare = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOnCloudflare(t *testing.T) {
	ranges := testRanges()
	t.Run("range hit v4", func(t *testing.T) {
		ok, err := OnCloudflare(context.Background(), "example.com", ranges, nil, []string{"104.16.132.229"}, nil)
		if err != nil || !ok {
			t.Fatalf("got (%v, %v), want (true, nil)", ok, err)
		}
	})
	t.Run("range hit v6", func(t *testing.T) {
		ok, err := OnCloudflare(context.Background(), "example.com", ranges, nil, nil, []string{"2606:4700:4700::1111"})
		if err != nil || !ok {
			t.Fatalf("got (%v, %v), want (true, nil)", ok, err)
		}
	})
	t.Run("x domain probe resolves", func(t *testing.T) {
		server := fakeDoH(t, "104.16.132.229")
		defer server.Close()
		cfg := &config.Config{XDomains: []string{"x.com"}, Upstreams: []string{server.URL},
			UpstreamTimeoutMs: 2500, MaxDNSPacketSize: 65535}
		ok, err := OnCloudflare(context.Background(), "x.com", ranges, cfg, []string{"3.5.140.1"}, nil)
		if err != nil || !ok {
			t.Fatalf("got (%v, %v), want (true, nil)", ok, err)
		}
	})
	t.Run("x domain probe empty answer", func(t *testing.T) {
		server := fakeDoH(t, "")
		defer server.Close()
		cfg := &config.Config{XDomains: []string{"x.com"}, Upstreams: []string{server.URL},
			UpstreamTimeoutMs: 2500, MaxDNSPacketSize: 65535}
		ok, err := OnCloudflare(context.Background(), "x.com", ranges, cfg, nil, nil)
		if err != nil || ok {
			t.Fatalf("got (%v, %v), want (false, nil)", ok, err)
		}
	})
	t.Run("x domain nil ctx skips probe", func(t *testing.T) {
		cfg := &config.Config{XDomains: []string{"x.com"}}
		ok, err := OnCloudflare(nil, "x.com", ranges, cfg, nil, nil)
		if err != nil || ok {
			t.Fatalf("got (%v, %v), want (false, nil)", ok, err)
		}
	})
	t.Run("x domain probe failure propagates error", func(t *testing.T) {
		cfg := &config.Config{XDomains: []string{"x.com"},
			Upstreams: []string{"http://127.0.0.1:1/dns-query"},
			UpstreamTimeoutMs: 2500, MaxDNSPacketSize: 65535}
		ok, err := OnCloudflare(context.Background(), "x.com", ranges, cfg, nil, nil)
		if ok || err == nil {
			t.Fatalf("got (%v, %v), want (false, error)", ok, err)
		}
	})
	t.Run("meta domain hit", func(t *testing.T) {
		cfg := &config.Config{MetaDomains: []string{"facebook.com"}}
		ok, err := OnCloudflare(context.Background(), "www.facebook.com", ranges, cfg, []string{"157.240.1.35"}, nil)
		if err != nil || !ok {
			t.Fatalf("got (%v, %v), want (true, nil)", ok, err)
		}
	})
	t.Run("ech domain hit", func(t *testing.T) {
		cfg := &config.Config{EchDomains: []string{"ech.example.com"}}
		ok, err := OnCloudflare(context.Background(), "sub.ech.example.com", ranges, cfg, nil, nil)
		if err != nil || !ok {
			t.Fatalf("got (%v, %v), want (true, nil)", ok, err)
		}
	})
	t.Run("no match", func(t *testing.T) {
		ok, err := OnCloudflare(context.Background(), "example.org", ranges, &config.Config{}, []string{"93.184.216.34"}, nil)
		if err != nil || ok {
			t.Fatalf("got (%v, %v), want (false, nil)", ok, err)
		}
	})
}

func TestRewriteAddresses(t *testing.T) {
	ranges := testRanges()
	poolBoth := &pool.Pool{
		IPv4: []string{"104.17.1.1", "104.17.1.2", "104.17.1.3"},
		IPv6: []string{"2606:4700:1111::1", "2606:4700:1111::2"},
		Scope: "isp:chinanet",
	}

	cfAnswer := func() *wire.Packet {
		return &wire.Packet{
			Header: wire.Header{ID: 7, Flags: 0x8180},
			Questions: []wire.Question{{Name: "www.example.com", Type: wire.TypeA, Class: wire.ClassIN}},
			Answers: []wire.Record{
				aRec("www.example.com", "104.16.1.1", 60),
				aRec("www.example.com", "104.16.1.2", 120),
				aaaaRec("www.example.com", "2606:4700:4700::1111", 90),
				httpsRec("www.example.com", []string{"104.16.1.1"}, []string{"2606:4700:4700::1111"}, 60),
			},
		}
	}

	t.Run("rewrites records and hints in sync", func(t *testing.T) {
		cfg := &config.Config{CFRewriteEnabled: true}
		resp := RewriteAddresses(cfAnswer(), ranges, poolBoth, cfg)
		if got, want := answerIPs(resp, wire.TypeA), poolBoth.IPv4; !slices.Equal(got, want) {
			t.Fatalf("A = %v, want %v", got, want)
		}
		if got, want := answerIPs(resp, wire.TypeAAAA), []string{v6("2606:4700:1111::1"), v6("2606:4700:1111::2")}; !slices.Equal(got, want) {
			t.Fatalf("AAAA = %v, want %v", got, want)
		}
		if len(resp.Answers) != 3+2+1 {
			t.Fatalf("answer count = %d, want 6", len(resp.Answers))
		}
		for _, r := range resp.Answers {
			if r.Type == wire.TypeA && r.TTL != 60 {
				t.Fatalf("A TTL = %d, want family minimum 60", r.TTL)
			}
		}
		hints := 0
		for i := range resp.Answers {
			if resp.Answers[i].Type != wire.TypeHTTPS {
				continue
			}
			hints++
			_, ipv4, ipv6, echBytes := wire.DescribeHTTPS(&resp.Answers[i])
			if !slices.Equal(ipv4, poolBoth.IPv4) {
				t.Fatalf("ipv4hint = %v, want %v", ipv4, poolBoth.IPv4)
			}
			if !slices.Equal(ipv6, []string{v6("2606:4700:1111::1"), v6("2606:4700:1111::2")}) {
				t.Fatalf("ipv6hint = %v, want pool v6", ipv6)
			}
			if len(echBytes) != 0 {
				t.Fatalf("unexpected ech param on plain rewrite")
			}
		}
		if hints != 1 {
			t.Fatalf("HTTPS records = %d, want 1", hints)
		}
		// encode round trip: the rewritten packet must survive the codec
		encoded, err := resp.Encode()
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		parsed, err := wire.Parse(encoded)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if got := answerIPs(parsed, wire.TypeA); !slices.Equal(got, poolBoth.IPv4) {
			t.Fatalf("round-trip A = %v, want %v", got, poolBoth.IPv4)
		}
	})
	t.Run("caps family at six", func(t *testing.T) {
		big := &pool.Pool{IPv4: []string{"104.17.1.1", "104.17.1.2", "104.17.1.3", "104.17.1.4", "104.17.1.5", "104.17.1.6", "104.17.1.8"}}
		cfg := &config.Config{CFRewriteEnabled: true}
		resp := RewriteAddresses(cfAnswer(), ranges, big, cfg)
		if got := answerIPs(resp, wire.TypeA); len(got) != 6 || got[5] != "104.17.1.6" {
			t.Fatalf("A = %v, want first six pool addresses", got)
		}
	})
	t.Run("non cloudflare answer untouched", func(t *testing.T) {
		cfg := &config.Config{CFRewriteEnabled: true}
		original := &wire.Packet{Answers: []wire.Record{aRec("example.org", "93.184.216.34", 60)}}
		resp := RewriteAddresses(original, ranges, poolBoth, cfg)
		if got := answerIPs(resp, wire.TypeA); !slices.Equal(got, []string{"93.184.216.34"}) {
			t.Fatalf("A = %v, want untouched", got)
		}
	})
	t.Run("empty pool untouched", func(t *testing.T) {
		cfg := &config.Config{CFRewriteEnabled: true}
		resp := RewriteAddresses(cfAnswer(), ranges, &pool.Pool{}, cfg)
		if got := answerIPs(resp, wire.TypeA); !slices.Equal(got, []string{"104.16.1.1", "104.16.1.2"}) {
			t.Fatalf("A = %v, want untouched", got)
		}
	})
	t.Run("rewrite disabled untouched", func(t *testing.T) {
		cfg := &config.Config{CFRewriteEnabled: false}
		resp := RewriteAddresses(cfAnswer(), ranges, poolBoth, cfg)
		if got := answerIPs(resp, wire.TypeA); !slices.Equal(got, []string{"104.16.1.1", "104.16.1.2"}) {
			t.Fatalf("A = %v, want untouched", got)
		}
	})
	t.Run("cf drop aaaa removes aaaa", func(t *testing.T) {
		cfg := &config.Config{CFRewriteEnabled: true, CFDropAAAA: true}
		resp := RewriteAddresses(cfAnswer(), ranges, poolBoth, cfg)
		if got := answerIPs(resp, wire.TypeAAAA); len(got) != 0 {
			t.Fatalf("AAAA = %v, want none", got)
		}
		if got := answerIPs(resp, wire.TypeA); !slices.Equal(got, poolBoth.IPv4) {
			t.Fatalf("A = %v, want %v", got, poolBoth.IPv4)
		}
	})
	t.Run("v4-only pool keeps v6 verbatim", func(t *testing.T) {
		v4Only := &pool.Pool{IPv4: poolBoth.IPv4}
		cfg := &config.Config{CFRewriteEnabled: true}
		resp := RewriteAddresses(cfAnswer(), ranges, v4Only, cfg)
		if got := answerIPs(resp, wire.TypeAAAA); !slices.Equal(got, []string{v6("2606:4700:4700::1111")}) {
			t.Fatalf("AAAA = %v, want verbatim", got)
		}
		for i := range resp.Answers {
			if resp.Answers[i].Type != wire.TypeHTTPS {
				continue
			}
			_, _, ipv6, _ := wire.DescribeHTTPS(&resp.Answers[i])
			if !slices.Equal(ipv6, []string{v6("2606:4700:4700::1111")}) {
				t.Fatalf("ipv6hint = %v, want verbatim", ipv6)
			}
		}
	})
}

func TestRewriteX(t *testing.T) {
	loadRanges(t)
	cfg := &config.Config{XDomains: []string{"x.com", "twimg.com"}}
	p := &pool.Pool{IPv4: []string{"104.17.9.1", "104.17.9.2"}, IPv6: []string{"2606:4700:2222::1"}}

	t.Run("x domain on cloudflare rewrites", func(t *testing.T) {
		q := query("x.com", wire.TypeA)
		resp := &wire.Packet{Header: wire.Header{ID: 3, Flags: 0x8180}, Questions: q.Questions,
			Answers: []wire.Record{
				aRec("x.com", "104.16.1.1", 60),
				aaaaRec("x.com", "2606:4700:4700::1111", 60),
				httpsRec("x.com", []string{"104.16.1.1"}, []string{"2606:4700:4700::1111"}, 60),
			}}
		out := RewriteX(resp, q, p, cfg)
		if got, want := answerIPs(out, wire.TypeA), p.IPv4; !slices.Equal(got, want) {
			t.Fatalf("A = %v, want %v", got, want)
		}
		if got := answerIPs(out, wire.TypeAAAA); len(got) != 0 {
			t.Fatalf("AAAA = %v, want none", got)
		}
		for i := range out.Answers {
			if out.Answers[i].Type != wire.TypeHTTPS {
				continue
			}
			_, ipv4, ipv6, _ := wire.DescribeHTTPS(&out.Answers[i])
			if !slices.Equal(ipv4, p.IPv4) {
				t.Fatalf("ipv4hint = %v, want %v", ipv4, p.IPv4)
			}
			if len(ipv6) != 0 {
				t.Fatalf("ipv6hint = %v, want removed", ipv6)
			}
		}
	})
	t.Run("subdomain of x domain counts", func(t *testing.T) {
		q := query("pbs.twimg.com", wire.TypeA)
		resp := &wire.Packet{Questions: q.Questions, Answers: []wire.Record{aRec("pbs.twimg.com", "104.16.1.1", 60)}}
		out := RewriteX(resp, q, p, cfg)
		if got := answerIPs(out, wire.TypeA); !slices.Equal(got, p.IPv4) {
			t.Fatalf("A = %v, want %v", got, p.IPv4)
		}
	})
	t.Run("non x domain untouched", func(t *testing.T) {
		q := query("example.com", wire.TypeA)
		resp := &wire.Packet{Questions: q.Questions, Answers: []wire.Record{aRec("example.com", "104.16.1.1", 60)}}
		out := RewriteX(resp, q, p, cfg)
		if got := answerIPs(out, wire.TypeA); !slices.Equal(got, []string{"104.16.1.1"}) {
			t.Fatalf("A = %v, want untouched", got)
		}
	})
	t.Run("not on cloudflare untouched", func(t *testing.T) {
		q := query("x.com", wire.TypeA)
		resp := &wire.Packet{Questions: q.Questions, Answers: []wire.Record{aRec("x.com", "3.5.140.1", 60)}}
		out := RewriteX(resp, q, p, cfg)
		if got := answerIPs(out, wire.TypeA); !slices.Equal(got, []string{"3.5.140.1"}) {
			t.Fatalf("A = %v, want untouched", got)
		}
	})
	t.Run("empty pool untouched", func(t *testing.T) {
		q := query("x.com", wire.TypeA)
		resp := &wire.Packet{Questions: q.Questions, Answers: []wire.Record{aRec("x.com", "104.16.1.1", 60)}}
		out := RewriteX(resp, q, &pool.Pool{}, cfg)
		if got := answerIPs(out, wire.TypeA); !slices.Equal(got, []string{"104.16.1.1"}) {
			t.Fatalf("A = %v, want untouched", got)
		}
	})
}

func TestPinAddresses(t *testing.T) {
	ips := []string{"104.17.5.1", "104.17.5.2"}

	t.Run("pins query-name records and drops aaaa", func(t *testing.T) {
		q := query("site.example.com", wire.TypeA)
		resp := &wire.Packet{Questions: q.Questions, Answers: []wire.Record{
			aRec("site.example.com", "104.16.1.1", 60),
			aRec("site.example.com", "104.16.1.2", 30),
			aaaaRec("site.example.com", "2606:4700:4700::1111", 60),
			aRec("other.example.com", "104.16.9.9", 60),
		}}
		out := PinAddresses(resp, q, ips)
		// records of other owners ride along untouched after the pinned block
		if got, want := answerIPs(out, wire.TypeA), append(slices.Clone(ips), "104.16.9.9"); !slices.Equal(got, want) {
			t.Fatalf("A = %v, want %v", got, want)
		}
		if got := answerIPs(out, wire.TypeAAAA); len(got) != 0 {
			t.Fatalf("AAAA = %v, want none", got)
		}
		for _, r := range out.Answers {
			if r.Type == wire.TypeA && wire.CanonicalName(r.Name) == "site.example.com" && r.TTL != 30 {
				t.Fatalf("pinned TTL = %d, want family minimum 30", r.TTL)
			}
		}
	})
	t.Run("records of other owners preserved", func(t *testing.T) {
		q := query("site.example.com", wire.TypeA)
		resp := &wire.Packet{Questions: q.Questions, Answers: []wire.Record{
			aRec("site.example.com", "104.16.1.1", 60),
			cnameRec("alias.example.com", "site.example.com", 60),
			aRec("alias.example.com", "104.16.2.2", 60),
		}}
		out := PinAddresses(resp, q, ips)
		found := false
		for _, r := range out.Answers {
			if r.Type == wire.TypeA && wire.CanonicalName(r.Name) == "alias.example.com" {
				found = true
			}
		}
		if !found {
			t.Fatalf("chain-owned A record dropped")
		}
	})
	t.Run("no query-name a record untouched", func(t *testing.T) {
		q := query("site.example.com", wire.TypeA)
		resp := &wire.Packet{Questions: q.Questions, Answers: []wire.Record{
			cnameRec("site.example.com", "edge.example.net", 60),
		}}
		out := PinAddresses(resp, q, ips)
		if len(out.Answers) != 1 || out.Answers[0].Type != wire.TypeCNAME {
			t.Fatalf("answers = %v, want untouched CNAME", out.Answers)
		}
	})
	t.Run("empty ips untouched", func(t *testing.T) {
		q := query("site.example.com", wire.TypeA)
		resp := &wire.Packet{Questions: q.Questions, Answers: []wire.Record{aRec("site.example.com", "104.16.1.1", 60)}}
		out := PinAddresses(resp, q, nil)
		if got := answerIPs(out, wire.TypeA); !slices.Equal(got, []string{"104.16.1.1"}) {
			t.Fatalf("A = %v, want untouched", got)
		}
	})
}

func TestPinHTTPSHints(t *testing.T) {
	t.Run("replaces v4 hint and removes v6 hint", func(t *testing.T) {
		ips := []string{"104.17.5.1", "104.17.5.2"}
		resp := &wire.Packet{Answers: []wire.Record{
			httpsRec("site.example.com", []string{"104.16.1.1"}, []string{"2606:4700:4700::1111"}, 60),
		}}
		out := PinHTTPSHints(resp, ips)
		_, ipv4, ipv6, _ := wire.DescribeHTTPS(&out.Answers[0])
		if !slices.Equal(ipv4, ips) {
			t.Fatalf("ipv4hint = %v, want %v", ipv4, ips)
		}
		if len(ipv6) != 0 {
			t.Fatalf("ipv6hint = %v, want removed", ipv6)
		}
	})
	t.Run("no https record untouched", func(t *testing.T) {
		resp := &wire.Packet{Answers: []wire.Record{aRec("site.example.com", "104.16.1.1", 60)}}
		out := PinHTTPSHints(resp, []string{"104.17.5.1"})
		if len(out.Answers) != 1 || out.Answers[0].Type != wire.TypeA {
			t.Fatalf("answers = %v, want untouched", out.Answers)
		}
	})
}

func TestInjectECH(t *testing.T) {
	cfgList := validECHList()

	t.Run("existing https record gets ech param", func(t *testing.T) {
		resp := &wire.Packet{Questions: []wire.Question{{Name: "example.com", Type: wire.TypeHTTPS, Class: wire.ClassIN}},
			Answers: []wire.Record{httpsRec("example.com", []string{"104.16.1.1"}, nil, 60)}}
		out := InjectECH(resp, cfgList, nil)
		if len(out.Answers) != 1 {
			t.Fatalf("answer count = %d, want 1", len(out.Answers))
		}
		_, _, _, echBytes := wire.DescribeHTTPS(&out.Answers[0])
		if !slices.Equal(echBytes, cfgList) {
			t.Fatalf("ech = %v, want %v", echBytes, cfgList)
		}
	})
	t.Run("no https record synthesizes one", func(t *testing.T) {
		resp := &wire.Packet{Questions: []wire.Question{{Name: "example.com", Type: wire.TypeHTTPS, Class: wire.ClassIN}},
			Answers: []wire.Record{aRec("example.com", "104.16.1.1", 60)}}
		out := InjectECH(resp, cfgList, []string{"h3", "h2"})
		var https *wire.Record
		for i := range out.Answers {
			if out.Answers[i].Type == wire.TypeHTTPS {
				https = &out.Answers[i]
			}
		}
		if https == nil {
			t.Fatalf("no HTTPS record synthesized")
		}
		if https.Name != "example.com" || https.TTL != 300 || https.Class != wire.ClassIN {
			t.Fatalf("record = %+v, want query name / IN / TTL 300", https)
		}
		sv, ok := https.RData.(wire.SVCB)
		if !ok || sv.Priority != 1 || sv.Target != "." {
			t.Fatalf("rdata = %+v, want SVCB priority 1 target .", https.RData)
		}
		alpn, _, _, echBytes := wire.DescribeHTTPS(https)
		if !slices.Equal(alpn, []string{"h3", "h2"}) {
			t.Fatalf("alpn = %v, want [h3 h2]", alpn)
		}
		if !slices.Equal(echBytes, cfgList) {
			t.Fatalf("ech = %v, want %v", echBytes, cfgList)
		}
		encoded, err := out.Encode()
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		if _, err := wire.Parse(encoded); err != nil {
			t.Fatalf("parse: %v", err)
		}
	})
	t.Run("short config list untouched", func(t *testing.T) {
		resp := &wire.Packet{Questions: []wire.Question{{Name: "example.com", Type: wire.TypeHTTPS, Class: wire.ClassIN}}}
		out := InjectECH(resp, []byte{0x00, 0x01, 0x02}, nil)
		if len(out.Answers) != 0 {
			t.Fatalf("answers = %v, want none", out.Answers)
		}
	})
}

func TestInjectConfigured(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString(validECHList())
	base := func() *wire.Packet {
		return &wire.Packet{Questions: []wire.Question{{Name: "private.example.net", Type: wire.TypeHTTPS, Class: wire.ClassIN}},
			Answers: []wire.Record{httpsRec("private.example.net", nil, nil, 60)}}
	}
	t.Run("configured domain injected", func(t *testing.T) {
		cfg := &config.Config{EchDomains: []string{"example.net"}, EchConfigBase64: encoded}
		out := InjectConfigured(base(), cfg)
		_, _, _, echBytes := wire.DescribeHTTPS(&out.Answers[0])
		if len(echBytes) == 0 {
			t.Fatalf("ech not injected")
		}
	})
	t.Run("invalid base64 untouched", func(t *testing.T) {
		cfg := &config.Config{EchDomains: []string{"example.net"}, EchConfigBase64: "!!!"}
		out := InjectConfigured(base(), cfg)
		_, _, _, echBytes := wire.DescribeHTTPS(&out.Answers[0])
		if len(echBytes) != 0 {
			t.Fatalf("ech injected despite invalid base64")
		}
	})
	t.Run("structurally invalid list untouched", func(t *testing.T) {
		bad := base64.StdEncoding.EncodeToString([]byte{0x00, 0x08, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05})
		cfg := &config.Config{EchDomains: []string{"example.net"}, EchConfigBase64: bad}
		out := InjectConfigured(base(), cfg)
		_, _, _, echBytes := wire.DescribeHTTPS(&out.Answers[0])
		if len(echBytes) != 0 {
			t.Fatalf("ech injected despite invalid structure")
		}
	})
	t.Run("domain not configured untouched", func(t *testing.T) {
		cfg := &config.Config{EchDomains: []string{"other.net"}, EchConfigBase64: encoded}
		out := InjectConfigured(base(), cfg)
		_, _, _, echBytes := wire.DescribeHTTPS(&out.Answers[0])
		if len(echBytes) != 0 {
			t.Fatalf("ech injected outside configured domains")
		}
	})
}

func TestFlatten(t *testing.T) {
	t.Run("chain records move to query name", func(t *testing.T) {
		resp := &wire.Packet{
			Header:    wire.Header{ID: 5, Flags: 0x8180},
			Questions: []wire.Question{{Name: "www.example.com", Type: wire.TypeA, Class: wire.ClassIN}},
			Answers: []wire.Record{
				cnameRec("www.example.com", "edge.example.net", 300),
				aRec("edge.example.net", "104.16.1.1", 60),
				aaaaRec("edge.example.net", "2606:4700:4700::1111", 60),
				httpsRec("edge.example.net", []string{"104.16.1.1"}, nil, 60),
			},
		}
		out := Flatten(resp)
		if out.Answers[0].Type != wire.TypeCNAME || out.Answers[0].Name != "www.example.com" {
			t.Fatalf("leading CNAME = %+v, want preserved", out.Answers[0])
		}
		for _, r := range out.Answers[1:] {
			if r.Name != "www.example.com" {
				t.Fatalf("record %q still owned by %q", wire.CanonicalName(r.Name), r.Name)
			}
		}
	})
	t.Run("multi-hop chain keeps cname links", func(t *testing.T) {
		resp := &wire.Packet{
			Questions: []wire.Question{{Name: "www.example.com", Type: wire.TypeA, Class: wire.ClassIN}},
			Answers: []wire.Record{
				cnameRec("www.example.com", "a.example.net", 300),
				cnameRec("a.example.net", "b.example.net", 300),
				aRec("b.example.net", "104.16.1.1", 60),
			},
		}
		out := Flatten(resp)
		if out.Answers[1].Type == wire.TypeCNAME && out.Answers[1].Name != "a.example.net" {
			t.Fatalf("chain CNAME renamed to %q", out.Answers[1].Name)
		}
		if out.Answers[2].Name != "www.example.com" {
			t.Fatalf("terminal record owner = %q, want query name", out.Answers[2].Name)
		}
	})
	t.Run("no cname untouched", func(t *testing.T) {
		resp := &wire.Packet{
			Questions: []wire.Question{{Name: "example.com", Type: wire.TypeA, Class: wire.ClassIN}},
			Answers:   []wire.Record{aRec("example.com", "104.16.1.1", 60)},
		}
		if out := Flatten(resp); len(out.Answers) != 1 || out.Answers[0].Name != "example.com" {
			t.Fatalf("answers = %v, want untouched", out.Answers)
		}
	})
	t.Run("cname owned by other name untouched", func(t *testing.T) {
		resp := &wire.Packet{
			Questions: []wire.Question{{Name: "www.example.com", Type: wire.TypeA, Class: wire.ClassIN}},
			Answers: []wire.Record{
				aRec("www.example.com", "104.16.1.1", 60),
				cnameRec("alias.example.net", "other.example.net", 300),
			},
		}
		out := Flatten(resp)
		if out.Answers[1].Name != "alias.example.net" {
			t.Fatalf("unrelated CNAME renamed to %q", out.Answers[1].Name)
		}
	})
}
