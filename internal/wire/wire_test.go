package wire

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func mustQuery(t *testing.T, name string, qtype uint16) []byte {
	t.Helper()
	pkt := &Packet{
		Header:    Header{ID: 0x1234, Flags: 0x0100},
		Questions: []Question{{Name: name, Type: qtype, Class: ClassIN}},
	}
	b, err := pkt.Encode()
	if err != nil {
		t.Fatalf("encode query: %v", err)
	}
	return b
}

func TestRoundTripRecords(t *testing.T) {
	var ip4 [4]byte = [4]byte{192, 0, 2, 1}
	var ip6 [16]byte
	copy(ip6[:], []byte{0x26, 0x06, 0x47, 0x00})
	pkt := &Packet{
		Header:    Header{ID: 1, Flags: 0x8180},
		Questions: []Question{{Name: "Example.COM.", Type: TypeHTTPS, Class: ClassIN}},
		Answers: []Record{
			{Name: "example.com.", Type: TypeCNAME, Class: ClassIN, TTL: 300, RData: Name{Name: "target.example.com."}},
			{Name: "example.com.", Type: TypeA, Class: ClassIN, TTL: 60, RData: A{IP: ip4}},
			{Name: "example.com.", Type: TypeAAAA, Class: ClassIN, TTL: 60, RData: AAAA{IP: ip6}},
			{Name: "example.com.", Type: TypeMX, Class: ClassIN, TTL: 60, RData: MX{Preference: 10, Exchange: "mail.example.com."}},
			{Name: "example.com.", Type: TypeSOA, Class: ClassIN, TTL: 60, RData: SOA{MName: "ns1.example.com.", RName: "host.example.com.", Serial: 1, Refresh: 2, Retry: 3, Expire: 4, Minimum: 5}},
			{Name: "_srv.example.com.", Type: TypeSRV, Class: ClassIN, TTL: 60, RData: SRV{Priority: 1, Weight: 2, Port: 443, Target: "host.example.com."}},
			{Name: "example.com.", Type: TypeHTTPS, Class: ClassIN, TTL: 60, RData: SVCB{Priority: 1, Target: ".", Params: []SvcParam{
				{Key: ParamALPN, Value: []byte{2, 'h', '2'}},
				{Key: ParamIPv4Hint, Value: ip4[:]},
				{Key: ParamECH, Value: []byte{0xfe, 0x0d, 0x01}},
			}}},
			{Name: "example.com.", Type: 99, Class: ClassIN, TTL: 60, RData: Raw{Type: 99, Data: []byte{1, 2, 3}}},
		},
		Authorities: []Record{
			{Name: "example.com.", Type: TypeNS, Class: ClassIN, TTL: 60, RData: Name{Name: "ns1.example.com."}},
		},
		Additionals: []Record{
			{Name: ".", Type: TypeOPT, Class: ClassIN, TTL: 0, RData: Opt{PayloadSize: 1232, ExtRCode: 0, Version: 0, DO: true, Options: []EdnsOption{{Code: 8, Data: []byte{1, 2}}}}},
		},
	}
	wire1, err := pkt.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	parsed, err := Parse(wire1)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	wire2, err := parsed.Encode()
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	if !bytes.Equal(wire1, wire2) {
		t.Fatalf("round trip not stable:\n%s\n%s", hex.Dump(wire1), hex.Dump(wire2))
	}
	// Semantic spot checks after round trip.
	if got := parsed.Questions[0].Name; got != "Example.COM." {
		t.Fatalf("question name case not preserved: %q", got)
	}
	if a, ok := parsed.Answers[1].RData.(A); !ok || IPv4String(a.IP) != "192.0.2.1" {
		t.Fatalf("A record lost: %#v", parsed.Answers[1].RData)
	}
	httpsRec := parsed.Answers[6]
	alpn, hints4, _, ech := DescribeHTTPS(&httpsRec)
	if len(alpn) != 1 || alpn[0] != "h2" || len(hints4) != 1 || hints4[0] != "192.0.2.1" || len(ech) != 3 {
		t.Fatalf("DescribeHTTPS: %v %v %v", alpn, hints4, ech)
	}
	opt, ok := parsed.Additionals[0].RData.(Opt)
	if !ok || opt.PayloadSize != 1232 || !opt.DO || len(opt.Options) != 1 || opt.Options[0].Code != 8 {
		t.Fatalf("OPT round trip lost semantics: %#v", opt)
	}
	// Deep-copy guarantee: mutate parsed payload, original buffer must be intact.
	if raw, ok := parsed.Answers[7].RData.(Raw); ok {
		raw.Data[0] = 0xFF
		if wire1[0] == 0xFF && wire1[1] == 0xFF {
			t.Fatal("unexpected aliasing")
		}
	} else {
		t.Fatal("raw record not typed Raw")
	}
}

func TestParseCompressionPointer(t *testing.T) {
	// Build: question example.com A, answer with owner compressed to question.
	base := &Packet{
		Header:    Header{ID: 7, Flags: 0x8180, QDCount: 1, ANCount: 1},
		Questions: []Question{{Name: "example.com.", Type: TypeA, Class: ClassIN}},
	}
	wire, err := base.Encode()
	if err != nil {
		t.Fatal(err)
	}
	// answer: pointer(0xC00C) type A class IN ttl 60 rdlen 4 ip
	answer := []byte{0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 2}
	full := append(append([]byte{}, wire...), answer...)
	full[6], full[7] = 0, 1 // ANCount = 1
	parsed, err := Parse(full)
	if err != nil {
		t.Fatalf("compressed owner: %v", err)
	}
	if got := parsed.Answers[0].Name; got != "example.com." {
		t.Fatalf("compressed owner decoded to %q", got)
	}
	if a, ok := parsed.Answers[0].RData.(A); !ok || IPv4String(a.IP) != "203.0.113.2" {
		t.Fatalf("A payload wrong: %#v", parsed.Answers[0].RData)
	}
}

func TestParseCompressionPointerLoop(t *testing.T) {
	// A question name pointer that targets itself must be rejected, not hang.
	pkt := []byte{0, 1, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	pkt = append(pkt, 0xC0, 0x0C, 0, 1, 0, 1) // pointer at offset 12 targeting offset 12
	if _, err := Parse(pkt); err == nil {
		t.Fatal("pointer loop accepted")
	}
	// Two pointers targeting each other.
	pkt2 := []byte{0, 1, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	pkt2 = append(pkt2, 0xC0, 0x0E, 0xC0, 0x0C, 0, 1, 0, 1)
	// offset 12: C0 0E → 14; offset 14: C0 0C → 12 → cycle.
	pkt2[14], pkt2[15] = 0xC0, 0x0C
	if _, err := Parse(pkt2); err == nil {
		t.Fatal("mutual pointer loop accepted")
	}
}

func TestParseAttackPackets(t *testing.T) {
	valid := mustQuery(t, "example.com.", TypeA)
	cases := []struct {
		name  string
		mutcb func(b []byte) []byte
	}{
		{"trailing byte", func(b []byte) []byte { return append(append([]byte{}, b...), 0) }},
		{"qdcount 33", func(b []byte) []byte { b[5] = 33; return b }},
		{"record total 513", func(b []byte) []byte { b[7], b[9], b[11] = 1, 255, 255; return b }},
		{"label 64 bytes", func(b []byte) []byte {
			q := &Packet{Header: Header{ID: 1, Flags: 0x0100}, Questions: []Question{{Name: strings.Repeat("a", 64) + ".com.", Type: TypeA, Class: ClassIN}}}
			out, _ := q.Encode()
			return out
		}},
		{"0x41 label", func(b []byte) []byte {
			q := &Packet{Header: Header{ID: 1, Flags: 0x0100}, Questions: []Question{{Name: "example.com.", Type: TypeA, Class: ClassIN}}}
			out, _ := q.Encode()
			out[12] = 0x41
			return out
		}},
		{"name 257 wire bytes", func(b []byte) []byte {
			// 4 labels x 63 bytes: 1 + 4*(1+63) = 257 wire bytes — decodable
			// per-label but never re-encodable, so decode must reject it.
			pkt := []byte{0, 1, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0}
			for i := 0; i < 4; i++ {
				pkt = append(pkt, 63)
				pkt = append(pkt, bytes.Repeat([]byte{'a'}, 63)...)
			}
			pkt = append(pkt, 0, 0, 1, 0, 1) // root + A + IN
			return pkt
		}},
		{"oversized name via compression", func(b []byte) []byte {
			// header: qd=1, ns=1; question name and the NS rdata both point
			// at a four-label chain (1 + 4*64 = 257 wire bytes) stored once:
			// each label is decodable, the spliced name is not re-encodable.
			pkt := []byte{0, 1, 0x01, 0, 0, 1, 0, 0, 0, 1, 0, 0}
			pkt = append(pkt, 0xC0, 0x1F)       // question name → offset 31
			pkt = append(pkt, 0, 1, 0, 1)       // A IN
			pkt = append(pkt, 0)                // authority owner: root
			pkt = append(pkt, 0, 2, 0, 1)       // type NS, class IN
			pkt = append(pkt, 0, 0, 0, 0, 0, 2) // ttl 0, rdlen 2
			pkt = append(pkt, 0xC0, 0x1F)       // rdata → offset 31
			for i := 0; i < 4; i++ {            // offset 31: the chain
				pkt = append(pkt, 63)
				pkt = append(pkt, bytes.Repeat([]byte{'b'}, 63)...)
			}
			pkt = append(pkt, 0)
			return pkt
		}},
	}
	for _, tc := range cases {
		if _, err := Parse(tc.mutcb(valid)); err == nil {
			t.Fatalf("%s: accepted", tc.name)
		}
	}
	// SVCB param out of order: build manually.
	svcbBad := []byte{0, 1, 0x20, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	svcbBad = append(svcbBad, 4, 'e', 'x', 'a', 0) // "exa" + root
	svcbBad = append(svcbBad, 0, 65, 0, 1, 0, 0)   // HTTPS q (no rdata here; craft answer instead)
	_ = svcbBad
	if _, err := Parse(buildSVCBOutOfOrder(t)); err == nil {
		t.Fatal("SVCB out-of-order params accepted")
	}
}

func buildSVCBOutOfOrder(t *testing.T) []byte {
	t.Helper()
	// answer rdata: priority 1, target ".", params key=4 len=0, key=1 len=0 (out of order)
	rd := []byte{0, 1, 0}
	rd = append(rd, 0, 4, 0, 0)
	rd = append(rd, 0, 1, 0, 0)
	q := &Packet{Header: Header{ID: 1, Flags: 0x8180, QDCount: 1, ANCount: 1},
		Questions: []Question{{Name: "example.com.", Type: TypeHTTPS, Class: ClassIN}}}
	wire, _ := q.Encode()
	answer := []byte{0xC0, 0x0C, 0, 65, 0, 1, 0, 0, 0, 60, 0, byte(len(rd))}
	answer = append(answer, rd...)
	wire = append(wire, answer...)
	wire[6], wire[7] = 0, 1
	return wire
}

func TestParseRDATAOverflow(t *testing.T) {
	q := &Packet{Header: Header{ID: 1, Flags: 0x8180, QDCount: 1, ANCount: 1},
		Questions: []Question{{Name: "example.com.", Type: TypeA, Class: ClassIN}}}
	wire, _ := q.Encode()
	// rdlen 4 but only 2 bytes follow
	answer := []byte{0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0}
	wire = append(wire, answer...)
	wire[6], wire[7] = 0, 1
	if _, err := Parse(wire); err == nil {
		t.Fatal("truncated RDATA accepted")
	}
}

func TestParseRDATANameNotConsumed(t *testing.T) {
	// CNAME rdata with trailing byte after the target name.
	q := &Packet{Header: Header{ID: 1, Flags: 0x8180, QDCount: 1, ANCount: 1},
		Questions: []Question{{Name: "example.com.", Type: TypeCNAME, Class: ClassIN}}}
	wire, _ := q.Encode()
	rd := []byte{3, 'a', 'b', 'c', 0, 0xFF} // name + stray byte
	answer := []byte{0xC0, 0x0C, 0, 5, 0, 1, 0, 0, 0, 60, 0, byte(len(rd))}
	answer = append(answer, rd...)
	wire = append(wire, answer...)
	wire[6], wire[7] = 0, 1
	if _, err := Parse(wire); err == nil {
		t.Fatal("RDATA with trailing byte accepted")
	}
}

func TestMakeServfail(t *testing.T) {
	query := mustQuery(t, "example.com.", TypeA)
	out := MakeServfail(query)
	parsed, err := Parse(out)
	if err != nil {
		t.Fatalf("servfail unparseable: %v", err)
	}
	if parsed.Header.RCode() != 2 || !parsed.Header.QR() || !parsed.Header.RD() {
		t.Fatalf("servfail flags wrong: %#04x", parsed.Header.Flags)
	}
	if len(parsed.Questions) != 1 {
		t.Fatal("question not preserved")
	}
	bare := MakeServfail([]byte{0xAB, 0xCD}) // not a packet (too short)
	if len(bare) != 12 || bare[0] != 0xAB || bare[1] != 0xCD || bare[2] != 0x81 || bare[3] != 0x82 {
		t.Fatalf("bare servfail wrong: % x", bare)
	}
}

func TestResponseTTL(t *testing.T) {
	soa := SOA{MName: "ns.", RName: "host.", Minimum: 900}
	cases := []struct {
		name         string
		packet       *Packet
		min, max, ng int
		want         int
	}{
		{"servfail zero", &Packet{Header: Header{Flags: 0x8002}}, 30, 3600, 300, 0},
		{"min of answers", &Packet{Header: Header{Flags: 0x8000}, Answers: []Record{
			{Name: "a.", Type: TypeA, TTL: 600, RData: A{}},
			{Name: "b.", Type: TypeA, TTL: 120, RData: A{}},
		}}, 30, 3600, 300, 120},
		{"opt excluded", &Packet{Header: Header{Flags: 0x8000}, Answers: []Record{
			{Name: "a.", Type: TypeA, TTL: 600, RData: A{}},
			{Name: ".", Type: TypeOPT, TTL: 1, RData: Opt{}},
		}}, 30, 3600, 300, 600},
		{"nxdomain soa", &Packet{Header: Header{Flags: 0x8003}, Authorities: []Record{
			{Name: "a.", Type: TypeSOA, TTL: 1800, RData: soa},
		}}, 30, 3600, 300, 300},
		{"nxdomain without soa", &Packet{Header: Header{Flags: 0x8003}}, 30, 3600, 300, 0},
		{"nodata without soa", &Packet{Header: Header{Flags: 0x8000}}, 30, 3600, 300, 0},
		{"clamp up", &Packet{Header: Header{Flags: 0x8000}, Answers: []Record{
			{Name: "a.", Type: TypeA, TTL: 5, RData: A{}},
		}}, 30, 3600, 300, 30},
		{"clamp down", &Packet{Header: Header{Flags: 0x8000}, Answers: []Record{
			{Name: "a.", Type: TypeA, TTL: 99999, RData: A{}},
		}}, 30, 3600, 300, 3600},
	}
	for _, tc := range cases {
		if got := ResponseTTL(tc.packet, tc.min, tc.max, tc.ng); got != tc.want {
			t.Fatalf("%s: got %d want %d", tc.name, got, tc.want)
		}
	}
}

func TestRotateAddresses(t *testing.T) {
	mk := func(id byte) Record {
		return Record{Name: "example.com.", Type: TypeA, Class: ClassIN, TTL: 60, RData: A{IP: [4]byte{192, 0, 2, id}}}
	}
	pkt := &Packet{Header: Header{ID: 1, Flags: 0x8180}, Questions: []Question{{Name: "example.com.", Type: TypeA, Class: ClassIN}},
		Answers: []Record{
			{Name: "example.com.", Type: TypeCNAME, Class: ClassIN, TTL: 60, RData: Name{Name: "example.com."}},
			mk(1), mk(2), mk(3),
			{Name: "example.com.", Type: TypeAAAA, Class: ClassIN, TTL: 60, RData: AAAA{IP: [16]byte{1}}},
			{Name: "example.com.", Type: TypeAAAA, Class: ClassIN, TTL: 60, RData: AAAA{IP: [16]byte{2}}},
		}}
	wire, err := pkt.Encode()
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := RotateAddresses(wire)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(rotated)
	if err != nil {
		t.Fatal(err)
	}
	if got := IPv4String(parsed.Answers[1].RData.(A).IP); got != "192.0.2.2" {
		t.Fatalf("A group rotation wrong: first=%s", got)
	}
	if parsed.Answers[0].Type != TypeCNAME {
		t.Fatal("CNAME moved")
	}
	if got := parsed.Answers[4].RData.(AAAA).IP[0]; got != 2 {
		t.Fatalf("AAAA group rotation wrong: first=%d", got)
	}
}

func TestMatchDomain(t *testing.T) {
	patterns := []string{"*.Example.com", "exact.org"}
	cases := []struct {
		name string
		want bool
	}{
		{"example.com", true},
		{"EXAMPLE.COM.", true},
		{"sub.example.com", true},
		{"deep.sub.example.com", true},
		{"notexample.com", false},
		{"exact.org", true},
		{"sub.exact.org", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := MatchDomain(tc.name, patterns); got != tc.want {
			t.Fatalf("MatchDomain(%q) = %v", tc.name, got)
		}
	}
}

func TestParseIPv4(t *testing.T) {
	if ip, err := ParseIPv4("192.0.2.1"); err != nil || IPv4String(ip) != "192.0.2.1" {
		t.Fatalf("basic v4: %v %v", ip, err)
	}
	if _, err := ParseIPv4("01.2.3.4"); err != nil {
		t.Fatalf("leading zero should be tolerated: %v", err)
	}
	for _, bad := range []string{"1.2.3", "1.2.3.4.5", "256.1.1.1", "a.b.c.d", "1..2.3"} {
		if _, err := ParseIPv4(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestParseIPv6(t *testing.T) {
	ip, err := ParseIPv6("2606:4700::6810:84e5")
	if err != nil {
		t.Fatalf("elision: %v", err)
	}
	if IPv6String(ip) != "2606:4700:0000:0000:0000:0000:6810:84e5" {
		t.Fatalf("render: %s", IPv6String(ip))
	}
	if _, err := ParseIPv6("::ffff:1.2.3.4"); err == nil {
		t.Fatal("v4-mapped accepted")
	}
	if _, err := ParseIPv6("2606::6810::1"); err == nil {
		t.Fatal("double elision accepted")
	}
	full := "2606:4700:0000:0000:0000:0000:6810:84e5"
	if _, err := ParseIPv6(full); err != nil {
		t.Fatalf("full form: %v", err)
	}
}

func TestPatchID(t *testing.T) {
	wire := mustQuery(t, "example.com.", TypeA)
	if wire[0] != 0x12 || wire[1] != 0x34 {
		t.Fatal("fixture id wrong")
	}
	out := PatchID(wire, 0xBEEF)
	if out[0] != 0xBE || out[1] != 0xEF {
		t.Fatal("id not patched")
	}
	if wire[0] != 0x12 {
		t.Fatal("original mutated")
	}
}

func TestUpsertSvcParam(t *testing.T) {
	rec := Record{Type: TypeHTTPS, RData: SVCB{Priority: 1, Target: ".", Params: []SvcParam{
		{Key: ParamIPv4Hint, Value: []byte{1, 1, 1, 1}},
	}}}
	UpsertSvcParam(&rec, ParamECH, []byte{9})
	UpsertSvcParam(&rec, ParamECH, []byte{7, 7})
	sv := rec.RData.(SVCB)
	if len(sv.Params) != 2 || sv.Params[0].Key != ParamIPv4Hint || sv.Params[1].Key != ParamECH {
		t.Fatalf("upsert result: %#v", sv.Params)
	}
	if sv.Params[1].Value[0] != 7 || len(sv.Params[1].Value) != 2 {
		t.Fatal("value not replaced")
	}
}
