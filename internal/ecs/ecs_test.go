package ecs

import (
	"testing"

	"github.com/jnuse/cfdoh/internal/config"
	"github.com/jnuse/cfdoh/internal/wire"
)

func queryPacket(id uint16, name string) *wire.Packet {
	return &wire.Packet{
		Header:    wire.Header{ID: id, Flags: 0x0100},
		Questions: []wire.Question{{Name: name, Type: wire.TypeA, Class: wire.ClassIN}},
	}
}

func optOf(t *testing.T, q *wire.Packet) wire.Opt {
	t.Helper()
	for _, r := range q.Additionals {
		if opt, ok := r.RData.(wire.Opt); ok {
			return opt
		}
	}
	t.Fatal("no OPT record in packet")
	return wire.Opt{}
}

func TestMakeTruncatesIPv4To24(t *testing.T) {
	v := Make("198.51.100.34", 24, 48)
	if v == nil {
		t.Fatal("Make returned nil")
	}
	if v.Family != 1 || v.Prefix != 24 {
		t.Fatalf("family/prefix = %d/%d", v.Family, v.Prefix)
	}
	if string(v.Addr) != string([]byte{198, 51, 100}) {
		t.Fatalf("addr = %v", v.Addr)
	}
	if v.Identity != "198.51.100/24" {
		t.Fatalf("identity = %q", v.Identity)
	}
}

func TestMakeMasksPartialByte(t *testing.T) {
	v := Make("198.51.100.34", 21, 48)
	if string(v.Addr) != string([]byte{198, 51, 96}) {
		t.Fatalf("addr = %v, want last byte masked to 96", v.Addr)
	}
	if v.Identity != "198.51.96/21" {
		t.Fatalf("identity = %q", v.Identity)
	}
}

func TestMakeTruncatesIPv6To48(t *testing.T) {
	v := Make("2001:db8:abcd:1234::1", 24, 48)
	if v == nil {
		t.Fatal("Make returned nil")
	}
	if v.Family != 2 || v.Prefix != 48 {
		t.Fatalf("family/prefix = %d/%d", v.Family, v.Prefix)
	}
	want := []byte{0x20, 0x01, 0x0d, 0xb8, 0xab, 0xcd}
	if string(v.Addr) != string(want) {
		t.Fatalf("addr = %v", v.Addr)
	}
	if v.Identity != "20010db8abcd/48" {
		t.Fatalf("identity = %q", v.Identity)
	}
}

func TestMakeRejectsInvalidIP(t *testing.T) {
	if Make("999.1.1.1", 24, 48) != nil {
		t.Fatal("invalid IPv4 accepted")
	}
	if Make("2001::zz", 24, 48) != nil {
		t.Fatal("invalid IPv6 accepted")
	}
	if Make("", 24, 48) != nil {
		t.Fatal("empty IP accepted")
	}
}

func TestShouldUse(t *testing.T) {
	cfg := &config.Config{EcsMode: "rules", EcsDomains: []string{".cn"}}
	cases := []struct {
		name     string
		mode     string
		override bool
		present  bool
		qname    string
		want     bool
	}{
		{"override enable", "off", true, true, "example.com", true},
		{"override disable", "always", false, true, "example.cn", false},
		{"mode off", "off", false, false, "example.cn", false},
		{"mode always", "always", false, false, "example.com", true},
		{"rules hit suffix", "rules", false, false, "www.Example.CN.", true},
		{"rules miss", "rules", false, false, "example.com", false},
		{"rules bare apex", "rules", false, false, "cn", true},
		{"rules not a suffix", "rules", false, false, "example.cn.evil.com", false},
	}
	for _, tc := range cases {
		cfg := &config.Config{EcsMode: tc.mode, EcsDomains: cfg.EcsDomains}
		q := queryPacket(1, tc.qname)
		if got := ShouldUse(q, cfg, tc.override, tc.present); got != tc.want {
			t.Fatalf("%s: ShouldUse = %v", tc.name, got)
		}
	}
}

func TestShouldUseNoQuestion(t *testing.T) {
	rules := &config.Config{EcsMode: "rules", EcsDomains: []string{".cn"}}
	if ShouldUse(&wire.Packet{}, rules, false, false) {
		t.Fatal("rules mode without question should not use ECS")
	}
	always := &config.Config{EcsMode: "always"}
	if !ShouldUse(&wire.Packet{}, always, false, false) {
		t.Fatal("always mode should use ECS even without a question")
	}
}

func TestAddSynthesizesOPT(t *testing.T) {
	v := Make("198.51.100.34", 24, 48)
	out := Add(queryPacket(1, "example.cn"), v)
	encoded, err := out.Encode()
	if err != nil {
		t.Fatal(err)
	}
	reparsed, err := wire.Parse(encoded)
	if err != nil {
		t.Fatal(err)
	}
	opt := optOf(t, reparsed)
	if opt.PayloadSize != 1232 {
		t.Fatalf("payload size = %d", opt.PayloadSize)
	}
	if len(opt.Options) != 1 || opt.Options[0].Code != optionCode {
		t.Fatalf("options = %v", opt.Options)
	}
	want := []byte{0, 1, 24, 0, 198, 51, 100}
	if string(opt.Options[0].Data) != string(want) {
		t.Fatalf("option data = %v, want %v", opt.Options[0].Data, want)
	}
}

func TestAddIsIdempotentAndPreservesOPT(t *testing.T) {
	q := queryPacket(1, "example.cn")
	q.Additionals = []wire.Record{{
		Name: ".", Type: wire.TypeOPT,
		RData: wire.Opt{
			PayloadSize: 4096, DO: true,
			Options: []wire.EdnsOption{
				{Code: 8, Data: []byte{0, 1, 32, 0, 10, 1, 2, 3, 4, 5, 6, 7}},
				{Code: 5, Data: []byte{9, 9}},
			},
		},
	}}
	stale := Make("10.1.2.3", 32, 48)
	out := Add(Add(q, stale), stale)

	var ecsCount, otherCount int
	opt := optOf(t, out)
	for _, o := range opt.Options {
		if o.Code == optionCode {
			ecsCount++
			want := []byte{0, 1, 32, 0, 10, 1, 2, 3}
			if string(o.Data) != string(want) {
				t.Fatalf("ecs data = %v", o.Data)
			}
		} else if o.Code == 5 {
			otherCount++
		}
	}
	if ecsCount != 1 {
		t.Fatalf("ecs options = %d, want 1", ecsCount)
	}
	if otherCount != 1 {
		t.Fatalf("other options = %d, want 1", otherCount)
	}
	if opt.PayloadSize != 4096 || !opt.DO {
		t.Fatalf("opt fields not preserved: size=%d do=%v", opt.PayloadSize, opt.DO)
	}
	if len(out.Additionals) != 1 {
		t.Fatalf("additionals = %d, want 1", len(out.Additionals))
	}
}

func TestRemoveStripsOnlyECS(t *testing.T) {
	q := queryPacket(1, "example.com")
	q.Additionals = []wire.Record{{
		Name: ".", Type: wire.TypeOPT,
		RData: wire.Opt{
			PayloadSize: 1400, DO: true,
			Options: []wire.EdnsOption{
				{Code: 8, Data: []byte{0, 1, 24, 0, 1, 2, 3}},
				{Code: 8, Data: []byte{0, 1, 16, 0, 9, 9}},
				{Code: 5, Data: []byte{1, 2}},
			},
		},
	}}
	out := Remove(q)
	opt := optOf(t, out)
	if len(opt.Options) != 1 || opt.Options[0].Code != 5 {
		t.Fatalf("options after remove = %v", opt.Options)
	}
	if opt.PayloadSize != 1400 || !opt.DO {
		t.Fatal("opt fields not preserved")
	}
	if out == q {
		t.Fatal("Remove must not mutate the input packet")
	}
	if Remove(queryPacket(2, "example.com")) == nil {
		t.Fatal("Remove of nil-safe packet failed")
	}
}
