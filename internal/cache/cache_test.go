package cache

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/jnuse/cfdoh/internal/config"
	"github.com/jnuse/cfdoh/internal/wire"
)

func queryPacket(id uint16, name string, qtype uint16) *wire.Packet {
	return &wire.Packet{
		Header:    wire.Header{ID: id, Flags: 0x0100},
		Questions: []wire.Question{{Name: name, Type: qtype, Class: wire.ClassIN}},
	}
}

func answerPacket(query *wire.Packet, ttl uint32, ips ...string) []byte {
	resp := &wire.Packet{Header: wire.Header{ID: query.Header.ID, Flags: 0x8180}, Questions: query.Questions}
	for _, ip := range ips {
		addr, _ := wire.ParseIPv4(ip)
		resp.Answers = append(resp.Answers, wire.Record{
			Name: query.Questions[0].Name, Type: wire.TypeA, Class: wire.ClassIN, TTL: ttl, RData: wire.A{IP: addr},
		})
	}
	out, _ := resp.Encode()
	return out
}

func nxdomainPacket(query *wire.Packet, soaTTL, soaMinimum uint32) []byte {
	resp := &wire.Packet{Header: wire.Header{ID: query.Header.ID, Flags: 0x8183}, Questions: query.Questions}
	resp.Authorities = append(resp.Authorities, wire.Record{
		Name: query.Questions[0].Name, Type: wire.TypeSOA, Class: wire.ClassIN, TTL: soaTTL,
		RData: wire.SOA{MName: "ns.example", RName: "host.example", Minimum: soaMinimum},
	})
	out, _ := resp.Encode()
	return out
}

func cfg() *config.Config {
	return &config.Config{
		CacheMinTTL:          30,
		CacheMaxTTL:          3600,
		NegativeCacheMaxTTL:  300,
		CacheStaleTTL:        600,
		CachePrefetchPercent: 10,
	}
}

// freeze returns the current clock plus a controllable override.
func freeze(t *testing.T) (base int64) {
	t.Helper()
	base = now()
	original := now
	t.Cleanup(func() { now = original })
	return base
}

func TestIdentityOfFoldsComponents(t *testing.T) {
	a, err := IdentityOf(queryPacket(0x1111, "Example.COM", wire.TypeA), "none", "")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := IdentityOf(queryPacket(0x2222, "example.com.", wire.TypeA), "none", "default")
	if a.Key != b.Key {
		t.Fatalf("ID and case must not change the key:\n%s\n%s", a.Key, b.Key)
	}
	if !strings.Contains(a.Text, "do=0") || !strings.Contains(a.Text, "cd=0") {
		t.Fatalf("text = %s", a.Text)
	}

	// DO and CD fold into the identity
	withDO := queryPacket(1, "example.com", wire.TypeA)
	withDO.Additionals = []wire.Record{{Name: ".", Type: wire.TypeOPT, RData: wire.Opt{PayloadSize: 1232, DO: true}}}
	c, _ := IdentityOf(withDO, "none", "")
	if !strings.Contains(c.Text, "do=1") {
		t.Fatalf("DO missing: %s", c.Text)
	}
	withCD := queryPacket(1, "example.com", wire.TypeA)
	withCD.Header.Flags = 0x0110
	d, _ := IdentityOf(withCD, "none", "")
	if !strings.Contains(d.Text, "cd=1") {
		t.Fatalf("CD missing: %s", d.Text)
	}

	// ECS identity and variant isolate entries
	e, _ := IdentityOf(queryPacket(1, "example.com", wire.TypeA), "198.51.100.0/24", "ip4=1.2.3.4")
	f, _ := IdentityOf(queryPacket(1, "example.com", wire.TypeA), "none", "ip4=1.2.3.4")
	g, _ := IdentityOf(queryPacket(1, "example.com", wire.TypeA), "198.51.100.0/24", "ip4=5.6.7.8")
	if e.Key == f.Key || e.Key == g.Key {
		t.Fatal("ecs/variant must isolate keys")
	}

	if _, err := IdentityOf(&wire.Packet{}, "none", ""); err == nil {
		t.Fatal("zero questions accepted")
	}
	two := queryPacket(1, "a.com", wire.TypeA)
	two.Questions = append(two.Questions, wire.Question{Name: "b.com", Type: wire.TypeA})
	if _, err := IdentityOf(two, "none", ""); err == nil {
		t.Fatal("two questions accepted")
	}
}

func TestPutGetFresh(t *testing.T) {
	freeze(t)
	c := New(4096)
	q := queryPacket(0x1111, "example.com", wire.TypeA)
	id, _ := IdentityOf(q, "none", "")

	ttl, stored := c.Put(id, answerPacket(q, 60, "192.0.2.1"), cfg())
	if !stored || ttl != 60 {
		t.Fatalf("put = %d/%v", ttl, stored)
	}

	other, _ := IdentityOf(queryPacket(0x9999, "example.com", wire.TypeA), "none", "")
	hit := c.Get(other, cfg())
	if hit == nil || hit.State != StateFresh {
		t.Fatalf("hit = %+v", hit)
	}
	parsed, err := wire.Parse(hit.Packet)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Header.ID != 0 {
		t.Fatalf("stored packet ID = %d, want 0 (caller patches)", parsed.Header.ID)
	}
	if hit.OrigTTL != 60 {
		t.Fatalf("orig ttl = %d", hit.OrigTTL)
	}
	if got := wire.IPv4String(parsed.Answers[0].RData.(wire.A).IP); got != "192.0.2.1" {
		t.Fatalf("address = %s", got)
	}

	miss, _ := IdentityOf(queryPacket(1, "other.com", wire.TypeA), "none", "")
	if c.Get(miss, cfg()) != nil {
		t.Fatal("unexpected hit")
	}
}

func TestPutClampsTTL(t *testing.T) {
	freeze(t)
	c := New(4096)
	q := queryPacket(1, "example.com", wire.TypeA)
	id, _ := IdentityOf(q, "none", "")

	if ttl, stored := c.Put(id, answerPacket(q, 5, "192.0.2.1"), cfg()); !stored || ttl != 30 {
		t.Fatalf("min clamp: %d/%v", ttl, stored)
	}
	if ttl, stored := c.Put(id, answerPacket(q, 99999, "192.0.2.1"), cfg()); !stored || ttl != 3600 {
		t.Fatalf("max clamp: %d/%v", ttl, stored)
	}
}

func TestPutRejectsServfailAndGarbage(t *testing.T) {
	freeze(t)
	c := New(4096)
	q := queryPacket(1, "example.com", wire.TypeA)
	id, _ := IdentityOf(q, "none", "")

	servfail := wire.MakeServfail(testQueryBytes(q))
	if _, stored := c.Put(id, servfail, cfg()); stored {
		t.Fatal("SERVFAIL must not be stored")
	}
	if _, stored := c.Put(id, []byte("garbage"), cfg()); stored {
		t.Fatal("garbage must not be stored")
	}
}

func TestPutNegativeCacheSOASemantics(t *testing.T) {
	freeze(t)
	c := New(4096)
	q := queryPacket(1, "missing.example.com", wire.TypeA)
	id, _ := IdentityOf(q, "none", "")

	ttl, stored := c.Put(id, nxdomainPacket(q, 900, 60), cfg())
	if !stored {
		t.Fatal("negative answer must be stored")
	}
	if ttl != 60 {
		t.Fatalf("negative ttl = %d, want min(900, 60, 300) = 60", ttl)
	}
	if c.Get(id, cfg()) == nil {
		t.Fatal("negative entry missing")
	}
}

func TestGetRefreshWindow(t *testing.T) {
	base := freeze(t)
	c := New(4096)
	q := queryPacket(1, "example.com", wire.TypeA)
	id, _ := IdentityOf(q, "none", "")
	c.Put(id, answerPacket(q, 100, "192.0.2.1"), cfg())

	now = func() int64 { return base + 50_000 } // 50s in: >10% remaining
	if hit := c.Get(id, cfg()); hit == nil || hit.State != StateFresh {
		t.Fatalf("state = %+v", hit)
	}
	now = func() int64 { return base + 95_000 } // 5s left: inside prefetch window
	hit := c.Get(id, cfg())
	if hit == nil || hit.State != StateRefresh {
		t.Fatalf("state = %+v", hit)
	}
}

func TestGetStaleWindow(t *testing.T) {
	base := freeze(t)
	c := New(4096)
	q := queryPacket(7, "example.com", wire.TypeA)
	id, _ := IdentityOf(q, "none", "")
	c.Put(id, answerPacket(q, 100, "192.0.2.1"), cfg())

	now = func() int64 { return base + 101_000 } // just expired
	hit := c.Get(id, cfg())
	if hit == nil || hit.State != StateStale {
		t.Fatalf("stale hit = %+v", hit)
	}
	parsed, _ := wire.Parse(hit.Packet)
	if parsed.Answers[0].TTL != 30 {
		t.Fatalf("stale ttl = %d, want 30", parsed.Answers[0].TTL)
	}
	if hit.OrigTTL != 100 {
		t.Fatalf("orig ttl = %d", hit.OrigTTL)
	}

	now = func() int64 { return base + 100_000 + 601_000 } // past the window
	if hit := c.Get(id, cfg()); hit != nil {
		t.Fatal("entry past the stale window must be dropped")
	}
	if c.Len() != 0 {
		t.Fatal("dropped entry must leave the cache")
	}
}

func TestGetStaleDisabled(t *testing.T) {
	base := freeze(t)
	c := New(4096)
	q := queryPacket(1, "example.com", wire.TypeA)
	id, _ := IdentityOf(q, "none", "")
	c.Put(id, answerPacket(q, 100, "192.0.2.1"), cfg())

	disabled := cfg()
	disabled.CacheStaleTTL = 0
	now = func() int64 { return base + 101_000 }
	if hit := c.Get(id, disabled); hit != nil {
		t.Fatal("stale serving disabled: expired entry must miss")
	}
}

func TestLRUEviction(t *testing.T) {
	freeze(t)
	c := New(128) // 8 per shard
	q := queryPacket(1, "example.com", wire.TypeA)
	first, _ := IdentityOf(queryPacket(1, "a0.example", wire.TypeA), "none", "")
	c.Put(first, answerPacket(q, 3600, "192.0.2.1"), cfg())
	for i := 1; i < 200; i++ {
		id, _ := IdentityOf(queryPacket(uint16(i), nameOf(i), wire.TypeA), "none", "")
		c.Put(id, answerPacket(queryPacket(uint16(i), nameOf(i), wire.TypeA), 3600, "192.0.2.1"), cfg())
	}
	if c.Len() > 128 {
		t.Fatalf("entries = %d, capacity exceeded", c.Len())
	}
	// the most recent insert survived
	lastID, _ := IdentityOf(queryPacket(199, nameOf(199), wire.TypeA), "none", "")
	if c.Get(lastID, cfg()) == nil {
		t.Fatal("recent entry evicted")
	}
}

func nameOf(i int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	return "n" + string(letters[i%26]) + string(letters[(i/26)%26]) + string(letters[(i/676)%26]) + ".example"
}

func TestSnapshotRoundTrip(t *testing.T) {
	base := freeze(t)
	c := New(4096)
	q := queryPacket(1, "example.com", wire.TypeA)
	fresh, _ := IdentityOf(q, "none", "")
	c.Put(fresh, answerPacket(q, 3600, "192.0.2.1"), cfg())
	expiring, _ := IdentityOf(queryPacket(2, "short.example", wire.TypeA), "none", "")
	c.Put(expiring, answerPacket(queryPacket(2, "short.example", wire.TypeA), 30, "192.0.2.2"), cfg())

	path := filepath.Join(t.TempDir(), "snapshot.json")
	if err := c.SaveSnapshot(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("temp file must be renamed away")
	}
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "@") || strings.Contains(string(data), "client") {
		t.Fatal("snapshot must not carry client identifying data")
	}

	// advance past the short entry's TTL before loading
	now = func() int64 { return base + 31_000 }
	loaded := New(4096)
	if err := loaded.LoadSnapshot(path); err != nil {
		t.Fatal(err)
	}
	if hit := loaded.Get(fresh, cfg()); hit == nil || hit.State != StateFresh {
		t.Fatalf("fresh entry lost: %+v", hit)
	}
	if hit := loaded.Get(expiring, cfg()); hit != nil {
		t.Fatal("expired entry must not be reloaded")
	}
}

func TestSnapshotMissingAndCorrupt(t *testing.T) {
	c := New(4096)
	if err := c.LoadSnapshot(filepath.Join(t.TempDir(), "absent.json")); err != nil {
		t.Fatalf("missing snapshot must not error: %v", err)
	}
	path := filepath.Join(t.TempDir(), "corrupt.json")
	os.WriteFile(path, []byte("{not json"), 0o600)
	if err := c.LoadSnapshot(path); err == nil {
		t.Fatal("corrupt snapshot must error")
	}
	os.WriteFile(path, []byte(`{"version":99,"entries":[]}`), 0o600)
	if err := c.LoadSnapshot(path); err == nil {
		t.Fatal("unknown version must error")
	}
}

func TestSaveSnapshotConcurrentSavesSerialize(t *testing.T) {
	// the periodic ticker and the shutdown save both target the same tmp
	// path; unsynchronized writers interleave inside the temp file and the
	// surviving snapshot ends up corrupt (or one rename fails on a tmp file
	// the other already moved away). The save mutex must serialize them.
	freeze(t)
	c := New(4096)
	for i := 0; i < 16; i++ {
		q := queryPacket(uint16(i), nameOf(i), wire.TypeA)
		id, _ := IdentityOf(q, "none", "")
		c.Put(id, answerPacket(q, 3600, "192.0.2.1"), cfg())
	}
	path := filepath.Join(t.TempDir(), "snapshot.json")
	const savers = 8
	var wg sync.WaitGroup
	errs := make(chan error, savers)
	for i := 0; i < savers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.SaveSnapshot(path); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent save failed: %v", err)
	}
	loaded := New(4096)
	if err := loaded.LoadSnapshot(path); err != nil {
		t.Fatalf("snapshot corrupted after concurrent saves: %v", err)
	}
	q := queryPacket(3, nameOf(3), wire.TypeA)
	id, _ := IdentityOf(q, "none", "")
	if hit := loaded.Get(id, cfg()); hit == nil || hit.State != StateFresh {
		t.Fatalf("entry lost after concurrent saves: %+v", hit)
	}
}

func testQueryBytes(q *wire.Packet) []byte {
	b, _ := q.Encode()
	return b
}
