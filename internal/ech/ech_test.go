package ech

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jnuse/cfdoh/internal/config"
	"github.com/jnuse/cfdoh/internal/wire"
)

// validList: declared=6 (len-2), first config length=2 (fits exactly).
var validList = []byte{0, 6, 1, 2, 0, 2, 3, 4}

func resetEch(t *testing.T, base int64) {
	t.Helper()
	mu.Lock()
	publish = make(map[string]*cachedConfig)
	publishOrder = nil
	meta = nil
	metaGen = 0
	mu.Unlock()
	original := now
	now = func() int64 { return base }
	t.Cleanup(func() { now = original })
}

func TestValidated(t *testing.T) {
	got, err := Validated(base64.StdEncoding.EncodeToString(validList))
	if err != nil || string(got) != string(validList) {
		t.Fatalf("Validated = %v %v", got, err)
	}
	bad := []string{
		"not base64!!",
		base64.StdEncoding.EncodeToString([]byte{0, 6, 1}),                 // too short
		base64.StdEncoding.EncodeToString([]byte{0, 99, 1, 2, 0, 2, 3, 4}), // declared mismatch
		base64.StdEncoding.EncodeToString([]byte{0, 6, 1, 2, 0, 9, 3, 4}),  // first config overruns
	}
	for _, encoded := range bad {
		if _, err := Validated(encoded); err == nil {
			t.Fatalf("Validated(%q) accepted", encoded)
		}
	}
}

func httpsAnswer(query []byte, ech []byte) []byte {
	parsed, _ := wire.Parse(query)
	resp := &wire.Packet{Header: wire.Header{ID: parsed.Header.ID, Flags: 0x8180}, Questions: parsed.Questions}
	resp.Answers = append(resp.Answers, wire.Record{
		Name: parsed.Questions[0].Name, Type: wire.TypeHTTPS, Class: wire.ClassIN, TTL: 300,
		RData: wire.SVCB{Priority: 1, Target: ".", Params: []wire.SvcParam{{Key: wire.ParamECH, Value: ech}}},
	})
	out, _ := resp.Encode()
	return out
}

func TestConfigForCachesAndValidates(t *testing.T) {
	resetEch(t, 1_000_000)
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		body := make([]byte, r.ContentLength)
		if _, err := r.Body.Read(body); err != nil && len(body) == 0 {
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(httpsAnswer(body, validList))
	}))
	defer srv.Close()
	cfg := &config.Config{Upstreams: []string{srv.URL}, UpstreamTimeoutMs: 1000, MaxDNSPacketSize: 4096}

	got, err := ConfigFor(context.Background(), "cloudflare-ech.com", cfg)
	if err != nil || string(got) != string(validList) {
		t.Fatalf("ConfigFor = %v %v", got, err)
	}
	if again, err := ConfigFor(context.Background(), "Cloudflare-ECH.com.", cfg); err != nil || string(again) != string(validList) {
		t.Fatalf("cached ConfigFor = %v %v", again, err)
	}
	if hits.Load() != 1 {
		t.Fatalf("upstream hits = %d, cache must serve the second call", hits.Load())
	}

	// expired cache refetches
	now = func() int64 { return 1_000_000 + 3_601_000 }
	if _, err := ConfigFor(context.Background(), "cloudflare-ech.com", cfg); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 2 {
		t.Fatalf("expired cache must refetch, hits = %d", hits.Load())
	}
}

func TestConfigForRejectsInvalidEch(t *testing.T) {
	resetEch(t, 1_000_000)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		if _, err := r.Body.Read(body); err != nil && len(body) == 0 {
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(httpsAnswer(body, []byte{0, 99, 1, 2, 0, 2, 3, 4})) // declared mismatch
	}))
	defer srv.Close()
	cfg := &config.Config{Upstreams: []string{srv.URL}, UpstreamTimeoutMs: 1000, MaxDNSPacketSize: 4096}
	if _, err := ConfigFor(context.Background(), "cloudflare-ech.com", cfg); err == nil {
		t.Fatal("invalid ECHConfigList must be rejected")
	}
}

// The ?ech= parameter accepts any syntactically valid domain, so the
// publish cache needs a hard cap: unbounded unique-domain queries would
// otherwise grow it without bound (C2/M2). Eviction is oldest-inserted
// first and a refresh counts as a new insertion.
func TestPublishCacheCapEvictsOldest(t *testing.T) {
	resetEch(t, 1_000_000)
	fresh := func() *cachedConfig { return &cachedConfig{data: validList, expiresAt: 1_000_000 + 60_000} }
	for i := 0; i < publishMaxEntries; i++ {
		storePublishLocked(fmt.Sprintf("d%d.example", i), fresh())
	}
	if len(publish) != publishMaxEntries || len(publishOrder) != publishMaxEntries {
		t.Fatalf("publish = %d entries / %d order slots", len(publish), len(publishOrder))
	}

	// one more unique domain evicts the oldest entry, not the newest
	storePublishLocked("new.example", fresh())
	if len(publish) != publishMaxEntries {
		t.Fatalf("publish size = %d, want cap %d", len(publish), publishMaxEntries)
	}
	if _, ok := publish["d0.example"]; ok {
		t.Fatal("the oldest entry must be evicted")
	}
	if _, ok := publish["new.example"]; !ok {
		t.Fatal("the newest entry must survive")
	}

	// a refreshed key counts as a new insertion and survives later inserts
	storePublishLocked("d1.example", fresh())
	for i := 2; i < 20; i++ {
		storePublishLocked(fmt.Sprintf("x%d.example", i), fresh())
	}
	if _, ok := publish["d1.example"]; !ok {
		t.Fatal("a refreshed key must not be evicted by later inserts")
	}
	if _, ok := publish["d2.example"]; ok {
		t.Fatal("stale keys must keep being evicted oldest-first")
	}
	if len(publish) != len(publishOrder) {
		t.Fatalf("map and order diverged: %d vs %d", len(publish), len(publishOrder))
	}
}

// Status takes two lock windows (MetaOverride, then its own); a concurrent
// report clearing the override in between used to nil-deref inside the
// second window (C3/M3).
func TestStatusSurvivesConcurrentClearMeta(t *testing.T) {
	resetEch(t, 1_000_000)
	SetMeta(validList, 3600, "probe-a", "rotated")
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 4000; j++ {
				Status()
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 2000; j++ {
			ClearMeta()
			SetMeta(validList, 3600, "probe-a", "rotated")
		}
	}()
	wg.Wait()
}

func TestMetaStateMachAndGeneration(t *testing.T) {
	resetEch(t, 1_000_000)
	if _, state := MetaOverride(); state != MetaSeed {
		t.Fatalf("initial state = %d", state)
	}
	seedTag := MetaCacheTag()

	SetMeta(validList, 3600, "probe-a", "rotated")
	cfgList, state := MetaOverride()
	if state != MetaLearned || string(cfgList) != string(validList) {
		t.Fatalf("override = %d %v", state, cfgList)
	}
	learnedTag := MetaCacheTag()
	if learnedTag == seedTag {
		t.Fatal("new key must bump the generation")
	}
	if st := Status(); st == nil || st.Mode != "learned" || !st.Active {
		t.Fatalf("status = %+v", st)
	}

	// renewal with identical bytes: no bump
	SetMeta(validList, 3600, "probe-a", "renewed")
	if MetaCacheTag() != learnedTag {
		t.Fatal("identical bytes must not bump")
	}
	// different key: bump
	SetMeta([]byte{0, 6, 9, 9, 0, 2, 3, 4}, 3600, "probe-a", "rotated again")
	rotatedTag := MetaCacheTag()
	if rotatedTag == learnedTag {
		t.Fatal("changed bytes must bump")
	}

	// suspension: nil config, suspended state, bump
	SetMetaSuspended(3600, "probe-a", "rejected")
	if _, state = MetaOverride(); state != MetaSuspended {
		t.Fatalf("suspended state = %d", state)
	}
	if st := Status(); st == nil || st.Mode != "suspended" {
		t.Fatalf("status = %+v", st)
	}
	if MetaCacheTag() == rotatedTag {
		t.Fatal("suspension must bump")
	}

	// expiry returns to seed and bumps
	now = func() int64 { return 1_000_000 + 3_601_000 }
	if _, state = MetaOverride(); state != MetaSeed {
		t.Fatalf("expired override = %d", state)
	}
	if MetaCacheTag() == rotatedTag {
		t.Fatal("expiry must bump")
	}
}

func TestMetaConfirmRenewAndClear(t *testing.T) {
	resetEch(t, 1_000_000)
	SetMeta(validList, 3600, "probe-a", "rotated")
	tag := MetaCacheTag()

	// verified with matching bytes renews without clearing
	MetaConfirm(validList, 3600, "probe-a")
	if _, state := MetaOverride(); state != MetaLearned {
		t.Fatalf("renewal state = %d", state)
	}
	if MetaCacheTag() != tag {
		t.Fatal("renewal must not bump")
	}

	// ok without verification clears back to seed
	MetaConfirm(nil, 3600, "probe-a")
	if _, state := MetaOverride(); state != MetaSeed {
		t.Fatalf("after confirm-clear state = %d", state)
	}

	// verified while suspended: clears (nothing to renew)
	SetMetaSuspended(3600, "probe-a", "rejected")
	MetaConfirm(validList, 3600, "probe-a")
	if _, state := MetaOverride(); state != MetaSeed {
		t.Fatalf("suspended confirm state = %d", state)
	}
}
