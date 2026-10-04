// Package ech sources ECHConfigList bytes: published-domain resolution with
// caching, base64 validation, and the Meta three-state override machine.
//
// 契约: .trellis/spec/arch/ech.md. 注入动作住 rewrite, 本模块只供配置字节;
// Meta 三态转移固定; 配置字节或过期变化递增代数, 代数折入缓存键.
package ech

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/jnuse/cfdoh/internal/config"
	"github.com/jnuse/cfdoh/internal/upstream"
	"github.com/jnuse/cfdoh/internal/wire"
)

// ECHConfigList size bounds and cache lifetime.
const (
	minEchBytes = 6
	maxEchBytes = 16384
	configTTL   = time.Hour

	// publishMaxEntries caps the published-domain resolution cache. The
	// ?ech= parameter accepts any syntactically valid domain, so without a
	// hard cap unauthenticated unique-domain queries would grow the cache
	// without bound; eviction is oldest-inserted first.
	publishMaxEntries = 256
)

// now is the clock hook for tests (unix milliseconds).
var now = func() int64 { return time.Now().UnixMilli() }

// MetaState is the Meta ECH override state.
type MetaState int

// Meta override states.
const (
	MetaSeed      MetaState = iota // no override: use the configured seed
	MetaLearned                    // learned key overrides the seed
	MetaSuspended                  // injection suspended
)

// StatusReport is the Meta state snapshot for /admin endpoints.
type StatusReport struct {
	Mode   string // "learned" or "suspended"
	Bytes  int
	Until  int64
	Source string
	Reason string
	Active bool
}

type metaOverride struct {
	config []byte // nil while suspended
	until  int64
	source string
	reason string
}

type cachedConfig struct {
	data      []byte
	expiresAt int64
}

var (
	mu           sync.Mutex
	publish      = make(map[string]*cachedConfig) // published-domain resolution cache
	publishOrder []string                         // publish keys in insertion order, oldest first
	meta         *metaOverride
	metaGen      int
)

// storePublishLocked caches one resolution, keeping the insertion order
// used for capacity eviction; refreshing an existing key counts as a new
// insertion. The caller holds mu.
func storePublishLocked(key string, cached *cachedConfig) {
	removePublishLocked(key)
	publish[key] = cached
	publishOrder = append(publishOrder, key)
	for len(publishOrder) > publishMaxEntries {
		oldest := publishOrder[0]
		publishOrder = publishOrder[1:]
		delete(publish, oldest)
	}
}

// removePublishLocked drops one cache entry and its order slot. The
// caller holds mu.
func removePublishLocked(key string) {
	delete(publish, key)
	for i, k := range publishOrder {
		if k == key {
			publishOrder = append(publishOrder[:i], publishOrder[i+1:]...)
			break
		}
	}
}

// ConfigFor returns the ECHConfigList published in the HTTPS records of
// sourceDomain, cached for one hour. Failures return an error; the caller
// (rewrite) must not let that block the answer.
func ConfigFor(ctx context.Context, sourceDomain string, cfg *config.Config) ([]byte, error) {
	key := wire.CanonicalName(sourceDomain)
	mu.Lock()
	if cached, ok := publish[key]; ok {
		if cached.expiresAt > now() && validEchBytes(cached.data) {
			data := cached.data
			mu.Unlock()
			return data, nil
		}
		removePublishLocked(key)
	}
	mu.Unlock()

	query := &wire.Packet{
		Header:    wire.Header{ID: randomID(), Flags: 0x0100},
		Questions: []wire.Question{{Name: sourceDomain, Type: wire.TypeHTTPS, Class: wire.ClassIN}},
	}
	encoded, err := query.Encode()
	if err != nil {
		return nil, err
	}
	result, err := upstream.Query(ctx, encoded, cfg, false)
	if err != nil {
		return nil, err
	}
	parsed, err := wire.ParseRelaxed(result.Packet)
	if err != nil {
		return nil, err
	}
	for i := range parsed.Answers {
		record := &parsed.Answers[i]
		if record.Type != wire.TypeHTTPS {
			continue
		}
		_, _, _, echBytes := wire.DescribeHTTPS(record)
		if !validEchBytes(echBytes) {
			continue
		}
		mu.Lock()
		storePublishLocked(key, &cachedConfig{data: echBytes, expiresAt: now() + configTTL.Milliseconds()})
		mu.Unlock()
		return echBytes, nil
	}
	return nil, fmt.Errorf("no ECHConfigList found for %s", sourceDomain)
}

// Validated decodes and structurally checks a base64 ECHConfigList. The list
// length field must match the byte count and the first ECHConfig must fit.
func Validated(encoded string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("invalid base64: %w", err)
	}
	if !validEchBytes(data) {
		return nil, errors.New("not a valid ECHConfigList")
	}
	return data, nil
}

// SetMeta installs a learned key override. A re-report of identical bytes
// (renewal) does not bump the generation.
func SetMeta(cfgList []byte, ttl int, source, reason string) {
	mu.Lock()
	defer mu.Unlock()
	sameKey := meta != nil && sameBytes(meta.config, cfgList)
	meta = &metaOverride{
		config: append([]byte(nil), cfgList...),
		until:  now() + int64(ttl)*1000,
		source: truncate(source, 64),
		reason: truncate(reason, 200),
	}
	if !sameKey {
		metaGen++
	}
	slog.Warn("event", "event", "meta_ech_rotated", "detail",
		fmt.Sprintf("source=%s bytes=%d ttl=%d", source, len(cfgList), ttl))
}

// SetMetaSuspended stops injecting: rewrite returns the untouched upstream
// answer for Meta domains.
func SetMetaSuspended(ttl int, source, reason string) {
	mu.Lock()
	defer mu.Unlock()
	sameKey := meta != nil && meta.config == nil
	meta = &metaOverride{
		until:  now() + int64(ttl)*1000,
		source: truncate(source, 64),
		reason: truncate(reason, 200),
	}
	if !sameKey {
		metaGen++
	}
	slog.Error("event", "event", "meta_ech_suspended", "detail",
		fmt.Sprintf("source=%s reason=%s ttl=%d", source, truncate(reason, 200), ttl))
}

// ClearMeta drops any override, returning Meta domains to the seed.
func ClearMeta() {
	mu.Lock()
	defer mu.Unlock()
	if meta != nil {
		metaGen++
	}
	meta = nil
}

// MetaConfirm handles a prober's "seed works" report: a learned key verified
// byte-for-byte is renewed instead of falling back to the (possibly dead)
// seed; otherwise any override is cleared.
func MetaConfirm(verified []byte, ttl int, source string) {
	mu.Lock()
	override := meta
	mu.Unlock()

	if override != nil && override.config != nil && sameBytes(override.config, verified) {
		SetMeta(override.config, ttl, source, "renewed")
		return
	}
	if override != nil {
		slog.Info("event", "event", "meta_ech_seed_ok", "detail", fmt.Sprintf("source=%s", source))
	}
	ClearMeta()
}

// MetaOverride returns the effective override: MetaLearned with the config
// bytes to inject, MetaSuspended to inject nothing, MetaSeed to use the
// configured seed. Expired overrides clear themselves (bumping the
// generation) and answer MetaSeed.
func MetaOverride() (cfgList []byte, state MetaState) {
	mu.Lock()
	defer mu.Unlock()
	if meta != nil && meta.until <= now() {
		meta = nil
		metaGen++
	}
	if meta == nil {
		return nil, MetaSeed
	}
	if meta.config == nil {
		return nil, MetaSuspended
	}
	return meta.config, MetaLearned
}

// MetaCacheTag is the generation tag folded into Meta HTTPS cache keys.
func MetaCacheTag() string {
	MetaOverride() // sweep expiry first
	mu.Lock()
	defer mu.Unlock()
	return fmt.Sprintf("meta%d", metaGen)
}

// Status renders the Meta override snapshot.
func Status() *StatusReport {
	_, state := MetaOverride()
	if state == MetaSeed {
		return nil
	}
	mu.Lock()
	defer mu.Unlock()
	// re-check under the lock: MetaOverride released it between the two
	// critical sections, and a concurrent report (ok branch → ClearMeta)
	// may have dropped the override inside that window
	if meta == nil {
		return nil
	}
	report := &StatusReport{
		Bytes:  len(meta.config),
		Until:  meta.until,
		Source: meta.source,
		Reason: meta.reason,
		Active: meta.until > now(),
	}
	if meta.config == nil {
		report.Mode = "suspended"
	} else {
		report.Mode = "learned"
	}
	return report
}

// validEchBytes checks the ECHConfigList structure: a 2-byte total length
// matching the remaining bytes and a first ECHConfig that fits.
func validEchBytes(data []byte) bool {
	if len(data) < minEchBytes || len(data) > maxEchBytes {
		return false
	}
	declared := int(binary.BigEndian.Uint16(data[0:2]))
	if declared != len(data)-2 {
		return false
	}
	firstConfigLength := int(binary.BigEndian.Uint16(data[4:6]))
	return firstConfigLength+6 <= len(data)
}

func sameBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func randomID() uint16 {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return uint16(time.Now().UnixNano())
	}
	return binary.BigEndian.Uint16(b[:])
}
