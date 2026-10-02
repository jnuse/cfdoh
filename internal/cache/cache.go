// Package cache implements the sharded LRU answer cache with TTL clamping,
// prefetch/serve-stale state judgment and versioned disk snapshots.
//
// 契约: .trellis/spec/arch/cache.md. 键由身份与变体两段构成; SERVFAIL 不入
// 缓存; stale 服务窗内 TTL 写 30; 快照走临时文件加原子改名且不含客户端 IP.
package cache

import (
	"container/list"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jnuse/cfdoh/internal/config"
	"github.com/jnuse/cfdoh/internal/wire"
)

// State is the read-time judgment of a cache hit.
type State string

// Cache hit states.
const (
	StateFresh   State = "fresh"
	StateRefresh State = "refresh"
	StateStale   State = "stale"
)

const (
	shardCount    = 16
	minEntries    = 128
	maxEntriesCap = 65536
	// staleResponseTTL is the TTL presented to clients when serving expired
	// data (RFC 8767 recommendation).
	staleResponseTTL = 30
	snapshotVersion  = 1
)

// now is the clock hook; tests shift it to exercise TTL windows.
var now = func() int64 { return time.Now().UnixMilli() }

// Identity is the two-segment cache key: Key is the stored map key, Text the
// human-readable form for explain output.
type Identity struct {
	Key  string
	Text string
}

// IdentityOf builds the cache identity of a query: canonical qname, type,
// class, DO, CD, ECS identity and the variant segment (request options, pool
// scope, generation tags). Exactly one question is required.
func IdentityOf(q *wire.Packet, ecsID, variant string) (*Identity, error) {
	if len(q.Questions) != 1 {
		return nil, errors.New("exactly one DNS question is required")
	}
	question := q.Questions[0]
	if ecsID == "" {
		ecsID = "none"
	}
	if variant == "" {
		variant = "default"
	}
	text := strings.Join([]string{
		wire.CanonicalName(question.Name),
		strconv.Itoa(int(question.Type)),
		strconv.Itoa(int(question.Class)),
		"do=" + digit(dnssecOK(q)),
		"cd=" + digit(q.Header.CD()),
		"ecs=" + ecsID,
		"variant=" + variant,
	}, "|")
	return &Identity{Key: text, Text: text}, nil
}

// Hit is one cache read result; Packet carries the stored answer (transaction
// ID zero) and the caller patches its own ID. State is the read-time judgment;
// OrigTTL is the TTL the entry was stored with.
type Hit struct {
	Packet  []byte
	State   State
	OrigTTL int
}

type entry struct {
	key       string
	packet    []byte
	expiresAt int64 // unix milliseconds
	origTTL   int
}

type shard struct {
	mu       sync.Mutex
	entries  map[string]*list.Element
	order    *list.List
	capacity int
}

// Cache is a sharded LRU safe for concurrent use.
type Cache struct {
	shards []*shard
}

// New builds a cache with the entry capacity clamped into [128, 65536],
// spread over 16 independently locked shards.
func New(maxEntries int) *Cache {
	if maxEntries < minEntries {
		maxEntries = minEntries
	}
	if maxEntries > maxEntriesCap {
		maxEntries = maxEntriesCap
	}
	c := &Cache{shards: make([]*shard, shardCount)}
	perShard := (maxEntries + shardCount - 1) / shardCount
	for i := range c.shards {
		c.shards[i] = &shard{entries: make(map[string]*list.Element), order: list.New(), capacity: perShard}
	}
	return c
}

func (c *Cache) shardOf(key string) *shard {
	h := fnv.New32a()
	h.Write([]byte(key))
	return c.shards[h.Sum32()%shardCount]
}

// Get returns the cached answer and its state. Expired entries inside the
// stale window come back with TTL 30 and State stale; entries past the window
// (or with stale serving disabled) are dropped. The prefetch window marks
// entries for background refresh. Both windows are read-time config policy.
func (c *Cache) Get(id *Identity, cfg *config.Config) *Hit {
	if id == nil || cfg == nil {
		return nil
	}
	s := c.shardOf(id.Key)
	s.mu.Lock()
	el, ok := s.entries[id.Key]
	if !ok {
		s.mu.Unlock()
		return nil
	}
	e := el.Value.(*entry)
	s.order.MoveToFront(el)
	remaining := e.expiresAt - now()
	if remaining <= 0 {
		staleWindow := int64(cfg.CacheStaleTTL) * 1000
		if staleWindow <= 0 || -remaining > staleWindow {
			s.remove(el)
			s.mu.Unlock()
			return nil
		}
		s.mu.Unlock()
		return &Hit{Packet: withTTL(e.packet, staleResponseTTL), State: StateStale, OrigTTL: e.origTTL}
	}
	packet := append([]byte(nil), e.packet...)
	origTTL := e.origTTL
	s.mu.Unlock()

	state := StateFresh
	if cfg.CachePrefetchPercent > 0 && remaining <= int64(origTTL)*int64(cfg.CachePrefetchPercent)*10 {
		state = StateRefresh
	}
	return &Hit{Packet: packet, State: state, OrigTTL: origTTL}
}

// Put validates, TTL-clamps and stores an answer. SERVFAIL (and anything
// with a computed TTL of zero) is never stored. The stored packet is ID
// normalized; the returned ttl is the clamped value actually stored.
func (c *Cache) Put(id *Identity, packet []byte, cfg *config.Config) (int, bool) {
	if id == nil || cfg == nil {
		return 0, false
	}
	parsed, err := wire.Parse(packet)
	if err != nil {
		return 0, false
	}
	ttl := wire.ResponseTTL(parsed, cfg.CacheMinTTL, cfg.CacheMaxTTL, cfg.NegativeCacheMaxTTL)
	if ttl <= 0 {
		return 0, false
	}
	e := &entry{
		key:       id.Key,
		packet:    wire.PatchID(packet, 0),
		expiresAt: now() + int64(ttl)*1000,
		origTTL:   ttl,
	}
	s := c.shardOf(id.Key)
	s.mu.Lock()
	defer s.mu.Unlock()
	if el, ok := s.entries[id.Key]; ok {
		el.Value = e
		s.order.MoveToFront(el)
		return ttl, true
	}
	el := s.order.PushFront(e)
	s.entries[id.Key] = el
	for s.order.Len() > s.capacity {
		oldest := s.order.Back()
		if oldest == nil {
			break
		}
		delete(s.entries, oldest.Value.(*entry).key)
		s.order.Remove(oldest)
	}
	return ttl, true
}

// Len reports the total entry count (tests and diagnostics).
func (c *Cache) Len() int {
	total := 0
	for _, s := range c.shards {
		s.mu.Lock()
		total += len(s.entries)
		s.mu.Unlock()
	}
	return total
}

func (s *shard) remove(el *list.Element) {
	delete(s.entries, el.Value.(*entry).key)
	s.order.Remove(el)
}

// withTTL rewrites every non-OPT record TTL across all sections.
func withTTL(packet []byte, ttl int) []byte {
	parsed, err := wire.Parse(packet)
	if err != nil {
		return append([]byte(nil), packet...)
	}
	patch := func(records []wire.Record) {
		for i := range records {
			if _, isOpt := records[i].RData.(wire.Opt); !isOpt {
				records[i].TTL = uint32(ttl)
			}
		}
	}
	patch(parsed.Answers)
	patch(parsed.Authorities)
	patch(parsed.Additionals)
	out, err := parsed.Encode()
	if err != nil {
		return append([]byte(nil), packet...)
	}
	return out
}

func dnssecOK(q *wire.Packet) bool {
	for _, r := range q.Additionals {
		if opt, ok := r.RData.(wire.Opt); ok && opt.DO {
			return true
		}
	}
	return false
}

func digit(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// snapshotFile is the on-disk snapshot; the format carries a version so a
// future change can still read older files. Client IPs never appear here.
type snapshotFile struct {
	Version int             `json:"version"`
	Entries []snapshotEntry `json:"entries"`
}

type snapshotEntry struct {
	Key       string `json:"key"`
	ExpiresAt int64  `json:"expires_at"`
	TTL       int    `json:"ttl"`
	Packet    string `json:"packet"` // base64 wire bytes
}

// SaveSnapshot writes all entries atomically (temp file + rename) as JSON.
func (c *Cache) SaveSnapshot(path string) error {
	snap := snapshotFile{Version: snapshotVersion}
	for _, s := range c.shards {
		s.mu.Lock()
		for el := s.order.Front(); el != nil; el = el.Next() {
			e := el.Value.(*entry)
			snap.Entries = append(snap.Entries, snapshotEntry{
				Key:       e.key,
				ExpiresAt: e.expiresAt,
				TTL:       e.origTTL,
				Packet:    base64.StdEncoding.EncodeToString(e.packet),
			})
		}
		s.mu.Unlock()
	}
	data, err := json.MarshalIndent(&snap, "", " ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// LoadSnapshot reads a snapshot back, keeping only unexpired entries and
// respecting capacity. A missing file is not an error (first boot); corrupt
// files and unknown versions are.
func (c *Cache) LoadSnapshot(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var snap snapshotFile
	if err := json.Unmarshal(data, &snap); err != nil {
		return fmt.Errorf("cache snapshot %s: %w", filepath.Base(path), err)
	}
	if snap.Version != snapshotVersion {
		return fmt.Errorf("cache snapshot %s: unsupported version %d", filepath.Base(path), snap.Version)
	}
	current := now()
	for _, se := range snap.Entries {
		if se.ExpiresAt <= current {
			continue
		}
		packet, err := base64.StdEncoding.DecodeString(se.Packet)
		if err != nil || len(packet) == 0 {
			continue
		}
		e := &entry{key: se.Key, packet: packet, expiresAt: se.ExpiresAt, origTTL: se.TTL}
		s := c.shardOf(se.Key)
		s.mu.Lock()
		if el, ok := s.entries[se.Key]; ok {
			el.Value = e
			s.order.MoveToFront(el)
		} else {
			el := s.order.PushFront(e)
			s.entries[se.Key] = el
			for s.order.Len() > s.capacity {
				oldest := s.order.Back()
				if oldest == nil {
					break
				}
				delete(s.entries, oldest.Value.(*entry).key)
				s.order.Remove(oldest)
			}
		}
		s.mu.Unlock()
	}
	return nil
}
