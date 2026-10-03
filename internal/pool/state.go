package pool

import (
	"encoding/json"
	"log/slog"
	"os"
)

// 探针态快照: 五张池表 (全国自学习, 专属, 运营商, GitHub, 站点) 的序列化
// 落盘与恢复. 契约: .trellis/spec/arch/pool.md — 插入序保留, 载入按序重放
// set (容量淘汰语义不降级); 专属池键为前缀串, 快照不含完整客户端 IP;
// 文件不存在视为无状态, 内容损坏记日志后保持空态, 不阻塞启动.

const snapshotVersion = 1

type snapshotFile struct {
	Version int              `json:"version"`
	Learned []snapshotPool   `json:"learned"` // 全国自学习表, 键为 source
	Scoped  []snapshotScoped `json:"scoped"`  // 专属池, 键为客户端前缀串
	Isp     []snapshotScoped `json:"isp"`     // 运营商池, 键为 "isp:<name>"
	Github  []snapshotHosts  `json:"github"`
	Sites   []snapshotHosts  `json:"sites"`
}

type snapshotPool struct {
	Source    string   `json:"source"`
	IPv4      []string `json:"ipv4"`
	IPv6      []string `json:"ipv6"`
	ExpiresAt int64    `json:"expiresAt"`
}

type snapshotScoped struct {
	Scope     string   `json:"scope"`
	Source    string   `json:"source"`
	IPv4      []string `json:"ipv4"`
	IPv6      []string `json:"ipv6"`
	ExpiresAt int64    `json:"expiresAt"`
}

type snapshotHosts struct {
	Source    string              `json:"source"`
	Hosts     map[string][]string `json:"hosts"`
	ExpiresAt int64               `json:"expiresAt"`
}

// SaveState serializes the five pool tables to path. Entries keep their
// insertion order and verbatim expiry; the write is atomic (same-directory
// temporary file + rename).
func SaveState(path string) error {
	file := snapshotFile{Version: snapshotVersion}

	mu.RLock()
	file.Learned = learnedSnapshots(defaults)
	file.Scoped = scopedSnapshots(scoped)
	file.Isp = scopedSnapshots(ispPools)
	mu.RUnlock()

	github.mu.Lock()
	file.Github = hostSnapshots(github)
	github.mu.Unlock()
	sites.mu.Lock()
	file.Sites = hostSnapshots(sites)
	sites.mu.Unlock()

	data, err := json.Marshal(file)
	if err != nil {
		return err
	}
	return writeStateFile(path, data)
}

// LoadState restores the five pool tables from a SaveState snapshot,
// replaying entries in insertion order through the normal set path.
// A missing file is a no-op; a corrupt file or unknown version logs a
// warning and keeps the current state; expired entries are skipped.
func LoadState(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var file snapshotFile
	if err := json.Unmarshal(data, &file); err != nil {
		slog.Warn("pool state snapshot unreadable; keeping empty state", "path", path, "error", err)
		return nil
	}
	if file.Version != snapshotVersion {
		slog.Warn("pool state snapshot has unknown version; keeping empty state", "path", path, "version", file.Version)
		return nil
	}

	current := now()
	mu.Lock()
	defaults = newPoolTable(MaxDefaultSources)
	scoped = newPoolTable(MaxScopedPools)
	ispPools = newPoolTable(MaxIspPools)
	seenDefault := make(map[string]bool, len(file.Learned))
	for _, entry := range file.Learned {
		if entry.Source == "" || seenDefault[entry.Source] || entry.ExpiresAt <= current {
			continue
		}
		seenDefault[entry.Source] = true
		defaults.set(entry.Source, &learnedPool{
			ipv4: entry.IPv4, ipv6: entry.IPv6, expiresAt: entry.ExpiresAt, source: entry.Source,
		})
	}
	restoreScoped(scoped, file.Scoped, current)
	restoreScoped(ispPools, file.Isp, current)
	mu.Unlock()

	github.restore(file.Github, current)
	sites.restore(file.Sites, current)
	return nil
}

// restoreScoped replays scoped-pool entries (专属池 / 运营商池) in order;
// caller holds mu.
func restoreScoped(t *poolTable, entries []snapshotScoped, current int64) {
	seen := make(map[string]bool, len(entries))
	for _, entry := range entries {
		if entry.Scope == "" || seen[entry.Scope] || entry.ExpiresAt <= current {
			continue
		}
		seen[entry.Scope] = true
		t.set(entry.Scope, &learnedPool{
			ipv4: entry.IPv4, ipv6: entry.IPv6, expiresAt: entry.ExpiresAt, source: entry.Source,
		})
	}
}

// restore rebuilds a per-host pool from a snapshot in insertion order,
// skipping expired entries. Snapshot hosts were canonicalized and validated
// when written; they are trusted as-is.
func (h *hostPools) restore(entries []snapshotHosts, current int64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sources = make(map[string]*hostReport)
	h.order.Init()
	for _, entry := range entries {
		if entry.Source == "" || len(entry.Hosts) == 0 || entry.ExpiresAt <= current {
			continue
		}
		h.sources[entry.Source] = &hostReport{hosts: entry.Hosts, expiresAt: entry.ExpiresAt}
		h.order.PushBack(entry.Source)
		for h.order.Len() > h.cap {
			oldest := h.order.Front()
			delete(h.sources, oldest.Value.(string))
			h.order.Remove(oldest)
		}
	}
}

func learnedSnapshots(t *poolTable) []snapshotPool {
	out := make([]snapshotPool, 0, len(t.entries))
	for _, pool := range t.snapshot() {
		out = append(out, snapshotPool{
			Source: pool.source, IPv4: pool.ipv4, IPv6: pool.ipv6, ExpiresAt: pool.expiresAt,
		})
	}
	return out
}

func scopedSnapshots(t *poolTable) []snapshotScoped {
	out := make([]snapshotScoped, 0, len(t.entries))
	for el := t.order.Front(); el != nil; el = el.Next() {
		key := el.Value.(string)
		pool := t.entries[key]
		out = append(out, snapshotScoped{
			Scope: key, Source: pool.source, IPv4: pool.ipv4, IPv6: pool.ipv6, ExpiresAt: pool.expiresAt,
		})
	}
	return out
}

// hostSnapshots reads a per-host pool; the caller holds h.mu.
func hostSnapshots(h *hostPools) []snapshotHosts {
	out := make([]snapshotHosts, 0, len(h.sources))
	for el := h.order.Front(); el != nil; el = el.Next() {
		source := el.Value.(string)
		report := h.sources[source]
		out = append(out, snapshotHosts{Source: source, Hosts: report.hosts, ExpiresAt: report.expiresAt})
	}
	return out
}

// writeStateFile writes data to path via a same-directory temporary file
// and an atomic rename.
func writeStateFile(path string, data []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}
