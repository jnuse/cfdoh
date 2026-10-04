package ech

import (
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"os"
)

// 探针态快照: 发布域名解析缓存与 Meta 状态的序列化落盘与恢复. 契约:
// .trellis/spec/arch/ech.md — metaGen 不入快照, 重启后从当前状态重新起算;
// Meta 配置以 base64 存, 空串表示暂停态; 文件不存在视为无状态, 内容损坏
// 记日志后保持空态, 不阻塞启动.

const snapshotVersion = 1

type snapshotFile struct {
	Version int                        `json:"version"`
	Publish map[string]snapshotPublish `json:"publish"` // 发布域名解析缓存
	Meta    *snapshotMeta              `json:"meta"`    // nil 表示种子态
}

type snapshotPublish struct {
	Config    string `json:"config"` // base64 ECHConfigList
	ExpiresAt int64  `json:"expiresAt"`
}

type snapshotMeta struct {
	Config string `json:"config"` // base64; 空串表示暂停态
	Until  int64  `json:"until"`
	Source string `json:"source"`
	Reason string `json:"reason"`
}

// SaveState serializes the publish-domain cache and the Meta override to
// path; the write is atomic (same-directory temporary file + rename). The
// generation counter is not persisted.
func SaveState(path string) error {
	mu.Lock()
	file := snapshotFile{Version: snapshotVersion, Publish: make(map[string]snapshotPublish, len(publish))}
	for domain, cached := range publish {
		file.Publish[domain] = snapshotPublish{
			Config:    base64.StdEncoding.EncodeToString(cached.data),
			ExpiresAt: cached.expiresAt,
		}
	}
	if meta != nil {
		entry := &snapshotMeta{Until: meta.until, Source: meta.source, Reason: meta.reason}
		if meta.config != nil {
			entry.Config = base64.StdEncoding.EncodeToString(meta.config)
		}
		file.Meta = entry
	}
	mu.Unlock()

	data, err := json.Marshal(file)
	if err != nil {
		return err
	}
	return writeStateFile(path, data)
}

// LoadState restores the publish-domain cache and the Meta override from a
// SaveState snapshot, skipping expired entries. A missing file is a no-op;
// a corrupt file or unknown version logs a warning and keeps the current
// state. metaGen is untouched (recomputed from the restored state onwards).
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
		slog.Warn("ech state snapshot unreadable; keeping empty state", "path", path, "error", err)
		return nil
	}
	if file.Version != snapshotVersion {
		slog.Warn("ech state snapshot has unknown version; keeping empty state", "path", path, "version", file.Version)
		return nil
	}

	current := now()
	mu.Lock()
	defer mu.Unlock()
	publish = make(map[string]*cachedConfig)
	publishOrder = nil
	for domain, entry := range file.Publish {
		if domain == "" || entry.ExpiresAt <= current {
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(entry.Config)
		if err != nil || !validEchBytes(decoded) {
			continue // defensive: snapshots only ever contain valid lists
		}
		storePublishLocked(domain, &cachedConfig{data: decoded, expiresAt: entry.ExpiresAt})
	}
	meta = nil
	if m := file.Meta; m != nil && m.Until > current {
		switch {
		case m.Config == "":
			meta = &metaOverride{until: m.Until, source: m.Source, reason: m.Reason}
		default:
			if decoded, err := base64.StdEncoding.DecodeString(m.Config); err == nil && validEchBytes(decoded) {
				meta = &metaOverride{config: decoded, until: m.Until, source: m.Source, reason: m.Reason}
			}
		}
	}
	return nil
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
