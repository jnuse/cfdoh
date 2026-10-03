package h3

import (
	"encoding/json"
	"log/slog"
	"os"
)

// 探针态快照: verdict 来源表的序列化落盘与恢复. 契约: .trellis/spec/arch/h3.md —
// generation 与 lastSnapshot 不入快照, 载入后经 refreshGenerationLocked 从当前
// 状态重新起算; 插入序保留, 容量上限不降级; 文件不存在视为无状态, 内容损坏
// 记日志后保持空态, 不阻塞启动.

const snapshotVersion = 1

type snapshotFile struct {
	Version int              `json:"version"`
	Sources []snapshotSource `json:"sources"`
}

type snapshotSource struct {
	Source    string          `json:"source"`
	Hosts     map[string]bool `json:"hosts"`
	ExpiresAt int64           `json:"expiresAt"`
}

// SaveState serializes the verdict source table to path, keeping insertion
// order and verbatim expiry; the write is atomic (same-directory temporary
// file + rename).
func SaveState(path string) error {
	mu.Lock()
	file := snapshotFile{Version: snapshotVersion, Sources: make([]snapshotSource, 0, len(sources))}
	for el := sourceOrder.Front(); el != nil; el = el.Next() {
		source := el.Value.(string)
		rep := sources[source]
		file.Sources = append(file.Sources, snapshotSource{
			Source: source, Hosts: rep.hosts, ExpiresAt: rep.expiresAt,
		})
	}
	mu.Unlock()

	data, err := json.Marshal(file)
	if err != nil {
		return err
	}
	return writeStateFile(path, data)
}

// LoadState restores the verdict source table from a SaveState snapshot,
// replaying sources in insertion order and skipping expired entries; the
// generation is recomputed from the restored state. A missing file is a
// no-op; a corrupt file or unknown version logs a warning and keeps the
// current state.
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
		slog.Warn("h3 state snapshot unreadable; keeping empty state", "path", path, "error", err)
		return nil
	}
	if file.Version != snapshotVersion {
		slog.Warn("h3 state snapshot has unknown version; keeping empty state", "path", path, "version", file.Version)
		return nil
	}

	current := now()
	mu.Lock()
	defer mu.Unlock()
	sources = make(map[string]*report)
	sourceOrder.Init()
	seen := make(map[string]bool, len(file.Sources))
	for _, entry := range file.Sources {
		if entry.Source == "" || seen[entry.Source] || entry.ExpiresAt <= current || len(entry.Hosts) == 0 {
			continue
		}
		seen[entry.Source] = true
		sources[entry.Source] = &report{hosts: entry.Hosts, expiresAt: entry.ExpiresAt}
		sourceOrder.PushBack(entry.Source)
		for sourceOrder.Len() > maxSources {
			oldest := sourceOrder.Front()
			delete(sources, oldest.Value.(string))
			sourceOrder.Remove(oldest)
		}
	}
	refreshGenerationLocked()
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
