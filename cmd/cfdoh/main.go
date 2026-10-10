// Command cfdoh is the server entry point: it loads the configuration,
// restores the cache and probe-state snapshots, schedules the background
// refresh tasks, and runs the HTTP service until SIGTERM/SIGINT. The exit
// order is fixed: stop accepting requests, write the snapshots, exit.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/jnuse/cfdoh/internal/cfrange"
	"github.com/jnuse/cfdoh/internal/config"
	"github.com/jnuse/cfdoh/internal/ech"
	"github.com/jnuse/cfdoh/internal/ecs"
	"github.com/jnuse/cfdoh/internal/h3"
	"github.com/jnuse/cfdoh/internal/httpapi"
	"github.com/jnuse/cfdoh/internal/hubfeed"
	"github.com/jnuse/cfdoh/internal/pool"
	"github.com/jnuse/cfdoh/internal/resolver"
)

const (
	cfrangeRefreshInterval = 24 * time.Hour
	cacheSnapshotInterval  = 10 * time.Minute
)

// probeStatePaths derives the pool/h3/ech snapshot file names from the
// directory of the cache snapshot path.
func probeStatePaths(cachePath string) (poolState, h3State, echState string) {
	dir := filepath.Dir(cachePath)
	return filepath.Join(dir, "pool-state.json"),
		filepath.Join(dir, "h3-state.json"),
		filepath.Join(dir, "ech-state.json")
}

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	slog.Info("startup", "version", httpapi.Version, "config", "\n"+cfg.SanitizedSummary())

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()

	// Boot restore: the Cloudflare ranges first (the pools and the rewrite
	// chain need them), then the cache and probe-state snapshots. Any
	// missing or corrupt snapshot only logs; startup never blocks.
	if _, err := cfrange.Load(ctx, cfg); err != nil {
		slog.Warn("cloudflare ranges unavailable at boot", "error", err.Error())
	}
	// The dynamic ECS domain table loads synchronously at boot (a failed
	// fetch keeps the previous/empty table and only logs) and refreshes on
	// the daily schedule below.
	if cfg.EcsDomainsURL != "" {
		if n, err := ecs.LoadDomains(ctx, cfg.EcsDomainsURL, cfg); err != nil {
			slog.Warn("ecs domain table unavailable at boot", "error", err.Error())
		} else {
			slog.Info("event", "event", "ecs_domains_loaded", "detail", fmt.Sprintf("entries=%d source=boot", n))
		}
	}
	if cfg.CachePersistPath != "" {
		if err := resolver.LoadCacheSnapshot(cfg.CachePersistPath, cfg); err != nil {
			slog.Warn("cache snapshot not restored", "error", err.Error())
		}
		poolState, h3State, echState := probeStatePaths(cfg.CachePersistPath)
		if err := pool.LoadState(poolState); err != nil {
			slog.Warn("pool state not restored", "error", err.Error())
		}
		if err := h3.LoadState(h3State); err != nil {
			slog.Warn("h3 state not restored", "error", err.Error())
		}
		if err := ech.LoadState(echState); err != nil {
			slog.Warn("ech state not restored", "error", err.Error())
		}
	}

	// Background tasks, all bound to the same ctx: the public pool feed,
	// the daily Cloudflare range refresh and the periodic cache snapshot.
	if err := hubfeed.Start(ctx, cfg); err != nil {
		slog.Warn("pool feed not started", "error", err.Error())
	}
	go schedule(ctx, cfrangeRefreshInterval, false, func() {
		if _, err := cfrange.Load(ctx, cfg); err != nil {
			slog.Warn("cloudflare range refresh failed", "error", err.Error())
		}
	})
	if cfg.EcsDomainsURL != "" {
		go schedule(ctx, cfrangeRefreshInterval, false, func() {
			if n, err := ecs.LoadDomains(ctx, cfg.EcsDomainsURL, cfg); err != nil {
				slog.Warn("ecs domain table refresh failed, keeping the previous table", "error", err.Error())
			} else {
				slog.Info("event", "event", "ecs_domains_loaded", "detail", fmt.Sprintf("entries=%d source=scheduled", n))
			}
		})
	}
	if cfg.CachePersistPath != "" {
		go schedule(ctx, cacheSnapshotInterval, false, func() {
			if err := snapshotAll(cfg); err != nil {
				slog.Warn("periodic snapshot failed", "error", err.Error())
			}
		})
	}

	// Run blocks until the signal cancels ctx (the HTTP server is shut
	// down inside), then the snapshots close the shutdown order.
	serveErr := httpapi.New(cfg).Run(ctx)
	if serveErr != nil {
		slog.Error("http service stopped with error", "error", serveErr.Error())
	}
	if cfg.CachePersistPath != "" {
		if err := snapshotAll(cfg); err != nil {
			slog.Warn("shutdown snapshot failed", "error", err.Error())
		} else {
			slog.Info("snapshots written", "dir", filepath.Dir(cfg.CachePersistPath))
		}
	}
	if serveErr != nil {
		return fmt.Errorf("http service: %w", serveErr)
	}
	return nil
}

// schedule runs fn on every tick until ctx is done; runFirst controls
// whether fn fires immediately (boot already loaded some state synchronously).
func schedule(ctx context.Context, interval time.Duration, runFirst bool, fn func()) {
	if runFirst {
		fn()
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			fn()
		}
	}
}

// snapshotAll writes the cache and the three probe-state files.
func snapshotAll(cfg *config.Config) error {
	if err := resolver.SaveCacheSnapshot(cfg.CachePersistPath); err != nil {
		return err
	}
	poolState, h3State, echState := probeStatePaths(cfg.CachePersistPath)
	if err := pool.SaveState(poolState); err != nil {
		return err
	}
	if err := h3.SaveState(h3State); err != nil {
		return err
	}
	return ech.SaveState(echState)
}
