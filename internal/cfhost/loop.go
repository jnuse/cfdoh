package cfhost

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"reflect"
	"time"
)

// Main loop orchestration: one RunOnce pass = fetch candidates -> probe ->
// hysteresis decision -> hosts update -> state save. RunLoop holds the
// single-instance lock and repeats passes on the configured interval.

// runProbes is the probe sweep seam (production: probeCandidates); tests
// inject deterministic outcomes to exercise the hosts-update path offline.
var runProbes = probeCandidates

// RunOnce executes one full pass. When every source fails and no previous
// candidate list exists it returns an error without touching hosts. When the
// v4 sweep fails entirely, hosts stays untouched but the state is updated.
// A transient hosts read/write failure skips the round: hosts, the current
// addresses and the fail streak stay as-is while the state (next run,
// candidates) is saved, so the daemon retries next cycle.
func RunOnce(ctx context.Context, cfg *Config) error {
	initLogging(cfg.stateDir())

	st, _ := loadState(cfg.StatePath)
	// Surface this process's file-log health to `cfhost status` (a service
	// daemon cannot show its stderr to anyone; see initLogging).
	st.LogNote = logNote()

	cands, allFailed := fetchCandidates(ctx, cfg.Sources, defaultFetcher, cfg.CandidateLimit)
	if allFailed || len(cands) == 0 {
		fallback := parseStateCandidates(st.Candidates)
		if len(fallback) == 0 {
			return fmt.Errorf("cfhost: no candidate sources succeeded and no previous candidates available")
		}
		cands = fallback
	}

	outcomes := runProbes(ctx, cands, cfg.probeOptions())
	byAddr := make(map[netip.Addr]probeOutcome, len(outcomes))
	okCount := 0
	for _, o := range outcomes {
		byAddr[o.addr] = o
		if o.ok {
			okCount++
		}
	}
	v4top, v6top := topByFamily(outcomes)

	// oldCur feeds the per-pass summary line: the address in force when
	// this pass started (st.CurrentV4 is overwritten by the decision below).
	oldCur := st.CurrentV4

	now := time.Now()
	st.NextRun = now.Add(cfg.Interval).Unix()
	st.Candidates = addrStrings(cands)

	// passDone emits the one-line per-pass summary: every pass logs exactly
	// one line, so a silent gap in the log can only mean the process was not
	// running. tested/ok describe the sweep, best_v4 the winner, decision
	// the outcome (updated / forced / kept / v4-fail / skipped).
	passDone := func(decision string) {
		best := "none 0ms"
		if v4top != nil {
			best = fmt.Sprintf("%s %dms", v4top.addr.String(), v4top.median.Milliseconds())
		}
		slog.Info("event", "event", "pass_done", "detail",
			fmt.Sprintf("tested=%d ok=%d best_v4=%s decision=%s", len(cands), okCount, best, decision))
	}

	if v4top == nil {
		// Full v4 sweep failure: keep hosts as-is (PRD F-024).
		st.FailStreak++
		st.LastSummary = fmt.Sprintf("tested=%d ok=%d best_v4=none 0ms", len(cands), okCount)
		if err := saveState(cfg.StatePath, st); err != nil {
			slog.Warn("cfhost: state save failed", "error", err.Error())
		}
		passDone("v4-fail")
		return nil
	}

	// --- v4 hysteresis ---
	curV4, curV4Err := netip.ParseAddr(st.CurrentV4)
	hasCurV4 := false
	curV4Alive := false
	curV4Median := time.Duration(0)
	if curV4Err == nil && st.CurrentV4 != "" {
		hasCurV4 = true
		if o, probed := byAddr[curV4.Unmap()]; probed && o.ok {
			curV4Median = o.median
			curV4Alive = true
		}
	}
	keepV4, streak, forced := decideHysteresis(hasCurV4, curV4Alive, st.FailStreak,
		cfg.FailoverRounds, curV4Median, v4top.median, cfg.Hysteresis)
	newV4 := v4top.addr
	if keepV4 {
		newV4 = curV4
	}

	// --- v6 hysteresis (no fail-streak; v6 loss keeps the old entry) ---
	newV6, hasV6 := decideV6(st.CurrentV6, byAddr, v6top, cfg.Hysteresis)

	written, err := updateHosts(cfg.HostsPath, cfg.ManagedDomains, newV4, newV6, hasV6)
	if err != nil {
		// Transient hosts read/write failure (errHostsSkipped): nothing was
		// written, the current addresses and the fail streak stay as-is, and
		// the scheduled next run persists so the daemon stays alive and
		// retries next cycle. A hosts write failure must never terminate the
		// daemon.
		if serr := saveState(cfg.StatePath, st); serr != nil {
			slog.Warn("cfhost: state save failed", "error", serr.Error())
		}
		passDone("skipped")
		return nil
	}
	st.FailStreak = streak
	st.CurrentV4 = newV4.String()
	st.CurrentV6 = ""
	if hasV6 {
		st.CurrentV6 = newV6.String()
	}
	st.LastSummary = fmt.Sprintf("tested=%d ok=%d best_v4=%s %dms",
		len(cands), okCount, v4top.addr.String(), v4top.median.Milliseconds())

	if written {
		flushDNS()
	}

	// decision detail: what changed and against which baseline
	switch {
	case forced:
		slog.Info("event", "event", "pass_done", "detail",
			fmt.Sprintf("tested=%d ok=%d best_v4=%s %dms decision=forced old=%s (fail-streak)",
				len(cands), okCount, v4top.addr.String(), v4top.median.Milliseconds(), oldCur))
	case keepV4:
		gain := 0.0
		if curV4Median > 0 {
			gain = (float64(curV4Median-v4top.median) / float64(curV4Median)) * 100
		}
		slog.Info("event", "event", "pass_done", "detail",
			fmt.Sprintf("tested=%d ok=%d best_v4=%s %dms decision=kept current=%s gain=%.1f%%",
				len(cands), okCount, v4top.addr.String(), v4top.median.Milliseconds(), oldCur, gain))
	default:
		// a switch decision: the block was written, or the rendered block
		// already matched the file (a state/file reconciliation pass)
		slog.Info("event", "event", "pass_done", "detail",
			fmt.Sprintf("tested=%d ok=%d best_v4=%s %dms decision=updated old=%s",
				len(cands), okCount, v4top.addr.String(), v4top.median.Milliseconds(), oldCur))
	}

	if err := saveState(cfg.StatePath, st); err != nil {
		slog.Warn("cfhost: state save failed", "error", err.Error())
	}
	return nil
}

// RunOnceLocked runs one pass under the single-instance lock. run-once
// shares the state file and hosts with the daemon; without the lock two
// processes race (state file last-writer-wins, hosts last-rename-wins) and
// can tear the recorded current address away from the hosts block. A live
// holder (daemon or another run-once) refuses the run; a stale lock is
// taken over — matching daemon startup semantics.
func RunOnceLocked(ctx context.Context, cfg *Config) error {
	release, err := acquireLock(cfg.StatePath)
	if err != nil {
		return err
	}
	defer release()
	return RunOnce(ctx, cfg)
}

// RunLoop acquires the single-instance lock and repeats RunOnce passes,
// sleeping until next_run between passes. On Windows, when started by the
// service manager it runs inside the service control loop instead.
func RunLoop(ctx context.Context, cfg *Config) error {
	initLogging(cfg.stateDir())
	return runSupervised(ctx, cfg)
}

// loopWithLock is the plain (non-service) loop body, shared by both platforms.
func loopWithLock(ctx context.Context, cfg *Config) error {
	release, err := acquireLock(cfg.StatePath)
	if err != nil {
		return err
	}
	defer release()
	for {
		cfg = reloadConfig(cfg)
		if err := RunOnce(ctx, cfg); err != nil {
			return err
		}
		st, _ := loadState(cfg.StatePath)
		timer := time.NewTimer(nextDelay(st, cfg.Interval))
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

// reloadConfig refreshes the configuration before each daemon pass so
// cfhost.json edits apply without a restart (run-once reads fresh on every
// invocation by nature). A failed or invalid reload keeps the previous
// configuration for this pass — a broken file must never kill the daemon.
// A reload that moves StatePath or HostsPath is refused with a warning:
// the running lock and the hosts anchor belong to the startup
// configuration; relocating them requires a restart.
func reloadConfig(cur *Config) *Config {
	fresh, err := LoadConfig()
	if err != nil {
		slog.Warn("cfhost: config reload failed, keeping the previous configuration", "error", err.Error())
		return cur
	}
	if fresh.StatePath != cur.StatePath || fresh.HostsPath != cur.HostsPath {
		slog.Warn("cfhost: config reload wants a new StatePath/HostsPath; restart to apply, keeping the previous configuration",
			"state_path", fresh.StatePath, "hosts_path", fresh.HostsPath)
		return cur
	}
	if !reflect.DeepEqual(fresh, cur) {
		slog.Info("event", "event", "config_reloaded", "detail", "cfhost.json changed; applied from this pass")
	}
	return fresh
}

// nextDelay returns how long the loop sleeps before the next pass. A
// missing or stale next_run (e.g. the state file could not be saved) falls
// back to a full interval so the loop never collapses into a busy spin.
func nextDelay(st clientState, interval time.Duration) time.Duration {
	if delay := time.Until(time.Unix(st.NextRun, 0)); delay > 0 {
		return delay
	}
	return interval
}

// decideHysteresis decides whether to keep the current v4 address:
//   - no current address            -> switch (fresh install)
//   - current failed this sweep     -> streak++; at FailoverRounds force a
//     switch, otherwise keep
//   - current alive                 -> switch only when the new median beats
//     current * (1 - hysteresis)
func decideHysteresis(hasCur, curOK bool, curStreak, failoverRounds int,
	curMedian, newMedian time.Duration, hysteresis float64) (keep bool, streak int, forced bool) {
	if !hasCur {
		return false, 0, false
	}
	if !curOK {
		s := curStreak + 1
		if s >= failoverRounds {
			return false, 0, true
		}
		return true, s, false
	}
	threshold := time.Duration(float64(curMedian) * (1 - hysteresis))
	if newMedian < threshold {
		return false, 0, false
	}
	return true, 0, false
}

// decideV6 picks the v6 address: a failed sweep or an insufficient gain keeps
// the current entry; a missing or failed current entry adopts the new top.
func decideV6(cur string, byAddr map[netip.Addr]probeOutcome, top *probeOutcome, hysteresis float64) (netip.Addr, bool) {
	if top == nil || !top.ok {
		if cur == "" {
			return netip.Addr{}, false
		}
		if a, err := netip.ParseAddr(cur); err == nil {
			return a, true
		}
		return netip.Addr{}, false
	}
	if cur == "" {
		return top.addr, true
	}
	curAddr, err := netip.ParseAddr(cur)
	if err != nil {
		return top.addr, true
	}
	o, probed := byAddr[curAddr.Unmap()]
	if !probed || !o.ok {
		return top.addr, true
	}
	threshold := time.Duration(float64(o.median) * (1 - hysteresis))
	if top.median < threshold {
		return top.addr, true
	}
	return curAddr, true
}

// topByFamily returns the best (lowest median, ties to earlier candidate
// order) probe outcome per address family.
func topByFamily(outcomes []probeOutcome) (v4, v6 *probeOutcome) {
	for i := range outcomes {
		o := &outcomes[i]
		if !o.ok {
			continue
		}
		if o.addr.Is4() {
			if v4 == nil || o.median < v4.median {
				v4 = o
			}
		} else {
			if v6 == nil || o.median < v6.median {
				v6 = o
			}
		}
	}
	return v4, v6
}

func (cfg *Config) probeOptions() probeOptions {
	return probeOptions{
		sni:         cfg.ManagedDomains[0],
		port:        "443",
		concurrency: cfg.Concurrency,
		rounds:      cfg.Rounds,
		timeoutMs:   cfg.Timeout,
		httpVerify:  cfg.HTTPVerify,
	}
}

func (cfg *Config) stateDir() string {
	return stateDirOf(cfg.StatePath)
}

func parseStateCandidates(list []string) []netip.Addr {
	var out []netip.Addr
	for _, s := range list {
		if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, a)
		}
	}
	return out
}

func addrStrings(addrs []netip.Addr) []string {
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.String())
	}
	return out
}
