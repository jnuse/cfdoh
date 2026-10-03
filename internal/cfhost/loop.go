package cfhost

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"time"
)

// Main loop orchestration: one RunOnce pass = fetch candidates -> probe ->
// hysteresis decision -> hosts update -> state save. RunLoop holds the
// single-instance lock and repeats passes on the configured interval.

// RunOnce executes one full pass. When every source fails and no previous
// candidate list exists it returns an error without touching hosts. When the
// v4 sweep fails entirely, hosts stays untouched but the state is updated.
func RunOnce(ctx context.Context, cfg *Config) error {
	initLogging(cfg.stateDir())

	st, _ := loadState(cfg.StatePath)

	cands, allFailed := fetchCandidates(ctx, cfg.Sources, defaultFetcher, cfg.CandidateLimit)
	if allFailed || len(cands) == 0 {
		fallback := parseStateCandidates(st.Candidates)
		if len(fallback) == 0 {
			return fmt.Errorf("cfhost: no candidate sources succeeded and no previous candidates available")
		}
		cands = fallback
	}

	outcomes := probeCandidates(ctx, cands, cfg.probeOptions())
	byAddr := make(map[netip.Addr]probeOutcome, len(outcomes))
	okCount := 0
	for _, o := range outcomes {
		byAddr[o.addr] = o
		if o.ok {
			okCount++
		}
	}
	v4top, v6top := topByFamily(outcomes)

	now := time.Now()
	st.NextRun = now.Add(cfg.Interval).Unix()
	st.Candidates = addrStrings(cands)

	if v4top == nil {
		// Full v4 sweep failure: keep hosts as-is (PRD F-024).
		st.FailStreak++
		st.LastSummary = fmt.Sprintf("tested=%d ok=%d best_v4=none 0ms", len(cands), okCount)
		if err := saveState(cfg.StatePath, st); err != nil {
			slog.Warn("cfhost: state save failed", "error", err.Error())
		}
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
	keepV4, streak, _ := decideHysteresis(hasCurV4, curV4Alive, st.FailStreak,
		cfg.FailoverRounds, curV4Median, v4top.median, cfg.Hysteresis)
	newV4 := v4top.addr
	if keepV4 {
		newV4 = curV4
	}
	st.FailStreak = streak

	// --- v6 hysteresis (no fail-streak; v6 loss keeps the old entry) ---
	newV6, hasV6 := decideV6(st.CurrentV6, byAddr, v6top, cfg.Hysteresis)

	written, err := updateHosts(cfg.HostsPath, cfg.ManagedDomains, newV4, newV6, hasV6)
	if err != nil {
		return fmt.Errorf("cfhost: hosts update: %w", err)
	}
	st.CurrentV4 = newV4.String()
	st.CurrentV6 = ""
	if hasV6 {
		st.CurrentV6 = newV6.String()
	}
	st.LastSummary = fmt.Sprintf("tested=%d ok=%d best_v4=%s %dms",
		len(cands), okCount, v4top.addr.String(), v4top.median.Milliseconds())

	if written {
		flushDNS()
		slog.Info("event", "event", "hosts_updated", "detail",
			fmt.Sprintf("domains=%d v4=%s v6=%s", len(cfg.ManagedDomains), newV4.String(), st.CurrentV6))
	} else if keepV4 {
		gain := 0.0
		if curV4Median > 0 {
			gain = (float64(curV4Median-v4top.median) / float64(curV4Median)) * 100
		}
		slog.Info("event", "event", "hosts_kept", "detail",
			fmt.Sprintf("current=%s candidate=%s gain=%.1f%%", newV4.String(), v4top.addr.String(), gain))
	}

	if err := saveState(cfg.StatePath, st); err != nil {
		slog.Warn("cfhost: state save failed", "error", err.Error())
	}
	return nil
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
		if err := RunOnce(ctx, cfg); err != nil {
			return err
		}
		st, _ := loadState(cfg.StatePath)
		delay := time.Until(time.Unix(st.NextRun, 0))
		if delay <= 0 {
			continue
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
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
