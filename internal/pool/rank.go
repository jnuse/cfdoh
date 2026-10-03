package pool

import (
	"fmt"

	"github.com/jnuse/cfdoh/internal/wire"
)

// Capacity constants (spec: 集中一处定义).
const (
	// PoolSize is the per-family serving size.
	PoolSize = 6
	// MaxScopedPools caps client-prefix pools, MaxDefaultSources caps
	// self-learning sources, MaxIspPools caps operator pools, MaxHostSources
	// caps per-host pool reporting sources.
	MaxScopedPools    = 32
	MaxDefaultSources = 8
	MaxIspPools       = 16
	MaxHostSources    = 8
	// minConsensus: below this many majority-vouched IPs the per-prober
	// lists are interleaved instead.
	minConsensus = 2
	// maxPerBlock: addresses served from one /24 (IPv6 /48).
	maxPerBlock = 2
)

// ScopeNational is the reserved nationwide pool scope.
const ScopeNational = "isp:national"

// addressBlock keys an address by its /24 (IPv4) or /48 (IPv6) block.
func addressBlock(ip string) string {
	if containsColon(ip) {
		if parsed, err := wire.ParseIPv6(ip); err == nil {
			return fmt.Sprintf("%d.%d.%d.%d.%d.%d",
				parsed[0], parsed[1], parsed[2], parsed[3], parsed[4], parsed[5])
		}
		return ip
	}
	if dot := lastDot(ip); dot > 0 {
		return ip[:dot]
	}
	return ip
}

func containsColon(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			return true
		}
	}
	return false
}

func lastDot(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '.' {
			return i
		}
	}
	return -1
}

type rankedIP struct {
	ip    string
	votes int
	avg   float64
}

// CombineRankings merges per-prober rankings (best first). An IP qualifies
// when a strict majority of probers vouches for it; more votes rank first,
// then the better average position; at most maxPerBlock addresses per block
// survive. With less agreement the lists are interleaved so every prober
// still contributes.
func CombineRankings(lists [][]string, size int) []string {
	var nonEmpty [][]string
	for _, list := range lists {
		if len(list) > 0 {
			nonEmpty = append(nonEmpty, list)
		}
	}
	if len(nonEmpty) == 0 {
		return nil
	}
	if len(nonEmpty) == 1 {
		return trimSize(nonEmpty[0], size)
	}
	needed := len(nonEmpty)/2 + 1
	type tally struct {
		votes     int
		positions int
	}
	tallies := make(map[string]*tally)
	for _, list := range nonEmpty {
		for index, ip := range list {
			entry := tallies[ip]
			if entry == nil {
				entry = &tally{}
				tallies[ip] = entry
			}
			entry.votes++
			entry.positions += index
		}
	}
	var consensus []rankedIP
	for ip, entry := range tallies {
		if entry.votes >= needed {
			consensus = append(consensus, rankedIP{
				ip:    ip,
				votes: entry.votes,
				avg:   float64(entry.positions) / float64(entry.votes),
			})
		}
	}
	sortByRank(consensus)
	perBlock := make(map[string]int)
	var out []string
	for _, item := range consensus {
		block := addressBlock(item.ip)
		if perBlock[block] >= maxPerBlock {
			continue
		}
		perBlock[block]++
		out = append(out, item.ip)
	}
	if len(out) >= minConsensus {
		return trimSize(out, size)
	}

	// too little agreement: interleave round-robin, skipping duplicates
	var interleaved []string
	seen := make(map[string]bool)
	for index := 0; len(interleaved) < size; index++ {
		progressed := false
		for _, list := range nonEmpty {
			if index >= len(list) {
				continue
			}
			progressed = true
			ip := list[index]
			if !seen[ip] {
				seen[ip] = true
				interleaved = append(interleaved, ip)
				if len(interleaved) >= size {
					break
				}
			}
		}
		if !progressed {
			break
		}
	}
	return interleaved
}

func trimSize(list []string, size int) []string {
	if len(list) <= size {
		return append([]string(nil), list...)
	}
	return append([]string(nil), list[:size]...)
}

func sortByRank(items []rankedIP) {
	for i := 1; i < len(items); i++ {
		for j := i; j > 0; j-- {
			a, b := items[j-1], items[j]
			if a.votes > b.votes || (a.votes == b.votes && a.avg < b.avg) ||
				(a.votes == b.votes && a.avg == b.avg && a.ip < b.ip) {
				break
			}
			items[j-1], items[j] = b, a
		}
	}
}
