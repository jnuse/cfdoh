// Package rewrite applies the answer-enhancement chain to decoded upstream
// responses: Cloudflare detection, preferred-address rewriting, host-pool
// pinning, ECH injection and CNAME flattening.
//
// 契约: .trellis/spec/arch/rewrite.md. 包无状态, 判定结果由调用方在一次请求
// 内缓存复用; 全部函数失败兜底返回原 resp (或 false), 绝不因增强失败丢弃应答;
// 地址记录与 HTTPS 提示必须同步改写, 不允许只改其一.
package rewrite

import (
	"context"
	"strconv"
	"strings"

	"github.com/jnuse/cfdoh/internal/cfrange"
	"github.com/jnuse/cfdoh/internal/config"
	"github.com/jnuse/cfdoh/internal/ech"
	"github.com/jnuse/cfdoh/internal/h3"
	"github.com/jnuse/cfdoh/internal/pool"
	"github.com/jnuse/cfdoh/internal/upstream"
	"github.com/jnuse/cfdoh/internal/wire"
)

// maxServePerFamily caps how many preferred addresses per family one answer
// serves (F-009: 每族 ≤ 6).
const maxServePerFamily = 6

// minECHConfigList is the structural lower bound of an ECHConfigList; shorter
// inputs never reach injection.
const minECHConfigList = 6

// OnCloudflare reports whether qname should be treated as a Cloudflare-served
// (or otherwise ECH-relevant) host. Determination priority: an upstream
// address inside the published ranges > the X-domain cdn.cloudflare.net
// probe > Meta/ECH domain configuration. A nil ctx skips the network probe.
func OnCloudflare(ctx context.Context, qname string, ranges *cfrange.Ranges, cfg *config.Config, upstreamV4, upstreamV6 []string) (bool, error) {
	if anyInRange(upstreamV4, ranges) || anyInRange(upstreamV6, ranges) {
		return true, nil
	}
	if cfg == nil {
		return false, nil
	}
	name := wire.CanonicalName(qname)
	if domainMatch(name, cfg.XDomains) {
		if ctx == nil {
			return false, nil
		}
		v4, v6, err := upstream.ResolveAddresses(ctx, name+".cdn.cloudflare.net", cfg)
		if err != nil {
			return false, err
		}
		return len(v4)+len(v6) > 0, nil
	}
	if domainMatch(name, cfg.MetaDomains) || domainMatch(name, cfg.EchDomains) {
		return true, nil
	}
	return false, nil
}

// UsesCloudflare reports whether any A/AAAA address (or HTTPS hint address)
// of the answer falls inside the published Cloudflare ranges.
func UsesCloudflare(resp *wire.Packet, ranges *cfrange.Ranges) bool {
	if resp == nil {
		return false
	}
	for i := range resp.Answers {
		r := &resp.Answers[i]
		switch rd := r.RData.(type) {
		case wire.A:
			if ranges.Contains(wire.IPv4String(rd.IP)) {
				return true
			}
		case wire.AAAA:
			if ranges.Contains(wire.IPv6String(rd.IP)) {
				return true
			}
		case wire.SVCB:
			_, ipv4, ipv6, _ := wire.DescribeHTTPS(r)
			if anyInRange(ipv4, ranges) || anyInRange(ipv6, ranges) {
				return true
			}
		}
	}
	return false
}

// RewriteAddresses replaces the A/AAAA records and HTTPS address hints of
// a Cloudflare-served answer with the preferred pool (each family capped at
// maxServePerFamily). The rewrite walks the records one by one: only
// records whose address (or hint) falls inside the published ranges are
// replaced or removed, so a mixed answer keeps its non-Cloudflare records
// verbatim (对齐 refer rewriteCloudflareAddresses). With CFDropAAAA the
// in-range AAAA records drop and every HTTPS record of the rewritten answer
// loses its ipv6hint. Every gate miss returns the answer untouched.
func RewriteAddresses(resp *wire.Packet, ranges *cfrange.Ranges, p *pool.Pool, cfg *config.Config) *wire.Packet {
	if resp == nil || cfg == nil || p == nil {
		return resp
	}
	if !cfg.CFRewriteEnabled || (len(p.IPv4) == 0 && len(p.IPv6) == 0) {
		return resp
	}
	if !UsesCloudflare(resp, ranges) {
		return resp
	}
	v4 := firstN(p.IPv4, maxServePerFamily)
	v6 := firstN(p.IPv6, maxServePerFamily)
	resp.Answers = rewriteInRange(cloneAnswers(resp), ranges, v4, v6, cfg.CFDropAAAA)
	return resp
}

// rewriteInRange rewrites each record the published ranges actually cover:
// an in-range A (AAAA) record expands to the whole pool once per owner
// (TTL the owner's in-range minimum, shape from its first in-range record),
// an in-range AAAA drops under dropAAAA, and HTTPS hints follow the same
// per-record range test. Records outside the ranges stay verbatim — a
// mixed answer keeps its non-Cloudflare records instead of being swapped
// wholesale. An in-range AAAA with an empty v6 pool (and no dropAAAA) also
// stays verbatim: an empty family never had addresses to swap in.
func rewriteInRange(records []wire.Record, ranges *cfrange.Ranges, ipv4, ipv6 []string, dropAAAA bool) []wire.Record {
	minTTL := make(map[string]uint32)
	for i := range records {
		if !recordReplaceable(&records[i], ranges, ipv4, ipv6, dropAAAA) {
			continue
		}
		key := familyOwnerKey(&records[i])
		if ttl, ok := minTTL[key]; !ok || records[i].TTL < ttl {
			minTTL[key] = records[i].TTL
		}
	}
	expanded := make(map[string]bool)
	out := make([]wire.Record, 0, len(records))
	for i := range records {
		r := records[i]
		if a, ok := r.RData.(wire.A); ok {
			if len(ipv4) > 0 && ranges.Contains(wire.IPv4String(a.IP)) {
				if key := familyOwnerKey(&r); !expanded[key] {
					expanded[key] = true
					out = append(out, expandOwner(&r, minTTL[key], ipv4, wire.TypeA)...)
				}
				continue
			}
		} else if aaaa, ok := r.RData.(wire.AAAA); ok {
			if ranges.Contains(wire.IPv6String(aaaa.IP)) {
				if dropAAAA {
					continue
				}
				if len(ipv6) > 0 {
					if key := familyOwnerKey(&r); !expanded[key] {
						expanded[key] = true
						out = append(out, expandOwner(&r, minTTL[key], ipv6, wire.TypeAAAA)...)
					}
					continue
				}
			}
		} else if r.Type == wire.TypeHTTPS {
			rewriteHintsInRange(&records[i], ranges, ipv4, ipv6, dropAAAA)
			r = records[i]
		}
		out = append(out, r)
	}
	return out
}

// recordReplaceable reports whether one record would be swapped for pool
// addresses (pass 1 of rewriteInRange: the per-owner TTL minimum only
// counts records that actually get replaced).
func recordReplaceable(r *wire.Record, ranges *cfrange.Ranges, ipv4, ipv6 []string, dropAAAA bool) bool {
	switch rd := r.RData.(type) {
	case wire.A:
		return len(ipv4) > 0 && ranges.Contains(wire.IPv4String(rd.IP))
	case wire.AAAA:
		return len(ipv6) > 0 && !dropAAAA && ranges.Contains(wire.IPv6String(rd.IP))
	}
	return false
}

// familyOwnerKey deduplicates pool expansion per address family and record
// owner: one owner's in-range records expand to the pool exactly once,
// where the first of them stood.
func familyOwnerKey(r *wire.Record) string {
	return strconv.Itoa(int(r.Type)) + "|" + wire.CanonicalName(r.Name)
}

// expandOwner builds one record per pool address from the owner's first
// in-range record; an unparseable pool address skips that address only.
func expandOwner(template *wire.Record, ttl uint32, addrs []string, rtype uint16) []wire.Record {
	out := make([]wire.Record, 0, len(addrs))
	for _, addr := range addrs {
		rd, ok := familyRData(rtype, addr)
		if !ok {
			continue
		}
		out = append(out, wire.Record{
			Name: template.Name, Type: rtype, Class: template.Class, TTL: ttl, RData: rd,
		})
	}
	return out
}

// rewriteHintsInRange rewrites the address hints of one HTTPS record so they
// stay in sync with the per-record rewrite above: a hint the ranges cover is
// replaced with the pool (kept verbatim when that pool family is empty),
// and CFDropAAAA removes the ipv6hint outright — a dropped family must not
// keep advertising addresses through its hint.
func rewriteHintsInRange(r *wire.Record, ranges *cfrange.Ranges, ipv4, ipv6 []string, dropAAAA bool) {
	_, hints4, hints6, _ := wire.DescribeHTTPS(r)
	if len(hints4) > 0 && len(ipv4) > 0 && anyInRange(hints4, ranges) {
		if packed := packHints(ipv4, 4); packed != nil {
			wire.UpsertSvcParam(r, wire.ParamIPv4Hint, packed)
		}
	}
	if len(hints6) > 0 && (dropAAAA || anyInRange(hints6, ranges)) {
		switch {
		case dropAAAA:
			removeSvcParam(r, wire.ParamIPv6Hint)
		case len(ipv6) > 0:
			if packed := packHints(ipv6, 16); packed != nil {
				wire.UpsertSvcParam(r, wire.ParamIPv6Hint, packed)
			}
		default:
			// in-range hint with an empty v6 pool stays verbatim: an empty
			// family has no addresses to swap in (空池不改写, 注册分歧).
		}
	}
}

// RewriteX rewrites answers for the configured X (multi-CDN) domains once
// the CALLER has determined they are currently served by Cloudflare (the
// resolver's classification: an answer address inside the published ranges
// or the "<name>.cdn.cloudflare.net" probe — F-014). A records go to the
// pool, AAAA records are dropped (X answers 403 over IPv6) and HTTPS hints
// follow (v4 replaced, v6 removed). The determination is not re-checked
// here: one request carries one classification verdict, re-deriving it
// locally would diverge from the probe on CNAME-setup hosts.
func RewriteX(resp, q *wire.Packet, p *pool.Pool, cfg *config.Config) *wire.Packet {
	if resp == nil || q == nil || len(q.Questions) == 0 || cfg == nil {
		return resp
	}
	if p == nil || len(p.IPv4) == 0 {
		return resp
	}
	if !domainMatch(q.Questions[0].Name, cfg.XDomains) {
		return resp
	}
	v4 := firstN(p.IPv4, maxServePerFamily)
	answers := cloneAnswers(resp)
	answers = replaceFamily(answers, wire.TypeA, v4)
	answers = dropType(answers, wire.TypeAAAA)
	for i := range answers {
		r := &answers[i]
		if r.Type != wire.TypeHTTPS {
			continue
		}
		if packed := packHints(v4, 4); packed != nil {
			wire.UpsertSvcParam(r, wire.ParamIPv4Hint, packed)
		}
		removeSvcParam(r, wire.ParamIPv6Hint)
	}
	resp.Answers = answers
	return resp
}

// PinAddresses pins the answer's A records to ips and drops every AAAA
// record (pinned hosts are served IPv4-only; an AAAA query loses its AAAA
// records even with no A records to pin — the drop is the point, F-014:
// GitHub 与站点池不返回 AAAA). Only A and AAAA queries pin. The pinned
// block takes the query name's own A records as its template; a CNAME-chain
// answer without query-name A records falls back to the first A record of
// the chain (any owner — the later Flatten step re-owns it under the query
// name), and an answer without any A record synthesizes the pinned block
// under the query name with TTL 60 (对齐 refer pinAddresses). Records of
// unrelated owners ride along untouched. Used for the site and GitHub host
// pools.
func PinAddresses(resp, q *wire.Packet, ips []string) *wire.Packet {
	if resp == nil || q == nil || len(q.Questions) == 0 || len(ips) == 0 {
		return resp
	}
	for _, ip := range ips {
		if _, err := wire.ParseIPv4(ip); err != nil {
			return resp
		}
	}
	qtype := q.Questions[0].Type
	if qtype == wire.TypeAAAA {
		answers := dropType(resp.Answers, wire.TypeAAAA)
		if len(answers) == len(resp.Answers) {
			return resp
		}
		resp.Answers = answers
		return resp
	}
	if qtype != wire.TypeA {
		return resp
	}
	qname := wire.CanonicalName(q.Questions[0].Name)
	qnameFirst, anyFirst := -1, -1
	for i, r := range resp.Answers {
		if r.Type != wire.TypeA {
			continue
		}
		if anyFirst < 0 {
			anyFirst = i
		}
		if qnameFirst < 0 && wire.CanonicalName(r.Name) == qname {
			qnameFirst = i
		}
	}
	// synthesize: no A record at all — the pinned block rides under the
	// query name (TTL 60); otherwise the target owner is the query name when
	// it owns A records, else the first A record's owner (CNAME-chain form).
	synthesize := qnameFirst < 0 && anyFirst < 0
	target := ""
	template := wire.Record{}
	ttl := uint32(60)
	if !synthesize {
		if qnameFirst >= 0 {
			template = resp.Answers[qnameFirst]
		} else {
			template = resp.Answers[anyFirst]
		}
		target = wire.CanonicalName(template.Name)
		ttl = template.TTL
		for _, r := range resp.Answers {
			if r.Type == wire.TypeA && wire.CanonicalName(r.Name) == target && r.TTL < ttl {
				ttl = r.TTL
			}
		}
	}
	answers := make([]wire.Record, 0, len(resp.Answers)+len(ips))
	pin := func() {
		for _, ip := range ips {
			v, err := wire.ParseIPv4(ip)
			if err != nil {
				continue
			}
			name, class := q.Questions[0].Name, wire.ClassIN
			if !synthesize {
				name, class = template.Name, template.Class
			}
			answers = append(answers, wire.Record{
				Name: name, Type: wire.TypeA, Class: class, TTL: ttl, RData: wire.A{IP: v},
			})
		}
	}
	pinned := false
	for _, r := range resp.Answers {
		if r.Type == wire.TypeAAAA {
			continue
		}
		if !synthesize && r.Type == wire.TypeA && wire.CanonicalName(r.Name) == target {
			if !pinned {
				pin()
				pinned = true
			}
			continue
		}
		answers = append(answers, r)
	}
	if synthesize {
		pin()
	}
	resp.Answers = answers
	return resp
}

// PinHTTPSHints replaces the ipv4hint of every HTTPS record with ips and
// removes its ipv6hint, keeping hints in sync with a pinned A-only answer.
// Without HTTPS records the answer is returned untouched.
func PinHTTPSHints(resp *wire.Packet, ips []string) *wire.Packet {
	if resp == nil || len(ips) == 0 {
		return resp
	}
	packed := packHints(ips, 4)
	if packed == nil {
		return resp
	}
	answers := cloneAnswers(resp)
	changed := false
	for i := range answers {
		r := &answers[i]
		if r.Type != wire.TypeHTTPS {
			continue
		}
		if _, ok := r.RData.(wire.SVCB); !ok {
			continue
		}
		wire.UpsertSvcParam(r, wire.ParamIPv4Hint, packed)
		removeSvcParam(r, wire.ParamIPv6Hint)
		changed = true
	}
	if !changed {
		return resp
	}
	resp.Answers = answers
	return resp
}

// InjectECH writes cfgList into the ech parameter of every HTTPS record; an
// answer without HTTPS records gets one synthesized under the query name
// (priority 1, target ".", TTL 300, ech plus alpn, alpn defaulting to h2).
// A non-nil alpn also replaces the ALPN of upstream records — the h3 verdict
// gate must reach existing records, not only synthesized ones; a nil alpn
// keeps the upstream ALPN as published. A config list shorter than
// minECHConfigList leaves the answer untouched.
func InjectECH(resp *wire.Packet, cfgList []byte, alpn []string) *wire.Packet {
	if resp == nil || len(cfgList) < minECHConfigList || len(resp.Questions) == 0 {
		return resp
	}
	qname := resp.Questions[0].Name
	answers := cloneAnswers(resp)
	found := false
	for i := range answers {
		r := &answers[i]
		if r.Type != wire.TypeHTTPS {
			continue
		}
		if _, ok := r.RData.(wire.SVCB); !ok {
			continue
		}
		wire.UpsertSvcParam(r, wire.ParamECH, cfgList)
		if len(alpn) > 0 {
			if packed := packAlpn(alpn); packed != nil {
				wire.UpsertSvcParam(r, wire.ParamALPN, packed)
			}
		}
		found = true
	}
	if !found {
		// a synthetic record always advertises an ALPN list, h2 when ungated
		synthAlpn := alpn
		if len(synthAlpn) == 0 {
			synthAlpn = []string{"h2"}
		}
		params := make([]wire.SvcParam, 0, 2)
		if packed := packAlpn(synthAlpn); packed != nil {
			params = append(params, wire.SvcParam{Key: wire.ParamALPN, Value: packed})
		}
		params = append(params, wire.SvcParam{Key: wire.ParamECH, Value: append([]byte(nil), cfgList...)})
		answers = append(answers, wire.Record{
			Name: qname, Type: wire.TypeHTTPS, Class: wire.ClassIN, TTL: 300,
			RData: wire.SVCB{Priority: 1, Target: ".", Params: params},
		})
	}
	resp.Answers = answers
	return resp
}

// InjectConfigured unconditionally injects the configured base64
// ECHConfigList (ECH_CONFIG_BASE64) into answers for the configured ECH
// domains, ALPN gated by the h3 verdicts. Validation failure returns the
// answer untouched.
func InjectConfigured(resp *wire.Packet, cfg *config.Config) *wire.Packet {
	if resp == nil || cfg == nil || len(resp.Questions) == 0 {
		return resp
	}
	if cfg.EchConfigBase64 == "" || !domainMatch(resp.Questions[0].Name, cfg.EchDomains) {
		return resp
	}
	cfgList, err := ech.Validated(cfg.EchConfigBase64)
	if err != nil {
		return resp
	}
	alpn, _ := h3.AlpnFor(resp.Questions[0].Name, nil)
	return InjectECH(resp, cfgList, alpn)
}

// Flatten moves the records riding a CNAME chain under the query name: when
// the answer starts with a query-name CNAME, every later non-CNAME record is
// re-owned by the query name so A/AAAA and HTTPS share one owner. The CNAME
// records keep their place; anything else is returned untouched.
func Flatten(resp *wire.Packet) *wire.Packet {
	if resp == nil || len(resp.Questions) == 0 || len(resp.Answers) < 2 {
		return resp
	}
	qname := resp.Questions[0].Name
	if resp.Answers[0].Type != wire.TypeCNAME {
		return resp
	}
	if wire.CanonicalName(resp.Answers[0].Name) != wire.CanonicalName(qname) {
		return resp
	}
	answers := cloneAnswers(resp)
	changed := false
	for i := 1; i < len(answers); i++ {
		if answers[i].Type == wire.TypeCNAME {
			continue
		}
		if wire.CanonicalName(answers[i].Name) != wire.CanonicalName(qname) {
			answers[i].Name = qname
			changed = true
		}
	}
	if !changed {
		return resp
	}
	resp.Answers = answers
	return resp
}

// domainMatch reports whether name equals a configured domain or is a
// subdomain of it (dot-boundary suffix match on canonical names).
func domainMatch(name string, domains []string) bool {
	name = wire.CanonicalName(name)
	if name == "" {
		return false
	}
	for _, domain := range domains {
		d := wire.CanonicalName(domain)
		if d == "" {
			continue
		}
		if name == d || strings.HasSuffix(name, "."+d) {
			return true
		}
	}
	return false
}

func anyInRange(addrs []string, ranges *cfrange.Ranges) bool {
	for _, addr := range addrs {
		if ranges.Contains(addr) {
			return true
		}
	}
	return false
}

// cloneAnswers copies the answer slice (record values included) so record
// mutation never reaches a packet another caller may still hold.
func cloneAnswers(resp *wire.Packet) []wire.Record {
	out := make([]wire.Record, len(resp.Answers))
	copy(out, resp.Answers)
	return out
}

func firstN(values []string, n int) []string {
	if len(values) > n {
		return values[:n]
	}
	return values
}

// replaceFamily swaps every record of rtype for one record per pool address
// (first address at the family's first position); Name and Class come from
// the first original record and TTL is the family's minimum. Without
// original records of the family, or with an unparseable pool address, the
// records are returned verbatim.
func replaceFamily(records []wire.Record, rtype uint16, addrs []string) []wire.Record {
	if len(addrs) == 0 {
		return records
	}
	first := -1
	ttl := uint32(0)
	for i, r := range records {
		if r.Type != rtype {
			continue
		}
		if first < 0 {
			first, ttl = i, r.TTL
		} else if r.TTL < ttl {
			ttl = r.TTL
		}
	}
	if first < 0 {
		return records
	}
	template := records[first]
	fresh := make([]wire.Record, 0, len(addrs))
	for _, addr := range addrs {
		rd, ok := familyRData(rtype, addr)
		if !ok {
			return records
		}
		fresh = append(fresh, wire.Record{
			Name: template.Name, Type: rtype, Class: template.Class, TTL: ttl, RData: rd,
		})
	}
	out := make([]wire.Record, 0, len(records)+len(fresh))
	inserted := false
	for _, r := range records {
		if r.Type == rtype {
			if !inserted {
				out = append(out, fresh...)
				inserted = true
			}
			continue
		}
		out = append(out, r)
	}
	return out
}

func dropType(records []wire.Record, rtype uint16) []wire.Record {
	out := make([]wire.Record, 0, len(records))
	for _, r := range records {
		if r.Type != rtype {
			out = append(out, r)
		}
	}
	return out
}

// removeSvcParam drops one parameter from an SVCB/HTTPS record in place.
func removeSvcParam(r *wire.Record, key uint16) {
	sv, ok := r.RData.(wire.SVCB)
	if !ok {
		return
	}
	params := make([]wire.SvcParam, 0, len(sv.Params))
	for _, param := range sv.Params {
		if param.Key != key {
			params = append(params, param)
		}
	}
	sv.Params = params
	r.RData = sv
}

func familyRData(rtype uint16, addr string) (wire.RData, bool) {
	switch rtype {
	case wire.TypeA:
		ip, err := wire.ParseIPv4(addr)
		if err != nil {
			return nil, false
		}
		return wire.A{IP: ip}, true
	case wire.TypeAAAA:
		ip, err := wire.ParseIPv6(addr)
		if err != nil {
			return nil, false
		}
		return wire.AAAA{IP: ip}, true
	}
	return nil, false
}

// packHints encodes addresses as an ipv4hint/ipv6hint parameter value; any
// unparseable address yields nil so callers can skip the upsert.
func packHints(addrs []string, size int) []byte {
	var out []byte
	for _, addr := range addrs {
		if size == 4 {
			ip, err := wire.ParseIPv4(addr)
			if err != nil {
				return nil
			}
			out = append(out, ip[:]...)
		} else {
			ip, err := wire.ParseIPv6(addr)
			if err != nil {
				return nil
			}
			out = append(out, ip[:]...)
		}
	}
	return out
}

// packAlpn encodes an ALPN list as the wire parameter value; entries longer
// than 255 bytes yield nil.
func packAlpn(alpn []string) []byte {
	var out []byte
	for _, entry := range alpn {
		if len(entry) > 255 {
			return nil
		}
		out = append(out, byte(len(entry)))
		out = append(out, entry...)
	}
	return out
}
