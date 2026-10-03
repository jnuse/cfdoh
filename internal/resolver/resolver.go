// Package resolver orchestrates the answer pipeline: the ECS decision, the
// two-segment cache identity, the upstream query, the rewrite chain and the
// serve policy (fresh direct, refresh serve-then-prefetch, HTTPS immediate
// serve from any cache state, stale fallback, SERVFAIL).
//
// 契约: .trellis/spec/arch/resolver.md. 缓存策略: fresh 直返; refresh 先答后刷;
// HTTPS 有缓存 (含过期) 立即返回并后台刷新; 上游全败用过期应答兜底, 无缓存返回
// SERVFAIL; 改写链单步失败只跳过不阻塞; explain 管线 (ResolveFresh) 不写缓存.
package resolver

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/jnuse/cfdoh/internal/cache"
	"github.com/jnuse/cfdoh/internal/cfrange"
	"github.com/jnuse/cfdoh/internal/config"
	"github.com/jnuse/cfdoh/internal/ech"
	"github.com/jnuse/cfdoh/internal/ecs"
	"github.com/jnuse/cfdoh/internal/h3"
	"github.com/jnuse/cfdoh/internal/isp"
	"github.com/jnuse/cfdoh/internal/pool"
	"github.com/jnuse/cfdoh/internal/rewrite"
	"github.com/jnuse/cfdoh/internal/rules"
	"github.com/jnuse/cfdoh/internal/upstream"
	"github.com/jnuse/cfdoh/internal/wire"
)

// Options carries the per-request inputs: the client identity, the explicit
// preferred-pool parameters and the cache variant segments contributed by
// request parameters.
type Options struct {
	ClientIP                          string
	CfDomains                         []string
	CfDomainIsDefault                 bool
	PreferredIPv4, PreferredIPv6      []string
	EchDomain, RulesURL, CacheVariant string
}

// Result is one fresh pipeline outcome: the finalized answer bytes (request
// ID patched, addresses rotated) and the winning upstream URL.
type Result struct {
	Packet   []byte
	Upstream string
}

// now is the clock hook for elapsed-time accounting.
var now = time.Now

// The package-level shared answer cache, lazily built on first use.
var (
	sharedMu sync.RWMutex
	shared   *cache.Cache
)

func sharedCache(cfg *config.Config) *cache.Cache {
	sharedMu.RLock()
	c := shared
	sharedMu.RUnlock()
	if c != nil {
		return c
	}
	capacity := 0
	if cfg != nil {
		capacity = cfg.CacheMaxEntries
	}
	sharedMu.Lock()
	defer sharedMu.Unlock()
	if shared == nil {
		shared = cache.New(capacity)
	}
	return shared
}

// Resolve answers one query through the cache strategy: parse and build the
// cache identity, serve a usable hit immediately (scheduling background
// refresh where due), otherwise run the fresh pipeline and fall back to a
// stale entry or SERVFAIL when every upstream fails. The returned bytes are
// always a complete DNS answer (never a partial rewrite).
func Resolve(ctx context.Context, query []byte, opts *Options, cfg *config.Config) ([]byte, error) {
	if opts == nil {
		opts = &Options{}
	}
	start := now()
	plan, err := prepareFull(ctx, query, opts, cfg)
	if err != nil {
		return nil, err
	}
	qtype := plan.base.query.Questions[0].Type
	hit := sharedCache(cfg).Get(plan.id, cfg)

	if hit != nil {
		switch {
		case hit.State == cache.StateRefresh:
			go refreshInBackground(ctx, query, opts, cfg)
			logQuery(cfg, plan, "prefetch", "", start)
			return serveHit(hit, query), nil
		case qtype == wire.TypeHTTPS && hit.State == cache.StateStale:
			go refreshInBackground(ctx, query, opts, cfg)
			logQuery(cfg, plan, "stale", "", start)
			return serveHit(hit, query), nil
		case hit.State == cache.StateStale:
			// plain types never serve stale up front; the fresh attempt
			// below falls back to this entry on total upstream failure
		default:
			logQuery(cfg, plan, "hit", "", start)
			return serveHit(hit, query), nil
		}
	}

	result, err := resolveFresh(ctx, query, opts, cfg, nil, true)
	if err == nil {
		logQuery(cfg, plan, "miss", hostOf(result.Upstream), start)
		return result.Packet, nil
	}
	if hit != nil && hit.State == cache.StateStale {
		logQuery(cfg, plan, "stale", "", start)
		return serveHit(hit, query), nil
	}
	logQuery(cfg, plan, "miss", "", start)
	return wire.MakeServfail(query), nil
}

// ResolveFresh runs the complete fresh pipeline (rules, upstream, rewrite
// chain) collecting the step-by-step decision chain into notes. It is the
// /explain entry point and never reads or writes the answer cache.
func ResolveFresh(ctx context.Context, query []byte, opts *Options, cfg *config.Config, notes *[]string) (*Result, error) {
	if opts == nil {
		opts = &Options{}
	}
	return resolveFresh(ctx, query, opts, cfg, notes, false)
}

// resolveFresh is the shared pipeline body; store selects whether the
// upstream answer is written back into the shared cache (service paths yes,
// explain no).
func resolveFresh(ctx context.Context, query []byte, opts *Options, cfg *config.Config, notes *[]string, store bool) (*Result, error) {
	plan, err := prepareFull(ctx, query, opts, cfg)
	if err != nil {
		return nil, err
	}
	if plan.base.ruleSet.ShouldBlock(plan.base.query) {
		note(notes, "rules: block rule matched, answering REFUSED without upstream")
		return &Result{Packet: finalizeAnswer(query, refusedFor(plan.base.query))}, nil
	}
	if plan.base.withECS {
		note(notes, "ecs: attached %s", plan.base.ecsID)
	} else {
		note(notes, "ecs: not attached (mode=%s client=%t)", cfg.EcsMode, plan.base.ecsVal != nil)
	}

	res, err := upstream.Query(ctx, plan.base.outbound, cfg, plan.base.withECS)
	if err != nil {
		note(notes, "upstream: all upstreams failed: %v", err)
		return nil, err
	}
	resp, err := wire.Parse(res.Packet)
	if err != nil {
		note(notes, "upstream: winning answer failed to parse: %v", err)
		return nil, err
	}
	note(notes, "upstream: winner %s", hostOf(res.Upstream))

	if store {
		if _, ok := sharedCache(cfg).Put(plan.id, res.Packet, cfg); !ok {
			note(notes, "cache: answer not stored (SERVFAIL or zero TTL)")
		}
	}
	applyRewriteChain(ctx, plan, resp, rewriteCfg(cfg, plan.pool), notes)
	return &Result{Packet: finalizeAnswer(query, resp), Upstream: res.Upstream}, nil
}

// rewriteCfg lifts the CF rewrite gate for this query when a usable pool
// exists: the reference treats any resolved pool (explicit parameters,
// learned pools, domain or static pools) as enabling the rewrite, with
// CF_REWRITE_ENABLED as a global on-switch on top (F-009: 改写启用条件为存在
// 任一可用池).
func rewriteCfg(cfg *config.Config, p *pool.Pool) *config.Config {
	if cfg.CFRewriteEnabled || p == nil || (len(p.IPv4) == 0 && len(p.IPv6) == 0) {
		return cfg
	}
	lifted := *cfg
	lifted.CFRewriteEnabled = true
	return &lifted
}

// refreshInBackground reruns the storing pipeline detached from the caller
// request; prefetch failures surface as prefetch_error events only.
func refreshInBackground(ctx context.Context, query []byte, opts *Options, cfg *config.Config) {
	if _, err := resolveFresh(context.WithoutCancel(ctx), query, opts, cfg, nil, true); err != nil {
		slog.Warn("event", "event", "prefetch_error", "detail", err.Error())
	}
}

// basePlan holds the query-derived state shared by both entry points.
type basePlan struct {
	query    *wire.Packet // parsed original query
	outbound []byte       // ECS-adjusted wire form sent upstream
	withECS  bool         // outbound packet actually carries ECS
	ecsVal   *ecs.Value
	ecsID    string
	ruleSet  *rules.RuleSet
}

// fullPlan extends basePlan with the pool resolution and the cache identity.
type fullPlan struct {
	base        *basePlan
	opts        *Options
	qname       string
	variant     string
	id          *cache.Identity
	pool        *pool.Pool
	clientScope string
	ispScope    string
}

// prepareBase parses the query, loads the rule set and settles the ECS
// decision (rule override wins over the configured mode; no client IP means
// no ECS option). The outbound packet carries ECS only when both the policy
// and a usable client subnet agree.
func prepareBase(ctx context.Context, query []byte, opts *Options, cfg *config.Config) (*basePlan, error) {
	q, err := wire.Parse(query)
	if err != nil {
		return nil, err
	}
	if len(q.Questions) != 1 {
		return nil, fmt.Errorf("query must carry exactly one question, got %d", len(q.Questions))
	}
	rs := loadRules(ctx, opts, cfg)
	v := ecs.Make(opts.ClientIP, cfg.EcsIPv4Prefix, cfg.EcsIPv6Prefix)
	override, present := rs.EcsOverride(q)
	useECS := ecs.ShouldUse(q, cfg, override, present)

	outbound := q
	withECS := false
	ecsID := ""
	if useECS && v != nil {
		outbound = ecs.Add(q, v)
		withECS = true
		ecsID = v.Identity
	} else {
		outbound = ecs.Remove(q)
	}
	encoded, err := outbound.Encode()
	if err != nil {
		return nil, err
	}
	return &basePlan{query: q, outbound: encoded, withECS: withECS, ecsVal: v, ecsID: ecsID, ruleSet: rs}, nil
}

// prepareFull resolves the preferred pool (narrow layers first; an explicit
// pool failure is an error, a default-pool failure merely serves unrewritten)
// and assembles the cache identity: the ECS identity plus the variant segment
// (request options, contributing pool scopes, site-pool tag, h3 and Meta
// generations).
func prepareFull(ctx context.Context, query []byte, opts *Options, cfg *config.Config) (*fullPlan, error) {
	base, err := prepareBase(ctx, query, opts, cfg)
	if err != nil {
		return nil, err
	}
	clientScope := ""
	if base.ecsVal != nil {
		clientScope = base.ecsVal.Identity
	}
	ispScope, _ := isp.ScopeOf(ctx, opts.ClientIP, cfg)
	p, poolErr := pool.Preferred(ctx, opts.PreferredIPv4, opts.PreferredIPv6, opts.CfDomains, opts.CfDomainIsDefault, cfg, clientScope, ispScope)
	explicit := len(opts.PreferredIPv4) > 0 || len(opts.PreferredIPv6) > 0 ||
		(!opts.CfDomainIsDefault && len(opts.CfDomains) > 0)
	if poolErr != nil {
		if explicit {
			return nil, poolErr
		}
		p = nil // default pool down: answer unrewritten, resolution continues
	}
	qname := wire.CanonicalName(base.query.Questions[0].Name)
	variant := buildVariant(opts, qname, p, cfg)
	id, err := cache.IdentityOf(base.query, base.ecsID, variant)
	if err != nil {
		return nil, err
	}
	return &fullPlan{base: base, opts: opts, qname: qname, variant: variant, id: id, pool: p, clientScope: clientScope, ispScope: ispScope}, nil
}

// loadRules resolves the effective rule set: the request-level ?rules= URL
// (through the same dynamic-rules defense chain) wins over the configured
// RULES_URL; every failure falls back to the embedded set.
func loadRules(ctx context.Context, opts *Options, cfg *config.Config) *rules.RuleSet {
	if opts != nil && opts.RulesURL != "" && opts.RulesURL != cfg.RulesURL {
		effective := *cfg
		effective.RulesURL = opts.RulesURL
		if rs, err := rules.Load(ctx, &effective); err == nil {
			return rs
		}
	}
	if rs, err := rules.Load(ctx, cfg); err == nil {
		return rs
	}
	return &rules.RuleSet{}
}

// buildVariant assembles the variant segment of the cache key. Pool flips
// (h3 verdicts, Meta ECH rotation, site-pool content) change their tag and
// therefore the key, taking effect immediately instead of waiting for TTLs.
func buildVariant(opts *Options, qname string, p *pool.Pool, cfg *config.Config) string {
	var parts []string
	if opts.CacheVariant != "" {
		parts = append(parts, "req="+opts.CacheVariant)
	}
	if p != nil && p.Scope != "" {
		parts = append(parts, "pools="+p.Scope)
	}
	if tag := pool.SitePoolTag(qname); tag != "" {
		parts = append(parts, tag)
	}
	parts = append(parts, h3.CacheTag())
	if domainMatch(qname, cfg.MetaDomains) {
		parts = append(parts, ech.MetaCacheTag())
	}
	return strings.Join(parts, ",")
}

// applyRewriteChain runs the ordered rewrite chain over one upstream answer.
// Every step is individually best-effort: a failing step is skipped (noted)
// and the answer still goes out.
func applyRewriteChain(ctx context.Context, plan *fullPlan, resp *wire.Packet, cfg *config.Config, notes *[]string) {
	q := plan.base.query
	qname := plan.qname

	resp = plan.base.ruleSet.Apply(q, resp)

	upstreamV4, upstreamV6 := answerAddresses(resp)
	onCF, cfErr := rewrite.OnCloudflare(ctx, qname, cfrange.Current(), cfg, upstreamV4, upstreamV6)
	if cfErr != nil {
		note(notes, "cloudflare: determination failed (%v), treated as not Cloudflare", cfErr)
	} else {
		note(notes, "cloudflare: %t (upstream v4=%v v6=%v)", onCF, upstreamV4, upstreamV6)
	}

	if plan.pool != nil {
		note(notes, "pool: scope=%q v4=%d v6=%d", plan.pool.Scope, len(plan.pool.IPv4), len(plan.pool.IPv6))
		if onCF {
			resp = rewrite.RewriteAddresses(resp, cfrange.Current(), plan.pool, cfg)
		}
		if domainMatch(qname, cfg.XDomains) {
			resp = rewrite.RewriteX(resp, q, plan.pool, cfg)
		}
	} else {
		note(notes, "pool: unavailable, answering unrewritten")
	}

	if ips := pool.SitePoolFor(qname); len(ips) > 0 {
		resp = rewrite.PinAddresses(resp, q, ips)
		resp = rewrite.PinHTTPSHints(resp, ips)
		note(notes, "site-pool: pinned %d addresses", len(ips))
	}
	githubPinned := false
	if ips := pool.GithubPoolFor(qname); len(ips) > 0 {
		resp = rewrite.PinAddresses(resp, q, ips)
		resp = rewrite.PinHTTPSHints(resp, ips)
		githubPinned = true
		note(notes, "github-pool: pinned %d addresses", len(ips))
	}

	if q.Questions[0].Type == wire.TypeHTTPS && !githubPinned {
		resp = injectECH(ctx, plan, resp, onCF, cfg, notes)
	}
	if onCF {
		resp = rewrite.Flatten(resp)
	}
}

// injectECH applies the ECH injection policy for one HTTPS answer, by source
// priority: request ?ech= domain, the Meta three-state override (Meta
// domains), the configured base64 list (ECH_DOMAINS), and finally the
// published source domain for Cloudflare-served hosts. Failures never block
// the answer.
func injectECH(ctx context.Context, plan *fullPlan, resp *wire.Packet, onCF bool, cfg *config.Config, notes *[]string) *wire.Packet {
	qname := plan.qname
	fallback := echAlpnFallback(qname, cfg)

	if domainMatch(qname, cfg.MetaDomains) {
		cfgList, state := ech.MetaOverride()
		switch state {
		case ech.MetaLearned:
			alpn, why := h3.AlpnFor(qname, fallback)
			note(notes, "ech: meta learned key injected (%s)", why)
			return rewrite.InjectECH(resp, cfgList, alpn)
		case ech.MetaSuspended:
			note(notes, "ech: meta injection suspended, upstream answer untouched")
			return resp
		default:
			if cfg.MetaEchConfigBase64 != "" {
				if seed, err := ech.Validated(cfg.MetaEchConfigBase64); err == nil {
					alpn, why := h3.AlpnFor(qname, fallback)
					note(notes, "ech: meta seed injected (%s)", why)
					return rewrite.InjectECH(resp, seed, alpn)
				}
				note(notes, "ech: meta seed invalid, not injected")
			}
			return resp
		}
	}

	if plan.opts.EchDomain != "" {
		if cfgList, err := ech.ConfigFor(ctx, plan.opts.EchDomain, cfg); err == nil {
			alpn, why := h3.AlpnFor(qname, fallback)
			note(notes, "ech: injected from request domain %s (%s)", plan.opts.EchDomain, why)
			return rewrite.InjectECH(resp, cfgList, alpn)
		}
		note(notes, "ech: request domain %s unusable, not injected", plan.opts.EchDomain)
	}

	resp = rewrite.InjectConfigured(resp, cfg)

	if cfg.EchEnabled && onCF {
		if cfgList, err := ech.ConfigFor(ctx, cfg.EchSourceDomain, cfg); err == nil {
			alpn, why := h3.AlpnFor(qname, fallback)
			note(notes, "ech: injected from %s (%s)", cfg.EchSourceDomain, why)
			return rewrite.InjectECH(resp, cfgList, alpn)
		}
		note(notes, "ech: source domain %s unusable, not injected", cfg.EchSourceDomain)
	}
	return resp
}

// echAlpnFallback is the ALPN list used when synthesizing an HTTPS record:
// X and Meta hosts are pinned to h2 absent measurements, everyone else gets
// no alpn parameter (upstream ALPN preserved on existing records).
func echAlpnFallback(qname string, cfg *config.Config) []string {
	if domainMatch(qname, cfg.XDomains) || domainMatch(qname, cfg.MetaDomains) {
		return []string{"h2"}
	}
	return nil
}

// ChromiumECHVerdict judges whether Chromium can use ECH for a host from its
// host_cache conditions: A/AAAA addresses exist under a single owner, and an
// HTTPS record with a matching (or ".") target carries an ech parameter.
func ChromiumECHVerdict(a, aaaa, https *wire.Packet) (usable bool, reason string) {
	owners := make(map[string]bool)
	addrs := 0
	for _, pkt := range []*wire.Packet{a, aaaa} {
		if pkt == nil {
			continue
		}
		for i := range pkt.Answers {
			switch pkt.Answers[i].RData.(type) {
			case wire.A, wire.AAAA:
				addrs++
				owners[wire.CanonicalName(pkt.Answers[i].Name)] = true
			}
		}
	}
	if addrs == 0 {
		return false, "no address records in the A/AAAA answers"
	}
	if len(owners) > 1 {
		return false, "address records have multiple owners"
	}
	var owner string
	for name := range owners {
		owner = name
	}
	if https == nil {
		return false, "no HTTPS answer"
	}
	for i := range https.Answers {
		r := &https.Answers[i]
		if r.Type != wire.TypeHTTPS {
			continue
		}
		sv, ok := r.RData.(wire.SVCB)
		if !ok {
			continue
		}
		// a "." target aliases the owner itself; compare canonically otherwise
		// (CanonicalName strips the root dot, so check the literal before it)
		if sv.Target != "." && wire.CanonicalName(sv.Target) != owner {
			return false, "HTTPS target does not match the address owner"
		}
		_, _, _, echBytes := wire.DescribeHTTPS(r)
		if len(echBytes) == 0 {
			return false, "HTTPS record carries no ech parameter"
		}
		return true, ""
	}
	return false, "no HTTPS record in the answer"
}

// answerAddresses collects the A/AAAA address strings of an answer.
func answerAddresses(resp *wire.Packet) (v4, v6 []string) {
	if resp == nil {
		return nil, nil
	}
	for i := range resp.Answers {
		switch rd := resp.Answers[i].RData.(type) {
		case wire.A:
			v4 = append(v4, wire.IPv4String(rd.IP))
		case wire.AAAA:
			v6 = append(v6, wire.IPv6String(rd.IP))
		}
	}
	return v4, v6
}

// refusedFor builds the REFUSED answer of a block rule: QR|RA set, rcode 3,
// the question preserved, opcode/RD/CD copied from the query.
func refusedFor(q *wire.Packet) *wire.Packet {
	return &wire.Packet{
		Header:    wire.Header{ID: q.Header.ID, Flags: 0x8000 | (q.Header.Flags & 0x7910) | 0x0080 | 3},
		Questions: q.Questions,
	}
}

// finalizeAnswer encodes the answer, patches the request transaction ID and
// rotates the A/AAAA groups.
func finalizeAnswer(rawQuery []byte, resp *wire.Packet) []byte {
	out, err := resp.Encode()
	if err != nil {
		return wire.MakeServfail(rawQuery)
	}
	out = wire.PatchID(out, idOf(rawQuery))
	if rotated, rerr := wire.RotateAddresses(out); rerr == nil {
		out = rotated
	}
	return out
}

// serveHit answers from a cache entry: the request ID is patched back in
// and the address order rotates on every serve, stale included.
func serveHit(hit *cache.Hit, rawQuery []byte) []byte {
	out := wire.PatchID(hit.Packet, idOf(rawQuery))
	if rotated, err := wire.RotateAddresses(out); err == nil {
		out = rotated
	}
	return out
}

// domainMatch reports whether name equals a configured domain or is one of
// its subdomains (dot-boundary suffix on canonical names).
func domainMatch(name string, domains []string) bool {
	cname := wire.CanonicalName(name)
	if cname == "" {
		return false
	}
	for _, domain := range domains {
		d := wire.CanonicalName(domain)
		if d == "" {
			continue
		}
		if cname == d || strings.HasSuffix(cname, "."+d) {
			return true
		}
	}
	return false
}

func idOf(query []byte) uint16 {
	if len(query) < 2 {
		return 0
	}
	return uint16(query[0])<<8 | uint16(query[1])
}

func hostOf(upstreamURL string) string {
	if u, err := url.Parse(upstreamURL); err == nil && u.Host != "" {
		return u.Host
	}
	return upstreamURL
}

// SaveCacheSnapshot writes the shared answer cache to path atomically. The
// entry point calls it periodically and on shutdown.
func SaveCacheSnapshot(path string) error {
	return sharedCache(nil).SaveSnapshot(path)
}

// LoadCacheSnapshot restores the shared answer cache from path. It builds
// the cache with cfg's capacity first, so boot restores work even before any
// query ran.
func LoadCacheSnapshot(path string, cfg *config.Config) error {
	return sharedCache(cfg).LoadSnapshot(path)
}

// CacheState reports the read-only cache state a query would serve from
// right now — "fresh", "refresh" or "stale" per the serve policy, or
// "none". /explain uses it to describe what a client would receive without
// touching the cache.
func CacheState(ctx context.Context, query []byte, opts *Options, cfg *config.Config) string {
	if opts == nil {
		opts = &Options{}
	}
	plan, err := prepareFull(ctx, query, opts, cfg)
	if err != nil {
		return "none"
	}
	qtype := plan.base.query.Questions[0].Type
	hit := sharedCache(cfg).Get(plan.id, cfg)
	if hit == nil {
		return "none"
	}
	if qtype == wire.TypeHTTPS && (hit.State == cache.StateRefresh || hit.State == cache.StateStale) {
		return string(hit.State) // HTTPS serves from any cached state
	}
	if hit.State == cache.StateStale {
		return "none" // plain types never serve stale up front
	}
	return string(hit.State)
}

// note appends one "step: conclusion" line to the explain notes.
func note(notes *[]string, format string, args ...any) {
	if notes == nil {
		return
	}
	*notes = append(*notes, fmt.Sprintf(format, args...))
}

// logQuery emits the dns_query event (DEBUG-gated): cache state, upstream
// host and elapsed time; the query name only with LOG_QUERIES.
func logQuery(cfg *config.Config, plan *fullPlan, state, upstreamHost string, start time.Time) {
	if cfg == nil || !cfg.Debug {
		return
	}
	namePart := ""
	if cfg.LogQueries {
		namePart = " qname=" + plan.qname
	}
	slog.Info("event", "event", "dns_query", "detail",
		fmt.Sprintf("cache=%s upstream=%s elapsed=%dms%s", state, upstreamHost, now().Sub(start).Milliseconds(), namePart))
}
