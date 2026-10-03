// Package httpapi exposes the cfdoh HTTP surface: the RFC 8484 DoH endpoint
// with path aliases, the explain / health / probe endpoints and the admin
// JSON API, served in either direct-TLS or reverse-proxy listen mode.
//
// 契约: .trellis/spec/arch/httpapi.md. 本模块只做 HTTP 编解码与转发, 解析逻辑全部
// 委托 resolver; admin 双令牌鉴权 (常数时间比较); 客户端识别按固定优先级取值;
// pprof 端点独立监听, 不挂主路由; 单步失败只影响该请求.
package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	_ "net/http/pprof" // registers on DefaultServeMux, served on the gated listener only
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/jnuse/cfdoh/internal/cfrange"
	"github.com/jnuse/cfdoh/internal/config"
	"github.com/jnuse/cfdoh/internal/ech"
	"github.com/jnuse/cfdoh/internal/ecs"
	"github.com/jnuse/cfdoh/internal/h3"
	"github.com/jnuse/cfdoh/internal/isp"
	"github.com/jnuse/cfdoh/internal/pool"
	"github.com/jnuse/cfdoh/internal/resolver"
	"github.com/jnuse/cfdoh/internal/rules"
	"github.com/jnuse/cfdoh/internal/wire"
)

// Version is embedded at build time (ldflags); /probe reports it.
var Version = "dev"

// adminBodyLimit caps every admin POST body at 1 MiB.
const adminBodyLimit = 1 << 20

// maxSelfcheckSources is the selfcheck report table cap (oldest evicted).
const maxSelfcheckSources = 8

// dnsGETParamMaxLen caps the base64url ?dns= parameter (RFC 8484 65535*4/3).
const dnsGETParamMaxLen = 87384

// ispNameRe is the operator-name whitelist for isp:* scopes.
var ispNameRe = regexp.MustCompile(`^[a-z][a-z0-9-]{1,23}$`)

// Server is the cfdoh HTTP server. It owns the selfcheck report table only;
// every other state piece belongs to its capability module.
type Server struct {
	cfg *config.Config

	selfMu     sync.Mutex
	selfchecks map[string]*selfcheckReport
	selfOrder  []string // insertion order, drives the 8-source cap
}

// New builds a server around one loaded configuration.
func New(cfg *config.Config) *Server {
	return &Server{cfg: cfg, selfchecks: make(map[string]*selfcheckReport)}
}

// Run serves until ctx is cancelled (graceful shutdown, 10 s grace) or the
// listener fails. Direct mode embeds TLS on cfg.Host:cfg.Port; otherwise the
// listener is plaintext reverse-proxy mode.
func (s *Server) Run(ctx context.Context) error {
	addr := fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	mode := "reverse"
	if s.cfg.TLSEnabled() {
		mode = "direct"
	}
	slog.Info("event", "event", "listening", "detail", fmt.Sprintf("mode=%s addr=%s", mode, addr))

	if s.cfg.PprofAddr != "" {
		go s.servePprof(ctx)
	}

	srv := &http.Server{Handler: s.handler()}
	serveErr := make(chan error, 1)
	go func() {
		var err error
		if mode == "direct" {
			err = srv.ServeTLS(ln, s.cfg.TLSCertFile, s.cfg.TLSKeyFile)
		} else {
			err = srv.Serve(ln)
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
			return
		}
		serveErr <- nil
	}()

	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}
		return <-serveErr
	}
}

// servePprof runs the debug endpoints on a dedicated listener gated by
// PPROF_ADDR. A listen failure is logged and never blocks the main service.
func (s *Server) servePprof(ctx context.Context) {
	ln, err := net.Listen("tcp", s.cfg.PprofAddr)
	if err != nil {
		slog.Warn("event", "event", "pprof_listen_failed", "detail", err.Error())
		return
	}
	slog.Info("event", "event", "listening", "detail", fmt.Sprintf("mode=pprof addr=%s", s.cfg.PprofAddr))
	srv := &http.Server{Handler: http.DefaultServeMux}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	_ = srv.Serve(ln)
}

// handler wires the route table and the Host check.
func (s *Server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", s.handleDoH)
	for _, alias := range s.cfg.PathAliases {
		if alias = strings.TrimSpace(alias); alias != "" && strings.HasPrefix(alias, "/") {
			mux.HandleFunc(alias, s.handleDoH)
		}
	}
	mux.HandleFunc("/explain", s.handleExplain)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})
	mux.HandleFunc("GET /probe", s.handleProbe)
	mux.HandleFunc("/admin/preferred", s.admin(s.handleAdminPreferred))
	mux.HandleFunc("/admin/site", s.admin(s.handleAdminSite))
	mux.HandleFunc("/admin/github", s.admin(s.handleAdminGithub))
	mux.HandleFunc("/admin/h3", s.admin(s.handleAdminH3))
	mux.HandleFunc("/admin/health", s.admin(s.handleAdminHealth))
	mux.HandleFunc("/admin/selfcheck", s.admin(s.handleAdminSelfcheck))
	return s.withHostCheck(mux)
}

// withHostCheck enforces PUBLIC_HOSTNAMES: a Host outside the set (and not
// localhost, port stripped, canonical) is answered 421.
func (s *Server) withHostCheck(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(s.cfg.PublicHostnames) > 0 {
			host := wire.CanonicalName(hostNoPort(r.Host))
			if host != "localhost" && !containsFold(s.cfg.PublicHostnames, host) {
				http.Error(w, "misdirected request", http.StatusMisdirectedRequest)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func hostNoPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

func containsFold(list []string, want string) bool {
	for _, item := range list {
		if strings.EqualFold(item, want) {
			return true
		}
	}
	return false
}

// handleProbe echoes the identified client IP, the listen mode and Version.
func (s *Server) handleProbe(w http.ResponseWriter, r *http.Request) {
	mode := "reverse"
	if s.cfg.TLSEnabled() {
		mode = "direct"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"client_ip": s.clientIP(r),
		"mode":      mode,
		"version":   Version,
	})
}

// clientIP resolves the request origin: gated origin-token header first
// (constant-time match), then X-Real-IP, CF-Connecting-IP, the first
// X-Forwarded-For value, and finally the TCP peer address. Every header
// value must parse as an IP or the chain moves on.
func (s *Server) clientIP(r *http.Request) string {
	if s.cfg.DohOriginToken != "" {
		if tok := r.Header.Get("X-DoH-Origin-Token"); tok != "" &&
			subtle.ConstantTimeCompare([]byte(tok), []byte(s.cfg.DohOriginToken)) == 1 {
			if ip := firstHeaderIP(r.Header.Get("X-DoH-Client-IP")); ip != "" {
				return ip
			}
		}
	}
	if ip := firstHeaderIP(r.Header.Get("X-Real-IP")); ip != "" {
		return ip
	}
	if ip := firstHeaderIP(r.Header.Get("CF-Connecting-IP")); ip != "" {
		return ip
	}
	if ip := firstHeaderIP(r.Header.Get("X-Forwarded-For")); ip != "" {
		return ip
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// firstHeaderIP validates the first comma-separated value as an IP.
func firstHeaderIP(value string) string {
	if value == "" {
		return ""
	}
	first := strings.TrimSpace(strings.SplitN(value, ",", 2)[0])
	if net.ParseIP(first) == nil {
		return ""
	}
	return first
}

// handleDoH serves the RFC 8484 endpoint: method, Accept, Content-Type and
// size checks, request-packet validation, request parameters, then the
// resolver. The answer always carries the three mandated headers and the
// request transaction ID; a resolver error degrades to SERVFAIL, never 5xx.
func (s *Server) handleDoH(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if accept := r.Header.Get("Accept"); accept != "" &&
		!strings.Contains(accept, "*/*") &&
		!strings.Contains(accept, "application/dns-message") {
		http.Error(w, "unacceptable accept header", http.StatusNotAcceptable)
		return
	}

	var query []byte
	switch r.Method {
	case http.MethodPost:
		media := strings.ToLower(strings.TrimSpace(strings.SplitN(r.Header.Get("Content-Type"), ";", 2)[0]))
		if media != "application/dns-message" {
			http.Error(w, "unsupported media type", http.StatusUnsupportedMediaType)
			return
		}
		if r.ContentLength > int64(s.cfg.MaxDNSPacketSize) {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, int64(s.cfg.MaxDNSPacketSize)+1))
		if err != nil {
			http.Error(w, "failed to read request body", http.StatusBadRequest)
			return
		}
		if len(body) > s.cfg.MaxDNSPacketSize {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
			return
		}
		query = body
	default:
		raw := r.URL.Query().Get("dns")
		if raw == "" || len(raw) > dnsGETParamMaxLen {
			http.Error(w, "missing or oversized dns parameter", http.StatusBadRequest)
			return
		}
		decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(raw, "="))
		if err != nil {
			http.Error(w, "invalid dns parameter encoding", http.StatusBadRequest)
			return
		}
		if len(decoded) > s.cfg.MaxDNSPacketSize {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
			return
		}
		query = decoded
	}

	pkt, err := wire.Parse(query)
	if err != nil {
		http.Error(w, "malformed DNS query", http.StatusBadRequest)
		return
	}
	if pkt.Header.QR() || pkt.Header.Opcode() != 0 || len(pkt.Questions) != 1 {
		http.Error(w, "invalid DNS query", http.StatusBadRequest)
		return
	}
	params, err := s.parseRequestParams(r.URL.Query())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	answer, err := resolver.Resolve(r.Context(), query, s.buildOptions(r, params), s.cfg)
	if err != nil {
		answer = wire.MakeServfail(query)
	}
	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(answer)
}

// requestParams is the parsed ?ip4/?ip6/?cf/?ech/?rules surface.
type requestParams struct {
	ip4, ip6 []string
	cf, ech  string
	rules    string
	variant  string // cache-variant segment contributed by the raw parameters
}

// parseRequestParams applies the strict per-parameter validation; any fault
// rejects the whole request with one error.
func (s *Server) parseRequestParams(q map[string][]string) (*requestParams, error) {
	get := func(key string) string {
		if vs := q[key]; len(vs) > 0 {
			return vs[0]
		}
		return ""
	}
	p := &requestParams{}
	var err error
	if p.ip4, err = parseIPList(get("ip4"), 4); err != nil {
		return nil, err
	}
	if p.ip6, err = parseIPList(get("ip6"), 6); err != nil {
		return nil, err
	}
	if raw := get("cf"); raw != "" {
		if !validDomainName(raw) {
			return nil, fmt.Errorf("invalid cf parameter %q", raw)
		}
		p.cf = raw
	}
	if raw := get("ech"); raw != "" {
		if !validDomainName(raw) {
			return nil, fmt.Errorf("invalid ech parameter %q", raw)
		}
		p.ech = raw
	}
	if raw := get("rules"); raw != "" {
		normalized, err := rules.ValidateDynamicURL(raw, s.cfg)
		if err != nil {
			return nil, err
		}
		p.rules = normalized
	}
	var parts []string
	for _, key := range []string{"ip4", "ip6", "cf", "ech", "rules"} {
		if v := get(key); v != "" {
			parts = append(parts, key+"="+v)
		}
	}
	p.variant = strings.Join(parts, "&")
	return p, nil
}

// parseIPList validates a comma-separated address list: raw string ≤ 1024
// bytes, 1–16 items, strict parse per family, normalized on output.
func parseIPList(raw string, family int) ([]string, error) {
	if raw == "" {
		return nil, nil
	}
	if len(raw) > 1024 {
		return nil, errors.New("address list too long")
	}
	parts := strings.Split(raw, ",")
	if len(parts) > 16 {
		return nil, errors.New("too many addresses")
	}
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if family == 4 {
			ip, err := wire.ParseIPv4(part)
			if err != nil {
				return nil, fmt.Errorf("invalid ipv4 address %q", part)
			}
			out = append(out, wire.IPv4String(ip))
		} else {
			ip, err := wire.ParseIPv6(part)
			if err != nil {
				return nil, fmt.Errorf("invalid ipv6 address %q", part)
			}
			out = append(out, wire.IPv6String(ip))
		}
	}
	return out, nil
}

// validDomainName is the domain-syntax whitelist: 1–253 bytes, optional
// trailing dot, dot-separated labels of 1–63 bytes over [A-Za-z0-9-].
func validDomainName(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	name := strings.TrimSuffix(s, ".")
	if name == "" {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// buildOptions maps the request surface onto the resolver options, folding
// the raw parameter text into the cache variant.
func (s *Server) buildOptions(r *http.Request, p *requestParams) *resolver.Options {
	opts := &resolver.Options{
		ClientIP:          s.clientIP(r),
		CfDomains:         s.cfg.CFPreferredDomain,
		CfDomainIsDefault: true,
		PreferredIPv4:     p.ip4,
		PreferredIPv6:     p.ip6,
		EchDomain:         p.ech,
		RulesURL:          p.rules,
		CacheVariant:      p.variant,
	}
	if p.cf != "" {
		opts.CfDomains = []string{p.cf}
		opts.CfDomainIsDefault = false
	}
	return opts
}

// handleExplain answers read-only diagnostics: the three type queries run
// through the fresh pipeline with notes, the pool plan is resolved the same
// way the resolver does, and the Chromium ECH verdict is computed from the
// three answers. Nothing is cached.
func (s *Server) handleExplain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	name := q.Get("name")
	if !validDomainName(name) {
		http.Error(w, "invalid or missing name parameter", http.StatusBadRequest)
		return
	}
	typeParam := strings.ToUpper(strings.TrimSpace(q.Get("type")))
	switch typeParam {
	case "": // all three types
	case "A", "AAAA", "HTTPS":
	default:
		http.Error(w, "invalid type parameter", http.StatusBadRequest)
		return
	}
	params, err := s.parseRequestParams(q)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	opts := s.buildOptions(r, params)

	ctx := r.Context()
	clientScope := ""
	if v := ecs.Make(opts.ClientIP, s.cfg.EcsIPv4Prefix, s.cfg.EcsIPv6Prefix); v != nil {
		clientScope = v.Identity
	}
	ispScope, _ := isp.ScopeOf(ctx, opts.ClientIP, s.cfg)

	type answerOut struct {
		Status   string           `json:"status"`
		Cache    string           `json:"cache"`
		Upstream string           `json:"upstream,omitempty"`
		Error    string           `json:"error,omitempty"`
		Notes    []string         `json:"notes"`
		Answers  []map[string]any `json:"answers"`
	}
	keys := []string{"A", "AAAA", "HTTPS"}
	types := []uint16{wire.TypeA, wire.TypeAAAA, wire.TypeHTTPS}
	answers := make(map[string]*answerOut, 3)
	packets := make([]*wire.Packet, 3)
	for i, qtype := range types {
		if typeParam != "" && keys[i] != typeParam {
			continue
		}
		out := &answerOut{Status: "ok", Notes: []string{}, Answers: []map[string]any{}}
		query := explainQuery(name, qtype)
		out.Cache = resolver.CacheState(ctx, query, opts, s.cfg)
		result, err := resolver.ResolveFresh(ctx, query, opts, s.cfg, &out.Notes)
		if err != nil {
			out.Status = "error"
			out.Error = err.Error()
		} else {
			out.Upstream = result.Upstream
			if pkt, perr := wire.Parse(result.Packet); perr == nil {
				packets[i] = pkt
				out.Answers = summarizeAnswers(pkt)
			}
		}
		answers[keys[i]] = out
	}
	// the Chromium verdict needs all three packets; filtered views leave it null
	var chromium any
	if packets[0] != nil && packets[1] != nil && packets[2] != nil {
		usable, reason := resolver.ChromiumECHVerdict(packets[0], packets[1], packets[2])
		chromium = map[string]any{"usable": usable, "reason": reason}
	}

	var poolView any
	p, perr := pool.Preferred(ctx, opts.PreferredIPv4, opts.PreferredIPv6, opts.CfDomains,
		opts.CfDomainIsDefault, s.cfg, clientScope, ispScope)
	switch {
	case perr != nil:
		poolView = map[string]any{"error": perr.Error()}
	case p != nil:
		poolView = map[string]any{"scope": p.Scope, "ipv4": p.IPv4, "ipv6": p.IPv6}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"client_ip":    opts.ClientIP,
		"pool":         poolView,
		"answers":      answers,
		"chromium_ech": chromium,
		"selfcheck":    s.selfcheckSlice(),
	})
}

// explainQuery builds one query packet with a random transaction ID.
func explainQuery(name string, qtype uint16) []byte {
	var id [2]byte
	if _, err := rand.Read(id[:]); err != nil {
		id = [2]byte{0, 1}
	}
	q := &wire.Packet{
		Header:    wire.Header{ID: binary.BigEndian.Uint16(id[:]), Flags: 0x0100},
		Questions: []wire.Question{{Name: name, Type: qtype, Class: wire.ClassIN}},
	}
	b, err := q.Encode()
	if err != nil {
		return nil // syntactically pre-validated; the pipeline reports the error
	}
	return b
}

// summarizeAnswers renders the answer section as compact JSON objects.
func summarizeAnswers(pkt *wire.Packet) []map[string]any {
	out := []map[string]any{}
	for i := range pkt.Answers {
		rec := &pkt.Answers[i]
		entry := map[string]any{"type": typeName(rec.Type), "name": rec.Name, "ttl": rec.TTL}
		switch rd := rec.RData.(type) {
		case wire.A:
			entry["value"] = wire.IPv4String(rd.IP)
		case wire.AAAA:
			entry["value"] = wire.IPv6String(rd.IP)
		case wire.SVCB:
			alpn, v4, v6, echList := wire.DescribeHTTPS(rec)
			entry["target"] = rd.Target
			entry["alpn"] = alpn
			entry["ipv4hint"] = v4
			entry["ipv6hint"] = v6
			entry["ech"] = len(echList) > 0
		}
		out = append(out, entry)
	}
	return out
}

var typeNames = map[uint16]string{
	wire.TypeA: "A", wire.TypeNS: "NS", wire.TypeCNAME: "CNAME", wire.TypeSOA: "SOA",
	wire.TypePTR: "PTR", wire.TypeMX: "MX", wire.TypeTXT: "TXT", wire.TypeAAAA: "AAAA",
	wire.TypeSRV: "SRV", wire.TypeDNAME: "DNAME", wire.TypeOPT: "OPT",
	wire.TypeSVCB: "SVCB", wire.TypeHTTPS: "HTTPS",
}

func typeName(t uint16) string {
	if n, ok := typeNames[t]; ok {
		return n
	}
	return fmt.Sprintf("TYPE%d", t)
}

// admin wraps one admin endpoint with the dual-token gate: no ADMIN_TOKEN
// configured means every /admin/* is 404; the bearer token is compared in
// constant time; the hub token enters the handler flagged (each handler
// enforces its own hub restrictions).
func (s *Server) admin(next func(w http.ResponseWriter, r *http.Request, isHub bool)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.AdminToken == "" {
			http.NotFound(w, r)
			return
		}
		token, ok := bearerToken(r)
		var isHub bool
		switch {
		case ok && subtle.ConstantTimeCompare([]byte(token), []byte(s.cfg.AdminToken)) == 1:
		case ok && s.cfg.HubToken != "" && subtle.ConstantTimeCompare([]byte(token), []byte(s.cfg.HubToken)) == 1:
			isHub = true
		default:
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r, isHub)
	}
}

// bearerToken extracts the Authorization: Bearer payload.
func bearerToken(r *http.Request) (string, bool) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return "", false
	}
	scheme, rest, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(rest) == "" {
		return "", false
	}
	return strings.TrimSpace(rest), true
}

// readAdminBody reads an admin POST body capped at 1 MiB (413 on overflow).
func readAdminBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	if r.ContentLength > adminBodyLimit {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, adminBodyLimit+1))
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return nil, false
	}
	if len(body) > adminBodyLimit {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return nil, false
	}
	return body, true
}

type preferredPost struct {
	IPv4   []string `json:"ipv4"`
	IPv6   []string `json:"ipv6"`
	TTL    int      `json:"ttl"`
	Source string   `json:"source"`
	Scope  string   `json:"scope"`
}

// handleAdminPreferred: GET aggregates every pool and probe state; POST
// reports a preferred pool. The hub token may only POST isp:* scopes.
func (s *Server) handleAdminPreferred(w http.ResponseWriter, r *http.Request, isHub bool) {
	if isHub {
		if r.Method != http.MethodPost {
			http.Error(w, "hub token may only report isp pools", http.StatusForbidden)
			return
		}
		body, ok := readAdminBody(w, r)
		if !ok {
			return
		}
		var req preferredPost
		if json.Unmarshal(body, &req) != nil || !strings.HasPrefix(req.Scope, "isp:") {
			http.Error(w, "hub token may only report isp pools", http.StatusForbidden)
			return
		}
		s.applyPreferred(w, r, &req)
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{
			"learned":   pool.LearnedStatus(),
			"scoped":    pool.ScopedStatus(),
			"isp":       pool.IspPoolStatus(),
			"github":    pool.GithubStatus(),
			"site":      pool.SiteStatus(),
			"ech":       ech.Status(),
			"h3":        h3.Status(),
			"selfcheck": s.selfcheckSlice(),
		})
	case http.MethodPost:
		body, ok := readAdminBody(w, r)
		if !ok {
			return
		}
		var req preferredPost
		if json.Unmarshal(body, &req) != nil {
			http.Error(w, "invalid json body", http.StatusBadRequest)
			return
		}
		s.applyPreferred(w, r, &req)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// applyPreferred validates one preferred-pool report and hands it to the
// pool layer. scope "client" is translated into the reporter's own ECS
// identity; isp:* addresses must sit inside the published Cloudflare ranges
// (any outsider rejects the whole batch).
func (s *Server) applyPreferred(w http.ResponseWriter, r *http.Request, req *preferredPost) {
	var scope string
	switch {
	case req.Scope == "default":
		scope = ""
	case req.Scope == "client":
		v := ecs.Make(s.clientIP(r), s.cfg.EcsIPv4Prefix, s.cfg.EcsIPv6Prefix)
		if v == nil {
			http.Error(w, "client scope requires an identifiable client address", http.StatusBadRequest)
			return
		}
		scope = v.Identity
	case strings.HasPrefix(req.Scope, "isp:") && ispNameValid(strings.TrimPrefix(req.Scope, "isp:")):
		scope = req.Scope
	default:
		http.Error(w, "invalid scope", http.StatusBadRequest)
		return
	}
	v4, err := normalizeAddrs(req.IPv4, 4)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	v6, err := normalizeAddrs(req.IPv6, 6)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if strings.HasPrefix(scope, "isp:") {
		all := append(append([]string{}, v4...), v6...)
		ranges := cfrange.Current()
		for _, addr := range all {
			if !ranges.Contains(addr) {
				http.Error(w, fmt.Sprintf("address %s outside the Cloudflare ranges", addr), http.StatusBadRequest)
				return
			}
		}
	}
	if err := pool.SetLearned(v4, v6, clamp(req.TTL, 60, 86400), truncate(req.Source, 64), scope); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// normalizeAddrs parses and normalizes one family's address list, capped at
// 64 entries, strict per item.
func normalizeAddrs(values []string, family int) ([]string, error) {
	if len(values) > 64 {
		return nil, errors.New("too many addresses")
	}
	out := make([]string, 0, len(values))
	for _, v := range values {
		if family == 4 {
			ip, err := wire.ParseIPv4(v)
			if err != nil {
				return nil, fmt.Errorf("invalid ipv4 address %q", v)
			}
			out = append(out, wire.IPv4String(ip))
		} else {
			ip, err := wire.ParseIPv6(v)
			if err != nil {
				return nil, fmt.Errorf("invalid ipv6 address %q", v)
			}
			out = append(out, wire.IPv6String(ip))
		}
	}
	return out, nil
}

func ispNameValid(name string) bool {
	return name != "national" && ispNameRe.MatchString(name)
}

type hostPoolPost struct {
	Source string              `json:"source"`
	TTL    int                 `json:"ttl"`
	Hosts  map[string][]string `json:"hosts"`
}

// handleAdminSite: GET reports the site pools, POST replaces one source's
// report (an absent host withdraws that source's override for it).
func (s *Server) handleAdminSite(w http.ResponseWriter, r *http.Request, isHub bool) {
	if isHub {
		http.Error(w, "hub token may only report isp pools", http.StatusForbidden)
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, pool.SiteStatus())
	case http.MethodPost:
		req, ok := s.decodeHostPool(w, r, false)
		if !ok {
			return
		}
		pool.SetSites(req.Source, req.Hosts, ttlOrDefault(req.TTL, 3600, 60, 86400))
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleAdminGithub: GET reports the GitHub pools, POST replaces one
// source's report; the pools are IPv4-only (a v6 address rejects the batch).
func (s *Server) handleAdminGithub(w http.ResponseWriter, r *http.Request, isHub bool) {
	if isHub {
		http.Error(w, "hub token may only report isp pools", http.StatusForbidden)
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, pool.GithubStatus())
	case http.MethodPost:
		req, ok := s.decodeHostPool(w, r, true)
		if !ok {
			return
		}
		if len(req.Hosts) == 0 {
			http.Error(w, "no hosts with IPs", http.StatusBadRequest)
			return
		}
		pool.SetGithub(req.Source, req.Hosts, ttlOrDefault(req.TTL, 3600, 60, 86400))
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// decodeHostPool reads, validates and normalizes one per-host pool report.
func (s *Server) decodeHostPool(w http.ResponseWriter, r *http.Request, v4Only bool) (*hostPoolPost, bool) {
	body, ok := readAdminBody(w, r)
	if !ok {
		return nil, false
	}
	var req hostPoolPost
	if json.Unmarshal(body, &req) != nil {
		http.Error(w, "invalid json body", http.StatusBadRequest)
		return nil, false
	}
	hosts := make(map[string][]string, len(req.Hosts))
	for host, addrs := range req.Hosts {
		if !validDomainName(host) {
			http.Error(w, fmt.Sprintf("invalid host %q", host), http.StatusBadRequest)
			return nil, false
		}
		normalized := make([]string, 0, len(addrs))
		for _, addr := range addrs {
			if v4Only {
				ip, err := wire.ParseIPv4(addr)
				if err != nil {
					http.Error(w, fmt.Sprintf("invalid ipv4 address %q", addr), http.StatusBadRequest)
					return nil, false
				}
				normalized = append(normalized, wire.IPv4String(ip))
				continue
			}
			if ip4, err := wire.ParseIPv4(addr); err == nil {
				normalized = append(normalized, wire.IPv4String(ip4))
			} else if ip6, err := wire.ParseIPv6(addr); err == nil {
				normalized = append(normalized, wire.IPv6String(ip6))
			} else {
				http.Error(w, fmt.Sprintf("invalid address %q", addr), http.StatusBadRequest)
				return nil, false
			}
		}
		hosts[host] = normalized
	}
	req.Source = truncate(req.Source, 64)
	req.Hosts = hosts
	return &req, true
}

type h3Post struct {
	Source   string          `json:"source"`
	TTL      int             `json:"ttl"`
	Verdicts map[string]bool `json:"verdicts"`
}

// handleAdminH3: GET reports the effective verdicts; POST replaces one
// source's verdict snapshot (whole-set overwrite).
func (s *Server) handleAdminH3(w http.ResponseWriter, r *http.Request, isHub bool) {
	if isHub {
		http.Error(w, "hub token may only report isp pools", http.StatusForbidden)
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, h3.Status())
	case http.MethodPost:
		body, ok := readAdminBody(w, r)
		if !ok {
			return
		}
		var req h3Post
		if json.Unmarshal(body, &req) != nil {
			http.Error(w, "invalid json body", http.StatusBadRequest)
			return
		}
		for host := range req.Verdicts {
			if !validDomainName(host) {
				http.Error(w, fmt.Sprintf("invalid host %q", host), http.StatusBadRequest)
				return
			}
		}
		h3.SetVerdicts(truncate(req.Source, 64), req.Verdicts, ttlOrDefault(req.TTL, 5400, 300, 86400))
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleAdminHealth summarizes the capability modules for a quick panel.
func (s *Server) handleAdminHealth(w http.ResponseWriter, r *http.Request, isHub bool) {
	if isHub {
		http.Error(w, "hub token may only report isp pools", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ranges := cfrange.Current()
	prefixes := 0
	loaded := ranges != nil
	if loaded {
		prefixes = len(ranges.V4) + len(ranges.V6)
		loaded = prefixes > 0
	}
	learnedSources := 0
	if report := pool.LearnedStatus(); report != nil {
		learnedSources = len(report.Sources)
	}
	metaMode, metaActive := "", false
	if e := ech.Status(); e != nil {
		metaMode, metaActive = e.Mode, e.Active
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":               true,
		"cfrange_loaded":   loaded,
		"cfrange_prefixes": prefixes,
		"modules": map[string]any{
			"pool": map[string]any{
				"learned_sources": learnedSources,
				"scoped_pools":    len(pool.ScopedStatus()),
				"isp_pools":       len(pool.IspPoolStatus()),
				"github_sources":  len(pool.GithubStatus().Sources),
				"site_sources":    len(pool.SiteStatus().Sources),
			},
			"h3":  map[string]any{"sources": len(h3.Status().Sources)},
			"ech": map[string]any{"mode": metaMode, "active": metaActive},
			"isp": map[string]any{"configured": s.cfg.IspTableURL != ""},
		},
	})
}

type selfcheckReport struct {
	Source    string   `json:"source"`
	OK        bool     `json:"ok"`
	Problems  []string `json:"problems"`
	Hosts     []string `json:"hosts"`
	UpdatedAt int64    `json:"updated_at"`
}

type selfcheckPost struct {
	Source   string   `json:"source"`
	OK       bool     `json:"ok"`
	Problems []string `json:"problems"`
	Hosts    []string `json:"hosts"`
}

// handleAdminSelfcheck stores and serves the self-check report table (at
// most 8 sources, overwrite by source, oldest evicted).
func (s *Server) handleAdminSelfcheck(w http.ResponseWriter, r *http.Request, isHub bool) {
	if isHub {
		http.Error(w, "hub token may only report isp pools", http.StatusForbidden)
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.selfcheckSlice())
	case http.MethodPost:
		body, ok := readAdminBody(w, r)
		if !ok {
			return
		}
		var req selfcheckPost
		if json.Unmarshal(body, &req) != nil {
			http.Error(w, "invalid json body", http.StatusBadRequest)
			return
		}
		source := truncate(strings.TrimSpace(req.Source), 64)
		if source == "" {
			http.Error(w, "missing source", http.StatusBadRequest)
			return
		}
		if len(req.Problems) > 50 {
			req.Problems = req.Problems[:50]
		}
		for i := range req.Problems {
			req.Problems[i] = truncate(req.Problems[i], 300)
		}
		s.storeSelfcheck(source, req.OK, req.Problems, req.Hosts)
		if !req.OK {
			slog.Warn("event", "event", "selfcheck_failed", "detail",
				fmt.Sprintf("source=%s problems=%v", source, req.Problems))
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// storeSelfcheck inserts or overwrites one report under the table lock.
func (s *Server) storeSelfcheck(source string, ok bool, problems, hosts []string) {
	s.selfMu.Lock()
	defer s.selfMu.Unlock()
	if _, exists := s.selfchecks[source]; !exists {
		s.selfOrder = append(s.selfOrder, source)
		if len(s.selfOrder) > maxSelfcheckSources {
			delete(s.selfchecks, s.selfOrder[0])
			s.selfOrder = s.selfOrder[1:]
		}
	}
	s.selfchecks[source] = &selfcheckReport{
		Source: source, OK: ok, Problems: problems, Hosts: hosts, UpdatedAt: time.Now().Unix(),
	}
}

// selfcheckSlice snapshots the report table in insertion order.
func (s *Server) selfcheckSlice() []*selfcheckReport {
	s.selfMu.Lock()
	defer s.selfMu.Unlock()
	out := make([]*selfcheckReport, 0, len(s.selfchecks))
	for _, source := range s.selfOrder {
		if report, ok := s.selfchecks[source]; ok {
			out = append(out, report)
		}
	}
	return out
}

// writeJSON emits one JSON body with the given status.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// ttlOrDefault treats a missing ttl (0) as def, then clamps to [lo, hi] —
// matching the reference defaults (host pools 3600, h3 verdicts 5400).
func ttlOrDefault(v, def, lo, hi int) int {
	if v == 0 {
		v = def
	}
	return clamp(v, lo, hi)
}
