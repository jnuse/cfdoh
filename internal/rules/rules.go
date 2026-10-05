// Package rules parses and applies the rule engine: three input shapes
// (bare array, rules object, host-map shorthand), a defensive remote loader
// and the shared evaluation entry points.
//
// 契约: .trellis/spec/arch/rules.md. 匹配条件全部 AND; block 首条命中即定;
// 响应类动作按序全部应用; 远程规则防御链 (协议, 白名单, 大小, 重定向) 不可削弱.
package rules

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/jnuse/cfdoh/internal/config"
	"github.com/jnuse/cfdoh/internal/wire"
)

// maxRules caps any parsed rule set.
const maxRules = 1000

// Action is a rule action type.
type Action string

// Rule action types.
const (
	ActionPassthrough  Action = "passthrough"
	ActionReplaceA     Action = "replace-a"
	ActionReplaceAAAA  Action = "replace-aaaa"
	ActionReplaceCNAME Action = "replace-cname"
	ActionRewriteHTTPS Action = "rewrite-https"
	ActionEnableECS    Action = "enable-ecs"
	ActionDisableECS   Action = "disable-ecs"
	ActionBlock        Action = "block"
)

// RuleMatch holds all AND-combined match conditions. Empty fields match
// anything. A wrong-typed qtype marks the rule as never matching (refer
// semantics: an unmatched-type condition cannot hit) instead of widening
// the match to every qtype.
type RuleMatch struct {
	DomainExact    []string
	DomainSuffix   []string
	QType          []uint16
	ResponseIPCIDR []string

	qtypeInvalid bool
}

// HTTPSReload rewrites ipv4hint/ipv6hint of HTTPS records.
type HTTPSReload struct {
	IPv4Hint []string
	IPv6Hint []string
}

// RuleAction carries every action shape; Type is the shorthand string form.
type RuleAction struct {
	Type         Action
	Values       []string
	ReplaceA     []string
	ReplaceAAAA  []string
	ReplaceCNAME []string
	RewriteHTTPS *HTTPSReload
	EnableECS    bool
	DisableECS   bool
	Block        bool
}

// Rule is one match/action pair with its compiled response CIDRs.
type Rule struct {
	Match  RuleMatch
	Action RuleAction

	cidrs []cidr
}

// RuleSet is an ordered rule collection.
type RuleSet struct {
	Rules []Rule
}

// Parse decodes the three accepted shapes: bare rule array, {"rules": [...]}
// wrapper and host-map shorthand. Rules accept the nested form and the flat
// shorthand (see parseRule). Wrong-typed fields are treated as absent, with
// one exception: a wrong-typed qtype makes the rule never match; non-object
// array items are skipped; the result is capped at maxRules.
func Parse(data []byte) (*RuleSet, error) {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil, errors.New("rules payload is empty")
	}
	switch trimmed[0] {
	case '[':
		return parseRuleArray([]byte(trimmed))
	case '{':
		var obj map[string]json.RawMessage
		if err := json.Unmarshal([]byte(trimmed), &obj); err != nil {
			return nil, fmt.Errorf("rules object: %w", err)
		}
		if raw, ok := obj["rules"]; ok {
			return parseRuleArray(raw)
		}
		return parseHostMap(obj)
	default:
		return nil, errors.New("rules payload must be a JSON array or object")
	}
}

func parseRuleArray(raw json.RawMessage) (*RuleSet, error) {
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, fmt.Errorf("rules array: %w", err)
	}
	out := &RuleSet{}
	for _, item := range items {
		if len(out.Rules) >= maxRules {
			break
		}
		trimmed := strings.TrimLeft(string(item), " \t\r\n")
		if !strings.HasPrefix(trimmed, "{") {
			continue // non-object items are skipped
		}
		rule, ok := parseRule(item)
		if !ok {
			continue
		}
		out.Rules = append(out.Rules, *rule)
	}
	return out, nil
}

// parseRule decodes one rule in either accepted form. The canonical form
// nests the conditions under "match" and carries the action under "action"
// (string shorthand or object); the flat shorthand puts the match conditions
// (domain_exact, domain_suffix, qtype, response_ip_cidr) and the replacement
// values (ipv4/ipv6, same keys as the host-map shorthand) on the rule object
// itself. Wrong-typed fields are treated as absent in both forms, except a
// wrong-typed qtype which makes the rule never match.
func parseRule(item json.RawMessage) (*Rule, bool) {
	var raw struct {
		Match          json.RawMessage `json:"match"`
		Action         json.RawMessage `json:"action"`
		DomainExact    json.RawMessage `json:"domain_exact"`
		DomainSuffix   json.RawMessage `json:"domain_suffix"`
		QType          json.RawMessage `json:"qtype"`
		ResponseIPCIDR json.RawMessage `json:"response_ip_cidr"`
		IPv4           []string        `json:"ipv4"`
		IPv6           []string        `json:"ipv6"`
	}
	if err := json.Unmarshal(item, &raw); err != nil {
		return nil, false
	}
	rule := &Rule{}
	if len(raw.Match) > 0 {
		parseMatch(raw.Match, &rule.Match)
	}
	// flat shorthand conditions merge after the nested ones; each accepts a
	// scalar or a list. A wrong-typed qtype poisons the merged condition
	// (never matches), every other wrong-typed field stays absent.
	rule.Match.DomainExact = append(rule.Match.DomainExact, stringOrList(raw.DomainExact)...)
	rule.Match.DomainSuffix = append(rule.Match.DomainSuffix, stringOrList(raw.DomainSuffix)...)
	if qtypes, ok := qtypeList(raw.QType); ok {
		rule.Match.QType = append(rule.Match.QType, qtypes...)
	} else {
		rule.Match.qtypeInvalid = true
	}
	rule.Match.ResponseIPCIDR = append(rule.Match.ResponseIPCIDR, stringOrList(raw.ResponseIPCIDR)...)
	if len(raw.Action) > 0 {
		parseAction(raw.Action, &rule.Action)
	}
	// flat ipv4/ipv6 carry replacement addresses exactly like host-map
	// values; they fill the action only when it did not carry its own list
	if len(rule.Action.ReplaceA) == 0 {
		rule.Action.ReplaceA = validAddresses(raw.IPv4, 4)
	}
	if len(rule.Action.ReplaceAAAA) == 0 {
		rule.Action.ReplaceAAAA = validAddresses(raw.IPv6, 6)
	}
	rule.compile()
	return rule, true
}

func parseMatch(raw json.RawMessage, m *RuleMatch) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return
	}
	m.DomainExact = stringList(fields["domain_exact"])
	m.DomainSuffix = stringList(fields["domain_suffix"])
	if qtypes, ok := qtypeList(fields["qtype"]); ok {
		m.QType = qtypes
	} else {
		m.qtypeInvalid = true
	}
	m.ResponseIPCIDR = stringList(fields["response_ip_cidr"])
}

func parseAction(raw json.RawMessage, a *RuleAction) {
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		a.Type = Action(strings.ToLower(strings.TrimSpace(text)))
		return
	}
	var fields struct {
		Type         string          `json:"type"`
		Values       []string        `json:"values"`
		ReplaceA     []string        `json:"replace_a"`
		ReplaceAAAA  []string        `json:"replace_aaaa"`
		ReplaceCNAME json.RawMessage `json:"replace_cname"`
		RewriteHTTPS *struct {
			IPv4Hint []string `json:"ipv4hint"`
			IPv6Hint []string `json:"ipv6hint"`
		} `json:"rewrite_https"`
		EnableECS  *bool `json:"enable_ecs"`
		DisableECS *bool `json:"disable_ecs"`
		Block      *bool `json:"block"`
	}
	if err := json.Unmarshal(raw, &fields); err != nil {
		return
	}
	a.Type = Action(strings.ToLower(strings.TrimSpace(fields.Type)))
	a.Values = fields.Values
	a.ReplaceA = fields.ReplaceA
	a.ReplaceAAAA = fields.ReplaceAAAA
	a.ReplaceCNAME = stringOrList(fields.ReplaceCNAME)
	if fields.RewriteHTTPS != nil {
		a.RewriteHTTPS = &HTTPSReload{IPv4Hint: fields.RewriteHTTPS.IPv4Hint, IPv6Hint: fields.RewriteHTTPS.IPv6Hint}
	}
	if fields.EnableECS != nil {
		a.EnableECS = *fields.EnableECS
	}
	if fields.DisableECS != nil {
		a.DisableECS = *fields.DisableECS
	}
	if fields.Block != nil {
		a.Block = *fields.Block
	}
}

func parseHostMap(obj map[string]json.RawMessage) (*RuleSet, error) {
	patterns := make([]string, 0, len(obj))
	for pattern := range obj {
		patterns = append(patterns, pattern)
	}
	sort.Strings(patterns)
	out := &RuleSet{}
	for _, pattern := range patterns {
		if len(out.Rules) >= maxRules {
			break
		}
		var value struct {
			IPv4 []string `json:"ipv4"`
			IPv6 []string `json:"ipv6"`
		}
		if err := json.Unmarshal(obj[pattern], &value); err != nil {
			continue
		}
		wildcard := strings.HasPrefix(pattern, "*.")
		domain := wire.CanonicalName(strings.TrimPrefix(pattern, "*."))
		if domain == "" || domain == "." || len(domain) > 253 {
			continue
		}
		var match RuleMatch
		if wildcard {
			match.DomainSuffix = []string{domain}
		} else {
			match.DomainExact = []string{domain}
		}
		if ipv4 := validAddresses(value.IPv4, 4); len(ipv4) > 0 {
			m := match
			m.QType = []uint16{wire.TypeA}
			out.Rules = append(out.Rules, Rule{Match: m, Action: RuleAction{ReplaceA: ipv4}})
		}
		if ipv6 := validAddresses(value.IPv6, 6); len(ipv6) > 0 {
			m := match
			m.QType = []uint16{wire.TypeAAAA}
			out.Rules = append(out.Rules, Rule{Match: m, Action: RuleAction{ReplaceAAAA: ipv6}})
		}
	}
	return out, nil
}

// Load resolves the effective rule set: embedded RULES_JSON first, then the
// remote RULES_URL when it passes the dynamic-rules defense chain. Every
// failure mode falls back to the embedded set; Load never hard-fails.
func Load(ctx context.Context, cfg *config.Config) (*RuleSet, error) {
	embedded := &RuleSet{}
	if parsed, err := Parse([]byte(cfg.RulesJSON)); err == nil {
		embedded = parsed
	} else {
		slog.Warn("rules: embedded rules failed to parse, using empty set", "error", err.Error())
	}
	if !strings.HasPrefix(cfg.RulesURL, "https://") {
		return embedded, nil
	}
	if _, err := ValidateDynamicURL(cfg.RulesURL, cfg); err != nil {
		slog.Warn("rules: remote URL rejected, using embedded rules", "error", err.Error())
		return embedded, nil
	}
	remote, ok := fetchRemote(ctx, cfg.RulesURL, cfg)
	if !ok {
		return embedded, nil
	}
	return remote, nil
}

// httpClient never follows redirects: a dynamic-rules redirect is a rejection.
var httpClient = &http.Client{
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

func fetchRemote(ctx context.Context, rawURL string, cfg *config.Config) (*RuleSet, bool) {
	timeout := 2 * cfg.UpstreamTimeoutMs
	if timeout > 5000 {
		timeout = 5000
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, false
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Cache-Control", "no-cache")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, false
	}
	if resp.ContentLength > int64(cfg.DynamicRulesMaxBytes) {
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(cfg.DynamicRulesMaxBytes)+1))
	if err != nil {
		return nil, false
	}
	if len(body) > cfg.DynamicRulesMaxBytes {
		return nil, false
	}
	parsed, err := Parse(body)
	if err != nil {
		return nil, false
	}
	if len(parsed.Rules) == 0 && !triviallyEmpty(body) {
		return nil, false
	}
	return parsed, true
}

func triviallyEmpty(body []byte) bool {
	switch strings.TrimSpace(string(body)) {
	case "[]", "{}", `{"rules":[]}`:
		return true
	}
	return false
}

// ValidateDynamicURL enforces the dynamic-rules defense chain on one URL:
// https only, whitelisted host, no credentials, port 443 or default, no
// fragment, bounded length. The returned string is the normalized URL.
func ValidateDynamicURL(raw string, cfg *config.Config) (string, error) {
	if len(raw) > 2048 {
		return "", errors.New("rules URL too long")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid rules URL: %w", err)
	}
	if u.Scheme != "https" {
		return "", errors.New("rules URL must use https")
	}
	host := u.Hostname()
	if host == "" {
		return "", errors.New("rules URL has no host")
	}
	if !hostAllowed(host, cfg.DynamicRuleHosts) {
		return "", fmt.Errorf("rules host %q is not allowed", host)
	}
	if u.User != nil {
		return "", errors.New("rules URL must not carry credentials")
	}
	if port := u.Port(); port != "" && port != "443" {
		return "", fmt.Errorf("rules URL port %q is not allowed", port)
	}
	if u.Fragment != "" || u.EscapedFragment() != "" {
		return "", errors.New("rules URL must not carry a fragment")
	}
	return u.String(), nil
}

func hostAllowed(host string, allowed []string) bool {
	for _, item := range allowed {
		if strings.EqualFold(strings.TrimSuffix(item, "."), strings.TrimSuffix(host, ".")) {
			return true
		}
	}
	return false
}

func (r *Rule) compile() {
	if len(r.Match.ResponseIPCIDR) == 0 {
		r.cidrs = nil
		return
	}
	for _, s := range r.Match.ResponseIPCIDR {
		if c, ok := parseCIDR(s); ok {
			r.cidrs = append(r.cidrs, c)
		}
	}
}

func stringList(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var items []string
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil
	}
	out := items[:0]
	for _, item := range items {
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

func stringOrList(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		if text != "" {
			return []string{text}
		}
		return nil
	}
	return stringList(raw)
}

// qtypeList decodes the qtype condition. ok is false when the field is
// present but wrong-typed (neither a number nor a list of numbers); callers
// must then treat the condition as never matching.
func qtypeList(raw json.RawMessage) (list []uint16, ok bool) {
	if len(raw) == 0 {
		return nil, true
	}
	var single uint16
	if err := json.Unmarshal(raw, &single); err == nil {
		return []uint16{single}, true
	}
	var items []uint16
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, false
	}
	return items, true
}

// validAddresses filters a host-map address list: strict parse per family,
// deduplicated, capped at 16 entries.
func validAddresses(values []string, family int) []string {
	var out []string
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		var ok bool
		if family == 4 {
			_, err := wire.ParseIPv4(value)
			ok = err == nil
		} else {
			_, err := wire.ParseIPv6(value)
			ok = err == nil
		}
		if !ok || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
		if len(out) >= 16 {
			break
		}
	}
	return out
}
