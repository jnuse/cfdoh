package rules

import (
	"github.com/jnuse/cfdoh/internal/wire"
)

// ShouldBlock reports whether any matching rule blocks the query; the first
// hit decides. response_ip_cidr conditions cannot match without a response,
// so request-time evaluation skips such rules.
func (rs *RuleSet) ShouldBlock(q *wire.Packet) bool {
	for i := range rs.Rules {
		rule := &rs.Rules[i]
		if !ruleMatches(rule, q, nil) {
			continue
		}
		if rule.Action.Block || rule.Action.Type == ActionBlock {
			return true
		}
	}
	return false
}

// EcsOverride returns the per-domain ECS override of the first matching rule
// that carries one; present reports whether an override exists.
func (rs *RuleSet) EcsOverride(q *wire.Packet) (value, present bool) {
	for i := range rs.Rules {
		rule := &rs.Rules[i]
		if !ruleMatches(rule, q, nil) {
			continue
		}
		if rule.Action.EnableECS || rule.Action.Type == ActionEnableECS {
			return true, true
		}
		if rule.Action.DisableECS || rule.Action.Type == ActionDisableECS {
			return false, true
		}
	}
	return false, false
}

// Apply runs every response-type action in rule order and returns the
// rewritten response. Request-type actions (block, ecs overrides) and
// passthrough are ignored here. replace only takes effect when the response
// already carries a record of the same type, inheriting the minimum TTL and
// the first owner.
func (rs *RuleSet) Apply(q, resp *wire.Packet) *wire.Packet {
	out := resp
	for i := range rs.Rules {
		rule := &rs.Rules[i]
		if !ruleMatches(rule, q, out) {
			continue
		}
		action := &rule.Action
		switch {
		case len(action.ReplaceA) > 0 || action.Type == ActionReplaceA:
			out = replaceAddressRecords(out, wire.TypeA, firstNonEmpty(action.ReplaceA, action.Values))
		case len(action.ReplaceAAAA) > 0 || action.Type == ActionReplaceAAAA:
			out = replaceAddressRecords(out, wire.TypeAAAA, firstNonEmpty(action.ReplaceAAAA, action.Values))
		case len(action.ReplaceCNAME) > 0 || action.Type == ActionReplaceCNAME:
			out = replaceCNAME(out, firstNonEmpty(action.ReplaceCNAME, action.Values))
		case action.RewriteHTTPS != nil || action.Type == ActionRewriteHTTPS:
			reload := action.RewriteHTTPS
			if reload == nil {
				reload = &HTTPSReload{}
			}
			out = rewriteHTTPS(out, reload)
		}
	}
	return out
}

// ruleMatches evaluates every present condition with AND semantics.
func ruleMatches(rule *Rule, q, resp *wire.Packet) bool {
	if q == nil || len(q.Questions) == 0 {
		return false
	}
	if rule.Match.qtypeInvalid {
		// a wrong-typed qtype condition never matches (refer semantics)
		return false
	}
	question := q.Questions[0]
	if len(rule.Match.QType) > 0 && !containsQType(rule.Match.QType, question.Type) {
		return false
	}
	if len(rule.Match.DomainExact) > 0 && !wire.MatchDomain(question.Name, rule.Match.DomainExact) {
		return false
	}
	if len(rule.Match.DomainSuffix) > 0 && !wire.MatchDomain(question.Name, suffixPatterns(rule.Match.DomainSuffix)) {
		return false
	}
	if len(rule.Match.ResponseIPCIDR) > 0 {
		if len(rule.cidrs) == 0 || resp == nil {
			return false
		}
		if !responseHasAddressIn(resp, rule.cidrs) {
			return false
		}
	}
	return true
}

// suffixPatterns turns domain_suffix items into wire wildcard patterns:
// "example.com", ".example.com" and "*.example.com" all match the domain
// itself and every subdomain.
func suffixPatterns(items []string) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		base := wire.CanonicalName(item)
		base = trimLeadingDotsAndWildcard(base)
		if base != "" {
			out = append(out, "*."+base)
		}
	}
	return out
}

func trimLeadingDotsAndWildcard(s string) string {
	s = trimPrefixWhile(s, "*.")
	s = trimPrefixWhile(s, ".")
	return s
}

func trimPrefixWhile(s, prefix string) string {
	for len(s) >= len(prefix) && s[:len(prefix)] == prefix {
		s = s[len(prefix):]
	}
	return s
}

func containsQType(list []uint16, qtype uint16) bool {
	for _, item := range list {
		if item == qtype {
			return true
		}
	}
	return false
}

func responseHasAddressIn(resp *wire.Packet, cidrs []cidr) bool {
	for _, record := range resp.Answers {
		switch rd := record.RData.(type) {
		case wire.A:
			for _, c := range cidrs {
				if c.containsV4(rd.IP) {
					return true
				}
			}
		case wire.AAAA:
			for _, c := range cidrs {
				if c.containsV6(rd.IP) {
					return true
				}
			}
		}
	}
	return false
}

func replaceAddressRecords(resp *wire.Packet, rtype uint16, values []string) *wire.Packet {
	var parsed []wire.Record
	for _, value := range values {
		if rtype == wire.TypeA {
			if ip, err := wire.ParseIPv4(value); err == nil {
				parsed = append(parsed, wire.Record{Name: "", Type: rtype, Class: wire.ClassIN, RData: wire.A{IP: ip}})
			}
		} else {
			if ip, err := wire.ParseIPv6(value); err == nil {
				parsed = append(parsed, wire.Record{Name: "", Type: rtype, Class: wire.ClassIN, RData: wire.AAAA{IP: ip}})
			}
		}
	}
	if len(parsed) == 0 {
		return resp
	}
	var matching []int
	for i, record := range resp.Answers {
		if record.Type == rtype {
			matching = append(matching, i)
		}
	}
	if len(matching) == 0 {
		return resp
	}
	ttl := resp.Answers[matching[0]].TTL
	for _, i := range matching {
		if resp.Answers[i].TTL < ttl {
			ttl = resp.Answers[i].TTL
		}
	}
	owner := resp.Answers[matching[0]].Name
	answers := make([]wire.Record, 0, len(resp.Answers)-len(matching)+len(parsed))
	for _, record := range resp.Answers {
		if record.Type != rtype {
			answers = append(answers, record)
		}
	}
	for i := range parsed {
		parsed[i].Name = owner
		parsed[i].TTL = ttl
		answers = append(answers, parsed[i])
	}
	out := *resp
	out.Answers = answers
	return &out
}

func replaceCNAME(resp *wire.Packet, values []string) *wire.Packet {
	if len(values) == 0 {
		return resp
	}
	target := values[0]
	changed := false
	answers := make([]wire.Record, len(resp.Answers))
	copy(answers, resp.Answers)
	for i := range answers {
		if answers[i].Type != wire.TypeCNAME {
			continue
		}
		answers[i].RData = wire.Name{Name: target}
		changed = true
	}
	if !changed {
		return resp
	}
	out := *resp
	out.Answers = answers
	return &out
}

func rewriteHTTPS(resp *wire.Packet, reload *HTTPSReload) *wire.Packet {
	var v4, v6 []byte
	for _, value := range reload.IPv4Hint {
		if ip, err := wire.ParseIPv4(value); err == nil {
			v4 = append(v4, ip[:]...)
		}
	}
	for _, value := range reload.IPv6Hint {
		if ip, err := wire.ParseIPv6(value); err == nil {
			v6 = append(v6, ip[:]...)
		}
	}
	if len(v4) == 0 && len(v6) == 0 {
		return resp
	}
	changed := false
	answers := make([]wire.Record, len(resp.Answers))
	copy(answers, resp.Answers)
	for i := range answers {
		if answers[i].Type != wire.TypeHTTPS {
			continue
		}
		if _, ok := answers[i].RData.(wire.SVCB); !ok {
			continue
		}
		if len(v4) > 0 {
			wire.UpsertSvcParam(&answers[i], wire.ParamIPv4Hint, v4)
		}
		if len(v6) > 0 {
			wire.UpsertSvcParam(&answers[i], wire.ParamIPv6Hint, v6)
		}
		changed = true
	}
	if !changed {
		return resp
	}
	out := *resp
	out.Answers = answers
	return &out
}

func firstNonEmpty(primary, fallback []string) []string {
	if len(primary) > 0 {
		return primary
	}
	return fallback
}
