// Package ecs builds and applies the EDNS Client Subnet option (RFC 7871).
//
// 契约: .trellis/spec/arch/ecs.md. 决策次序: 规则覆盖 > 模式 off > 模式 always
// > 模式 rules; 注入幂等 (替换已有 ECS option), 剥离删除全部 ECS option, 均不
// 破坏 OPT 其余字段; wire 操作全部经由 wire 模块.
package ecs

import (
	"encoding/binary"
	"strconv"
	"strings"

	"github.com/jnuse/cfdoh/internal/config"
	"github.com/jnuse/cfdoh/internal/wire"
)

// optionCode is the EDNS option code of ECS (RFC 7871).
const optionCode uint16 = 8

// Value is a truncated client subnet ready for the ECS option.
type Value struct {
	Family   uint16
	Prefix   uint8
	Addr     []byte
	Identity string
}

// Make truncates clientIP to the family prefix (v4 /24 and v6 /48 by config).
// Unparseable or absent input yields nil. The identity is the canonical text
// of the truncated subnet and folds into the cache identity.
func Make(clientIP string, v4Prefix, v6Prefix int) *Value {
	if strings.Contains(clientIP, ".") {
		ip, err := wire.ParseIPv4(clientIP)
		if err != nil {
			return nil
		}
		prefix := clamp(v4Prefix, 0, 32)
		addr := truncate(ip[:], prefix)
		return &Value{
			Family:   1,
			Prefix:   uint8(prefix),
			Addr:     addr,
			Identity: strings.Join(decimalBytes(addr), ".") + "/" + strconv.Itoa(prefix),
		}
	}
	ip, err := wire.ParseIPv6(clientIP)
	if err != nil {
		return nil
	}
	prefix := clamp(v6Prefix, 0, 128)
	addr := truncate(ip[:], prefix)
	return &Value{
		Family:   2,
		Prefix:   uint8(prefix),
		Addr:     addr,
		Identity: hexBytes(addr) + "/" + strconv.Itoa(prefix),
	}
}

// ShouldUse decides whether the outbound query carries ECS. A rule override
// (present) wins over the configured mode; rules mode matches the question
// name against ECS_DOMAINS by suffix.
func ShouldUse(q *wire.Packet, cfg *config.Config, override, present bool) bool {
	if present {
		return override
	}
	switch cfg.EcsMode {
	case "off":
		return false
	case "always":
		return true
	}
	if len(q.Questions) == 0 {
		return false
	}
	return domainMatches(q.Questions[0].Name, cfg.EcsDomains)
}

// Add returns a packet with the ECS option replaced (idempotent) or injected.
// An existing OPT record keeps its payload size, DO bit and other options; a
// missing OPT is synthesized with payload size 1232 and TTL 0.
func Add(q *wire.Packet, v *Value) *wire.Packet {
	if q == nil || v == nil {
		return q
	}
	option := encodeOption(v)
	out := clonePacket(q)
	hasOpt := false
	for i := range out.Additionals {
		opt, ok := out.Additionals[i].RData.(wire.Opt)
		if !ok {
			continue
		}
		hasOpt = true
		options := make([]wire.EdnsOption, 0, len(opt.Options)+1)
		for _, o := range opt.Options {
			if o.Code != optionCode {
				options = append(options, o)
			}
		}
		opt.Options = append(options, option)
		out.Additionals[i].RData = opt
	}
	if !hasOpt {
		out.Additionals = append(out.Additionals, wire.Record{
			Name:  ".",
			Type:  wire.TypeOPT,
			RData: wire.Opt{PayloadSize: 1232, Options: []wire.EdnsOption{option}},
		})
	}
	return out
}

// Remove returns a packet with every ECS option stripped; other OPT fields
// and options survive. Packets without ECS come back unchanged.
func Remove(q *wire.Packet) *wire.Packet {
	if q == nil {
		return q
	}
	out := clonePacket(q)
	changed := false
	for i := range out.Additionals {
		opt, ok := out.Additionals[i].RData.(wire.Opt)
		if !ok {
			continue
		}
		kept := make([]wire.EdnsOption, 0, len(opt.Options))
		for _, o := range opt.Options {
			if o.Code != optionCode {
				kept = append(kept, o)
			}
		}
		if len(kept) != len(opt.Options) {
			changed = true
			opt.Options = kept
			out.Additionals[i].RData = opt
		}
	}
	if !changed {
		return q
	}
	return out
}

// domainMatches matches suffix-style ECS domain lists (".cn", "*.example.com",
// "example.org") via the shared wire matcher: leading-dot and wildcard forms
// become suffix-or-exact patterns, bare names stay exact.
func domainMatches(name string, patterns []string) bool {
	if len(patterns) == 0 {
		return false
	}
	normalized := make([]string, 0, len(patterns))
	for _, raw := range patterns {
		p := strings.TrimPrefix(wire.CanonicalName(raw), "*.")
		if strings.HasPrefix(p, ".") {
			normalized = append(normalized, "*"+p)
		} else {
			normalized = append(normalized, p)
		}
	}
	return wire.MatchDomain(name, normalized)
}

func encodeOption(v *Value) wire.EdnsOption {
	data := make([]byte, 4+len(v.Addr))
	binary.BigEndian.PutUint16(data[0:2], v.Family)
	data[2] = v.Prefix
	data[3] = 0 // scope prefix length, always zero on queries
	copy(data[4:], v.Addr)
	return wire.EdnsOption{Code: optionCode, Data: data}
}

func truncate(ip []byte, prefix int) []byte {
	length := (prefix + 7) / 8
	out := make([]byte, length)
	copy(out, ip[:length])
	if remaining := prefix % 8; remaining != 0 && length > 0 {
		out[length-1] &= byte(0xff << (8 - remaining))
	}
	return out
}

func clonePacket(q *wire.Packet) *wire.Packet {
	out := &wire.Packet{
		Header:      q.Header,
		Questions:   q.Questions,
		Answers:     q.Answers,
		Authorities: q.Authorities,
	}
	out.Additionals = make([]wire.Record, len(q.Additionals))
	copy(out.Additionals, q.Additionals)
	return out
}

func clamp(v, min, max int) int {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

func decimalBytes(b []byte) []string {
	out := make([]string, len(b))
	for i, v := range b {
		out[i] = strconv.Itoa(int(v))
	}
	return out
}

func hexBytes(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, v := range b {
		out = append(out, digits[v>>4], digits[v&0x0f])
	}
	return string(out)
}
