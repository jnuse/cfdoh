package wire

import (
	"fmt"
	"strconv"
	"strings"
)

// CanonicalName strips one trailing dot and lowercases; all name comparisons
// go through this normalization while storage keeps original case.
func CanonicalName(name string) string {
	name = strings.TrimSuffix(name, ".")
	return strings.ToLower(name)
}

// MatchDomain reports whether name matches any pattern. Patterns are matched
// canonically: a plain pattern matches exactly; "*.example.com" matches both
// "example.com" and any subdomain of it.
func MatchDomain(name string, patterns []string) bool {
	cn := CanonicalName(name)
	for _, pattern := range patterns {
		p := CanonicalName(pattern)
		if strings.HasPrefix(p, "*.") {
			suffix := p[1:] // ".example.com"
			if cn == p[2:] || strings.HasSuffix(cn, suffix) {
				return true
			}
			continue
		}
		if cn == p {
			return true
		}
	}
	return false
}

// ParseIPv4 parses a strict dotted-quad; leading zeros are tolerated.
func ParseIPv4(s string) ([4]byte, error) {
	var ip [4]byte
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return ip, fmt.Errorf("invalid IPv4 %q: want 4 parts", s)
	}
	for i, part := range parts {
		if part == "" || len(part) > 3 {
			return ip, fmt.Errorf("invalid IPv4 %q: bad part %q", s, part)
		}
		v, err := strconv.Atoi(part)
		if err != nil || v < 0 || v > 255 {
			return ip, fmt.Errorf("invalid IPv4 %q: bad part %q", s, part)
		}
		ip[i] = byte(v)
	}
	return ip, nil
}

// ParseIPv6 parses IPv6 text with "::" support. Any form containing a dot
// (embedded IPv4 tail, IPv4-mapped notation) is rejected so address-family
// detection by textual shape stays unambiguous.
func ParseIPv6(s string) ([16]byte, error) {
	var ip [16]byte
	if strings.Contains(s, ".") {
		return ip, fmt.Errorf("invalid IPv6 %q: embedded IPv4 forms rejected", s)
	}
	head, tail, hasElision := strings.Cut(s, "::")
	if strings.Count(s, "::") > 1 {
		return ip, fmt.Errorf("invalid IPv6 %q: multiple elisions", s)
	}
	var headGroups, tailGroups []uint16
	var err error
	if headGroups, err = parseIPv6Groups(head); err != nil {
		return ip, err
	}
	if hasElision {
		if tailGroups, err = parseIPv6Groups(tail); err != nil {
			return ip, err
		}
	} else if tail != "" || strings.HasSuffix(s, ":") && strings.HasPrefix(s, ":") {
		return ip, fmt.Errorf("invalid IPv6 %q", s)
	}
	total := len(headGroups) + len(tailGroups)
	if hasElision {
		if total >= 8 {
			return ip, fmt.Errorf("invalid IPv6 %q: elision with %d groups", s, total)
		}
	} else if total != 8 {
		return ip, fmt.Errorf("invalid IPv6 %q: want 8 groups, got %d", s, total)
	}
	for i, g := range headGroups {
		ip[i*2] = byte(g >> 8)
		ip[i*2+1] = byte(g)
	}
	for i, g := range tailGroups {
		pos := 16 - (len(tailGroups)-i)*2
		ip[pos] = byte(g >> 8)
		ip[pos+1] = byte(g)
	}
	return ip, nil
}

func parseIPv6Groups(s string) ([]uint16, error) {
	if s == "" {
		return nil, nil
	}
	parts := strings.Split(s, ":")
	out := make([]uint16, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			return nil, fmt.Errorf("invalid IPv6 group %q", part)
		}
		if len(part) > 4 {
			return nil, fmt.Errorf("invalid IPv6 group %q", part)
		}
		v, err := strconv.ParseUint(part, 16, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid IPv6 group %q", part)
		}
		out = append(out, uint16(v))
	}
	return out, nil
}

// IPv4String renders a 4-byte address in dotted-quad form.
func IPv4String(ip [4]byte) string {
	return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
}

// IPv6String renders a 16-byte address as 8 full hex groups without "::"
// compression, keeping identity strings stable.
func IPv6String(ip [16]byte) string {
	const hexDigits = "0123456789abcdef"
	var sb strings.Builder
	for i := 0; i < 16; i += 2 {
		if i > 0 {
			sb.WriteByte(':')
		}
		sb.WriteByte(hexDigits[ip[i]>>4])
		sb.WriteByte(hexDigits[ip[i]&0x0f])
		sb.WriteByte(hexDigits[ip[i+1]>>4])
		sb.WriteByte(hexDigits[ip[i+1]&0x0f])
	}
	return sb.String()
}
