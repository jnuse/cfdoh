package rules

import (
	"strconv"
	"strings"

	"github.com/jnuse/cfdoh/internal/wire"
)

// cidr is a compiled response_ip_cidr matcher. v4 and v6 live in one type;
// families never cross-match.
type cidr struct {
	v4   bool
	addr [16]byte
	ones int
}

// parseCIDR parses "addr/prefix" strictly with the wire address parsers. A
// missing prefix means a host route (/32 or /128).
func parseCIDR(s string) (cidr, bool) {
	var c cidr
	text, bits, hasPrefix := strings.Cut(strings.TrimSpace(s), "/")
	if strings.Contains(text, ".") {
		ip, err := wire.ParseIPv4(text)
		if err != nil {
			return c, false
		}
		ones := 32
		if hasPrefix {
			n, err := strconv.Atoi(bits)
			if err != nil || n < 0 || n > 32 {
				return c, false
			}
			ones = n
		}
		c.v4, c.ones = true, ones
		copy(c.addr[:4], ip[:])
		return c, true
	}
	ip, err := wire.ParseIPv6(text)
	if err != nil {
		return c, false
	}
	ones := 128
	if hasPrefix {
		n, err := strconv.Atoi(bits)
		if err != nil || n < 0 || n > 128 {
			return c, false
		}
		ones = n
	}
	c.ones = ones
	copy(c.addr[:], ip[:])
	return c, true
}

func (c cidr) containsV4(ip [4]byte) bool {
	if !c.v4 {
		return false
	}
	var full [16]byte
	copy(full[:4], ip[:])
	return c.prefixMatch(full)
}

func (c cidr) containsV6(ip [16]byte) bool {
	if c.v4 {
		return false
	}
	return c.prefixMatch(ip)
}

func (c cidr) prefixMatch(ip [16]byte) bool {
	size := 4
	if !c.v4 {
		size = 16
	}
	bytes := c.ones / 8
	if bytes > 0 {
		for i := 0; i < bytes && i < size; i++ {
			if c.addr[i] != ip[i] {
				return false
			}
		}
	}
	if remaining := c.ones % 8; remaining != 0 && bytes < size {
		mask := byte(0xff << (8 - remaining))
		if c.addr[bytes]&mask != ip[bytes]&mask {
			return false
		}
	}
	return true
}
