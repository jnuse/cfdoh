package wire

import (
	"sync/atomic"
)

// rotation is the process-wide rotation counter: every served answer bumps it
// so clients that always dial the first address spread across the pool.
var rotation atomic.Uint64

// RotateAddresses rotates A and AAAA answer records: each address-family
// group is cyclically left-shifted by the counter modulo the group size;
// other records and the relative order of groups stay in place. A packet
// that cannot be re-encoded is returned unchanged.
func RotateAddresses(packet []byte) ([]byte, error) {
	pkt, err := Parse(packet)
	if err != nil {
		return packet, nil
	}
	n := int(rotation.Add(1))
	idx4, idx6 := recordIndexes(pkt.Answers, TypeA), recordIndexes(pkt.Answers, TypeAAAA)
	if len(idx4) < 2 && len(idx6) < 2 {
		return packet, nil
	}
	rotated := make([]Record, len(pkt.Answers))
	copy(rotated, pkt.Answers)
	rotateGroup(rotated, idx4, n)
	rotateGroup(rotated, idx6, n)
	out, err := (&Packet{Header: pkt.Header, Questions: pkt.Questions, Answers: rotated, Authorities: pkt.Authorities, Additionals: pkt.Additionals}).Encode()
	if err != nil {
		return packet, nil
	}
	return out, nil
}

func recordIndexes(records []Record, rtype uint16) []int {
	var out []int
	for i, r := range records {
		if r.Type == rtype {
			out = append(out, i)
		}
	}
	return out
}

func rotateGroup(records []Record, indexes []int, n int) {
	if len(indexes) < 2 {
		return
	}
	shift := n % len(indexes)
	if shift == 0 {
		return
	}
	group := make([]Record, len(indexes))
	for i, idx := range indexes {
		group[i] = records[idx]
	}
	for i, idx := range indexes {
		records[idx] = group[(i+shift)%len(group)]
	}
}

// MakeServfail builds a SERVFAIL response for the query wire packet. On a
// parseable query the response keeps opcode, RD and CD (mask 0x7910), sets
// QR|RA and rcode 2, and preserves the question. An unparseable query yields
// a bare 12-byte header with the request ID and flags 0x8182.
func MakeServfail(query []byte) []byte {
	if pkt, err := Parse(query); err == nil {
		pkt.Header.Flags = 0x8000 | (pkt.Header.Flags & 0x7910) | 0x0080 | 2
		pkt.Answers, pkt.Authorities, pkt.Additionals = nil, nil, nil
		if out, err := pkt.Encode(); err == nil {
			return out
		}
	}
	out := make([]byte, 12)
	if len(query) >= 2 {
		out[0], out[1] = query[0], query[1]
	}
	out[2], out[3] = 0x81, 0x82
	return out
}

// PatchID returns a copy of packet with the transaction ID replaced.
func PatchID(packet []byte, id uint16) []byte {
	out := make([]byte, len(packet))
	copy(out, packet)
	out[0] = byte(id >> 8)
	out[1] = byte(id)
	return out
}

// ResponseTTL computes the cacheable TTL for a response:
//   - SERVFAIL: 0 (never cached);
//   - normal answers: the minimum TTL across answer records excluding OPT;
//   - negative answers (NXDOMAIN, or empty answers) carrying a SOA in
//     authority: min(SOA TTL, SOA minimum, negMax); without a SOA: 0 —
//     nothing anchors the negativity, so the answer is not cacheable
//     (aligns the baseline);
//   - the result is clamped into [minTTL, maxTTL]; non-positive values stay 0.
func ResponseTTL(p *Packet, minTTL, maxTTL, negMax int) int {
	if p.Header.RCode() == 2 {
		return 0
	}
	negative := p.Header.RCode() == 3 || len(p.Answers) == 0
	if negative {
		for _, r := range p.Authorities {
			if soa, ok := r.RData.(SOA); ok {
				return clampTTL(minInt(int(r.TTL), int(soa.Minimum), negMax), minTTL, maxTTL)
			}
		}
		return 0
	}
	minimum := -1
	for _, r := range p.Answers {
		if _, isOpt := r.RData.(Opt); isOpt {
			continue
		}
		if minimum < 0 || int(r.TTL) < minimum {
			minimum = int(r.TTL)
		}
	}
	if minimum < 0 {
		minimum = 0
	}
	return clampTTL(minimum, minTTL, maxTTL)
}

func clampTTL(v, minTTL, maxTTL int) int {
	if v <= 0 {
		return 0
	}
	if v < minTTL {
		return minTTL
	}
	if v > maxTTL {
		return maxTTL
	}
	return v
}

func minInt(values ...int) int {
	m := values[0]
	for _, v := range values[1:] {
		if v < m {
			m = v
		}
	}
	return m
}
