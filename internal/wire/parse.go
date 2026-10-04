package wire

import (
	"errors"
	"fmt"
)

// parse errors are sentinel-wrapped via fmt.Errorf; callers match on message
// content only for tests.

type parser struct {
	buf []byte
	off int
}

func (p *parser) remaining() int { return len(p.buf) - p.off }

func (p *parser) u8() (uint8, error) {
	if p.remaining() < 1 {
		return 0, errors.New("unexpected end of message")
	}
	v := p.buf[p.off]
	p.off++
	return v, nil
}

func (p *parser) u16() (uint16, error) {
	if p.remaining() < 2 {
		return 0, errors.New("unexpected end of message")
	}
	v := uint16(p.buf[p.off])<<8 | uint16(p.buf[p.off+1])
	p.off += 2
	return v, nil
}

func (p *parser) u32() (uint32, error) {
	if p.remaining() < 4 {
		return 0, errors.New("unexpected end of message")
	}
	v := uint32(p.buf[p.off])<<24 | uint32(p.buf[p.off+1])<<16 | uint32(p.buf[p.off+2])<<8 | uint32(p.buf[p.off+3])
	p.off += 4
	return v, nil
}

func (p *parser) take(n int) ([]byte, error) {
	if n < 0 || p.remaining() < n {
		return nil, errors.New("unexpected end of message")
	}
	out := make([]byte, n)
	copy(out, p.buf[p.off:p.off+n])
	p.off += n
	return out, nil
}

// Parse decodes a complete DNS message. It rejects trailing bytes, oversized
// counts, hostile label types, out-of-order SVCB params and any structure that
// would alias the input buffer (all decoded payloads are deep-copied).
func Parse(b []byte) (*Packet, error) {
	return parse(b, false)
}

// ParseRelaxed decodes a DNS message the way tolerant resolvers treat
// upstream responses: the header counts define the message and bytes beyond
// the last declared record are ignored (the dns-packet baseline behavior).
// Inbound queries keep the strict Parse (F-002 rejects trailing bytes).
func ParseRelaxed(b []byte) (*Packet, error) {
	return parse(b, true)
}

func parse(b []byte, allowTrailing bool) (*Packet, error) {
	if len(b) < 12 {
		return nil, fmt.Errorf("message too short: %d bytes", len(b))
	}
	p := &parser{buf: b}
	h := Header{
		ID:      mustU16(b[0:2]),
		Flags:   mustU16(b[2:4]),
		QDCount: mustU16(b[4:6]),
		ANCount: mustU16(b[6:8]),
		NSCount: mustU16(b[8:10]),
		ARCount: mustU16(b[10:12]),
	}
	p.off = 12
	if h.QDCount > maxQuestions {
		return nil, fmt.Errorf("question count %d exceeds %d", h.QDCount, maxQuestions)
	}
	total := int(h.QDCount) + int(h.ANCount) + int(h.NSCount) + int(h.ARCount)
	if total > maxTotalRecords {
		return nil, fmt.Errorf("record count %d exceeds %d", total, maxTotalRecords)
	}
	pkt := &Packet{Header: h}
	for i := 0; i < int(h.QDCount); i++ {
		name, err := p.decodeName()
		if err != nil {
			return nil, err
		}
		qtype, err := p.u16()
		if err != nil {
			return nil, err
		}
		qclass, err := p.u16()
		if err != nil {
			return nil, err
		}
		pkt.Questions = append(pkt.Questions, Question{Name: name, Type: qtype, Class: qclass})
	}
	var err error
	if pkt.Answers, err = p.decodeRecords(int(h.ANCount)); err != nil {
		return nil, err
	}
	if pkt.Authorities, err = p.decodeRecords(int(h.NSCount)); err != nil {
		return nil, err
	}
	if pkt.Additionals, err = p.decodeRecords(int(h.ARCount)); err != nil {
		return nil, err
	}
	if !allowTrailing && p.off != len(b) {
		return nil, fmt.Errorf("trailing data: %d bytes after message", len(b)-p.off)
	}
	return pkt, nil
}

func (p *parser) decodeRecords(n int) ([]Record, error) {
	if n == 0 {
		return nil, nil
	}
	out := make([]Record, 0, n)
	for i := 0; i < n; i++ {
		name, err := p.decodeName()
		if err != nil {
			return nil, err
		}
		rtype, err := p.u16()
		if err != nil {
			return nil, err
		}
		rclass, err := p.u16()
		if err != nil {
			return nil, err
		}
		ttl, err := p.u32()
		if err != nil {
			return nil, err
		}
		rdlen, err := p.u16()
		if err != nil {
			return nil, err
		}
		if p.remaining() < int(rdlen) {
			return nil, errors.New("truncated RDATA")
		}
		rdEnd := p.off + int(rdlen)
		rd, err := p.decodeRData(rtype, rclass, ttl, rdEnd)
		if err != nil {
			return nil, fmt.Errorf("record %s type %d: %w", name, rtype, err)
		}
		if p.off != rdEnd {
			return nil, fmt.Errorf("record %s type %d: RDATA not fully consumed", name, rtype)
		}
		out = append(out, Record{Name: name, Type: rtype, Class: rclass, TTL: ttl, RData: rd})
	}
	return out, nil
}

func (p *parser) decodeRData(rtype, rclass uint16, ttl uint32, rdEnd int) (RData, error) {
	switch rtype {
	case TypeA:
		if p.remaining() < 4 || p.off+4 > rdEnd {
			return nil, errors.New("A RDATA must be 4 bytes")
		}
		var ip [4]byte
		copy(ip[:], p.buf[p.off:p.off+4])
		p.off += 4
		return A{IP: ip}, nil
	case TypeAAAA:
		if p.remaining() < 16 || p.off+16 > rdEnd {
			return nil, errors.New("AAAA RDATA must be 16 bytes")
		}
		var ip [16]byte
		copy(ip[:], p.buf[p.off:p.off+16])
		p.off += 16
		return AAAA{IP: ip}, nil
	case TypeCNAME, TypeNS, TypePTR, TypeDNAME:
		name, err := p.decodeName()
		if err != nil {
			return nil, err
		}
		return Name{Name: name}, nil
	case TypeMX:
		pref, err := p.u16()
		if err != nil {
			return nil, err
		}
		exchange, err := p.decodeName()
		if err != nil {
			return nil, err
		}
		return MX{Preference: pref, Exchange: exchange}, nil
	case TypeSOA:
		mname, err := p.decodeName()
		if err != nil {
			return nil, err
		}
		rname, err := p.decodeName()
		if err != nil {
			return nil, err
		}
		serial, err := p.u32()
		if err != nil {
			return nil, err
		}
		refresh, err := p.u32()
		if err != nil {
			return nil, err
		}
		retry, err := p.u32()
		if err != nil {
			return nil, err
		}
		expire, err := p.u32()
		if err != nil {
			return nil, err
		}
		minimum, err := p.u32()
		if err != nil {
			return nil, err
		}
		return SOA{MName: mname, RName: rname, Serial: serial, Refresh: refresh, Retry: retry, Expire: expire, Minimum: minimum}, nil
	case TypeSRV:
		prio, err := p.u16()
		if err != nil {
			return nil, err
		}
		weight, err := p.u16()
		if err != nil {
			return nil, err
		}
		port, err := p.u16()
		if err != nil {
			return nil, err
		}
		target, err := p.decodeName()
		if err != nil {
			return nil, err
		}
		return SRV{Priority: prio, Weight: weight, Port: port, Target: target}, nil
	case TypeHTTPS, TypeSVCB:
		return p.decodeSVCB(rdEnd)
	case TypeOPT:
		// OPT: class carries payload size; TTL carries ext-rcode/version/DO.
		var opt Opt
		opt.PayloadSize = rclass
		opt.ExtRCode = uint8(ttl >> 24)
		opt.Version = uint8(ttl >> 16)
		opt.DO = ttl&0x8000 != 0
		for p.off < rdEnd {
			code, err := p.u16()
			if err != nil {
				return nil, err
			}
			length, err := p.u16()
			if err != nil {
				return nil, err
			}
			if p.off+int(length) > rdEnd {
				return nil, errors.New("EDNS option exceeds RDATA boundary")
			}
			data, err := p.take(int(length))
			if err != nil {
				return nil, err
			}
			opt.Options = append(opt.Options, EdnsOption{Code: code, Data: data})
		}
		return opt, nil
	default:
		if p.remaining() < rdEnd-p.off {
			return nil, errors.New("truncated RDATA")
		}
		n := rdEnd - p.off
		data, err := p.take(n)
		if err != nil {
			return nil, err
		}
		return Raw{Type: rtype, Data: data}, nil
	}
}

func (p *parser) decodeSVCB(rdEnd int) (RData, error) {
	priority, err := p.u16()
	if err != nil {
		return nil, err
	}
	target, err := p.decodeName()
	if err != nil {
		return nil, err
	}
	sv := SVCB{Priority: priority, Target: target}
	var lastKey uint16 = 0
	first := true
	for p.off < rdEnd {
		key, err := p.u16()
		if err != nil {
			return nil, err
		}
		if !first && key <= lastKey {
			return nil, fmt.Errorf("SvcParam keys must be strictly increasing (got %d after %d)", key, lastKey)
		}
		first = false
		lastKey = key
		length, err := p.u16()
		if err != nil {
			return nil, err
		}
		if p.off+int(length) > rdEnd {
			return nil, errors.New("SvcParam value exceeds RDATA boundary")
		}
		value, err := p.take(int(length))
		if err != nil {
			return nil, err
		}
		sv.Params = append(sv.Params, SvcParam{Key: key, Value: value})
	}
	return sv, nil
}

func mustU16(b []byte) uint16 { return uint16(b[0])<<8 | uint16(b[1]) }
