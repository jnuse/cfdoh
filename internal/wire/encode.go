package wire

import (
	"errors"
	"fmt"
)

// Encode rebuilds the wire form. Names are never compressed; section counts
// come from the slice lengths, not from Header count fields.
func (p *Packet) Encode() ([]byte, error) {
	out := make([]byte, 0, 512)
	h := p.Header
	h.QDCount = uint16(len(p.Questions))
	h.ANCount = uint16(len(p.Answers))
	h.NSCount = uint16(len(p.Authorities))
	h.ARCount = uint16(len(p.Additionals))
	out = appendU16(out, h.ID)
	out = appendU16(out, h.Flags)
	out = appendU16(out, h.QDCount)
	out = appendU16(out, h.ANCount)
	out = appendU16(out, h.NSCount)
	out = appendU16(out, h.ARCount)
	for _, q := range p.Questions {
		var err error
		out, err = appendName(out, q.Name)
		if err != nil {
			return nil, err
		}
		out = appendU16(out, q.Type)
		out = appendU16(out, q.Class)
	}
	var err error
	for i := range p.Answers {
		if out, err = appendRecord(out, &p.Answers[i]); err != nil {
			return nil, err
		}
	}
	for i := range p.Authorities {
		if out, err = appendRecord(out, &p.Authorities[i]); err != nil {
			return nil, err
		}
	}
	for i := range p.Additionals {
		if out, err = appendRecord(out, &p.Additionals[i]); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func appendRecord(out []byte, r *Record) ([]byte, error) {
	var err error
	out, err = appendName(out, r.Name)
	if err != nil {
		return nil, err
	}
	out = appendU16(out, r.Type)
	// OPT keeps its payload size in the class field; other records carry class.
	if opt, ok := r.RData.(Opt); ok {
		out = appendU16(out, opt.PayloadSize)
	} else {
		out = appendU16(out, r.Class)
	}
	var ttl uint32
	if opt, ok := r.RData.(Opt); ok {
		ttl = uint32(opt.ExtRCode)<<24 | uint32(opt.Version)<<16
		if opt.DO {
			ttl |= 0x8000
		}
	} else {
		ttl = r.TTL
	}
	out = appendU32(out, ttl)
	rd, err := encodeRData(r)
	if err != nil {
		return nil, err
	}
	if len(rd) > 0xFFFF {
		return nil, fmt.Errorf("RDATA too large: %d bytes", len(rd))
	}
	out = appendU16(out, uint16(len(rd)))
	return append(out, rd...), nil
}

func encodeRData(r *Record) ([]byte, error) {
	switch rd := r.RData.(type) {
	case A:
		return rd.IP[:], nil
	case AAAA:
		return rd.IP[:], nil
	case Name:
		return appendName(nil, rd.Name)
	case MX:
		out := appendU16(nil, rd.Preference)
		return appendName(out, rd.Exchange)
	case SOA:
		out, err := appendName(nil, rd.MName)
		if err != nil {
			return nil, err
		}
		if out, err = appendName(out, rd.RName); err != nil {
			return nil, err
		}
		out = appendU32(out, rd.Serial)
		out = appendU32(out, rd.Refresh)
		out = appendU32(out, rd.Retry)
		out = appendU32(out, rd.Expire)
		out = appendU32(out, rd.Minimum)
		return out, nil
	case SRV:
		out := appendU16(nil, rd.Priority)
		out = appendU16(out, rd.Weight)
		out = appendU16(out, rd.Port)
		return appendName(out, rd.Target)
	case SVCB:
		out := appendU16(nil, rd.Priority)
		var err error
		if out, err = appendName(out, rd.Target); err != nil {
			return nil, err
		}
		for _, param := range rd.Params {
			if len(param.Value) > 0xFFFF {
				return nil, fmt.Errorf("SvcParam %d value too large", param.Key)
			}
			out = appendU16(out, param.Key)
			out = appendU16(out, uint16(len(param.Value)))
			out = append(out, param.Value...)
		}
		return out, nil
	case Opt:
		out := make([]byte, 0, 16)
		for _, opt := range rd.Options {
			out = appendU16(out, opt.Code)
			out = appendU16(out, uint16(len(opt.Data)))
			out = append(out, opt.Data...)
		}
		return out, nil
	case Raw:
		return cloneBytes(rd.Data), nil
	default:
		return nil, errors.New("unknown RData type")
	}
}

// appendName writes an uncompressed name. Labels must be 1..63 bytes and the
// total encoding (labels plus length prefixes) must not exceed 255 bytes.
func appendName(out []byte, name string) ([]byte, error) {
	if name == "" || name == "." {
		return append(out, 0), nil
	}
	rest := name
	total := 1
	for rest != "" {
		var label string
		for i := 0; i < len(rest); i++ {
			if rest[i] == '.' {
				label = rest[:i]
				rest = rest[i+1:]
				goto found
			}
		}
		label = rest
		rest = ""
	found:
		if label == "" {
			return nil, fmt.Errorf("empty label in name %q", name)
		}
		if len(label) > maxLabelLength {
			return nil, fmt.Errorf("label exceeds %d bytes in name %q", maxLabelLength, name)
		}
		total += len(label) + 1
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	if total > maxWireName {
		return nil, fmt.Errorf("name %q exceeds %d wire bytes", name, maxWireName)
	}
	return append(out, 0), nil
}

func appendU16(out []byte, v uint16) []byte {
	return append(out, byte(v>>8), byte(v))
}

func appendU32(out []byte, v uint32) []byte {
	return append(out, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}
