package wire

import "sort"

// DescribeHTTPS extracts the commonly consumed SvcParams of an HTTPS/SVCB
// record: alpn (key 1), ipv4hint (key 4), ipv6hint (key 6) and the raw ech
// config list (key 5). Hint lengths must be exact multiples of the address
// size; violations surface as errors from the caller's encode round trip.
func DescribeHTTPS(r *Record) (alpn []string, ipv4, ipv6 []string, ech []byte) {
	sv, ok := r.RData.(SVCB)
	if !ok {
		return nil, nil, nil, nil
	}
	for _, param := range sv.Params {
		switch param.Key {
		case ParamALPN:
			alpn = parseAlpnList(param.Value)
		case ParamIPv4Hint:
			ipv4 = parseHints(param.Value, 4)
		case ParamIPv6Hint:
			ipv6 = parseHints(param.Value, 16)
		case ParamECH:
			ech = cloneBytes(param.Value)
		}
	}
	return alpn, ipv4, ipv6, ech
}

func parseAlpnList(value []byte) []string {
	var out []string
	for off := 0; off < len(value); {
		length := int(value[off])
		if off+1+length > len(value) {
			return out
		}
		out = append(out, string(value[off+1:off+1+length]))
		off += 1 + length
	}
	return out
}

func parseHints(value []byte, size int) []string {
	var out []string
	for off := 0; off+size <= len(value); off += size {
		switch size {
		case 4:
			var ip [4]byte
			copy(ip[:], value[off:off+4])
			out = append(out, IPv4String(ip))
		case 16:
			var ip [16]byte
			copy(ip[:], value[off:off+16])
			out = append(out, IPv6String(ip))
		}
	}
	return out
}

// UpsertSvcParam replaces (or inserts) the parameter with the given key and
// keeps the parameter list sorted by key with duplicates removed. The record
// is mutated in place.
func UpsertSvcParam(r *Record, key uint16, value []byte) {
	sv, ok := r.RData.(SVCB)
	if !ok {
		return
	}
	params := make([]SvcParam, 0, len(sv.Params)+1)
	for _, param := range sv.Params {
		if param.Key != key {
			params = append(params, param)
		}
	}
	params = append(params, SvcParam{Key: key, Value: cloneBytes(value)})
	sort.Slice(params, func(i, j int) bool { return params[i].Key < params[j].Key })
	sv.Params = params
	r.RData = sv
}
