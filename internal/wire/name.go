package wire

// decodeName decodes a possibly-compressed domain name starting at p.off.
// Compression pointers may target any offset inside the message; cycles are
// defeated by a visited-offset set plus a jump budget. The decoded name is
// capped at maxWireName wire bytes and maxNameLabels labels — a name that
// cannot be re-encoded is rejected here, keeping Parse→Encode an
// equivalence. Returns the decoded name and the offset just past the name
// in the stream that contained it.
func (p *parser) decodeName() (string, error) {
	start := p.off
	visited := make(map[int]bool)
	jumps := 0
	off := p.off
	labels := make([][]byte, 0, 8)
	wireLen := 1 // trailing root byte
	for {
		if off >= len(p.buf) {
			return "", errName("name runs past end of message")
		}
		length := p.buf[off]
		switch length & 0xC0 {
		case 0x00:
			if length == 0 {
				off++
				if start == p.off {
					// No pointer was followed: stream position advances past this name.
					p.off = off
				}
				return joinLabels(labels), nil
			}
			if int(length) > len(p.buf)-off-1 {
				return "", errName("label runs past end of message")
			}
			labels = append(labels, cloneBytes(p.buf[off+1:off+1+int(length)]))
			wireLen += 1 + int(length)
			if wireLen > maxWireName {
				return "", errName("name exceeds 255 wire bytes")
			}
			if len(labels) > maxNameLabels {
				return "", errName("too many labels in name")
			}
			off += 1 + int(length)
		case 0xC0:
			if len(p.buf)-off < 2 {
				return "", errName("truncated compression pointer")
			}
			target := int(p.buf[off]&0x3F)<<8 | int(p.buf[off+1])
			if start == p.off {
				// First pointer: stream position advances past the 2-byte pointer.
				p.off = off + 2
			}
			if visited[target] {
				return "", errName("compression pointer loop")
			}
			visited[target] = true
			jumps++
			if jumps > maxNameJumps {
				return "", errName("too many compression pointer jumps")
			}
			off = target
		default:
			return "", errName("unsupported label type 0x40/0x80")
		}
	}
}

func joinLabels(labels [][]byte) string {
	total := 0
	for _, l := range labels {
		total += len(l) + 1
	}
	if total == 0 {
		return "."
	}
	out := make([]byte, 0, total)
	for _, l := range labels {
		out = append(out, l...)
		out = append(out, '.')
	}
	return string(out)
}

func cloneBytes(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

type errName string

func (e errName) Error() string { return string(e) }
