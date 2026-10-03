// Package wire implements DNS message parsing and encoding.
//
// 契约: .trellis/spec/arch/wire.md. 编码永不压缩; 解码支持压缩指针并带防环;
// 全部防御性检查 (计数上限, 尾随字节, label 类型, SVCB 参数递增, 深拷贝) 不降级.
package wire

// Record type constants (DNS wire values).
const (
	TypeA     uint16 = 1
	TypeNS    uint16 = 2
	TypeCNAME uint16 = 5
	TypeSOA   uint16 = 6
	TypePTR   uint16 = 12
	TypeMX    uint16 = 15
	TypeTXT   uint16 = 16
	TypeAAAA  uint16 = 28
	TypeSRV   uint16 = 33
	TypeDNAME uint16 = 39
	TypeOPT   uint16 = 41
	TypeSVCB  uint16 = 64
	TypeHTTPS uint16 = 65
)

// ClassIN is the only QCLASS served.
const ClassIN uint16 = 1

// SVCB/HTTPS SvcParamKey constants (RFC 9460).
const (
	ParamALPN     uint16 = 1
	ParamPort     uint16 = 3
	ParamIPv4Hint uint16 = 4
	ParamECH      uint16 = 5
	ParamIPv6Hint uint16 = 6
)

// Defensive limits.
const (
	maxQuestions    = 32
	maxTotalRecords = 512
	maxNameJumps    = 32
	maxLabelLength  = 63
	maxWireName     = 255
)

// Header is the 12-byte DNS message header.
type Header struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

// Question is one entry of the question section.
type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

// RData is the sealed interface for typed record data.
type RData interface{ rData() }

// A is an IPv4 address record payload.
type A struct{ IP [4]byte }

// AAAA is an IPv6 address record payload.
type AAAA struct{ IP [16]byte }

// Name carries a single domain name (CNAME, NS, PTR, DNAME payloads).
type Name struct{ Name string }

// MX is a mail-exchange payload.
type MX struct {
	Preference uint16
	Exchange   string
}

// SOA is a start-of-authority payload.
type SOA struct {
	MName   string
	RName   string
	Serial  uint32
	Refresh uint32
	Retry   uint32
	Expire  uint32
	Minimum uint32
}

// SRV is a service-location payload.
type SRV struct {
	Priority uint16
	Weight   uint16
	Port     uint16
	Target   string
}

// SVCB is the SVCB/HTTPS payload; Record.Type distinguishes the two.
type SVCB struct {
	Priority uint16
	Target   string
	Params   []SvcParam
}

// Opt is the EDNS OPT pseudo-record. Its wire class field carries the UDP
// payload size and its wire TTL carries ext-rcode/version/DO; those are not
// ordinary record semantics and are never rewritten as such.
type Opt struct {
	PayloadSize uint16
	ExtRCode    uint8
	Version     uint8
	DO          bool
	Options     []EdnsOption
}

// Raw carries an uninterpreted payload for any unsupported record type.
type Raw struct {
	Type uint16
	Data []byte
}

func (A) rData()    {}
func (AAAA) rData() {}
func (Name) rData() {}
func (MX) rData()   {}
func (SOA) rData()  {}
func (SRV) rData()  {}
func (SVCB) rData() {}
func (Opt) rData()  {}
func (Raw) rData()  {}

// SvcParam is one SVCB/HTTPS service parameter.
type SvcParam struct {
	Key   uint16
	Value []byte
}

// EdnsOption is one EDNS0 option inside an OPT record.
type EdnsOption struct {
	Code uint16
	Data []byte
}

// Record is one resource record. Name retains original case; comparisons go
// through CanonicalName.
type Record struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	RData RData
}

// Packet is a full DNS message. Section counts are derived from slice lengths
// on encode; header count fields are ignored by Encode.
type Packet struct {
	Header      Header
	Questions   []Question
	Answers     []Record
	Authorities []Record
	Additionals []Record
}

// RCode returns the 4-bit response code of the header flags.
func (h Header) RCode() uint16 { return h.Flags & 0x0f }

// QR reports the response bit.
func (h Header) QR() bool { return h.Flags&0x8000 != 0 }

// Opcode returns the 4-bit opcode.
func (h Header) Opcode() uint16 { return (h.Flags >> 11) & 0x0f }

// RD reports the recursion-desired bit.
func (h Header) RD() bool { return h.Flags&0x0100 != 0 }

// CD reports the checking-disabled bit.
func (h Header) CD() bool { return h.Flags&0x0010 != 0 }
