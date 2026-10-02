# wire

业务逻辑:
- 解析 A, AAAA, CNAME, NS, PTR, DNAME, MX, SOA, SRV, HTTPS, SVCB, OPT; 其余类型以 raw 字节透传.
- 名字解码支持压缩指针, 已访问偏移集合加 32 跳上限防环; 拒绝 0x40/0x80 高位 label.
- 编码一律不压缩; label 1..63 字节, 全名含长度前缀不超过 255 字节.
- qdcount 超过 32 或四段记录总数超过 512 拒绝解析; 解析完成后拒绝尾随字节; SVCB 参数 key 严格递增.
- 解码出的 RDATA 深拷贝, 与输入缓冲解耦; OPT 记录的 class 与 ttl 字段按 EDNS 语义读写, 不作为普通记录.
- IPv6 渲染为 8 组完整 hex; 地址文本解析拒绝 IPv4-mapped IPv6.
- 名字比较先规范化 (去尾点 + 小写); 域名匹配提供精确与通配后缀两种语义, 供 rules, ecs, h3 复用.

对外接口:

```go
type Packet struct { /* Header, Questions, Answers, Authorities, Additionals */ }
type Record struct { Name string; Type, Class uint16; TTL uint32; RData RData }

func Parse(b []byte) (*Packet, error)
func (p *Packet) Encode() ([]byte, error)
func CanonicalName(name string) string
func MatchDomain(name string, patterns []string) bool
func ParseIPv4(s string) ([4]byte, error)
func ParseIPv6(s string) ([16]byte, error)
func MakeServfail(query []byte) []byte
func PatchID(packet []byte, id uint16) []byte
func ResponseTTL(p *Packet, minTTL, maxTTL, negMaxTTL int) int
func RotateAddresses(packet []byte) ([]byte, error)
```

HTTPS/SVCB 参数读写:

```go
type SvcParam struct { Key uint16; Value []byte }
func DescribeHTTPS(r *Record) (alpn []string, ipv4, ipv6 []string, ech []byte)
func UpsertSvcParam(r *Record, key uint16, value []byte)
```

数据所有权: — (纯函数, 无状态).

扩展规则:
- 新记录类型扩展 RData 封闭接口与编解码对, 不改 Parse 与 Encode 主流程.
- 域名匹配语义变更须同步 rules, ecs, h3 的调用方语义.
- 防御性检查清单 (计数上限, 尾随字节, label 类型, 参数递增) 不可放松.

事件目录: 无.
