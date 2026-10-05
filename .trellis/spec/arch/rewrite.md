# rewrite

业务逻辑:
- 判定: 应答地址落在 Cloudflare 网段即判定; 多 CDN 域名 (X 族) 叠加 "<域名>.cdn.cloudflare.net" 可解析性判定.
- 改写: A/AAAA 与 HTTPS 记录地址提示替换为优选池 (每族至多 6); 替换以记录为单位 — 仅地址 (或提示) 落在网段内的记录被替换或移除, 混合应答的非 Cloudflare 记录原样保留 (对齐 refer); 空池族 (v4 或 v6) 的原记录与地址提示均原样保留, 两族对称; X 域名仅改写判定由 Cloudflare 服务的应答且不返回 AAAA.
- CF_DROP_AAAA 开启时, 经通用改写的应答去除网段内的 AAAA 记录并同步移除 HTTPS 记录的 ipv6hint (X 改写去除全部 AAAA 与 ipv6hint); 非改写应答不受影响.
- 钉住: 站点池与 GitHub 池的主机强制为池地址并去 IPv6, 不经优选池选择.
- 注入: ECH 配置写入 HTTPS 记录 ech 参数, ALPN 按 h3 门控; 上游无 HTTPS 记录时补造一条.
- 展平: CNAME 链上的记录移到查询名下, 判定用上游原始地址 (优选地址不必落网段). 边界: 删除判定用并存式 — 存在 qname CNAME 且应答含 qname 非 CNAME 记录 (归名产物与钉住补造产物同样触发) 时删除链上全部 CNAME (对齐 refer flattenAliases 与 Cloudflare CNAME Flattening; RFC 1034 禁止 CNAME 与其他类型同名并存); 移动记录不按别名 TTL 封顶; 要求首条记录为查询名持有的 CNAME, 其后的非 CNAME 记录无条件归名到查询名 (refer 仅沿链改名); 无并存 (全 CNAME, 或 CNAME 属其他 owner) 时保持原样.

对外接口:

```go
func OnCloudflare(ctx context.Context, qname string, ranges *cfrange.Ranges, cfg *config.Config, upstreamV4, upstreamV6 []string) (bool, error)
func UsesCloudflare(resp *wire.Packet, ranges *cfrange.Ranges) bool
func RewriteAddresses(resp *wire.Packet, ranges *cfrange.Ranges, p *pool.Pool, cfg *config.Config) *wire.Packet
func RewriteX(resp, q *wire.Packet, p *pool.Pool, cfg *config.Config) *wire.Packet
func PinAddresses(resp, q *wire.Packet, ips []string) *wire.Packet
func PinHTTPSHints(resp *wire.Packet, ips []string) *wire.Packet
func InjectECH(resp *wire.Packet, cfgList []byte, alpn []string) *wire.Packet
func InjectConfigured(resp *wire.Packet, cfg *config.Config) *wire.Packet
func Flatten(resp *wire.Packet) *wire.Packet
```

数据所有权: — (无状态; 判定结果由调用方在一次请求内缓存复用).

扩展规则:
- 新特殊域名族群 (类 GitHub, X) 扩展判定加改写对, 不混入通用改写路径.
- 注入与改写的失败兜底语义 (跳过该步, 返回未改写应答) 不可动.
- 地址与提示必须同步改写, 不允许只改其一.

事件目录: 无.
