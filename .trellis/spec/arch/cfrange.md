# cfrange

业务逻辑:
- Cloudflare IPv4/IPv6 网段从官方 URL 拉取, 每日刷新, 失败沿用旧表.
- 命中判定基于 netip.Prefix; 运营商池推送前的逐地址校验也消费本模块.

对外接口:

```go
type Ranges struct { V4, V6 []netip.Prefix }
func Load(ctx context.Context, cfg *config.Config) (*Ranges, error)
func Current() *Ranges
func (r *Ranges) Contains(ip string) bool
```

数据所有权: 当前网段表与拉取时刻 (Load 成功后原子换入, Current 供 hubfeed 与 rewrite 消费).

扩展规则:
- 来源 URL 可配置; 多来源合并须去重.
- 判定语义 (地址在网段内) 保持纯函数, 不掺杂域名逻辑.

事件目录: 无.
