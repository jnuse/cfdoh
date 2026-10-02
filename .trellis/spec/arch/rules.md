# rules

业务逻辑:
- 三形态输入 (裸数组, 对象包裹, host-map 简写) 解析为统一规则集, 上限 1000 条.
- 远程规则仅 https, 主机须在白名单, 大小受限, 拒绝重定向; 加载失败回退内嵌规则.
- 匹配条件全部 AND: domain_exact, domain_suffix, qtype, response_ip_cidr.
- block 首条命中即定; 响应类动作按序全部应用; replace 仅在原应答已有同型记录时生效并继承原最小 TTL 与 owner.

对外接口:

```go
type RuleSet struct { Rules []Rule }
func Parse(data []byte) (*RuleSet, error)
func Load(ctx context.Context, cfg *config.Config) (*RuleSet, error)
func (rs *RuleSet) ShouldBlock(q *wire.Packet) bool
func (rs *RuleSet) EcsOverride(q *wire.Packet) (value, present bool)
func (rs *RuleSet) Apply(q, resp *wire.Packet) *wire.Packet
func ValidateDynamicURL(raw string, cfg *config.Config) (string, error)
```

数据所有权: — (规则集由调用方持有).

扩展规则:
- 新动作类型扩展 RuleAction; 新匹配条件扩展 RuleMatch; 不改 Apply 主循环骨架.
- 远程加载的防御链 (协议, 白名单, 大小, 重定向) 不可削弱.
- 请求级规则与全局规则共用同一求值入口.

事件目录: 无.
