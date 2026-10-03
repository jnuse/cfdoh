# resolver

业务逻辑:
- 计划: 依据客户端 IP 与请求选项完成 ECS 决策, 构造缓存身份 (池 scope, 站点池标签, h3 与 Meta 代数折入变体).
- 缓存策略: fresh 直返; refresh 先答后刷 (后台再验证); HTTPS 类型有缓存 (含过期) 立即返回并后台刷新; 上游全部失败用过期应答兜底, 无缓存返回 SERVFAIL.
- 改写链编排次序: 响应规则 → Cloudflare 改写 → X 判定与改写 → 站点池与 GitHub 钉住 → ECH 注入 (含 Meta 分支) → CNAME 展平.
- 每次应答轮转 A/AAAA 顺序; 上游应答事务 ID 回填请求 ID.
- 单步改写失败只跳过该步, 不阻塞应答.
- 优选池准备: 默认池解析失败放行不改写, 显式指定失败返回错误.
- explain 复用同一管线并收集逐步决策链; 不写缓存.

对外接口:

```go
type Options struct { ClientIP string; CfDomains []string; CfDomainIsDefault bool; PreferredIPv4, PreferredIPv6 []string; EchDomain, RulesURL, CacheVariant string }
type Result struct { Packet []byte; Upstream string }
func Resolve(ctx context.Context, query []byte, opts *Options, cfg *config.Config) ([]byte, error)
func ResolveFresh(ctx context.Context, query []byte, opts *Options, cfg *config.Config, notes *[]string) (*Result, error)
func ChromiumECHVerdict(a, aaaa, https *wire.Packet) (usable bool, reason string)
func SaveCacheSnapshot(path string) error
func LoadCacheSnapshot(path string, cfg *config.Config) error
func CacheState(ctx context.Context, query []byte, opts *Options, cfg *config.Config) string
```

数据所有权: — (状态住各能力模块).

扩展规则:
- 改写链新步骤插入编排序列并同步 PRD; 兜底语义不可动.
- 缓存策略参数只从 config 读入.
- 本模块不感知 HTTP (请求解码与响应编码住 httpapi).

事件目录:
- dns_query — 每次查询应答; detail: cache 态, 上游主机名, 耗时; 查询域名仅在 LOG_QUERIES 开启时携带.
- cache_write_error — 缓存写失败; detail: 错误信息.
- prefetch_error — 后台刷新失败; detail: 错误信息.
