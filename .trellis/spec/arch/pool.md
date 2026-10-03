# pool

业务逻辑:
- 取池按池层优先序窄优先, 每地址族独立补足到 6 条; 各层 TTL 惰性过期, 过期自动回落.
- 显式请求参数越过前四层学习池.
- 自学习池按上报来源分存, 读时合并: 严格多数认可才入选, 票数降序, 平票按平均位置, 每 /24 (IPv6 /48) 最多 2 个; 共识不足交错合并.
- 运营商池与专属池按 scope 键整份覆盖; 全国池是保留 scope.
- 按主机池 (站点池, GitHub 池) 按来源整份覆盖, 读时跨来源多数决; 站点池标签为合并内容的哈希.
- 容量: 自学习 8 来源, 专属 32, 运营商 16, 按主机池各 8 来源; 超限按最早插入淘汰.
- 上报地址逐个强校验; 优选域名解析容忍单域名失败, 全部失败才报错.

对外接口:

```go
type Pool struct { IPv4, IPv6 []string; Scope string }
type SourceStatus struct { Source string; IPv4, IPv6 []string; ExpiresAt int64 }
type LearnedReport struct { IPv4, IPv6 []string; ExpiresAt int64; Sources []SourceStatus }
type ScopedReport struct { Scope string; IPv4, IPv6 []string; ExpiresAt int64; Active bool }
type IspPoolReport struct { Scope string; IPv4, IPv6 []string; ExpiresAt int64; Active bool }
type HostPoolStatus struct { Sources []HostSourceStatus; Hosts map[string][]string }
type HostSourceStatus struct { Source string; Hosts int; ExpiresAt int64 }
func Preferred(ctx context.Context, explicitV4, explicitV6, domains []string, usingDefault bool, cfg *config.Config, clientScope, ispScope string) (*Pool, error)
func SetLearned(ipv4, ipv6 []string, ttl int, source, scope string) error
func CombineRankings(lists [][]string, size int) []string
func SetGithub(source string, hosts map[string][]string, ttl int)
func SetSites(source string, hosts map[string][]string, ttl int)
func GithubPoolFor(host string) []string
func SitePoolFor(host string) []string
func SitePoolTag(host string) string
func LearnedStatus() *LearnedReport
func ScopedStatus() []ScopedReport
func IspPoolStatus() []IspPoolReport
func GithubStatus() *HostPoolStatus
func SiteStatus() *HostPoolStatus
```

数据所有权: 自学习, 专属, 运营商三张学习池表; 站点与 GitHub 两张按主机池表.

扩展规则:
- 新池层插入优先序须经 PRD 与 CDD 变更, 插入点写在池层优先序条目.
- 容量常量集中一处定义.
- 投票与限段规则 (严格多数, 每 /24 两个) 是防污染核心, 不可简化.
- Meta ECH 状态不入本模块 (住 ech).

事件目录:
- preferred_pool_updated — 学习池写入; detail: source, scope, 地址数, ttl.
- github_pools_updated — GitHub 池整份覆盖; detail: source, 主机数, ttl.
- site_pools_updated — 站点池整份覆盖; detail: source, 主机列表, ttl.
