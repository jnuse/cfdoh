# Terms

cfdoh 的概念命名真源: 术语, 定义, 代码命名. 概念先于代码 — 需求分析阶段即可入表, 代码命名留空处落码时同变更回填.

## 组件

| 术语 | 定义 | 代码命名 |
|---|---|---|
| 服务端 | 部署在 Cloudflare 代理后的源站, 提供 DoH 解析与应答改写; 独立二进制 `cfdoh`. | `cmd/cfdoh` |
| 客户端 | 用户机上的常驻服务, 拉取候选, 本地测速, 维护 hosts; 独立二进制 `cfhost`, 与服务端无接口耦合. | `cmd/cfhost` |

## 优选池

| 术语 | 定义 | 代码命名 |
|---|---|---|
| 优选池 | 按池层优先序组织的优选地址集合, 每地址族至多服务 6 条, 各层带 TTL 惰性过期, 窄层不足由宽层补足. | `Pool` |
| 池层优先序 | 取池顺序, 窄优先: 专属池 → 运营商池 → 全国池 → 自学习池 → 优选域名池; 显式请求参数越过前四层. | `poolLayer` (编排住 `Preferred`) |
| 专属池 | 探针以 scope `client` 上报的池, 只服务与上报者同 /24 (IPv6 /48) 前缀的客户端. | scope `client` |
| 运营商池 | 测速站发布的按运营商聚合池, scope 形如 `isp:<name>`; 由公开池拉取或推送写入, 入池前逐地址校验在 Cloudflare 网段内. | scope `isp:<name>` |
| 全国池 | 测速站由各运营商池汇总生成的池, scope `isp:national`, 服务全体默认池使用者. | `ScopeNational` |
| 自学习池 | 探针以 scope `default` 上报的池 (含客户端可选上报), 按上报来源分存, 读时按严格多数投票合并. | scope `default` |
| 优选域名 | 配置的社区维护域名, 解析其地址合并为最宽层池; 与静态地址列表同层. | `CFPreferredDomain` |

## 按主机池

| 术语 | 定义 | 代码命名 |
|---|---|---|
| 按主机池 | 以主机名为键的地址池结构: 每上报来源整份覆盖, 读取时跨来源按多数决合并, 过期回落. | `GithubPoolFor` / `SitePoolFor` (状态 `HostPoolStatus`) |
| 站点池 | 源站经普通优选池不可达的站点的端到端验证地址, 命中时钉住该池并去 IPv6, ECH 保留. | `SetSites` / `SitePoolFor` (私有表 `sites`) |
| GitHub 池 | GitHub 系主机各自的实测可达地址, 命中时钉住, 不返回 AAAA, 不注入 ECH. | `pool.GithubPoolFor` |

## 数据来源与鉴权

| 术语 | 定义 | 代码命名 |
|---|---|---|
| 探针 | 向管理端点上报实测结论的外部程序; 上报内容含优选地址, h3 结论, 自检等. | — |
| 公开池 API | 测速站发布的只读池快照接口, 按运营商与地址族分池, 数组顺序即质量顺序; 服务端定时拉取, 客户端可作候选源. | `POOL_FEED_URL` |
| 测速站 | 众包测速聚合方 (cfhub), 聚合探针结果为各运营商公开池; 服务端经公开池 API 拉取其发布结果. | — |
| 上报来源 | 标识一份上报出自哪个探针的字符串, 钳 64 字符; 同来源新报告覆盖旧报告. | `Source` |
| 管理令牌 | ADMIN_TOKEN, 管理端点全权凭据; 未配置时全部管理端点返回 404. | `AdminToken` |
| 推送令牌 | HUB_TOKEN, 测速站主动推送专用凭据, 只能写运营商池, 不能读取状态; 补充通道, 主数据源为公开池拉取. | `HubToken` |
| 自检 | 探针按来源上报的服务端自身健康结论 (ok, problems, hosts); 上限 8 来源, 失败结论记告警日志; 经 /admin/selfcheck 读写, 仅管理令牌. | `selfcheck` |

## 解析流水线

| 术语 | 定义 | 代码命名 |
|---|---|---|
| 上游 | 服务端转发查询的外部 DoH 解析器列表, 仅接受 https; ECS 查询走路由到独立列表. | `Upstreams` |
| 对冲 | 上游查询策略: 顺序启动, 对冲间隔内无结果即启动下一个, 首个合法应答胜出. | `HedgeMs` |
| Cloudflare 网段 | 从 Cloudflare 官方列表每日刷新的 IPv4/IPv6 地址段, 判定站点是否由 Cloudflare 服务. | `cfrange.Ranges` (当前表 `Current`) |
| Cloudflare 判定 | 判定应答是否落在 Cloudflare 网段; 多 CDN 域名叠加查 `<域名>.cdn.cloudflare.net` 可解析性. | `OnCloudflare` |
| 改写 | 把应答中 Cloudflare 的 A/AAAA 与 HTTPS 地址提示替换为优选池地址. | `RewriteAddresses` |
| 钉住 | 把指定主机的应答地址强制为某组地址 (站点池, GitHub 池), 不经优选池选择. | `PinAddresses` |
| CNAME 展平 | 把 CNAME 链上的记录移到查询名下, 使 A/AAAA 与 HTTPS 同名, 满足 Chromium 使用 ECH 的条件. | `Flatten` |
| 轮转 | 每次应答把 A/AAAA 记录按类型分组循环左移, 分散只连首个地址的客户端. | `wire.RotateAddresses` |
| 回落 | 上层资源缺失或失效时逐层退到更宽资源, 解析不中断的可靠性机制. | — |
| X 域名 | X (Twitter) 系域名, 经 X_DOMAINS 配置; 在多家 CDN 间切换, 当前应答落在 Cloudflare 网段或 `<域名>.cdn.cloudflare.net` 可解析才判定由 Cloudflare 服务; 仅改写判定的应答且不返回 AAAA. | `RewriteX` |
| 规则 | 按域名, 类型与应答地址匹配并改写或屏蔽解析的配置项; 动作八种, 含 block 与 replace 族. | `rules.Rule` |
| 动态规则 | 请求级 `?rules=` 或远程 URL 加载的规则, 主机须在白名单内, 大小受限. | `rules.Load` (校验 `ValidateDynamicURL`) |

## 缓存

| 术语 | 定义 | 代码命名 |
|---|---|---|
| 应答缓存 | 按 DNS 应答为单位的 LRU 缓存, TTL 钳制, 可选落盘快照. | `cache.Cache` |
| 缓存身份 | 缓存键前段: 规范化查询名, 类型, 类, DO, CD 与 ECS 身份串. | `cache.Identity` (构造 `IdentityOf`) |
| 缓存变体 | 缓存键后段: 请求参数, 池 scope, 池内容标签, 站点池标签与代数等影响应答的因素. | `buildVariant` |
| 预取 | 剩余 TTL 低于原 TTL 指定比例时先返回缓存再后台刷新. | `StateRefresh` / `refreshInBackground` |
| 过期应答 | 超过 TTL 但仍在过期服务窗口内的缓存条目; 上游全部失败时以此应答, 记录 TTL 写为 30. | `StateStale` (stale 服务 TTL 30) |
| 代数 | h3 结论与 Meta ECH 的快照版本号, 变化即递增并折入缓存键, 使翻转即刻生效. | `h3.CacheTag` / `ech.MetaCacheTag` |
| 快照 | 缓存或探针态的磁盘持久化文件, 定时与退出时写, 启动时回读. | `SaveSnapshot`/`LoadSnapshot` (缓存), `SaveState`/`LoadState` (探针态) |
| 探针态 | pool/h3/ech 三模块的可持久化运行状态 (学习池表, h3 结论, Meta ECH), 随缓存快照同目录落盘, 重启回读, 损坏不阻塞启动. | `SaveState` / `LoadState` |
| 缓存态 | 一条缓存条目当前可服务程度的判定 (fresh/refresh/stale, 未命中为 none); explain 与服务策略以此分支. | `cache.State` (查询 `resolver.CacheState`) |
| 并发合并 | 同键并发未命中查询合并为一次上游外发的防击穿机制. | `singleflight` |

## ECH 与 ALPN

| 术语 | 定义 | 代码命名 |
|---|---|---|
| ECH 配置 | 注入 HTTPS 记录 ech 参数的 ECHConfigList 字节串, 来源为发布域名解析, 静态配置或学习值. | `ech.ConfigFor` / `ech.Validated` |
| 发布域名 | 承载 ECH 配置的解析来源域名, 默认 `cloudflare-ech.com`. | `EchSourceDomain` |
| Meta 三态 | META_DOMAINS 圈定的 Meta 系域名 (facebook, instagram 等) 的 ECH 配置运行状态: 种子有效, 学习新钥, 暂停注入. | `ech.MetaState` |
| h3 结论 | 探针按主机上报的 QUIC+ECH 可达判定; 全部来源确认才允许 h3, 任一否认即否决. | `h3.Verdict` (查询 `VerdictFor`) |

## ECS

| 术语 | 定义 | 代码命名 |
|---|---|---|
| ECS | 按模式 (off/always/rules) 决定是否把客户端子网带给上游, 换取国内 CDN 就近; 出向查询多余 ECS 剥离. | `ecs.Value` (构造 `Make`) |
| ECS 身份串 | 客户端子网截断后的规范化表示 (v4 /24, v6 /48), 折入缓存身份隔离应答. | `ecs.Value.Identity` |
| 运营商表 | "运营商 + CIDR" 文本表, 定时刷新, 同地址命中多网段取最长前缀; 识别结果用于选运营商池. | `isp` (查询 `ScopeOf`) |

## 服务端 HTTP 面

| 术语 | 定义 | 代码命名 |
|---|---|---|
| 客户端识别 | 解析请求来源地址的取值链: X-Real-IP → CF-Connecting-IP → X-Forwarded-For 首值 → TCP 对端; 自定义信任头 X-DoH-Client-IP 经 DOH_ORIGIN_TOKEN 门控优先. | `clientIP` |
| 请求参数 | DoH 查询级可选参数 (?ip4, ?ip6, ?cf, ?ech, ?rules), 语法与上限强校验, 全部折入缓存变体; 显式池参数越过前四层学习池. | `requestParams` (解析 `parseRequestParams`) |
| 路径别名 | 映射到 /dns-query 的等效路径, 经 PATH_ALIASES 配置, 校验链与主路径一致. | `PathAliases` |
| explain | 只读诊断端点: 对三类型分别跑 fresh 管线并输出客户端 IP, 生效池, 逐步判定链, 缓存态与 Chromium ECH 可用性; 不写缓存. | `handleExplain` (管线 `ResolveFresh`) |

## 客户端

| 术语 | 定义 | 代码命名 |
|---|---|---|
| 候选 | 一轮拉取得到的待测优选地址集合, 多源合并去重, 仅公网单播; 源四形态: 公开池 API, 通用 https API, 优选域名, 静态列表. | `fetchCandidates` |
| 本地测速 | 对候选地址 443 端口的 TCP+TLS 握手计时 (可选 HTTP 端到端验证 /cdn-cgi/trace), 多轮取中位, 失败淘汰. | `probeCandidates` (单址 `probeAddress`) |
| 在用地址 | 当前写入 hosts 的最优地址; 滞回窗口内不切换, 连续失效达阈值强制重选. | `State.CurrentV4` / `State.CurrentV6` |
| 状态文件 | 客户端本机持久化 JSON (在用地址, 上轮摘要, 下次刷新时刻, 连续失败计数, 上轮候选), 损坏容忍视为空态. | `State` (路径 `StatePath`) |
| 单实例锁 | 状态目录下的锁文件 (含 PID), 重复启动检测到活实例即退出, 死实例覆盖; 仅常驻模式持有. | `acquireLock` (锁文件 `cfhost.lock`) |
| 管辖域名 | 客户端配置的 Cloudflare 代理域名列表 (含 DoH 域名), hosts 中只写列表内域名. | `ManagedDomains` |
| hosts 区块 | hosts 文件中带 `# BEGIN cfhost` / `# END cfhost` 标记的段落, 区块外内容逐字节保留. | `updateHosts` (拼接 `spliceBlock`) |
| 滞回 | 切换在用地址的防抖策略: 新地址需优于在用地址指定比例才生效. | `decideHysteresis` (比例 `Hysteresis`) |
