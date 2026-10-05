# Requirements

cfdoh 的行为级需求: 每项功能的用户故事从 background.md 推导, 验收可测. 行为基线为 refer/edge-smart-doh, 验收对照其 /explain 输出与测试用例. F-001 至 F-022 为服务端, F-023 至 F-027 为客户端.

## 功能需求

### F-001 DoH 查询端点 (P0)

用户故事: 作为浏览器用户, 我希望用标准 RFC 8484 DoH 端点解析域名, 以便无需客户端定制即获得优选地址与 ECH.

主流程: 客户端 GET `?dns=<base64url>` 或 POST application/dns-message → 校验请求 → 解析查询 → 应答 DNS wire 报文.

业务规则:
- Accept 必须允许 application/dns-message (缺失或 `*/*` 视为允许), 否则 406
- POST 的 Content-Type 必须为 application/dns-message (忽略参数), 否则 415
- GET 缺 dns 参数返回 400; base64url 字符集与长度 (≤ 87384) 校验, 非法返回 400
- 请求包超过 MAX_DNS_PACKET_SIZE 返回 413, Content-Length 预检与实际读取双检
- 非 GET/POST 返回 405
- 查询必须恰好 1 个 question, QR 未置位, opcode 为 0, 否则 400
- 支持可配置的路径别名映射到 /dns-query (如 /linuxdo)
- 应答头: Content-Type application/dns-message, Cache-Control no-store, X-Content-Type-Options nosniff; 事务 ID 回填请求 ID
- 应答前的 A/AAAA 记录按 type 分组循环左移轮转顺序, 分散只连首个地址的客户端

异常:
- 上游全部失败且存在可服务过期缓存 → 返回过期应答
- 上游全部失败且无缓存 → 返回 SERVFAIL (保留 opcode/RD/CD 位, 置 QR|RA, rcode 2)
- 改写链中任何一步失败 → 返回未改写的上游应答, 不因增强功能失败而拒绝解析

埋点: dns_query (cache ∈ hit/miss/prefetch/stale, 上游主机名, 耗时), DEBUG 门控, LOG_QUERIES 才含查询域名

验收标准:
- Given 合法 GET 查询, When 请求 /dns-query, Then 200 且应答 ID 与请求一致
- Given QR 置位的请求包, When 请求, Then 400
- Given Accept: text/html, When 请求, Then 406
- Given 配置别名路径, When 请求别名, Then 行为与 /dns-query 一致

### F-002 DNS wire 编解码 (P0)

用户故事: 作为解析服务, 我需要完整解析与重建 DNS 报文, 以便在改写与缓存中操作结构化记录.

业务规则:
- 解析支持 A, AAAA, CNAME, NS, PTR, DNAME, MX, SOA, SRV, HTTPS, SVCB, OPT; 其余类型 raw 透传
- 名字解码支持压缩指针 (0xc0), 防环: 已访问偏移集合 + 32 跳上限; 指针目标可为包内任意偏移
- 拒绝 0x40/0x80 高位 label 类型
- 编码一律不压缩; label 1..63 字节, 全名含长度前缀 ≤ 255 字节
- qdcount > 32 或四段记录总数 > 512 拒绝解析
- 解析完成后拒绝尾随字节
- SVCB/HTTPS 参数 key 严格递增, 乱序或重复拒绝
- OPT 记录的 class 语义为 UDP payload size, ttl 语义为 ext-rcode/version/DO, 不作为普通记录改写
- 解码出的 RDATA 深拷贝, 与输入缓冲解耦
- IPv6 文本渲染为 8 组完整 hex (不用 ::), 保证身份串稳定
- 名字比较先规范化 (去尾点 + 小写) 再比较, 保留原大小写存储
- 地址解析拒绝 IPv4-mapped IPv6 文本 (如 ::ffff:1.2.3.4), 避免地址族判定歧义

验收标准:
- Given 参考实现的 packet 测试用例集, When 移植执行, Then 全部通过
- Given 含压缩指针成环的报文, When 解析, Then 返回错误而非死循环
- Given 任意可解析报文, When 解析后重新编码, Then 各 section 记录语义等价

### F-003 上游查询与对冲 (P0)

用户故事: 作为解析服务, 我需要在单个上游变慢或不可用时仍快速拿到合法应答, 以保证解析可用性.

主流程: 编码上游查询 → 顺序启动上游 → hedge 间隔无结果即启动下一个 → 首个合法应答胜出 → 中止其余在飞请求.

业务规则:
- 上游仅接受 https URL; 空上游列表直接判定失败
- 每次尝试独立超时 UPSTREAM_TIMEOUT_MS (默认 2500, 钳 250–15000)
- UPSTREAM_HEDGE_MS (默认 100, 钳 0–5000); 0 关闭对冲, 退化为失败后才启动下一个的串行回退
- 单上游失败立即启动下一个
- 应答校验链: HTTP 2xx, Content-Type 为 application/dns-message, 字节数 ≤ MAX_DNS_PACKET_SIZE, QR 位置位, 事务 ID 与查询一致
- 携带 ECS 的查询路由到 ECS_UPSTREAMS, 其余走 UPSTREAMS
- 同名并发未命中查询合并为一次上游外发 (singleflight)

验收标准:
- Given 首上游 50ms 内正常返回, When 查询, Then 不启动第二上游
- Given 首上游超过 hedge 间隔无响应, When 查询, Then 并发启动后续上游并取首个合法应答
- Given 全部上游失败, When 查询, Then 进入过期缓存兜底路径, 无缓存时返回 SERVFAIL
- Given 同键 50 个并发未命中查询, When 上游侧计数, Then 外发查询为 1

### F-004 应答缓存 (P0)

用户故事: 作为解析服务, 我需要按影响应答的因素隔离缓存上游应答, 以降低上游压力与查询延迟.

业务规则:
- 缓存键分量: 规范化 qname + qtype + qclass + DO 位 + CD 位 + ECS 身份串 + variant (请求参数, 池 scope, 池内容标签, 站点池标签, h3 与 Meta ECH 的 generation)
- SERVFAIL 不缓存
- 应答 TTL 取 answers 中非 OPT 记录最小值; 负应答 (NXDOMAIN 或空 answer 且含 SOA) 取 min(SOA ttl, SOA minimum, NEGATIVE_CACHE_MAX_TTL); 最终钳制 [CACHE_MIN_TTL, CACHE_MAX_TTL]; TTL 0 的记录视为不可缓存, 不钳入区间
- 剩余 TTL ≤ 原 TTL 的 CACHE_PREFETCH_PERCENT% 时立即返回并后台刷新
- 过期不超过 CACHE_STALE_TTL 且上游全部失败时返回过期应答, 其记录 TTL 写为 30
- HTTPS 类型查询只要缓存存在 (含过期) 立即返回并后台刷新: Chromium 拿到 A/AAAA 后对 HTTPS 记录只等约 50ms
- LRU 容量 CACHE_MAX_ENTRIES (默认 4096, 钳 128–65536)
- CACHE_PERSIST_PATH 设置时定期与退出时快照落盘 (临时文件 + 原子改名), 启动时回读未过期条目
- 池翻转 (任一池表有效内容变化含惰性过期, h3 verdict, Meta ECH 代数) 通过内容哈希/generation 折入缓存键, 翻转即刻生效, 不等 TTL

验收标准:
- Given 同键查询在 TTL 内, When 第二次请求, Then 不外发上游
- Given 运营商 A 与 B 的同域名查询命中不同池, When 各自缓存, Then 键不同, 互不污染
- Given 上游全挂且存在过期 1 小时内的应答, When 查询, Then 返回过期应答 (TTL 30) 而非 SERVFAIL
- Given HTTPS 查询存在过期缓存, When 请求, Then 立即返回且后台触发刷新
- Given h3 verdict 翻转, When 后续 HTTPS 查询, Then 新应答即时反映

### F-005 客户端识别 (P0)

用户故事: 作为解析服务, 我需要知道请求的来源地址, 以选择运营商池与构造 ECS 子网.

业务规则:
- 取值顺序: X-Real-IP → CF-Connecting-IP → X-Forwarded-For 首值
- 反代模式下, 入口用 TCP 对端地址补齐缺失的 X-Real-IP, 客户端无法伪造网络身份
- 支持经 DOH_ORIGIN_TOKEN 门控的自定义信任头 (供 CDN 前置场景)
- 客户端 IP 仅用于选池与构造 ECS 子网, 不写日志, 不落盘

验收标准:
- Given 反代注入 X-Real-IP, When 查询, Then /explain 显示该 IP 且池按该 IP 选择
- Given 直连无识别头, When 查询, Then 以 TCP 对端地址作为客户端 IP

### F-006 运营商识别 (P1)

用户故事: 作为访问者, 我希望拿到本运营商线路实测的优选地址, 而非全国混合结果.

业务规则:
- 从 ISP_TABLE_URL 拉取 "<运营商> <CIDR>" 文本表 (≤ 4MiB), 每 10 分钟刷新, 内容不变不重建; 兼容 china-operator-ip 类按运营商分文件的公开列表
- 加载失败 60 秒内不重试, 期间旧表继续服务
- 运营商名匹配 [a-z][a-z0-9-]{1,23}, 保留名 national 禁用; 非法行静默跳过; 有效条目为 0 视为加载失败
- v4/v6 独立查找结构, 支持网段嵌套; 同 IP 命中多网段时取最精确 (最长前缀)
- 未配置 ISP_TABLE_URL 时功能关闭, 全员走全国层
- 运营商识别结果永不阻塞查询: 查不到即回落全国池

验收标准:
- Given 电信网段 IP 与已有 isp:chinanet 池, When 查询, Then 选用该池且缓存键含该 scope
- Given 表刷新失败, When 查询, Then 继续用旧表应答, 解析不受影响
- Given 大网段与小网段嵌套且归属不同, When 查询, Then 取小网段的运营商

### F-007 优选池分层 (P0)

用户故事: 作为访问者, 我希望应答地址来自对我的线路最有发言权的池子, 且任何一层失效都能自动回落.

业务规则:
- 优先级 (窄优先): 显式参数指定 (?ip4/?ip6/?cf) > 客户端前缀专属池 (v4 /24, v6 /48) > 运营商池 isp:<name> > 全国池 isp:national > 自学习池 > 优选域名池/静态池
- 每地址族独立取用, 服务上限 6 条; 窄层不足时从宽层补足
- 各层 TTL + 惰性过期; 停止上报后 TTL 到期自动失效, 请求自然回落, 解析不中断
- 存储上限: 自学习 8 source, 专属池 32, 运营商池 16, 超限按最早插入淘汰
- 自学习池按探针 source 分存, 读时合并 (combineRankings): 当选需严格多数 (floor(n/2)+1) 探针认可; 票数降序, 平票按平均位置升序; 每 /24 (v6 /48) 最多 2 个入选
- 共识结果不足 2 个时, 多列表轮转交错合并, 每个探针仍有贡献
- 优选域名解析单域名失败容忍, 全部失败才报错; 报错仅在显式 ?cf= 时返回 502, 默认池场景放行不改写
- CF_DROP_AAAA 开启时 v6 池清空
- 实际贡献的窄层 scope 记入缓存 variant

验收标准:
- Given 探针以 scope "client" 上报且与查询客户端同 /24, When 查询, Then 优先用该专属池
- Given 三探针列表无严格多数共识, When 读池, Then 输出交错合并且每 /24 不超过 2 个
- Given 探针与 hub 全部停止上报, When 各池 TTL 过期后查询, Then 落到优选域名池, 应答仍完成改写或原样返回

### F-008 池上报接口 (P1)

用户故事: 作为探针或测速站的运维方, 我希望用令牌把实测地址池推给服务, 作为拉取主链路的补充通道.

业务规则:
- 本端点是兼容与补充通道, 主数据源见 F-028 公开池拉取
- POST /admin/preferred {ipv4, ipv6, ttl, source, scope}; scope ∈ default / client (上报者自身前缀) / isp:<name>
- ADMIN_TOKEN 全权; HUB_TOKEN 仅允许写 isp:* 池且 GET 返回 403
- 未配置 ADMIN_TOKEN 时全部 /admin/* 返回 404
- Bearer 令牌常数时间比较; 错误令牌 401
- 地址逐个强校验, 每族上报上限 64 条; ttl 钳 60–86400; source 截断 64 字符
- isp 池逐 IP 校验落在 Cloudflare 公布网段内, 任一地址在外整批 400 拒绝
- scope "client" 无法确定上报者地址时 400

埋点: preferred_pool_updated

验收标准:
- Given HUB_TOKEN 携带 scope "default", When POST, Then 403
- Given hub 推送含非 Cloudflare 网段地址的 isp 池, When POST, Then 400 整批拒绝
- Given 错误令牌, When POST, Then 401
- Given 未配置令牌, When POST, Then 404

### F-009 Cloudflare 判定与地址改写 (P0)

用户故事: 作为浏览器用户, 我希望 Cloudflare 站点的应答地址替换为优选池地址, 以获得更快的直连.

业务规则:
- Cloudflare IPv4/IPv6 网段列表从官方 URL 拉取, 每日刷新, 失败用旧表
- 应答地址落入网段即判定为 Cloudflare 站点
- A/AAAA 记录替换为优选池 (每族 ≤ 6); HTTPS 记录的 ipv4hint/ipv6hint 同步替换
- 非 Cloudflare 应答原样返回
- CF_DROP_AAAA 开启时改写后的应答去掉 AAAA
- 请求显式指定池 (?ip4/?ip6/?cf) 时跳过 1–4 层学习池
- 改写启用条件: CF_REWRITE_ENABLED 开启, 或该查询存在任一可用池时请求级自动提升 (rewriteCfg; 详见改写门控 note)

验收标准:
- Given Cloudflare 站点 A 查询与有效池, When 应答, Then A 记录全部来自池内且多次应答顺序轮转
- Given 非 Cloudflare 站点, When 应答, Then 与上游应答一致
- Given HTTPS 应答含地址提示, When 改写, Then 提示与 A/AAAA 同步替换

### F-010 ECH 注入 (P0)

用户故事: 作为浏览器用户, 我希望 HTTPS 记录携带 ECH 配置, 以便握手时真实域名被加密.

业务规则:
- ECH_ENABLED 开启时, 对判定为 Cloudflare 的站点的 HTTPS 查询注入 ECHConfigList
- 配置来源优先级: 请求 ?ech= 指定域名 > ECH_CONFIG_BASE64 > ECH_SOURCE_DOMAIN (默认 cloudflare-ech.com) 的 HTTPS 记录 (缓存)
- 上游无 HTTPS 记录时补造一条 (含 ech 参数与按 h3 门控的 alpn)
- 非 Cloudflare 站点不注入
- 注入失败不阻塞应答
- ECH_DOMAINS + ECH_CONFIG_BASE64 对指定域名无条件注入

验收标准:
- Given Cloudflare 站点 HTTPS 查询, When 应答, Then HTTPS 记录含 ech 参数
- Given 非 Cloudflare 站点 HTTPS 查询, When 应答, Then 无注入
- Given ECH_SOURCE_DOMAIN 不可达, When 查询, Then 应答正常返回 (可能无 ECH), 不报错

### F-011 h3 门控 (P1)

用户故事: 作为浏览器用户, 我希望只对 QUIC+ECH 实测可达的站点拿到 h3, 以避免必然失败的 QUIC 尝试.

业务规则:
- POST /admin/h3 {source, ttl, verdicts: {host: bool}}; 每 source 整份覆盖, 上限 8 source, 每份 64 host
- 合并语义: 同一 host 全部 source 都 ok 才允许 h3, 任一 fail 即否决
- host 按后缀最长匹配, verdict 作用于该 host 及其子域
- 无 verdict 数据时: 一般站点保留上游 ALPN, X 域名与 Meta 固定 h2
- verdict 快照变化递增 generation, 折入 HTTPS 缓存键, 翻转即刻生效
- verdict 过期后回到默认策略

埋点: h3_verdicts_updated

验收标准:
- Given 两探针对同一站点一 ok 一 fail, When 查询该站点 HTTPS, Then ALPN 不含 h3
- Given verdict 翻转, When 后续查询, Then 新应答立即反映, 不等缓存 TTL

### F-012 CNAME 展平 (P0)

用户故事: 作为 Chromium 用户, 我希望 A/AAAA 与 HTTPS 记录挂在同一个名字下, 以便 ECH 生效.

业务规则:
- 对 ECH 主机 (按上游地址判定为 Cloudflare, Meta 域名, ECH_DOMAINS) 的 A/AAAA/HTTPS 应答, 把 CNAME 链上的记录移到查询名下, 并删除链上全部 CNAME (RFC 1034: CNAME 不与其他类型同名并存; 对齐 Cloudflare CNAME Flattening)
- 判定用上游原始地址: 改写后的优选地址不必落在 Cloudflare 公布网段内
- 非 ECH 主机不改

验收标准:
- Given Cloudflare 站点经 CNAME 链解析, When 查询 A 与 HTTPS, Then 全部记录 owner 为查询名且 /explain 判定 Chromium 可用 ECH

### F-013 ECS 子网 (P1)

用户故事: 作为国内用户, 我希望国内域名按我的位置返回 CDN 节点, 其他域名不泄露子网信息.

业务规则:
- ECS_MODE ∈ off / always / rules (默认 rules: 命中 ECS_DOMAINS 后缀, 默认 .cn)
- 规则可逐域名覆盖 enable-ecs / disable-ecs, 优先于模式
- 子网取客户端 v4 /24, v6 /48; 无客户端 IP 则不带 ECS
- 需要时向上游查询注入 ECS (幂等替换已有); 不需要时剥离请求中已有 ECS
- 不破坏已有 OPT 记录的 payload size 与 DO 位; 无 OPT 时合成 (class 1232, ttl 0)
- ECS 查询走 ECS_UPSTREAMS; ECS 身份串折入缓存键

验收标准:
- Given example.cn 查询与 IPv4 客户端, When 上游收到报文, Then OPT 含 code 8 且地址截断为 /24
- Given example.com 同条件, When 上游报文, Then 无 ECS option
- Given 请求自带 ECS, When 转发, Then 出向报文至多一个 ECS option

### F-014 特殊站点处理 (P1)

用户故事: 作为 GitHub 与 X 用户, 我希望这些站点的特殊网络行为被单独处理, 以获得可达的地址.

业务规则:
- GitHub: GITHUB_DOMAINS 域名的 A 记录钉住该主机独立测速池 (POST /admin/github {source, ttl, hosts: {host: [v4]}}), 不返回 AAAA, 不注入 ECH; 池按 source 覆盖, 读时多数决合并, 过期回落原样应答
- X: X_DOMAINS 域名在多家 CDN 间切换; 当前应答在 Cloudflare 网段, 或 <域名>.cdn.cloudflare.net 可解析, 才判定由 Cloudflare 服务; 仅改写判定的应答且不返回 AAAA (X 对 IPv6 到达返回 403)
- 站点池: POST /admin/site {source, ttl, hosts} 上报端到端验证过的 IP; 命中站点的 A/AAAA 钉住该池 (去 v6), HTTPS 提示同步, ECH 保留; 上报不再包含该站点时覆盖自动撤销

埋点: github_pools_updated, site_pools_updated

验收标准:
- Given github.com 存在测速池, When 查询 A, Then 仅返回池内 IPv4
- Given X 域名当前不由 Cloudflare 服务, When 查询, Then 应答原样
- Given sitecheck 上报撤销某站点, When 其 TTL 过后查询, Then 回到普通优选池

### F-015 Meta ECH (P2)

用户故事: 作为 Meta 系站点用户, 我希望拿到密钥轮换后仍有效的 ECH 配置.

业务规则:
- META_ECH_CONFIG_BASE64 为种子配置; Meta 不在 DNS 发布 ECH
- 三态: 种子有效 (探针报 ok, 清除覆盖) / 学习新钥 (rotated + echConfig, 校验合法 base64) / 暂停注入 (broken)
- 学习态 TTL 钳 300–604800; 暂停时 TTL 上限 86400
- 配置字节或过期变化递增 generation, 折入缓存键, 轮换即刻生效
- 暂停时不注入, 返回未污染的上游应答
- 学习钥报 ok 且附带字节一致的 verified 时续期, 不回落种子

埋点: meta_ech_seed_ok, meta_ech_rotated, meta_ech_suspended

验收标准:
- Given 探针报 rotated 且配置合法, When 后续 Meta HTTPS 查询, Then 注入学习钥且缓存即刻换代
- Given 报 broken, When 查询, Then 不注入任何配置
- Given 报 ok, When 处理, Then 清除覆盖回到种子

### F-016 规则引擎 (P1)

用户故事: 作为运维者, 我希望能按域名, 类型与应答地址改写或屏蔽特定解析, 以覆盖未预见的场景.

业务规则:
- 三种来源: RULES_JSON 内嵌 / RULES_URL 远程 / 请求 ?rules=; 上限 1000 条
- 远程与请求级规则: 仅 https, hostname 必须命中 DYNAMIC_RULE_HOSTS 白名单, 禁 credentials 与非 443 端口, 大小 ≤ DYNAMIC_RULES_MAX_BYTES (默认 262144, 钳 1KiB–1MiB), 拒绝重定向; 加载失败回退内嵌
- 匹配条件全部 AND: domain_exact, domain_suffix (自动补前导点), qtype, response_ip_cidr (按应答中 A/AAAA 地址命中)
- 动作: passthrough / replace-a / replace-aaaa / replace-cname / rewrite-https (改写 ipv4hint/ipv6hint) / enable-ecs / disable-ecs / block
- block 首条命中即定, 返回 REFUSED (rcode 3) 空应答, 不外发上游
- 响应类动作顺序全部应用; replace 仅在原应答已有同型记录时生效, 继承原最小 TTL 与 owner
- 支持 host-map 简写 ({"*.example.com": {ipv4: [...]}}) 展开为等价规则

验收标准:
- Given block 规则命中, When 查询, Then rcode 3 且无上游外发
- Given replace-a 规则与含 A 记录的上游应答, When 应用, Then 地址替换且 TTL 取原最小值
- Given 远程规则源返回非法 JSON, When 加载, Then 用内嵌规则继续应答

### F-017 请求参数 (P2)

用户故事: 作为高级用户, 我希望按请求指定优选来源与规则, 以自定义解析行为.

业务规则:
- ?ip4= / ?ip6=: 逗号分隔, 原始串 ≤ 1024 字符, 每族 1–16 个, 逐个强校验, 非法 400
- ?cf=<域名>: 用该域名解析出的地址做优选池; 域名语法白名单校验
- ?ech=<域名>: 从该域名的 HTTPS 记录取 ECH 配置
- ?rules=<URL>: 动态规则, 遵守 F-016 的白名单与大小限制
- 全部参数折入缓存 variant, 不同参数的应答互不污染

验收标准:
- Given ?ip4=a,b 且查询 Cloudflare 站点, When 应答, Then A 记录为指定地址
- Given ?ip4 含非法地址, When 请求, Then 400
- Given ?rules 指向白名单外主机, When 请求, Then 400

### F-018 explain 端点 (P1)

用户故事: 作为运维者与用户, 我希望看到任一域名每一步判定与实际应答, 以诊断优选与 ECH 是否生效.

业务规则:
- GET /explain?name=<域名>[&type=A|AAAA|HTTPS]; name 与 type 语法校验, 非法 400
- 输出: 客户端 IP, 生效池与 scope, 各类型应答 (缓存态, 逐步判定链, 上游来源), Chromium ECH 可用性判定 (按 Chromium host_cache 条件: 地址存在, 单一 owner, HTTPS 记录 target 一致, 含 ech 参数), 自检状态
- 只读: 不写缓存
- 接受与 /dns-query 相同的请求参数, 保证与实际服务行为一致

验收标准:
- Given Cloudflare 站点三类型查询, When /explain, Then chromium 判定可用且 steps 含池选择, 改写, ECH 注入各步
- Given 非法 name, When 请求, Then 400

### F-019 健康与探针端点 (P2)

用户故事: 作为运维者, 我希望有存活检查与请求环境回显端点, 以接入监控.

业务规则:
- GET /health 返回 {ok: true}; 其他方法 405
- GET /probe 返回客户端 IP 与部署信息 (监听模式, 版本); 其他方法 405

验收标准:
- Given 服务运行, When GET /health, Then 200 且 ok 为 true
- Given 任意请求, When GET /probe, Then 返回服务端看到的客户端 IP

### F-020 管理状态查询与自检 (P2)

用户故事: 作为运维者, 我希望读取全部池与探针上报的状态, 以掌握服务运行面.

业务规则:
- GET /admin/preferred (ADMIN_TOKEN): 返回自学习, 专属, 运营商, GitHub, 站点, Meta ECH, 自检, h3 全量状态
- GET /admin/site, /admin/github, /admin/h3, /admin/health, /admin/selfcheck: 各自状态
- POST /admin/selfcheck {source, ok, problems, hosts}: 自检上报, 上限 8 source, problems 截 50 条/300 字; 失败时记录错误日志
- 鉴权遵循 F-008 的令牌规则

埋点: selfcheck_failed

验收标准:
- Given ADMIN_TOKEN, When GET /admin/preferred, Then 返回全部池状态 JSON
- Given hub 令牌, When GET /admin/preferred, Then 403

### F-023 候选拉取与校验 (P0)

用户故事: 作为客户端 daemon, 我需要从多个来源获取候选优选地址, 以保证候选覆盖与获取可用性.

业务规则:
- 源类型: 公开池 API (按配置的运营商取池, 默认全国), HTTP(S) API 返回地址列表, 优选域名 (系统 DNS 解析其 A 记录), 静态列表 (配置内嵌)
- 远程源仅接受 https 且走系统证书校验; 拉取用系统 DNS, 不依赖 daemon 自身
- 多源结果合并去重; 仅保留公网单播地址, 过滤回环, 私网, 链路本地
- 单源失败容忍, 跳过该源; 全部源失败时沿用上一轮候选
- 候选数量上限可配, 超出截断

验收标准:
- Given 配置 API 源与域名源, When 拉取, Then 候选为两源并集去重
- Given 单源失败, When 拉取, Then 其余源结果照常进入候选
- Given 候选含私网地址, When 校验, Then 被过滤不进入测速

### F-024 本地测速与选优 (P0)

用户故事: 作为客户端 daemon, 我需要在本机线路上实测候选地址的连通与延迟, 以选出当前最优.

业务规则:
- 测速方法: 对候选地址 443 端口发起 TCP 连接与 TLS 握手, SNI 用配置域名之一, 记录握手总耗时; 默认开启 (可关闭) 的 HTTP 端到端验证 (请求 /cdn-cgi/trace 并校验响应)
- 并发批量执行, 单地址超时可配 (默认 2 秒), 失败或超时淘汰
- 多轮采样取中位耗时; 通过率纳入判据
- 滞回防抖: 新最优需优于当前在用地址一定比例 (默认 20%)才切换
- 首次无在用地址时直接取最优
- 在用地址连续失效达到可配轮数时强制重选
- 测速结论仅保存在本机状态文件

验收标准:
- Given 100 个候选地址, When 一轮测速, Then 全部得到耗时或淘汰标记
- Given 在用地址仍居首且新地址仅快 5%, When 本轮结束, Then 不切换
- Given 在用地址连续 3 轮 (可配) 失效, When 本轮结束, Then 强制切换到新最优

### F-025 hosts 管理 (P0)

用户故事: 作为客户端 daemon, 我需要把配置的全部域名钉到当前最优地址, 且不破坏 hosts 文件的其余内容.

业务规则:
- 管辖域名: 配置列表, 一项或多项, 均为 Cloudflare 代理域名 (含 DoH 域名); 列表外的域名一律不写
- 只维护带标记的区块 (# BEGIN cfhost 至 # END cfhost), 区块外内容逐字节保留
- 每域名写入指向当前最优 IPv4 地址的行; 有可用 IPv6 优选时同法追加对应行
- 原子更新: 临时文件优先写系统 TEMP 目录 (避开 etc 目录的杀软扫描闸), 跨卷或 TEMP 不可用时回退 hosts 同目录; 先写完整内容再 rename 替换, 保留原文件权限; rename 遇杀软句柄 (access denied / sharing violation) 以 200ms 间隔至多重试 5 次, 重试耗尽按本轮跳过 (不写 hosts, 在用地址不变, 守护不退出)
- 最优地址未变化时不重写文件
- 更新后刷新系统 DNS 缓存 (Windows 为 ipconfig /flushdns)

验收标准:
- Given 配置两个域名, When 更新, Then 区块内两行均指向当前最优地址
- Given hosts 含用户手动条目, When 更新, Then 区块外条目逐字节保留
- Given 最优地址未变化, When 本轮, Then hosts 文件不被重写

### F-026 客户端常驻服务与安装 (P0)

用户故事: 作为用户, 我希望一次安装后客户端长期自动运行, 无需手工干预.

业务规则:
- Windows: 原生服务子命令 install/uninstall/start/stop, 免第三方工具, 服务账户运行; Linux: 提供 systemd 单元
- 定时轮询 (默认 60 分钟, 可配); 提供 run-once 子命令手动执行一轮
- 单实例保护, 重复启动不产生并发写入
- 日志带轮转; status 子命令输出当前在用地址, 上轮测速摘要, 下次刷新时间
- 安装文档说明安全软件对 hosts 修改的放行要求与代理客户端分流冲突场景

验收标准:
- Given Windows 安装服务后系统重启, When 服务自启, Then 完成一轮拉取测速与 hosts 刷新
- Given 服务运行中, When 执行 status, Then 输出当前在用地址与上轮摘要
- Given 重复启动第二实例, When 启动, Then 检测到锁后退出且不影响首实例

### F-027 客户端配置 (P1)

用户故事: 作为用户, 我希望通过配置文件调整域名列表, 来源与测速参数, 以适配自己的线路.

业务规则:
- 配置文件与环境变量两种输入; 环境变量优先
- 必填项: 管辖域名列表 (≥ 1), 候选源列表 (≥ 1)
- 可调项: 测速并发数, 单地址超时, 采样轮数, 滞回比例, 强制重选轮数, 轮询周期, hosts 路径 (默认系统标准路径)
- 域名逐个语法校验; 远程源仅接受 https
- 重启生效, 不做热重载

验收标准:
- Given 仅填域名与源, When 启动, Then 其余参数取默认值正常运行
- Given 域名列表为空, When 启动, Then 报错退出且不修改 hosts
- Given 配置文件与环境变量同键, When 启动, Then 环境变量值生效

### F-021 服务端部署与运行形态 (P0)

用户故事: 作为运维者, 我希望单个二进制完成部署, 重启不丢探针态, 升级期间不向浏览器返回瞬时错误.

业务规则:
- 单静态二进制, 无外部运行时依赖
- 两种监听模式: 直连模式 (内嵌 TLS, HTTP/1.1 与 HTTP/2, 证书文件路径配置) 与反代模式 (默认 127.0.0.1:8787 明文, TLS 由前置反代终止)
- PUBLIC_HOSTNAMES 非空时校验 Host, 不在集合内 (localhost 除外) 返回 421
- 收到 SIGTERM/SIGINT: 停止接收新请求 → 探针态与缓存快照落盘 → 退出
- 启动时回读快照, 探针上报的池无需等下一次上报即恢复
- pprof 调试端点, 独立开关门控, 默认关闭
- 提供 systemd 单元文件与反代配置样例

验收标准:
- Given 探针上报池后发 SIGTERM 再启动, When 启动完成, Then 池立即可用
- Given 直连模式配置证书, When 浏览器经 h2 查询, Then 正常应答
- Given PUBLIC_HOSTNAMES 配置后收到其他 Host, When 请求, Then 421

### F-022 服务端配置体系 (P0)

用户故事: 作为运维者, 我希望全部行为经环境变量调节且默认值开箱可用, 以最低成本部署与调优.

业务规则:
- 支持环境变量 (命名与参考实现一致) 与配置文件两种输入, 语义相同
- 数值项全部带钳制区间, 超界值钳到边界
- 令牌类变量缺失即关闭对应端点 (ADMIN_TOKEN 空 → /admin/* 404)
- 默认上游: cloudflare, google, quad9; 默认 ECS rules + .cn; 默认缓存 TTL 30/3600, stale 86400, 预取 10%
- 配置解析结果在启动日志中输出脱敏摘要

验收标准:
- Given 零配置启动, When 查询, Then 默认上游正常应答且无池不改写
- Given 数值超区间, When 启动, Then 值钳到边界且日志可见提示
- Given 同时提供环境变量与配置文件, When 启动, Then 环境变量优先

### F-028 公开池拉取 (P0)

用户故事: 作为服务端运维者, 我希望定时拉取测速站已发布的公开池并校验后入池, 以在无自建探针体系时获得持续更新的优选数据.

主流程: 定时拉取公开池 API → 解析运营商与地址族 → 逐池校验 → 写入运营商池与全国池.

业务规则:
- 拉取周期可配 (默认 5 分钟); API URL 可配 (默认 cfhub 公开池端点), 置空停用本功能
- 仅采用 published 为真的池; 池内地址顺序即质量顺序, 每地址族取至多 6 条
- 按 isp 字段写入运营商池 (scope isp:<name>), national 写入全国池
- 任一地址不在 Cloudflare 公布网段内则整池不采用, 其余池不受影响
- 拉取成功后池有效期可配 (默认 30 分钟); 拉取失败沿用旧池, 过期后逐层回落不中断解析
- 拉取与入池不阻塞查询路径 (后台执行)

埋点: pool_feed_refresh (结果摘要: 各池地址数, 耗时), pool_feed_rejected (整池拒绝; 原因)

验收标准:
- Given API 可达且含已发布的电信池, When 拉取, Then isp:chinanet 池刷新且仅含 Cloudflare 网段地址
- Given 某池含非 Cloudflare 网段地址, When 拉取, Then 该池不采用, 其余池照常写入
- Given 拉取失败且旧池在有效期内, When 查询, Then 继续用旧池应答

### F-029 Docker 镜像与 Compose 部署 (P1)

用户故事: 作为服务端运维者, 我希望用 docker compose 一键部署 cfdoh, 镜像取自 GHCR, 以最低成本获得可维护的部署.

业务规则:
- 多阶段构建: 构建阶段静态编译, 运行阶段最小镜像, 含系统 CA 证书, 以非 root 用户运行
- 镜像发布到 GHCR, tag 含 latest 与版本号
- 提供 compose 样例: 端口映射, 环境变量注入, 快照目录挂载为卷
- 镜像内二进制与同提交的 release 产物同源
- /health 可作容器健康检查

验收标准:
- Given compose 样例与环境变量文件, When docker compose up, Then 服务启动且 /health 返回 ok
- Given 拉取版本 tag 镜像, When 运行 --version, Then 输出与 tag 一致的版本号
- Given 容器运行, When 检查进程用户, Then 非 root

### F-030 发布流水线 (P1)

用户故事: 作为用户与运维者, 我希望打 tag 即自动产出服务端与客户端的全部发布物, 以获得可验证的版本化交付.

业务规则:
- CI: push 与 PR 触发测试与构建检查, 全绿才可合并
- Release: 推送 vX.Y.Z tag 触发, 产物:
  - cfdoh: linux/amd64 与 linux/arm64 压缩包
  - cfhost: windows/amd64 压缩包与 linux/amd64 压缩包
  - 全部产物的 sha256 校验和文件
  - GHCR 镜像 (版本 tag 与 latest)
- 二进制内嵌版本号与提交哈希, --version 可查
- 任一测试失败则流水线失败且不发布

验收标准:
- Given main 分支 PR, When CI 运行, Then 测试与构建检查执行并回传状态
- Given 推送 v1.0.0 tag, When Action 完成, Then release 含两种服务端包, 两种客户端包, 校验和, GHCR 出现 1.0.0 与 latest 镜像
- Given 任一测试失败, When 流水线运行, Then 失败退出且无任何发布

## 约束

- 行为基线: 应答语义以 refer/edge-smart-doh 为对照; 有意分歧须在 arch/cdd 层登记并给出理由.
- 许可证: 参考实现为 AGPL-3.0, 本项目作为网络服务提供时保持源码公开, 许可证与之兼容.
- 平台范围: 服务端仅自托管 Linux 服务器形态; 客户端 Windows 服务优先, 兼发 Linux 构建; 不含边缘 Worker 类运行时.
- hosts 管辖: 客户端只写配置列表内的 Cloudflare 代理域名; 不做通用 hosts 管理工具.
- 隐私: 服务端默认零查询日志, 客户端 IP 不写日志不落盘, 快照与持久化文件不含客户端 IP; 客户端默认不上报, 开启可选上报时仅发测速结论且仅发给自己配置的服务端.
- Go 工具链: 单模块; 服务端 wire 编解码层自研; 引入的第三方库限于 TLS/QUIC 与运行时基础设施, 防御性检查不因引入库而降级.
