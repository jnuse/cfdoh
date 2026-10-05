# 审查报告: httpapi + config + 服务端入口

组名: E (httpapi / config / server-entry, 安全敏感面)

## 审查文件清单

- internal/httpapi/httpapi.go (1165 行, 全读)
- internal/httpapi/httpapi_test.go (测试, 确认钉住行为)
- internal/config/config.go (296 行, 全读)
- internal/config/config_test.go (测试)
- cmd/cfdoh/main.go (148 行, 全读)
- 跨模块抽查 (仅签名与交互语义): internal/cfrange/cfrange.go, internal/pool/{pool,hostpools}.go, internal/ech/ech.go, internal/h3/h3.go, internal/ecs/ecs.go, internal/rules/rules.go, internal/wire/ip.go, internal/wire (MakeServfail), internal/resolver/resolver.go (ResolveFresh/CacheState)
- refer 基线对照: refer/edge-smart-doh/src/index.ts (acceptsDns, readDnsRequest, validateQuery, metaEch 三态分支), refer/edge-smart-doh/src/rewrite.ts (validatedEchConfig)
- spec: .trellis/spec/arch/httpapi.md, .trellis/spec/arch/config.md, .trellis/spec/arch/server-entry.md, .trellis/spec/prd/requirements.md (F-001/005/008/017/018/019/020/021/022), 决策 note 2026-10-04-metaech-坏载荷上报保持原态

## 运行过的命令与结果

| 命令 | 结果 |
|---|---|
| go vet ./internal/httpapi/ ./internal/config/ ./cmd/cfdoh/ | 通过, 无输出 |
| go test -race ./internal/httpapi/ ./internal/config/ | ok 1.585s / ok 1.009s, 无 race |
| go test ./internal/httpapi/ -run TestAdminHealth -count=1 | FAIL: `Get "http://127.0.0.1:43531/admin/health": EOF` — finding #1 的 panic 复现 (全量套件因测试顺序耦合而掩盖) |

## Findings

### 1. [high] internal/httpapi/httpapi.go:975-976 — /admin/health 对 nil 状态解引用, 默认部署下必然 panic

代码:
```go
"github_sources":  len(pool.GithubStatus().Sources),
"site_sources":    len(pool.SiteStatus().Sources),
```

违反 spec: PRD F-020 "GET /admin/site, /admin/github, /admin/h3, /admin/health, /admin/selfcheck: 各自状态" — /admin/health 应返回各模块状态.

失败模式: `pool.GithubStatus()` / `pool.SiteStatus()` 在无活跃池时返回 nil (internal/pool/hostpools.go:119-120 `if len(active) == 0 { return nil }`). 默认部署 (从未有 github/site 上报) 或全部上报过期后, 携带合法 ADMIN_TOKEN 的 GET /admin/health 触发 nil 解引用 panic; net/http 恢复 panic 时直接关闭连接, 监控端拿到 EOF/连接重置而非 JSON, F-020 端点完全不可用. 已实证: 单独运行 TestAdminHealth 即失败于 EOF; 全量测试通过仅因 TestAdminSiteGithubH3 先运行污染了全局 pool store. 同函数内 LearnedStatus 与 ech.Status 都做了 nil 检查, 唯独这两处遗漏; ech.Status() 在种子态同样返回 nil, 属同类契约.

最小修复: 仿照同函数 learnedSources 的写法, 对两个状态先判 nil 再取 len (或由 pool 层保证返回非 nil 空对象, 二选一).

### 2. [low] internal/httpapi/httpapi.go:255-258 — Accept 校验用整头子串匹配, 较 refer 更宽松且未登记分歧

代码:
```go
if accept := r.Header.Get("Accept"); accept != "" &&
    !strings.Contains(accept, "*/*") &&
    !strings.Contains(accept, "application/dns-message") {
```

违反 spec: PRD F-001 "Accept 必须允许 application/dns-message (缺失或 `*/*` 视为允许), 否则 406"; PRD 约束 "行为基线: 应答语义以 refer/edge-smart-doh 为对照; 有意分歧须在 arch/cdd 层登记" — httpapi.md 未登记此差异. refer (src/index.ts:65-68) 为 `accept === "*/*" || split(",").some(item => item.trim().startsWith(DNS_CONTENT_TYPE))`.

失败模式: (a) `Accept: xapplication/dns-message` 实际并不允许 application/dns-message, refer 返回 406, 本实现因子串命中放行 200; (b) `Accept: */*;q=0` (整头拒绝语义) refer 406, 本实现因 Contains("*/*") 放行 200. 标准客户端不受影响, 属基线行为偏差与语义过宽, 非 安全漏洞.

最小修复: 改为按 refer 语义逐逗号项 trim 后 startsWith 判定, `*/*` 仅精确匹配; 或在 httpapi.md 登记放宽理由.

### 3. [low] internal/httpapi/httpapi.go:141-145 — PATH_ALIASES 重复或与内置路由冲突导致启动 panic

代码:
```go
mux.HandleFunc("/dns-query", s.handleDoH)
for _, alias := range s.cfg.PathAliases {
    if alias = strings.TrimSpace(alias); alias != "" && strings.HasPrefix(alias, "/") {
        mux.HandleFunc(alias, s.handleDoH)
```

违反 spec: PRD F-022 "数值项全部带钳制区间... 配置解析结果在启动日志中输出" 体现的配置错误可诊断原则; config.md 对 PATH_ALIASES 未定义任何致命语义. (config.go 的 strList 不去重, "/a,/a" 保留两个重复项.)

失败模式: 运维配置 PATH_ALIASES="/dns-query" 或 "/explain" 或 "/health" 或重复别名 (任一与已注册模式完全相同) → http.ServeMux.Handle 对重复模式 panic ("http: multiple registrations for ...") → 进程带栈崩溃, 报错形态是 panic 而非可读的配置错误. 仅影响启动期, 失败快速可见, 无远程可利用面.

最小修复: 注册前查重 (对内置路由表与已注册别名集合去重, 冲突项记告警跳过).

### 4. [low] internal/config/config.go:282 — 配置文件单行超过 64KiB 使 Load 失败退出, 阻断合法内嵌规则配置

代码:
```go
scanner := bufio.NewScanner(f)
```

违反 spec: arch/config.md CFDOH_CONFIG 行 "文件不存在报错; 畸形行忽略并告警" 的容错语义; 且 PRD F-016 允许 "RULES_JSON 内嵌... 上限 1000 条" — 1000 条规则的单行合法 JSON 约 50-100KB, 超过 bufio.Scanner 默认 64KiB token 上限.

失败模式: CFDOH_CONFIG 指向的文件中 RULES_JSON=<约 70KB JSON> (合法配置) → scanner.Err() 返回 "token too long" → Load 返回 error → cfdoh 启动失败. 该长行并非 "畸形行", 却得到比畸形行更严重的处理 (畸形行忽略告警, 长合法行致命). 环境变量途径 RULES_JSON 不经过 scanner, 存在绕过, 但配置文件是 spec 认可的一等输入.

最小修复: `scanner.Buffer(make([]byte, 0, 64*1024), 4<<20)` 将单行上限提到 4MiB, 超限再按畸形行告警忽略.

### 5. [info] internal/httpapi/httpapi.go:1021,1160-1162 — 数值 ttl 显式传 0/负数被当作缺省, 与 refer 的钳制语义存在边缘差异

代码:
```go
if ttl <= 0 { ttl = 86400 }          // applyMetaEchReport
if v == 0 { v = def }                // ttlOrDefault
```

不确定点说明: Go 的 int 无法区分 "字段缺失" 与 "显式 0", 实现统一按缺省处理 (metaEch 0 → 86400, h3 0 → 5400); refer (index.ts:703) 对显式数值 0 钳到下限 300. 探针正常不会发送 ttl:0, 无实际故障可演示, 仅记录语义差; 若要严格对齐需改用 *int 字段.

## 已核对无问题

- 非 GET/POST → 405 + Allow: GET, POST (httpapi.go:250-253) -> 与 refer 一致
- Accept 缺失视为允许; POST Content-Type 忽略参数后须为 application/dns-message 否则 415 (httpapi.go:260-263) -> 一致 (边缘宽松见 finding #2)
- GET 双检: 缺 dns/超 87384/非法 base64url → 400; 解码后超 MAX_DNS_PACKET_SIZE → 413 (httpapi.go:271-288) -> 与 refer 及 F-001 一致
- POST 双检 413: Content-Length 预检 + LimitReader(max+1) 实读复核, chunked 无 CL 亦被实读兜住 (httpapi.go:264-270) -> 一致
- 非法请求包 400; 恰好 1 question / QR 未置位 / opcode 0 (httpapi.go:290-299) -> 与 refer validateQuery 一致
- 别名路径注册到同一 handler, 校验链与 /dns-query 完全一致 (httpapi.go:141-146) -> F-001 验收满足
- Host 校验: PUBLIC_HOSTNAMES 非空时 canonical + 去端口 + localhost 豁免, 其余 421 (httpapi.go:128-141) -> F-021 一致
- 未配置 ADMIN_TOKEN 时全部 /admin/* 返回 404, 含仅配 HUB_TOKEN 场景 (httpapi.go:561-564) -> F-008 一致
- 双令牌 Bearer 常数时间比较: AdminToken 分支恒先执行 (与令牌身份无关的比较顺序), 错误令牌 401 (httpapi.go:566-576) -> 无时序旁路
- HUB_TOKEN 权限收窄: 非 POST 或非 isp: 前缀 scope → 403 (GET 403 含于非 POST 分支); site/github/h3/health/selfcheck 五端点 hub 一律 403 (各 handler 首段) -> F-008/F-020 一致
- scope 链: default/client/isp:<合法名>, national 保留名拒绝, client 无法识别上报者地址 → 400 (httpapi.go:728-742) -> F-006/F-008 一致
- 上报地址逐个强校验: 严格 ParseIPv4/ParseIPv6 (v6 拒 IPv4-mapped 文本), 每族 64 上限, ttl 钳 60-86400, source 截 64 (httpapi.go:744-766, normalizeAddrs) -> F-008 一致
- isp 池逐地址 CF 网段校验, 任一在外整批 400; cfrange.Current() nil 时 Contains 判 false (nil-safe, 冷启动窗口内拒绝上报, 符合强校验语义) (httpapi.go:754-763 + cfrange.go:65-68) -> F-008 一致
- github 空 hosts → 400; site 空列表为合法撤销; site/github ttl 缺省 3600 钳 60-86400, github 仅收 v4 (httpapi.go:806-840) -> F-014/httpapi.md 一致
- h3: host 域名白名单校验, ttl 缺省 5400 钳 300-86400 (httpapi.go:876-896) -> F-011 一致
- metaEch 三态: rotated 非法 echConfig → 400 保持原态且发 meta_ech_report_rejected (detail 含 state kept); ok + verified 字节一致续期不换代; ok 其他情况清除回种子; broken 钳上限 86400; 与 problems/hosts 共存一次上报; 全分支与 refer index.ts:698-736 逐行对齐 (含 invalid verified 视为无 verified) (httpapi.go:1019-1056) -> 决策 note 与 F-015 一致, 区分性场景已被 TestAdminSelfcheckMetaEch 钉死
- 自检表至多 8 source 最旧淘汰; problems 截 50 条/300 字; 失败上报发 selfcheck_failed (detail: source, problems) (httpapi.go:1064-1141) -> F-020/httpapi.md 事件目录一致
- 客户端识别取值链: X-DoH-Origin-Token 常数时间门控 X-DoH-Client-IP 首值 → X-Real-IP → CF-Connecting-IP → XFF 首值 → TCP 对端; 每级解析失败跳下一级 (httpapi.go:209-236) -> F-005 一致 (对受信头额外做 IP 解析校验, 较 refer 更严, 防御性增强)
- pprof: PPROF_ADDR 独立监听与门控, 空即关闭, 监听失败仅告警, 主路由不挂 DefaultServeMux (httpapi.go:112-127) -> F-021/httpapi.md 一致
- admin POST body 1MiB 双检 413 (readAdminBody) -> 无资源耗尽面
- ?ip4/?ip6: 原始串 ≤1024, 1-16 个逐个强校验; ?cf/?ech 域名语法白名单; ?rules 走 rules.ValidateDynamicURL (https/主机白名单/禁 credentials/仅 443/禁 fragment/≤2048); 全部折入缓存 variant (httpapi.go:300-395) -> F-016/F-017 一致
- explain: GET only + name/type 语法校验 400; 接受与 /dns-query 相同参数面; ResolveFresh store=false 不写缓存 (resolver.go:132-136,142) -> F-018 一致
- /health 仅 GET 200 {ok:true}, /probe 仅 GET 返回客户端 IP + 模式 + 版本 (方法模式由 ServeMux 405) -> F-019 一致
- SERVFAIL 兜底: MakeServfail 保留 opcode/RD/CD, 置 QR|RA, rcode 2 (wire 层 0x7910 掩码核对) -> F-001 一致
- config 钳制区间/默认值与 config.md 环境变量对照表逐项一致 (UPSTREAM_TIMEOUT 2500/250-15000, HEDGE 100/0-5000, CACHE_MIN 30/0-3600, CACHE_MAX 3600/1-86400, NEG 300/0-3600, STALE 86400/0-604800, PREFETCH 10/0-90, ENTRIES 4096/128-65536, ECS_PREFIX 24/0-32 与 48/0-128, DYN_BYTES 262144/1024-1048576, MAX_PKT 4096/512-65535, POOL_FEED 300/60-3600 与 1800/300-86400, PORT 8787/1-65535) -> 全部一致
- config: 环境变量优先于文件; 畸形行忽略告警; 非法数值回退默认告警; 钳制记 "clamped to minimum/maximum"; ECS_MODE 非法回退 rules; UPSTREAMS/ECS_UPSTREAMS 仅留 https; POOL_FEED_URL 显式置空或非 https 停用并告警; 令牌缺失即关; bool 仅 true (大小写不敏感) 为真; META_DOMAINS 六域/X_DOMAINS/GITHUB_DOMAINS/DYNAMIC_RULE_HOSTS 默认与表一致 -> 一致
- SanitizedSummary: 三令牌与 IspTableURL/MetaEchConfigBase64/PoolFeedURL/PersistPath/PprofAddr 均只输出 on/off, 无令牌或配置载荷泄露 (config_test 钉住) -> 一致
- 入口: 退出次序 停收 (Run 内 Shutdown, 10s 宽限) → 快照 (缓存 + pool/h3/ech, 路径派生自缓存路径目录) → 退; 启动先回读快照再监听, 缺失/损坏仅告警; cfrange 每日 / hubfeed / 缓存 10min 快照统一 ctx 调度; isp 惰性刷新不在入口 -> server-entry.md 全部一致
- Run/servePprof goroutine 生命周期: serveErr 缓冲 1 单发送, Shutdown 后 Serve 返回 ErrServerClosed 发 nil, 无死锁/泄漏 -> 核对通过
- selfchecks 表 mutex 保护完整, 无 race (go test -race 通过) -> 核对通过

## 严重度计数

high: 1 · medium: 0 · low: 3 · info: 1
