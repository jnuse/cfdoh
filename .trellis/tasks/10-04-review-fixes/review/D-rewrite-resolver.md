# D 组审查报告: rewrite + resolver (解析管线核心)

审查人: Go reviewer (只读). 日期: 2026-10-04. 仓库: /root/cfdoh @ main (c0c3bb6).

## 审查文件清单

非测试源文件 (逐行全读):
- internal/rewrite/rewrite.go (548 行)
- internal/resolver/resolver.go (707 行)

测试文件 (通读, 确认钉住面):
- internal/rewrite/rewrite_test.go (715 行)
- internal/resolver/resolver_test.go (728 行)

spec 层 (先读):
- .trellis/spec/arch/rewrite.md, .trellis/spec/arch/resolver.md
- .trellis/spec/prd/requirements.md (F-004, F-009, F-010, F-012, F-014, F-017, F-018, 约束)
- .trellis/notes/implemented/feature/2026-10-04-cf-改写门控在有可用优选池时自动提升.md

refer 基线抽查 (怀疑不匹配处):
- refer/edge-smart-doh/src/index.ts (handleDns 缓存策略, resolveFresh 改写链, classify 闭包)
- refer/edge-smart-doh/src/rewrite.ts (rewriteCloudflareAddresses, rewriteXAddresses, pinAddresses, pinHttpsHints, flattenAliases, injectEchBytes, injectEch)

依赖面签名/语义抽查 (不改判, 仅核对调用假设):
- internal/cache/cache.go (Get/Put/IdentityOf, SERVFAIL 不缓存, stale TTL 30)
- internal/pool/pool.go (Preferred, CFDropAAAA 清空 v6), internal/pool/hostpools.go, contenttag.go
- internal/h3/h3.go (AlpnFor 无 verdict 回落 fallback, CacheTag)
- internal/ech/ech.go (MetaOverride 三态, MetaCacheTag, ConfigFor, Validated)
- internal/wire/misc.go (RotateAddresses 按族循环左移, MakeServfail mask 0x7910, PatchID)
- internal/config/config.go (XDomains/GithubDomains/MetaDomains 默认值)

决策 note 检索: notes.py search "钉住" / "X 判定" — 下述各分歧均无登记.

## 运行过的命令与结果

- `go vet ./internal/rewrite/ ./internal/resolver/` — 通过, 无输出.
- `go test -race ./internal/rewrite/ ./internal/resolver/` — `ok github.com/jnuse/cfdoh/internal/rewrite 1.017s`, `ok github.com/jnuse/cfdoh/internal/resolver 3.274s`.

## Findings (按严重度排序)

### M1 [medium] rewrite.go:129 — X 改写判定未叠加 cdn.cloudflare.net 探测, 服务路径 probe 永不参与改写

代码 (rewrite.go:129, RewriteX 内部自判):
```go
if !UsesCloudflare(resp, cfrange.Current()) {
    return resp
}
```
resolver.go:396-398 调用处直接透传, 未把 classify() 结果交给 RewriteX; classify (含 probe) 仅在 HTTPS/ECH 分支或 explain (resolver.go:387-389) 触达.

违反 spec 原句 (arch/rewrite.md 判定): "判定: 应答地址落在 Cloudflare 网段即判定; 多 CDN 域名 (X 族) 叠加 \\"<域名>.cdn.cloudflare.net\\" 可解析性判定." refer 对应实现 (index.ts classify): `direct || viaCname`, viaCname 即 servedByCloudflare probe; refer X 分支 `if (await classify()) rewriteXAddresses(...)` 消费 probe 结果.

失败模式: X 域名经 CNAME setup 接入 Cloudflare (应答地址为 BYOIP/自有前缀, 不在公布网段, refer 注释举 claude.ai 160.79.104.10 为例), 优选池 v4 非空 → spec 与 refer 判定 "由 Cloudflare 服务" → A 记录钉住优选池; 代码 UsesCloudflare 仅看应答本地地址 → false → 原样返回 → 该 X 域名持续拿到未优选且可能不可达的地址, 且无任何日志.

最小修复: resolver 的 X 分支改为 `if classify() { resp = rewrite.RewriteX(resp, q, plan.pool, cfg) }` (RewriteX 去掉内部网段复判或降级为快速路径).

### M2 [medium] rewrite.go:186-188 — PinAddresses 对 CNAME 链应答不钉住, 站点池/GitHub 池被架空

代码:
```go
if first < 0 {
    return resp
}
```
(176-185 行只统计 owner 为 qname 的 A 记录; 链上 A 记录 owner 是链目标名, first 恒为 -1, 整体原样返回, 连 AAAA 去除也一并跳过.)

违反 spec 原句 (arch/rewrite.md 钉住): "钉住: 站点池与 GitHub 池的主机强制为池地址并去 IPv6, 不经优选池选择." refer pinAddresses (rewrite.ts:235-253) 以 `existing[0]?.name ?? question.name` 为 owner, 对任意 owner 的 A 记录钉住 (无 qname-owned A 时也在 qname 下补造), 并先于本步删除全部 A/AAAA.

失败模式: sitecheck 上报的站点其上游 A 应答为 CNAME 链 (CNAME setup 常见形态: qname CNAME→edge, A edge). 触发后: (a) 若 edge 地址在 CF 网段, 前一步通用改写已把地址换成通用优选池 — 而 "origin 经通用池不可达" 正是该站点进入站点池的理由, 结果不可达依旧; (b) 若不在网段 (GitHub), 应答保持上游地址且 AAAA 未去. 两种情况下站点池/GitHub 池记录完全无效. 注: rewrite_test.go "no query-name a record untouched" 钉住了现状, 但该分歧未在 arch/cdd 层登记, 与 spec 句直接冲突.

最小修复: 无 qname-owned A 记录时回退用应答中首条 A 记录作模板钉住 (无任何 A 记录时如 refer 在 qname 下补造), 再依赖链上既有的 Flatten 归名.

### M3 [medium] rewrite.go:104-105 — 混合应答整族替换: 非 Cloudflare 网段的地址也被换成优选池

代码 (RewriteAddresses, 门控为整包级 UsesCloudflare):
```go
answers = replaceFamily(answers, wire.TypeA, v4)
answers = replaceFamily(answers, wire.TypeAAAA, v6)
```
replaceFamily (400-433) 替换该类型全部记录, 不逐条检查地址是否在网段; 同根, 108 行 `dropType(answers, wire.TypeAAAA)` 在 CF_DROP_AAAA 下丢弃全部 AAAA (含非网段记录).

违反约束 (PRD 约束): "行为基线: 应答语义以 refer/edge-smart-doh 为对照; 有意分歧须在 arch/cdd 层登记并给出理由." refer rewriteCloudflareAddresses (rewrite.ts:139-190) 逐记录过滤: 仅替换地址 inAnyCidr 的 A/AAAA, 仅移除 in-range (或 DropAAAA 时 in-range) 的 hint/AAAA, 非 CF 记录原样保留. 此分歧未登记.

失败模式: 一个应答同时含 CF 与非 CF 地址记录 (多 CDN 切换期, GeoDNS 混合返回, 或 HTTPS hint 在网段而 A 记录在合作 CDN) → 任一记录命中网段即整族替换 → 非 CF 源站的地址被替换为 CF 优选池, 客户端带该源站 SNI 连 CF 边缘 → 握手/回源失败. 同理 DropAAAA 会误删非 CF 的 AAAA 记录.

最小修复: replaceFamily 与 AAAA 丢弃前逐条按 ranges 过滤 (与 refer 对齐), 网段判断可复用 cfrange.Contains.

### L4 [low] resolver.go:175-179 — cache_write_error 事件无发射点

代码:
```go
if _, ok := sharedCache(cfg).Put(plan.id, encoded, cfg); !ok {
    note(notes, "cache: answer not stored (SERVFAIL or zero TTL)")
```
服务路径 notes 为 nil, note() 丢弃; Encode 失败分支 (179) 同样只 note.

违反 spec 原句 (arch/resolver.md 事件目录): "cache_write_error — 缓存写失败; detail: 错误信息." refer 在同位置发射 (index.ts:257-258, DEBUG 门控).

失败模式: 缓存写路径异常 (编码失败等) 完全静默, 运维按 spec 事件目录配置告警永远收不到该事件, 缓存命中率异常下跌时无从定位.

最小修复: store 分支两个失败点补 `slog.Debug/Warn("event", "event", "cache_write_error", ...)` (与 prefetch_error 同款).

### L5 [low] rewrite.go:106 — CF_DROP_AAAA 下改写应答的 HTTPS ipv6hint 残留, 双栈客户端仍被引到已禁用的 IPv6

代码:
```go
answers = rewriteHTTPSHints(answers, v4, v6)
```
DropAAAA 开启时 pool.Preferred 已把 v6 清空 (pool.go: `if cfg.CFDropAAAA { ipv6 = []string{} }`), rewriteHTTPSHints (437-460) 对空族原样保留 hint → AAAA 记录已删而 ipv6hint 仍指向 CF IPv6.

违反约束 (PRD 约束, 未登记分歧): refer rewriteHttpsHints (rewrite.ts:131-135) 在 `config.cfDropAaaa` 时移除 ipv6hint. spec 原句 (arch/rewrite.md): "CF_DROP_AAAA 开启时, 经改写 (含 X 改写) 的应答去除 AAAA 记录" — 只登记了记录级去除, hint 级残留属未登记偏差.

失败模式: 运营商 v6 质量差而开 DropAAAA; 改写后的 HTTPS 应答 AAAA 全删但 ipv6hint 完整保留 → 支持 hint 的客户端 (Chromium) 直接对 hinted v6 发起连接, 绕过 DropAAAA 的意图, 连接超时后才回退.

最小修复: RewriteAddresses 在 cfg.CFDropAAAA 分支同步 `removeSvcParam(r, wire.ParamIPv6Hint)`.

### I6 [info] resolver.go:353-365 — 判定地址在响应规则之后采样, 非严格 "上游原始地址"

代码顺序: `resp = plan.base.ruleSet.Apply(q, resp)` 先于 `upstreamV4, upstreamV6 := answerAddresses(resp)` 与 `upstreamUsesCF := rewrite.UsesCloudflare(resp, ranges)`. spec 原句 (F-012): "判定用上游原始地址". refer 用 originalResponse 采样 (规则改写前的包). 触发: replace-a/replace-aaaa 规则把 CF 站点地址换成非 CF (或反向) → 展平门控与 ECH 分类随规则地址翻转. 影响限于配置了地址替换规则的角落场景; 不确定是否有意 (若有意应在 spec 登记 "原始 = 规则后, 改写前").

### I7 [info] rewrite.go:216-247 (Flatten) — 与 refer flattenAliases 存在四处未登记语义差异

(1) 保留 CNAME 记录 (refer 删除链上 CNAME); (2) 移动记录不按 alias TTL 封顶 (refer `ttl = min(record.ttl, aliasTtl)`, 客户端可能以超过别名有效期的 TTL 缓存地址); (3) 要求 Answers[0] 恰为 qname-owned CNAME (refer 从 question 名沿链 walk, 与记录位置无关); (4) Answers[0] 之后所有非 CNAME 记录无条件改名为 qname (refer 仅改链上成员). spec 原句 "CNAME 链上的记录移到查询名下" 粗粒度匹配代码, 主流应答形态下结果等价; 按 PRD 约束这些差异未登记, 建议在 arch/rewrite.md 补一句边界描述而非改码.

另记 (未列正式 finding): v6 池为空且未开 DropAAAA 时 in-range ipv6hint 保留不动, 为 rewrite_test.go "v4-only pool keeps v6 verbatim" 钉住的有意行为, refer 会移除 — 同样未在 spec 层登记, 与 L5 一并补登记即可.

## 已核对无问题清单

- 改写链次序 响应规则 → CF 改写 → X 判定改写 → 站点池/GitHub 钉住 → ECH 注入 (含 Meta 分支) → CNAME 展平 → resolver.go:353-428 顺序与 spec 逐项一致 (X 判定语义偏差见 M1).
- 单步失败跳过不阻塞应答 → 各步 best-effort 返回原 resp; classify 失败按非 Cloudflare 处理并记录 note; 上游全败走 stale/SERVFAIL 兜底.
- 池内容标签在 pool.Preferred 取池之前采样 (同一次解析键与应答见同一代池) → resolver.go:318-321 先 ContentTag 后 Preferred, 注释说明的竞态方向 (宁可留死条目不串代) 成立.
- fresh 直返 / refresh 先答后刷 / HTTPS 有缓存含过期立即返回并后台刷新 / 上游全败用过期兜底 / 无缓存 SERVFAIL (TTL 写 30, 保留 opcode/RD/CD) → resolver.go:135-166 与 cache.Get 状态机一致, 四个测试用例分别钉住.
- SERVFAIL 不缓存 → cache.Put 对 rcode 2 计 TTL 0 拒绝, TestResolveUpstreamServfailNotCached 钉住.
- 显式指定池失败返回错误, 默认池失败放行不改写 → prepareFull 的 explicit 判定 (含 CfDomainIsDefault 豁免) 与 F-007 一致, 测试钉住.
- 改写门控 CF_REWRITE_ENABLED OR 池非空, rewriteCfg 派生请求级副本不动原始 cfg → resolver.go:203-212 浅拷贝仅置 CFRewriteEnabled, 与决策 note 逐字对齐; 双重提升幂等无害.
- 每次应答轮转 A/AAAA 顺序 (按 type 分组循环左移) + 事务 ID 回填请求 ID → serveHit 与 finalizeAnswer 均 PatchID+RotateAddresses, cache 路径与 miss 路径一致, 测试钉住.
- explain 复用同一管线且不写缓存 → resolveFresh store=false, 测试断言 cache.Len()==0; CacheState 只读.
- 地址与 HTTPS 提示同步改写 (通用路径与钉住路径) → RewriteAddresses 同步替换 hints; PinHTTPSHints v4 换 v6 删 (DropAAAA hint 残留见 L5).
- 展平判定用改写前地址 (优选地址不必落网段) → upstreamV4/V6 与 upstreamUsesCF 在 CF 改写/钉住/ECH 之前采样 (规则先于采样见 I6).
- 非 Cloudflare 站点不注入 ECH, 注入失败不阻塞, 上游无 HTTPS 记录时补造 (TTL 300, priority 1, target ".", alpn 缺省 h2) → injectECH 各分支与 F-010/F-011 一致; X 与 Meta 无测量时固定 h2 (echAlpnFallback), 一般站点 nil 保留上游 ALPN.
- Meta 三态 (learned 注入 / suspended 原样 / seed 校验后注入) 与 MetaCacheTag 折入 Meta 域缓存键 → injectECH Meta 分支与 F-015 一致, 测试钉住.
- ECH 来源优先级 ?ech= > ECH_CONFIG_BASE64 > ECH_SOURCE_DOMAIN, ECH_DOMAINS+base64 无条件注入 → injectECH 分支次序与 F-010 一致 (?ech= 失败向下一级回落).
- GitHub/站点钉住域名不经通用 ECH 注入, 站点池保留上游 ECH → resolver.go:419 门控 !githubPinned && !sitePinned 与 F-014 一致.
- ChromiumECHVerdict 条件 (地址存在, 单一 owner, target 一致含 ".", 含 ech 参数) → 与 F-018 一致, 测试钉住.
- block 规则 REFUSED (rcode 3, QR|RA, opcode/RD/CD 保留, 不外发上游) → refusedFor mask 0x7910, 测试钉住.
- 并发与资源 → sharedCache 双检锁正确; rewrite 包无状态; 后台刷新经 context.WithoutCancel 脱离请求生命周期; go test -race 通过, 无新增 goroutine/fd 泄漏迹象.
- dns_query (hit/miss/prefetch/stale, DEBUG 门控, LOG_QUERIES 才含域名) 与 prefetch_error 事件 → logQuery/refreshInBackground 实现一致 (cache_write_error 见 L4).

## 严重度计数

- high: 0
- medium: 3 (M1 X 判定缺 probe, M2 CNAME 链不钉住, M3 混合应答整族替换)
- low: 2 (L4 cache_write_error 缺发射点, L5 DropAAAA 下 ipv6hint 残留)
- info: 2 (I6 判定地址采样时机, I7 Flatten 未登记差异)
