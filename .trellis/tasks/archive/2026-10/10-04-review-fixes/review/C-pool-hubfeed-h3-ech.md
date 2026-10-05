# 只读审查报告: pool + hubfeed + h3 + ech 模块组

## 头部

- 组名: C (pool / hubfeed / h3 / ech)
- spec 依据: `.trellis/spec/arch/pool.md`, `.trellis/spec/arch/hubfeed.md`, `.trellis/spec/arch/h3.md`, `.trellis/spec/arch/ech.md`; PRD F-007 / F-011 / F-015 / F-028; 决策 note `2026-10-04-metaech-坏载荷上报保持原态-推翻清除回种子.md`; refer 基线 `refer/edge-smart-doh/src/{preferred,h3}.ts`, `refer/edge-smart-doh/src/dns/ecs.ts`.

审查文件清单 (非测试, 逐行读完):

- internal/pool/pool.go (446 行)
- internal/pool/rank.go (173 行)
- internal/pool/contenttag.go (136 行)
- internal/pool/hostpools.go (219 行)
- internal/pool/state.go (208 行)
- internal/hubfeed/hubfeed.go (222 行)
- internal/h3/h3.go (223 行)
- internal/h3/state.go (113 行)
- internal/ech/ech.go (291 行)
- internal/ech/state.go (131 行)

测试文件 (读取以确认钉住范围): pool_test.go, contenttag_test.go, pool/state_test.go, hubfeed_test.go, h3_test.go, h3/state_test.go, ech_test.go, ech/state_test.go.
边界引用 (只读核对, 不属审查对象): internal/httpapi/httpapi.go (?ech=/admin 面), internal/resolver/resolver.go (ConfigFor 调用点), internal/config/config.go (pool feed 默认值), internal/wire/ip.go (MatchDomain/CanonicalName), cmd/cfdoh/main.go (启动顺序).

运行过的命令与结果:

- `go vet ./internal/pool/ ./internal/hubfeed/ ./internal/h3/ ./internal/ech/` → 通过, 无输出.
- `go test -race ./internal/pool/ ./internal/hubfeed/ ./internal/h3/ ./internal/ech/` → 4 包全部 `ok` (各约 1.0s), 无竞态报错.

---

## Findings (按严重度排序)

### 1. [medium] internal/hubfeed/hubfeed.go:133 — hubfeed 周期刷新令相同内容翻转 ContentTag, 违反 "相同内容重复上报不换标签"

代码 (hubfeed.go:133, 按 Go map 随机迭代序逐池写入):

```go
for scope, families := range adopted {
    ...
    pool.SetLearned(families[0], families[1], cfg.PoolFeedTTLSec, "pool-feed", scope)
```

关联代码:

- pool.go:86-99 `poolTable.set` 对已存在键先删除再 `PushBack` (键被移到最新位置, order 序随写入顺序变化):
  ```go
  if _, ok := t.entries[key]; ok {
      delete(t.entries, key)
      ...
  }
  t.entries[key] = pool
  t.order.PushBack(key)
  ```
- contenttag.go:104-109 `appendLearnedLocked` 严格按 `t.order` 插入序序列化:
  ```go
  for el := t.order.Front(); el != nil; el = el.Next() {
      key := el.Value.(string)
      ...
      fmt.Fprintf(b, "%c|%q|%s|%s\n", kind, key, ...)
  ```

违反的 spec 原句: pool.md "内容标签 (ContentTag): ... 相同内容重复上报不换标签, 重启后同内容同标签"; PRD F-028 "拉取周期可配 (默认 5 分钟)" (即稳态下同一份内容每 5 分钟整表重写一次).

具体失败模式: 拉取成功且各池内容与上一周期完全相同 (稳态) 时, `adopted` 是 Go map, 迭代顺序随机; 假设两个 scope A/B, 周期 1 按 [A,B] 写入得到 order [A,B], 周期 2 按 [B,A] 写入得到 order [B,A] (set 的重定位使序跟随写入序). ContentTag 按 order 序拼字节串, 字节序不同 → FNV-64a 不同 → 标签翻转. 后果: resolver 缓存键整体换代, 全量应答缓存每 5 分钟被冲刷一次, 恰是标签设计明确要防止的 (contenttag.go 头注 "periodic no-op reports do not flush the answer cache"). 单 scope 部署不触发; multi-scope (national + 各 isp) 是默认形态. 现有测试只钉了单 source 重报不换标签 (TestContentTagFlipsOnPoolMutation), 未覆盖多 scope 周期重写.

最小修复建议: `appendLearnedLocked` 序列化前对每张学习表的键排序, 使哈希与插入序无关 (isp/scoped 表键序无行为语义, 排序零副作用).

### 2. [medium] internal/ech/ech.go:68 — publish 缓存无容量上限, 公开 ?ech= 参数可无界消耗内存

代码 (ech.go:68, 86, 116):

```go
publish = make(map[string]*cachedConfig) // published-domain resolution cache
...
if cached.expiresAt > now() && validEchBytes(cached.data) { ... }
delete(publish, key)   // 仅同键再次读取且已过期时惰性删除
...
publish[key] = &cachedConfig{data: echBytes, expiresAt: now() + configTTL.Milliseconds()}
```

违反的不变量: ech.md "发布域名解析走 upstream 辅助解析, 结果带缓存, 失败不阻塞应答" 只定义了缓存行为未设上限; 本条按安全准则 (资源耗尽) 判定. 上游入口 httpapi.go:359-364 对 `?ech=` 仅做域名语法校验 (`validDomainName`, 无白名单), resolver.go:465-466 将其原样传入 `ech.ConfigFor`.

具体失败模式: 任一未认证 DoH 客户端携带 `?ech=<唯一随机子域>` 反复查询; 若攻击者控制一个泛解析域 (wildcard HTTPS 记录带合法 ech 参数, 或复用任何对外发布 ECH 的域), 每个唯一域名成功解析后写入一条 ≤ 16384 字节 (maxEchBytes) 的缓存项, TTL 1 小时, 且只有同一键被再次查询且已过期才会被删除 — 从不复访的键永久驻留. 内存随查询数线性无界增长, 可达 O(攻击查询数 × 16KiB), 构成 DoS.

最小修复建议: 给 publish 表加容量上限 (同库惯用的插入序 + 超限最早淘汰), 或仅允许 ECH_DOMAINS / ECH_SOURCE_DOMAIN 白名单内的域名进入缓存.

### 3. [medium] internal/ech/ech.go:230-241 — Status() 在 MetaOverride 与取锁之间存在窗口, meta 可被并发置 nil 导致 nil 解引用 panic

代码 (ech.go:230-241):

```go
func Status() *StatusReport {
	_, state := MetaOverride()   // 内部自行加锁后解锁
	if state == MetaSeed {
		return nil
	}
	mu.Lock()
	defer mu.Unlock()
	report := &StatusReport{
		Bytes:  len(meta.config),
		Until:  meta.until,      // meta 可能已为 nil
```

违反的不变量: ech.md "Meta 三态状态机转移固定" 隐含 Status 与状态迁移互斥一致; 对照 refer `metaEchStatus` 先判 `if (!metaEch) return undefined` 再取字段, 无此窗口.

具体失败模式: goroutine A 调 Status() (httpapi.go:701 /admin 状态面板, :963 selfcheck), MetaOverride 返回非 MetaSeed 后释放 mu; goroutine B 并发执行 applyMetaEchReport 的 "ok" 分支调 ClearMeta() 将 meta 置 nil; A 随后取 mu 并解引用 `meta.until` → nil 指针解引用 panic. net/http 会按连接恢复, 但该 admin 请求 500 中断并落栈日志. 触发需要两个 admin 请求在毫秒窗口内交错, 真实但概率低.

最小修复建议: 取到 mu 后复查 `if meta == nil { return nil }` 再构造 report.

### 4. [medium] internal/pool/rank.go:130-150 — 共识不足的交错合并输出没有每 /24 (v6 /48) ≤ 2 限制, 违反 PRD F-007 验收原句

代码 (rank.go:130-150, 交错路径无 perBlock 检查; 对照共识路径 rank.go:106-117 有):

```go
	// too little agreement: interleave round-robin, skipping duplicates
	var interleaved []string
	seen := make(map[string]bool)
	for index := 0; len(interleaved) < size; index++ {
		...
			ip := list[index]
			if !seen[ip] {
				seen[ip] = true
				interleaved = append(interleaved, ip)
```

违反的 spec 原句: PRD F-007 验收标准 "Given 三探针列表无严格多数共识, When 读池, Then 输出交错合并且每 /24 不超过 2 个"; pool.md 扩展规则 "投票与限段规则 (严格多数, 每 /24 两个) 是防污染核心, 不可简化".

具体失败模式: 三个探针列表无任何严格多数 IP 时输出交错合并, 若某探针独有列表的 6 个地址同属一个 /24, 交错输出可含同 /24 的全部地址; 该 /24 被封锁时优选池实际可用多样性归零 — 正是限段规则要防的场景. 注意: refer 基线 `combineRankings` 的交错路径同样无每块上限 (preferred.ts), 即 PRD 验收原句与 refer 行为本身冲突, 需先对账裁决方向: 改代码补上限, 或修正 PRD 验收措辞. 现有测试 TestCombineRankingsInterleaveWithoutConsensus 未钉每块上限.

最小修复建议: 交错循环复用共识路径的 perBlock 计数 (达到 maxPerBlock 即跳过该地址); 若裁定维持 refer 行为则改 PRD 验收句.

### 5. [low] internal/pool/pool.go:376-380 — LearnedStatus().Sources 混入已过期 source, 且 defaults 表过期项无任何清理路径, 偏离 refer

代码 (pool.go:376-380):

```go
	for _, pool := range defaults.snapshot() {   // snapshot 不滤过期
		report.Sources = append(report.Sources, SourceStatus{
			Source: pool.source, ...
```

违反的不变量: refer `learnedPoolStatus` 经 `activeDefaults()` 先剪除过期 source 再列出; spec pool.md "自学习池 ... 过期自动回落" (呈现层应反映回落后状态). defaults 表的惰性删除只发生在 `poolTable.get` (仅 scoped/isp 键会走到), defaults 键永不被 get, 过期项只能被同 source 重报或容量淘汰 (上限 8) 覆盖.

具体失败模式: 探针停报后 TTL 到期, 全国池应答正确回落 (activeLearned 过滤), 但 `/admin/preferred` 的 Sources 列表仍显示已过期探针及其过期时刻, 运维误判仍有探针在报. 内存有界 (8 条), 无应答层影响.

最小修复建议: Sources 列表只输出 `expiresAt > now()` 的表项.

### 6. [info] internal/pool/pool.go:345-348 — 解析成功但零地址的优选域名被计为失败, 全部零地址时行为偏离 refer

代码 (pool.go:345-348):

```go
		if result.v4 == nil && result.v6 == nil {
			failures++
			continue
		}
```

spec 原句: pool.md "优选域名解析容忍单域名失败, 全部失败才报错". refer 用 `Promise.allSettled`, 成功但空列表的域名不算 failure, 全部成功但全空时返回空池不报错; 本实现把 "成功但零地址" 计入 failures, 所有域名都如此时返回错误 (显式 ?cf= 场景 502). 仅上游对全部优选域名返回 NOERROR 空应答这一边角可触发, 影响极窄; "零地址算不算失败" 规格未定义, 列为待对账不确定项.

### 7. [info] internal/h3/h3.go:70-73 — 单份上报超 64 主机时按字典序截断, refer 按 JSON 插入序截断

代码 (h3.go:70-73):

```go
	sort.Strings(names) // deterministic cap
	if len(names) > maxHosts {
		names = names[:maxHosts]
	}
```

spec 原句: h3.md "上限 8 来源, 每份 64 主机"; PRD F-011 同句, 均未定义溢出策略. refer `setH3Verdicts` 用 `Object.entries(verdicts).slice(0, MAX_HOSTS)` 按上报顺序保留前 64. 探针上报超过 64 主机时, 两侧存活的主机集合不同 (探针意图排序丢失), 有效 verdict 可能不同. httpapi 不做条数拒绝, 截断路径可达. 确定性截断本身更可复现, 属未钉分歧, 建议在 spec 补一句溢出策略.

---

## 已核对无问题清单 (高风险不变量逐条)

- 取池层优先序 client 前缀 > isp:<name> > isp:national > 自学习, national 层在 ispScope 即 national 时不重复加入 → 与 pool.md 及 PRD F-007 一致 (pool.go:216-233).
- 每地址族独立补足到 6, 窄层不足从宽层补, 不因窄层 v4 遮蔽宽层 v6 → fillFamily 正确 (pool.go:236-264), 测试钉住.
- 显式请求参数越过前四层学习池 (显式族不 fill; ?cf= 由 usingDefault=false 跳过) → 符合.
- 严格多数 = floor(n/2)+1, 票数降序, 平票平均位置升序, 再平按 IP 字典序 → rank.go:66, sortByRank 正确; 测试钉住.
- 共识路径每 /24 (v6 /48) 最多 2 个 → rank.go:106-117 正确 (v6 取前 6 字节 = /48, 与 refer 一致); 测试钉住.
- 容量 自学习 8 / 专属 32 / 运营商 16 / 主机池 8, 超限最早插入淘汰, 重报键移到最新 → 与 refer setLearnedPool/HostPools.set 语义一致 (rank.go 常量集中定义).
- CF_DROP_AAAA: v6 学习层不参与补足且最终清空 (含显式 v6) → 正确, 测试钉住.
- ContentTag: 固定表序 D→C→I→G→S, 主机列表排序, FNV-64a, 全空态恒为 "0", horizon 取被折叠条目的最早过期时刻, 到期重算 → 逻辑正确, 测试钉住 (单 source 场景); 多 scope 稳定性缺口见 Finding 1.
- 锁序 tagMu → mu → github.mu → sites.mu, 五表全部写入经 mutate, 无倒置路径 (SaveState/Preferred/poolFor 各只持单锁, 不构成环) → 无死锁.
- 相同内容重启同标签 (快照按插入序重放, order 保留) → 测试钉住.
- 站点池标签 = 合并后池内容 FNV-32a "site" 前缀, 同内容同标签, 无活跃池返回空 → 与 refer sitePoolCacheTag 逐字节一致.
- hubfeed: 仅 published 为真; 每族保序取至多 6; 逐池 CF 网段校验整池拒绝且污染超出第 6 条仍整池拒绝 (validateAddresses 全量校验后才截断); 失败沿用旧池由惰性过期回落; 后台 goroutine 随 ctx 退出, 不阻塞查询 → 全部符合, 测试钉住 (含 TestPollutionBeyondCapStillRejectsWholePool).
- hubfeed 周期默认 5 分钟, TTL 默认 30 分钟, URL 置空停用, 非 https 停用 → config.go:201-212 钳制正确 (hubfeed.go 内 60s 兜底不可达).
- h3 全票制: 全部报告来源 ok 才允许, 任一 fail 否决 (未列出主机的来源不参与否决, 与 refer effective() 一致) → 正确, 测试钉住.
- h3 后缀最长匹配且覆盖主机自身与子域: MatchDomain("*."+host) 的 "apex 或后缀" 语义与 refer domainMatches("."+host) 等价 (wire/ip.go:19-36) → 正确, 测试钉住.
- h3 代数只在有效快照变化时递增, 相同重报不 bump, 过期剪除变化 bump, "h3g" 前缀格式, 代数不入快照重启重算 → 正确, 测试钉住.
- h3 容量 8 来源 / 每份 64 主机, 超限最早淘汰 → 正确, 测试钉住.
- ech base64 → ECHConfigList 结构校验 (总长字段 + 首配置长度边界) 正确, 非法拒绝; 发布域名缓存 1h, 键经 CanonicalName 归一, 命中不再外呼 → 测试钉住.
- Meta 三态: rotated 坏载荷 400 且保持原态 (httpapi 层无 ClearMeta 副作用, "state kept") → 与 2026-10-04 决策 note 一致; TTL 钳 300–604800 与 broken ≤ 86400 在 httpapi 落地; ok 且 verified 字节一致续期不回落种子; 过期清扫 bump 代数; suspended 续期同态不 bump; 代数不入快照 → 全部符合, 测试钉住.
- 三模块快照: 缺失文件 no-op, 损坏/未知版本记日志保持空态不阻塞启动, 写入 tmp+rename 原子, 版本号字段在位, pool 快照 scope client 键为前缀串不含完整客户端 IP → 全部符合, 测试钉住.
- 事件目录: preferred_pool_updated / github_pools_updated / site_pools_updated / h3_verdicts_updated / meta_ech_seed_ok / meta_ech_rotated / meta_ech_suspended / pool_feed_refresh / pool_feed_rejected 的 detail 字段构成与各 spec 事件目录逐条一致.
- 对外接口签名与 pool.md / h3.md / ech.md 声明的类型与函数逐一比对一致.
- 并发: `go test -race` 四包全绿; Preferred 对惰性过期条目持写锁 (曾有读锁竞态, 现有回归测试钉住); hubfeed ticker/goroutine 无泄漏; resp.Body 均 defer Close.

---

## 结尾计数

- high: 0
- medium: 4 (ContentTag 周期翻转; ?ech= 无界缓存; ech.Status TOCTOU; 交错合并无限段)
- low: 1 (LearnedStatus 过期 source 残留)
- info: 2 (零地址优选域名计失败; h3 溢出截断策略与 refer 不同)
