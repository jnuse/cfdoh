# A 组审查报告: wire + ecs + rules

## 头部

- 组名: A (wire + ecs + rules)
- 审查文件 (全部非测试 .go 文件, 逐行通读):
  - internal/wire/: parse.go, name.go, encode.go, types.go, ip.go, misc.go, svcparam.go
  - internal/ecs/: ecs.go
  - internal/rules/: rules.go, apply.go, cidr.go
- 测试文件通读程度: wire_test.go, ecs_test.go, rules_test.go 全读, 用于确认不变量是否被固定.
- refer 基线抽查: refer/edge-smart-doh/src/dns/{name.ts, packet.ts, ecs.ts, https-rr.ts}, src/rules.ts, src/cidr.ts, src/upstream.ts, src/cache.ts (rotateAddressRecords).
- spec 依据: .trellis/spec/arch/wire.md, .trellis/spec/arch/ecs.md, .trellis/spec/arch/rules.md, .trellis/spec/prd/requirements.md (F-002, F-004 行 88, F-013, F-016); notes.py 检索 ParseRelaxed / trailing / relaxed 均无登记.

### 运行过的命令与结果

```
cd /root/cfdoh && go vet ./internal/wire/ ./internal/ecs/ ./internal/rules/ && go test -race ./internal/wire/ ./internal/ecs/ ./internal/rules/
-> go vet: 通过, 无输出
-> go test -race: 三包全部 ok (wire 1.009s, ecs 1.008s, rules 1.030s), 无 race 告警
```

---

## Findings

### 1. [medium] internal/wire/parse.go:66 — ParseRelaxed 放松尾随字节检查, 违反 wire spec "防御性检查清单不可放松"

代码 (parse.go:62-68, 117):

```go
func ParseRelaxed(b []byte) (*Packet, error) { return parse(b, true) }
...
if !allowTrailing && p.off != len(b) {
```

违反 spec 原句:
- wire.md L7: "解析完成后拒绝尾随字节; SVCB 参数 key 严格递增."
- wire.md L44: "防御性检查清单 (计数上限, 尾随字节, label 类型, 参数递增) 不可放松."
- PRD F-002: "解析完成后拒绝尾随字节".

失败模式: ParseRelaxed 被上游应答路径采用 (internal/upstream/upstream.go:183,233, internal/resolver/resolver.go:162, internal/ech/ech.go:102). 上游返回带尾随字节的报文时 cfdoh 接受并服务; refer 基线全程严格 (refer packet.ts:177 `if (offset !== input.length) throw "Trailing data"`, upstream.ts:27 用同一严格解析校验应答, 非法即弃). 同一字节流在本仓库内出现两种解析语义: 应答校验用宽松 ParseRelaxed, 而 RotateAddresses (misc.go:18) 用严格 Parse, 同一应答在管线内可解析与不可解析并存. 该分歧在 spec 与 Agent Notes 中均无登记.

最小修复: 在 wire.md 登记该有意偏差 (上游应答宽松, 入站查询严格), 或让上游应答路径也走严格 Parse.

### 2. [low] internal/wire/name.go:7 — decodeName 解码侧无总长 255 与 label 数上限, 接受无法重编码的名字

代码 (name.go:28-31, 43-45, 无任何长度统计):

```go
labels = append(labels, cloneBytes(p.buf[off+1:off+1+int(length)]))
...
return joinLabels(labels), nil
```

违反 spec 原句:
- PRD F-002 验收 3: "Given 任意可解析报文, When 解析后重新编码, Then 各 section 记录语义等价".
- wire.md L6: "编码一律不压缩; label 1..63 字节, 全名含长度前缀不超过 255 字节." (编码侧由 encode.go:175 强制, 解码侧无对应检查.)

失败模式: 报文携带总长超 255 字节的名字 (每个 label ≤63, 无指针环) 时, Parse 成功, 但 Encode 必然失败 (encode.go:175). 调用链只能落入兜底 (如 MakeServfail 裸头), 破坏 "可解析即可重编码" 的验收承诺. refer 解码侧显式拒绝 (refer name.ts:39 `if (++labelsSeen > MAX_LABELS) throw`, :45 `if (name.length > 253) throw`). 无 DoS (跳数 32 上限 + 报文长度天然有界).

最小修复: decodeName 内累计 wire 长度, 超 255 或 label 数超 128 时报错, 与 refer 对齐.

### 3. [low] internal/wire/misc.go:109 — 负应答无 SOA 时返回 negMax 而非 0, 与 refer 基线相反

代码 (misc.go:102-110):

```go
negative := p.Header.RCode() == 3 || len(p.Answers) == 0
if negative {
    for _, r := range p.Authorities {
        if soa, ok := r.RData.(SOA); ok { ... }
    }
    return clampTTL(negMax, minTTL, maxTTL)
}
```

违反 spec 原句:
- PRD 行 88 (F-004): "负应答 (NXDOMAIN 或空 answer 且含 SOA) 取 min(SOA ttl, SOA minimum, NEGATIVE_CACHE_MAX_TTL); 最终钳制 [CACHE_MIN_TTL, CACHE_MAX_TTL]" — 仅定义含 SOA 情形, 未授权无 SOA 负应答取 negMax.

失败模式: 上游返回 NXDOMAIN/NODATA 且 authority 无 SOA (或 authority 为空) 时, refer getResponseTtl 返回 0 (不缓存, refer packet.ts:315 `if (ttl === undefined) return 0`), cfdoh 返回钳制后的 negMax (默认 300s), 负应答被缓存. 上游瞬态异常产生无 SOA 负应答时, 错误结果被缓存 negMax 秒.

最小修复: 无 SOA 的负应答返回 0, 与 refer 对齐 (或登记偏差).

### 4. [low] internal/wire/misc.go:127 — clampTTL 对 0 值不钳入 [minTTL, maxTTL], 违反 PRD 字面与 refer 行为

代码 (misc.go:126-130):

```go
func clampTTL(v, minTTL, maxTTL int) int {
    if v <= 0 {
        return 0
    }
```

违反 spec 原句:
- PRD 行 88: "最终钳制 [CACHE_MIN_TTL, CACHE_MAX_TTL]" — 字面上任何结果 (含 0) 应落入区间.

失败模式: 上游应答记录 TTL=0 时, refer 返回 minTTL (packet.ts:316 `Math.max(minTtl, Math.min(maxTtl, ttl))` → 30), cfdoh 返回 0 即不缓存. 负缓存分支 min(SOA ttl, minimum, negMax)=0 时两者同样分歧. 行为方向上 cfdoh 更符合 DNS "TTL 0 不缓存" 惯例, 但与 PRD 字面及 refer 均不一致且未登记.

最小修复: 在 PRD 行 88 补一句 "TTL 0 的记录视为不可缓存" 登记该偏差, 或改为严格钳制.

### 5. [info] internal/rules/rules.go:439 — qtype 错型字段被当作无条件匹配, refer 中永不匹配

代码 (rules.go:439-451):

```go
func qtypeList(raw json.RawMessage) []uint16 {
    ...
    if err := json.Unmarshal(raw, &single); err == nil { return []uint16{single} }
    var items []uint16
    if err := json.Unmarshal(raw, &items); err != nil { return nil }
```

规则作者写 `qtype: "A"` (字符串) 时, cfdoh 解析为空 → 视为无 qtype 条件 → 规则匹配所有类型; refer (rules.ts qtypeMatches) 中 `["A"].includes(65)` 恒 false → 规则永不匹配. 分歧方向是放宽: 误配字符串 qtype 的 block 规则会在 refer 拒绝命中的情况下于 cfdoh 命中全部类型. rules.md 未定义错型字段语义; 代码注释 ("Wrong-typed fields are treated as absent") 自我登记但 spec 未登记. 不确定项目维护者是否视其为有意行为, 故记 info.

### 6. [info] internal/rules/rules.go:236 — host-map 展开按 pattern 字典序, refer 保 JSON 插入序

代码 (rules.go:236):

```go
sort.Strings(patterns)
```

refer hostMapRules 用 Object.entries 保持插入序. 当 host-map 同时含重叠 pattern (如 `*.example.com` 与 `api.example.com`) 时, 展开后的规则顺序不同, 影响 "block 首条命中即定" 与同型 replace 的叠加次序 (后写的 replace 覆盖先写的). JSON 对象键序在规范上无语义, 字典序是确定性选择; 未登记. 影响仅在多 pattern 重叠且动作冲突的配置下出现.

### 7. [info] internal/rules/cidr.go:28,44 — CIDR 缺前缀视为 /32 或 /128 主机路由, refer 拒绝

代码 (cidr.go:26-31):

```go
ones := 32
if hasPrefix { ... }
```

refer parseCidr (cidr.ts) 中 `rawPrefix === undefined` 直接 throw → 整条规则 response_ip_cidr 无效永不匹配. cfdoh 将 "1.2.3.4" 视作 /32 主机路由正常匹配. 方向为放宽接受面, 注释自我登记, spec 未定义前缀语法, 记 info.

---

## 已核对无问题清单

高风险不变量逐条验证 (不变量 -> 结论):

- 压缩指针防环: visited 偏移集合 + 32 跳上限 (name.go:17-45), 自指与互指环均被测试固定 (TestParseCompressionPointerLoop) -> 正确, 与 refer MAX_POINTER_HOPS=32 对齐.
- 0x40/0x80 label 拒绝 (name.go:42-43 default 分支), 0x41 用例固定 -> 正确.
- qdcount>32 或四段总数>512 拒绝 (parse.go:88-95, 常量 types.go:50-51) -> 正确, 与 refer packet.ts:170 对齐.
- 严格 Parse 拒绝尾随字节 (parse.go:117), 测试固定 -> 正确 (ParseRelaxed 见 finding 1).
- SVCB 参数 key 严格递增, 乱序/重复拒绝 (parse.go:305-307); UpsertSvcParam 去重+排序维持递增 (svcparam.go:44-58) -> 正确, 与 refer https-rr.ts:30 对齐.
- RDATA 深拷贝与输入缓冲解耦: take/cloneBytes/A/AAAA 逐字节复制 (parse.go:41-56, name.go:60-64), 别名测试固定 -> 正确.
- OPT 语义: class=PayloadSize, ttl=ExtRCode/Version/DO 读写 (parse.go:313-322, encode.go:47-61), DO 取 ttl&0x8000 -> 正确, 不作普通记录改写.
- IPv6 渲染 8 组完整小写 hex (ip.go:130-146), 测试固定 -> 正确.
- IPv4-mapped / 含点 IPv6 文本拒绝 (ip.go:70-73), 多重 "::" 拒绝, 组长 ≤4 hex, 非 8 组拒绝 (ip.go:75-113) -> 与 refer parseIpv6 逐分支对齐.
- 轮转只动 A/AAAA 组: recordIndexes 分组, rotateGroup 组内左移 n%len, CNAME 位置不变有测试 (misc.go:14-61, TestRotateAddresses); 进程级 atomic 计数逐次应答递增符合 wire.md 原句; 重组失败原样返回 -> 正确, 与 refer cache.ts:54-75 轮转数学一致.
- 域名规范化去尾点+小写 (ip.go:9-12), 存储保留原大小写 (测试固定); MatchDomain 通配后缀+精确语义与 refer domainMatches 逐分支一致, "notexample.com" 不误命中 -> 正确.
- 编码不压缩, label 1..63, 全名 ≤255 (encode.go:146-177), 空 label 拒绝, 64 字节 label 测试固定 -> 正确.
- appendRecord RDATA 总长 >0xFFFF 拒绝 (encode.go:72-74), 覆盖 OPT option 超长场景 -> 正确.
- MakeServfail 保留 opcode/RD/CD (掩码 0x7910), QR|RA|rcode2, 不可解析查询落 12 字节裸头 0x8182 (misc.go:64-88) -> 与 refer makeServfail 同构, 测试固定.
- PatchID 拷贝不改原包 (misc.go:80-87), 测试固定 -> 正确.
- ECS 决策次序 规则覆盖>off>always>rules (ecs.go:60-78) -> 与 refer shouldUseEcs 一致, 测试固定.
- ECS 子网 v4 /24, v6 /48 截断含部分字节掩码 (ecs.go:33-57, truncate), 身份串格式 (v4 十进制点分/prefix, v6 连续 hex/prefix) 与 refer makeEcsValue 完全一致 -> 正确.
- ECS Add 幂等: 替换全部已有 code 8 option, 保留 payload size/DO/其余 option; 无 OPT 合成 Name "." + PayloadSize 1232 + TTL 0, 编码后 class=1232 ttl=0 (ecs.go:84-117) -> 正确, 多 OPT 记录行为与 refer addEcs 逐一致.
- ECS Remove 删除全部 ECS option, 无变化返回原包, 不动其余字段 (ecs.go:120-146) -> 正确, 测试固定.
- 规则三形态解析 (裸数组/对象包裹/host-map), 上限 1000, 非对象项跳过 (rules.go:83-131, 236-277) -> 与 refer normalizeRules 对齐, 测试固定.
- 匹配条件全 AND: qtype/domain_exact/domain_suffix/response_ip_cidr 逐项短路 (apply.go:75-99); response_ip_cidr 无响应或编译失败时不匹配, 与 refer matches() 一致 -> 正确.
- domain_suffix 自动补前导点语义 ("example.com" 匹配自身+子域) (apply.go:101-124) -> 与 refer rules.ts 的 map("." + item) + domainMatches 语义一致.
- block 首条命中即定 (apply.go:10-22, 只返回布尔, REFUSED 与不外发由服务层负责) -> 正确, 测试固定.
- replace 仅原应答已有同型记录时生效, 继承最小 TTL 与首 owner (apply.go:152-186) -> 正确, 测试固定; replace-cname 原位改写保留 TTL/owner 与 refer 一致.
- 响应类动作按序全部应用, 后规则作用于前规则结果 (apply.go:46-72, TestApplyRunsEveryMatchingRuleInOrder) -> 正确; 单规则内动作互斥与 refer else-if 链一致.
- rewrite-https 仅动 type 65 记录, 逐 hint 校验丢弃非法地址, 与 refer 一致 (apply.go:214-245).
- 远程规则防御链: 仅 https, 主机白名单 EqualFold (rules.go:283-316), credentials 拒, 端口仅缺省/443, fragment 拒, URL ≤2048, ContentLength 与 LimitReader+1 双重大小校验, 重定向不跟随 (ErrUseLastResponse + 2xx 校验, rules.go:296-345), 加载失败回退内嵌, 空规则白名单 `[]/{}/{"rules":[]}` (rules.go:346-352) -> 全部与 refer loadRules 对齐, 测试固定.
- cidr 家族不交叉 (v4/v6 标志), 前缀 0-32/0-128 越界拒, 位掩码数学 (cidr.go:56-82) -> 与 refer addressInCidr 一致.
- 并发: 三包均无共享可变状态 (wire rotation 为 atomic, httpClient 只读), go test -race 通过 -> 无竞争.

---

## 结尾计数

- high: 0
- medium: 1 (ParseRelaxed 尾随字节放松, 未登记偏差)
- low: 3 (解码侧超长名接受; 负应答无 SOA 取 negMax; TTL 0 不钳制)
- info: 3 (qtype 错型放宽; host-map 字典序; CIDR 无前缀主机路由)
