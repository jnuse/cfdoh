# 审查报告 B: upstream + cache + cfrange + isp

## 头部

- 组名: B (upstream / cache / cfrange / isp)
- 审查文件 (全文精读):
  - internal/upstream/upstream.go
  - internal/cache/cache.go
  - internal/cfrange/cfrange.go
  - internal/isp/isp.go
- 佐证阅读 (交叉核对, 非本组): internal/config/config.go, internal/wire/misc.go, internal/wire/parse.go (节选), internal/ecs/ecs.go, internal/resolver/resolver.go (消费点), internal/pool/pool.go (消费点), cmd/cfdoh/main.go (快照与每日刷新接线), refer/edge-smart-doh/src/upstream.ts (行为基线), 四个对应 *_test.go, Go 标准库 net/netip 源码 (PrefixFrom/Masked/ParsePrefix 行为确认).
- spec 依据: .trellis/spec/arch/upstream.md, cache.md, cfrange.md, isp.md, config.md (环境变量对照表), .trellis/spec/prd/requirements.md F-003/F-004/F-006/F-009.
- 运行命令与结果:
  - `go vet ./internal/upstream/ ./internal/cache/ ./internal/cfrange/ ./internal/isp/` → 通过, 无输出.
  - `go test -race ./internal/upstream/ ./internal/cache/ ./internal/cfrange/ ./internal/isp/` → 全部 ok (upstream 1.276s, cache 1.014s, cfrange 1.013s, isp 1.246s).

## Findings

### 1. [medium] internal/isp/isp.go:213 — IPv4-mapped CIDR (bits>32) 经 Unmap 后产生零值 Prefix, 一行即污染整个 v6 区间表

代码原文:
```go
prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()).Masked()
```

违反 spec 原句: isp.md "运营商名白名单校验, 保留名 national 禁用, 非法行静默跳过", "v4 与 v6 独立查找结构; 同地址命中多网段取最长前缀 (嵌套取最精确)"; F-006 "非法行静默跳过".

失败模式: 表源 (ISP_TABLE_URL 指向端点被投毒, 合并器缺陷或传输损坏) 输出一行如 `foo ::ffff:1.2.3.0/120`. netip.ParsePrefix 接受它 (16 字节地址, 120 ≤ 128); Unmap 后 PrefixFrom(v4 地址, 120) 因 120 > 32 构造出无效前缀 (Bits() 返回 -1), Masked() 内部调用 ip.Prefix(-1) 返回错误被忽略, 整体得到零值 Prefix. 随后 start = 零地址 (Is4() 为 false, 条目落入 v6 表), lastAddress 的 hostBits = 128-(-1) = 129, 16 字节全部置 1, end = ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff (isp.go:304-311). 该行变成覆盖整个 IPv6 空间的区间: 所有未被真实网段 (更精确, 查找时仍优先) 覆盖的 IPv6 客户端都被赋予 scope isp:foo 而非回落全国层, 造成错池选择与缓存 variant 污染. 本应按 "非法行静默跳过" 丢弃. 已对照 Go 1.26 标准库源码确认 PrefixFrom/Masked/ParsePrefix 的每一步行为; 测试 TestParseTableValidation 未覆盖 mapped CIDR, 属真实盲区.

最小修复: Unmap 后校验 prefix.IsValid() (等价 bits ≤ Addr().BitLen()), 无效即 continue.

### 2. [medium] internal/config/config.go:160 — ECS_UPSTREAMS 未设置时回退到内置默认三元组, 不跟随 UPSTREAMS (跨模块发现, 直接影响本组 upstream 的 ECS 路由不变量与 config.md 对照表核对项)

代码原文:
```go
cfg.EcsUpstreams = httpsOnly(src.strList("ECS_UPSTREAMS", defaultUpstreams))
```

违反 spec 原句: config.md 环境变量对照表 "| ECS_UPSTREAMS | ECS 查询走的上游 | 同 UPSTREAMS | 同上 |"; upstream.md "携带 ECS 的查询路由到 ECS 上游列表, 其余走普通列表".

失败模式: 运维仅配置 UPSTREAMS=自有转发上游, 未设 ECS_UPSTREAMS. 默认 ECS_MODE=rules 下全部 .cn 域名查询携带 ECS, 经 upstream.Query (upstream.go:50-53) 路由到 EcsUpstreams = cloudflare/google/quad9 内置默认, 而非运维配置的自有上游 — 与 "同 UPSTREAMS" 的回退合同相反, 携带客户端子网的查询向第三方公共上游泄露. notes 与测试均未登记此为有意分歧.

最小修复: 回退值改取解析后的 UPSTREAMS (原始串或 cfg.Upstreams 重组).

### 3. [low] internal/cache/cache.go:303 — SaveSnapshot 无并发自保护, 定时保存与退出保存重叠时交错写同一 tmp 路径可损坏快照

代码原文:
```go
tmp := path + ".tmp"
if err := os.WriteFile(tmp, data, 0o600); err != nil {
```

违反 spec 原句: cache.md "快照定时与退出时写 (临时文件加原子改名), 启动回读未过期条目"; F-004 "CACHE_PERSIST_PATH 设置时定期与退出时快照落盘 (临时文件 + 原子改名)".

失败模式: SIGTERM 恰好落在每 10 分钟一次的定时快照 (cmd/cfdoh/main.go:91-95) 写入尚未结束时, 退出路径 (main.go:104-109) 立即再次 SaveSnapshot, 两条路径无互斥. 两个保存各持独立 fd 写同一 tmp: 第二次 O_TRUNC 截断文件而首个 fd 偏移不受影响, 最终内容为两份 JSON 交错混写; rename 落盘的是损坏文件, 且第二个 rename 因 tmp 已被移走而报错. 下次启动 LoadSnapshot 判 corrupt 拒载, 缓存冷启动 (不崩溃, 仅丢失缓存与探针态恢复延迟). 触发窗口为快照写入时长 (毫秒级), 概率低但确定可达.

最小修复: 模块内为保存路径加一把互斥锁 (或 tmp 文件名带唯一后缀).

## 已核对无问题

- 对冲语义 (间隔内无结果启动下一个: upstream.go:107; 单上游失败立即启动下一个: upstream.go:138-143; 首个合法应答 CAS 胜出: upstream.go:130-133; 返回即 cancel 中止全部在飞: upstream.go:75-76) 与 upstream.md 一致; 失败触发的启动不清除在制定时器导致后续上游略提前的语义与 refer/edge-smart-doh/src/upstream.ts:68 逐句相同, 属基线行为, 非偏差.
- 全部失败报错并记 upstream_failure 事件, detail 为错误链摘要 (upstream.go:147-150, 165-168), 符合事件目录.
- 应答校验链五项齐备且顺序不削弱: HTTP 2xx (upstream.go:199), Content-Type 去参数+大小写不敏感 (upstream.go:200-206), 大小 ≤ MaxDNSPacketSize (LimitReader+1 边界正确, upstream.go:207-212), QR 位置位 (upstream.go:218), 事务 ID 一致 (upstream.go:220).
- 空上游/空 ECS 上游列表直接失败 (upstream.go:49-54); ECS 查询独立路由 EcsUpstreams (upstream.go:50-53).
- singleflight 合并: 键为 ID 归零后报文 sha256 + ecs 标志 (upstream.go:63-66), 共享交换不随单一调用方取消中断 (WithoutCancel); hedge 内 next/pending/errs 全程持锁, settled 原子, failure 单发送者, 无锁序与双发问题.
- ResolveAddresses 直接调 Query, 不经过应答缓存 (upstream.go 全文无 cache 引用); A/AAAA 双族并发对冲, 单族失败容忍, 双族失败才报错 (upstream.go:238-246).
- 超时与对冲参数只从 config 读入, 模块内无默认值 (upstream.go:101, 107); httpClient 拒绝跟随重定向, 重定向表现为非 2xx 失败 (upstream.go:37-41).
- SERVFAIL 不入缓存: Put 经 wire.ResponseTTL, rcode 2 返回 0 即拒存 (cache.go:183-186; wire/misc.go:103-105).
- TTL 语义: answers 非 OPT 最小值; 负应答 (NXDOMAIN 或空 answer) 取 min(SOA ttl, SOA minimum, NEGATIVE_CACHE_MAX_TTL); 最终钳制 [CACHE_MIN_TTL, CACHE_MAX_TTL], 非正值不缓存 (wire/misc.go:98-137), 与 cache.md/F-004 一致.
- 键两段构成: 规范化名|类型|类|DO|CD|ECS 身份串|variant, 恰好 1 question 才建键 (cache.go:64-88).
- 状态判定: 预取换算 remaining(ms) ≤ origTTL(s)×percent×10 数学正确 (cache.go:136-138); stale 窗口含边界, 窗口外删除; stale 命中 TTL 写 30 且跳过 OPT (withTTL, cache.go:246-260); 预取比例与过期窗口读时经 cfg 传入 (Get 签名).
- 缓存读写无别名竞争: Get 返回副本, Put 以新 entry 整体替换, 存储后 packet 不可变 (cache.go:122, 132-134, 185-196); 分片锁独立, 无跨锁顺序.
- LRU 容量钳 128–65536 (cache.go:60-70); 超限逐最早插入条目.
- 快照: 临时文件+原子改名 (cache.go:303-310); 带版本号, 未知版本拒读 (cache.go:337-340); 只回读未过期条目且尊重容量 (cache.go:342-360); 缺文件非错误 (cache.go:325-330).
- 快照不含客户端 IP: 快照仅存键/过期时刻/原 TTL/base64 体; 键中 ECS 段为截断前缀 (如 1.2.3.0/24, ecs.go:43,56), 非完整 IP, 与 cache.md "身份含 ECS 身份串" 的登记设计一致.
- cfrange: 双列表均成功才 atomic 换入 (cfrange.go:50-57); 任一失败返回错误且不动旧表, 每日调度沿用旧表 (main.go:85-89); Contains 纯函数, Unmap 处理 mapped 地址, nil 表安全; 1MiB 读取上限, 前缀去重, 全畸形列表视为失败 (cfrange.go:99-102).
- isp: 运营商名正则 ^[a-z][a-z0-9-]{1,23}$ 且 national 禁用 (isp.go:31, 207-210); 表 ≤ 4MiB (isp.go:163-166); 0 有效条目视为加载失败 (isp.go:226-228); 内容不变不重建 (原文比较, isp.go:170-174); 失败 60 秒退避对首载与旧表服务期均适用, 期间旧表继续服务 (isp.go:101-117); 识别永不阻塞查询 — 网络与解析在锁外执行, 查询仅短暂持锁, 首载后台进行未命中回落 (isp.go:69-91, 120-140); 嵌套最长前缀经 "排序区间表+单调栈父指针+二分回溯" 实现, 构造与查询逻辑均验证正确, 三层嵌套已被测试钉住.
- 钳制区间与 config.md 对照表逐行一致: UPSTREAM_TIMEOUT_MS 250–15000, UPSTREAM_HEDGE_MS 0–5000, CACHE_MIN_TTL 0–3600, CACHE_MAX_TTL 1–86400, NEGATIVE_CACHE_MAX_TTL 0–3600, CACHE_STALE_TTL 0–604800, CACHE_PREFETCH_PERCENT 0–90, CACHE_MAX_ENTRIES 128–65536, MAX_DNS_PACKET_SIZE 512–65535, CF_IPV4_URL/CF_IPV6_URL 默认官方端点, ISP_TABLE_URL 空=关闭 (config.go:147-161, 178, 182-184, 204).
- ResolveAddresses 返回 (空, 空, nil) 的语义 (上游合法 SERVFAIL/空应答): pool.mergedDomainPool 将其计为该域名失败 (pool.go:333-339), 与 F-007 "全部失败才报错" 兼容, 未发现可触发缺陷.

## 计数

- high: 0
- medium: 2
- low: 1
- info: 0
