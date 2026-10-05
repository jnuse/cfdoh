# PRD: 审查修复

## Goal

收口全仓代码审查 (review/ 目录 6 份报告, high 2 / medium 11 / low 15 / info 9): high 与 medium 全修, low 按 "对齐 refer 除非 PRD 明文" 原则修齐, info 以 spec 登记为主 (有安全/语义风险的修齐 refer). 行为变更同步 spec 与测试.

## 裁决 (菜包 2026-10-04 拍板)

1. M4 交错合并每 /24 ≤2: 对齐 PRD 补产品限段, spec 登记强于 refer 的防污染分歧.
2. M10 ParseRelaxed 尾随豁免: wire.md 收编登记 (仅上游应答四面, 入向与缓存保持严格).
3. low/info 原则: 对齐 refer, 除非 PRD 明文或行为更正确且登记偏差 (L4 TTL 0 属此类: 登记 PRD "TTL 0 视为不可缓存").

## 逐条清单 (编号为任务内统一 ID; 细节真源 = review/ 对应报告)

### High (2) — 全修
| ID | 报告 | 位置 | 问题 |
|---|---|---|---|
| H1 | E1 | httpapi.go:975 | /admin/health 解引用 nil 状态, 默认部署必 panic; TestAdminHealth 单跑即红 |
| H2 | F1 | service_windows.go:44 | 服务安装传 "run" 子命令, 入口无此分支 → Windows 服务自启 exit 2 |

### Medium (11) — 全修
| ID | 报告 | 位置 | 问题 |
|---|---|---|---|
| M1 | C1 | hubfeed.go:133 等 | 多 scope map 迭代序使相同内容周期刷新翻转 ContentTag, 全量缓存被冲刷 |
| M2 | C2 | ech.go:68 | publish 缓存无上限, ?ech= 唯一域可无界灌入 (每条 ≤16KiB) |
| M3 | C3 | ech.go:230 | Status() 锁窗口内 meta 可被置 nil → panic |
| M4 | C4 | rank.go:130 | 交错合并无每 /24 ≤2 (对齐 PRD, 裁决 1) |
| M5 | B1 | isp.go:213 | mapped CIDR Unmap 产生 bits=-1, 单行污染全 v6 区间表 |
| M6 | B2 | config.go:160 | ECS_UPSTREAMS 未设回退内置三元组而非 UPSTREAMS, 隐私泄露面 |
| M7 | D1 | rewrite.go:129 | X 改写缺 <域名>.cdn.cloudflare.net 探测, CNAME setup 的 X 域名永不改写 |
| M8 | D2 | rewrite.go:186 | PinAddresses 无 qname-owned A 即整体放行, 站点池/GitHub 池被 CNAME 链架空 |
| M9 | D3 | rewrite.go:104 | 整包级网段门控 + 整族替换, 混合应答的非 CF 地址被换成 CF 池 |
| M10 | A1 | parse.go:66 | ParseRelaxed 尾随豁免未登记 (裁决 2: spec 收编) |
| M11 | F2 | cfhost/config.go:234 | 域名校验用 trim 副本存储留原始串, 带空白域名静默失效 |

### Low (15) — 按原则修
| ID | 报告 | 方向 |
|---|---|---|
| L1 | B3 | cache 快照双写加互斥 (锁或唯一 tmp 名) |
| L2 | A2 | decodeName 补 255/label 数上限 (对齐 refer) |
| L3 | A3 | 无 SOA 负应答返回 0 不缓存 (对齐 refer) |
| L4 | A4 | TTL 0 不钳制: 登记偏差到 PRD F-004 (TTL 0 视为不可缓存), 行为保留 |
| L5 | C5 | LearnedStatus 只列未过期 source (对齐 refer) |
| L6 | D4 | store 路径补发 cache_write_error 事件 |
| L7 | D5 | DropAAAA 同步移除 ipv6hint (对齐 refer) |
| L8 | E2 | Accept 按逗号项 startsWith 判定, */* 精确匹配 (对齐 refer) |
| L9 | E3 | PATH_ALIASES 注册前查重, 冲突告警跳过 |
| L10 | E4 | 配置文件单行上限提至 4MiB |
| L11 | F3 | 单实例锁 O_CREATE+O_EXCL 原子创建 |
| L12 | F4 | status 配置加载失败时单独读 CFHOST_STATE_PATH |
| L13 | F5 | 日志轮转在写入路径触发, 常驻期间生效 |
| L14 | F6 | 状态落盘失败时兜底休眠 Interval, 轮询不坍缩 |
| L15 | F7 | hosts 读瞬时错误按本轮跳过处理, 不终止守护 |

### Info (9) — 登记为主
| ID | 报告 | 方向 |
|---|---|---|
| I1 | A5 | qtype 错型: 修齐 refer (错型条件永不匹配, 消除 block 扩大风险) |
| I2 | A6 | host-map 字典序: 登记保留 (确定性选择) |
| I3 | A7 | CIDR 无前缀视 /32: 登记保留 (无风险放宽) |
| I4 | C6 | 零地址优选域名计失败: 登记边界 |
| I5 | C7 | h3 溢出字典序截断: 登记保留 |
| I6 | D-I6 | 判定地址规则后采样: 登记为有意 (原始 = 规则后改写前) |
| I7 | D-I7 | Flatten 四处差异 + v6 hint 保留: 登记边界描述 |
| I8 | E5 | ttl 0 当缺省: 登记 (int 无法区分, 接受现状) |
| I9 | F8 | cfhost 远程源 CheckRedirect 拒绝降级 https→http (PRD F-023 明文 https) |

## Acceptance Criteria

- [x] H1/H2 修复且各有回归测试: TestAdminHealth 单跑绿 (无顺序依赖); 服务模式可经 "run" 参数进入
- [x] 11 条 medium 全修, 每条有 Go 单测钉住修复行为
- [x] 15 条 low 按方向修齐; L4 与 info 类登记落入对应 spec (wire.md, rewrite.md, rules.md, pool.md, h3.md, httpapi.md, config.md, cfhost.md, prd F-004)
- [x] 与修复冲突的既有测试改判并说明 (逐条在 implement.md 勾选时登记)
- [x] go build ./... && go vet ./... && go test -race ./... 全绿
- [x] python3 -m unittest discover -s test/acceptance 127 例全绿 (用例与修复冲突时修用例并登记, 语义以修复后 spec 为准)
- [x] M4/M10 裁决落 spec: pool.md 登记限段强于 refer; wire.md 收编 ParseRelaxed 豁免

## Constraints

- 不改 acceptance 套件用例语义, 除非与修复行为冲突 (冲突时修用例并在勾选行登记理由).
- 修复不改既有正常路径行为语义 (除报告指出的缺陷路径).
- 每批一 commit, 批内回退到批首.
