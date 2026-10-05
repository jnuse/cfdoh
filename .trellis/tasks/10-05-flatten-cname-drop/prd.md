# PRD: 展平删除链上 CNAME, 消除非法同名并存应答

## Goal

修复 rewrite.Flatten 在 CNAME 链展平归名时保留链上 CNAME 造成的非法应答 (RFC 1034: CNAME 节点不得与其他记录类型同名并存). 实测 (菜包 2026-10-05): www.runoob.com (CF 站 + 上游应答 CNAME 首位形态) 经本服务解析后, 浏览器报 "找不到服务器 IP 地址" — Windows/Chrome 严格解析器拒收非法应答; 关闭 DoH 后同站可访问, 确认根因在本服务产物.

## 缺陷

- internal/rewrite/rewrite.go Flatten: Answers[0] 为 qname-owned CNAME 时, 其后非 CNAME 记录归名到 qname, 但**链上 CNAME (含首条) 保留**.
- 产物: `qname CNAME xxx` + `qname A 172.64.x` 同名并存 — RFC 非法, 严格解析器拒收.
- 触发面: 所有 "CF 站点 + 上游应答 CNAME 首位" 形态 (改写路径主流形态); 上游已预展平 (A 直接挂 qname) 的域不受影响 (菜包自己的站即此形态, 可正常访问).
- 历史注记: 全仓审查 D 报告 I7 曾登记 "链上 CNAME 记录保留 (refer 删除)" 并判断 "主流应答形态结果等价" — 该判断错误, 本次推翻.

## 修法

- Flatten 归名时**删除链上全部 CNAME 记录** (对齐 refer flattenAliases 与 Cloudflare 权威侧 CNAME Flattening 语义: 对外应答链消失, 记录直接挂查询名).
- 客户端影响: 零损失 (浏览器透明跟随链, 拍平后少一跳); Chromium ECH 判定所需的同名条件不变.
- rewrite.md 展平边界描述同步改判: "链上 CNAME 记录保留" → "展平删除链上 CNAME (对齐 refer 与 Cloudflare CNAME Flattening)".

## 交付项 2: 同族残留一并消除 (菜包 2026-10-05 拍板)

- 缺陷: 钉住补造场景 — PinAddresses 对全 CNAME 无 A 的上游应答在 qname 下补造 A 后, qname CNAME 与补造 A 同名并存 (同族非法产物, 修复前即有).
- 修法: Flatten 的删除条件从 "归名发生" 扩为 "存在 qname-owned CNAME 且应答含 qname-owned 非 CNAME 记录时删除该 CNAME" (消除并存的通用判定, 不依赖归名路径).
- 同步: rewrite.md 边界句 "无归名对象时保持原样" 改为并存判定描述; 单测覆盖钉住补造后无 CNAME 残留.

## 验收标准

- [x] Go 单测: CNAME 首位形态展平后应答仅含归名记录, 无 CNAME 残留; 非 CNAME 首位形态与不触发形态行为不变.
- [x] 既有钉住 "CNAME 保留" 的测试改判 (chain records move / multi-hop chain 两个子测试改判, check overlay 探针实证旧代码下红).
- [x] go build ./... && go vet ./... && go test -race ./... 全绿.
- [x] acceptance f009/f010/f012/f014 相关模块全绿 (17 例).
- [x] rewrite.md 登记句更新 (含交付项 2 并存判定描述).
- [x] 交付项 2: 钉住补造场景并存消除; coexist 判定单测钉住; PinAddresses 补造顺序确认门控可达.

## 约束

- 不动改写链其余步骤 (改写/钉住/ECH 注入顺序与语义不变).
- 与 v1.2.2 (hosts 写韧性) 同批发版, 发版由菜包拍板.
