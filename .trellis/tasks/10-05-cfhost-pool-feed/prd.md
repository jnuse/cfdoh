# PRD: cfhost pool 源解析对齐 cfhub 真实格式

## Goal

修复 v1.2.0 cfhost 的 `pool:` 源解析: 解析器与 cfhub 真实端点格式完全不匹配, 公开池候选全部丢失. 修复后 cfhost 能从 cfhub 拉到全部 published 候选并参与测速选优.

## 缺陷

- 现象 (用户机器实测): `source=pool:https://cfhub.1molchuan.top/api/v1/pools#national error="pool feed: json: cannot unmarshal object into Go value of type []cfhost.poolFeedEntry"`
- 根因: internal/cfhost/sources.go 的 poolFeedEntry 期望裸数组 + 每项顶层 ipv4/ipv6 字段; cfhub 真实返回 (2026-10-05 实测) 为 `{"pools": [{"isp": "national", "family": 4, "ips": [{"ip": "172.64.145.93", "median_ms": ..., "votes": ...}], "published": true}]}` — 顶层对象包裹, IP 在 ips[].ip 嵌套.
- 对照: 服务端 internal/hubfeed/hubfeed.go 的 feedDoc/feedPool 解析同一端点是正确实现; cfhost 侧从未对过真实端点, 单测用 mock 掩盖.

## 修法

- cfhost pool 源解析对齐 hubfeed 的 feedDoc 结构 ({"pools":[{isp, family, ips:[{ip}], published}]}).
- 过滤语义保留: 只取 published 且 isp 匹配 (#<isp> 缺省 national); v4/v6 按地址本身族归类 (ips 数组混合族时逐个判定).
- 后续链路 (公网单播过滤, 去重, 上限) 不动.

## 交付项 2: http_verify 默认开启 (菜包 2026-10-05 拍板)

- 现状: HTTP 端到端验证可选且默认关闭; 默认部署下假活地址 (握手通但应用层不通) 可能被钉进 hosts.
- 变更: 默认值翻转为 true; 配置文件键 http_verify 改指针字段 (bool 零值无法区分未设与显式 false, 现有 `if fc.HTTPVerify {=true}` 只能开不能关; 参照 hysteresis 指针先例); 环境变量 CFHOST_HTTP_VERIFY 已支持显式 false, 不动.
- 措辞同步: PRD F-024 "可选开启" 改 "默认开启 (可关闭)"; spec cfhost.md 默认值同步.
- 验收: 单测钉住 默认 true / 文件显式 false 关闭 / 环境变量 false 关闭 三态.

## 交付项 3: 轮询周期默认 1 小时 (菜包 2026-10-05 拍板)

- 现状: defaultInterval = 10 分钟 (PRD F-026 "定时轮询 (默认 10 分钟, 可配)").
- 依据: 数据源 (cfhub 探针池) 1 小时刷新一版, 10 分钟轮询 5/6 无效; 降低水源与本机负载.
- 代价 (已知情): 滞回换优发现延迟最长 1 小时; 在用地址连续失效强制切换 (FailoverRounds=3) 最长 3 小时.
- 变更: defaultInterval 改 60 分钟; CFHOST_INTERVAL_MIN 钳制区间 (1min–24h) 不动; 既有钉 10 分钟默认的测试改判.
- 措辞同步: PRD F-026 与 spec cfhost.md 默认值.

## 验收标准

- [x] 单测用真实端点样例 (脱敏 fixture, 含 national + isp 池 + 未发布池) 钉住解析与过滤.
- [x] go build ./... && go vet ./... && go test -race ./... 全绿.
- [x] 真实端点手动验证: 对 cfhub run-once 拉到 >3 个候选 (修复前 domain 源仅 3 个), 无 source failed 告警. (implement 阶段实测: 8 候选, tested=8 ok=6, best_v4=172.66.0.126, hosts 正常写入)
- [x] cfhost.md 的 pool 源格式描述同步真实格式.
- [x] http_verify 默认 true; 文件显式 false 与环境变量 false 均可关闭 (三态单测); PRD F-024 与 cfhost.md 措辞同步. (check 补强: env > file > default 优先级钉住)
- [x] 轮询默认 60 分钟; 既有默认值测试改判登记 (TestLoadConfigDefaults: Interval 10min→60min, HTTPVerify false→true); PRD F-026 与 cfhost.md 同步.

## 约束

- 不改 hubfeed; 不改服务端.
- 发版 v1.2.1 由菜包拍板, 不在本任务内自动执行.
