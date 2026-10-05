# Journal - jnuse (Part 1)

> AI development session journal
> Started: 2026-10-02

---



## Session 1: cfdoh 批 4-6 实现与交付收口

**Date**: 2026-10-04
**Task**: cfdoh 批 4-6 实现与交付收口
**Branch**: `main`

### Summary

完成批 4 后半至批 6: httpapi (DoH 校验链, 双令牌 admin, explain 含缓存态与 type 过滤), cmd/cfdoh (信号, 快照编排, 后台调度), cfhost 全量 (四形态候选源, TLS 测速, 滞回, hosts 区块, Windows 服务抽象), 交付资产 (Dockerfile, compose, CI/release, systemd 单元, README). e2e 经代理真实上游全链路通过 (health/DoH 三类型/explain/快照/重启恢复), cfhost run-once 实测通过. 复验修正: 根 target 判定, stale 轮转, 改写门控池提升 (记 note), admin ttl 缺省对齐 refer, GET 超包 413, cfhost 入口落穿. cdd 术语回填 14 处并新增服务端 HTTP 面组; systemd 单元登记 build-release; 派遣纪律 note 落盘.

### Git Commits

| Hash | Message |
|------|---------|
| `0283aa3` | (see git log) |
| `e80c4a6` | (see git log) |
| `12bc288` | (see git log) |
| `46161c8` | (see git log) |
| `4be2b87` | (see git log) |
| `61faaed` | (see git log) |

### Status

[OK] **Completed**


## Session 2: acceptance-py 验收套件批 3-6 与任务收口

**Date**: 2026-10-04
**Task**: 10-04-acceptance-py
**Branch**: `main`

### Summary

验收套件批 3-6 落地: 池与改写 54 例 (含 6 根因修复: 缓存存改写后包, ParseRelaxed 上游面, applyRewriteChain 丢结果, rules 扁平简写, metaEch selfcheck 通道, pool ContentTag), 上游与生命周期 24 例, cfhost 进程级 11 例, 静态交付 4 例, live 层 7 例吸收并删除 e2e.sh. 127 例全绿 (~375s), live 代理双 scheme 实跑通过. 裁决一次: f026 周期用例走最小可表达周期 (方案 B, note 已 implemented). spec 回填: config.md 环境变量对照表 (唯一真源), pool/cache/resolver/cdd 登记 ContentTag 变体. CI 挂 acceptance 步 + 低端口 sysctl 前置. 遗留后续任务: cfhost 钳制区间补 spec; metaEch rotated 非法 base64 分歧 (400+清种子, 已登记 httpapi.md) 待菜包复核认可.

### Git Commits

| Hash | Message |
|------|---------|
| `9678061` | fix: defects surfaced by pool/rewrite acceptance run |
| `f4a59f5` | impl: pool and rewrite acceptance cases (batch 3) |
| `34b9520` | impl: upstream and lifecycle acceptance cases (batch 4) |
| `907bb33` | impl: cfhost acceptance cases (batch 5) |
| `a647dde` | impl: delivery static checks, live layer, ci acceptance step (batch 6) |
| `885750f` | spec: env var reference table, pool content tag in cache variant |

### Status

[OK] **Completed**

---

## Session 3: 全仓审查修复 37 条五批收口

**Date**: 2026-10-05
**Task**: 10-04-review-fixes
**Branch**: `main`

### Summary

37 条审查发现五批全修: H1/H2 (admin health nil 契约 + Windows 服务 run 入口), M1-M11 (ContentTag 键排序, ech 缓存上限 256, Status 锁内复查, 交错限段, isp mapped CIDR, ECS 回退, classify 门控 X, PinAddresses 回退补造, 逐记录网段过滤, ParseRelaxed 登记收编, cfhost 域名规范化), L1-L15, I1-I9 (修齐或登记). 三条裁决落 spec + note: 交错限段强于 refer (M4), ParseRelaxed 仅上游四面豁免 (M10), low-info 对齐原则 (L4 登记偏差). 改判登记 3 处 (批 1 state_test 空态断言, 批 3 rewrite_test 两处旧缺陷钉子), 根因修复 1 处 (M4 限段暴露 resolver 测试学习池顺序污染 → ResetLearnedPoolsForTesting). 每批 trellis-implement → 主会话复验 → trellis-check 复核 → 勾选 → commit. 终态: go 三连 -race 绿, acceptance 127 例全绿, verify_spec 32 文档合规, notes verify 7 条过.

### Git Commits

| Hash | Message |
|------|---------|
| `16ee173` | fix: admin health nil contract and windows service run entry (batch 1) |
| `6505492` | fix: content tag ordering, ech cache cap, status race, isp and ecs fallbacks (batch 2) |
| `e5fd2e0` | fix: classify-gated x rewrite, pin fallback synthesis, per-record filtering (batch 3) |
| `5465224` | fix: cfhost domain normalization, lock, rotation, loop and redirect hardening (batch 4) |
| `37e3852` | fix: interleave block cap, wire name limits, negative ttl, rules and alias hardening with spec registrations (batch 5) |

### Status

[OK] **Completed**

---

## Session 4: cfhost pool 源格式修复与默认值调整

**Date**: 2026-10-05
**Task**: 10-05-cfhost-pool-feed
**Branch**: `main`

### Summary

菜包机器实测发现 v1.2.0 cfhost pool 源对 cfhub 真实格式完全不匹配 ({"pools":[{isp,family,ips:[{ip}],published}]} vs 假想的裸数组+顶层 ipv4/ipv6), 公开池候选全部丢失. 修复: 解析对齐 hubfeed 同构 feedDoc, 过滤语义保留, 真实格式脱敏 fixture 钉住, 真实端点实测 8 候选. 同任务两默认值拍板变更: http_verify 默认开 (文件键改 *bool 指针支持显式关, env>file>default 优先级钉住), 轮询默认 10min→60min (对齐 cfhub 探针 1h 出数节奏, 代价: 滞回发现延迟最长 1h, 失效强制切换最长 3h). PRD F-024/F-026 与 cfhost.md 同步. 待菜包拍板发 v1.2.1.

### Git Commits

| Hash | Message |
|------|---------|
| `7e7366a` | fix: cfhost pool feed format, default http verify and hourly interval |
| `f2b3730` | chore(task): archive 10-05-cfhost-pool-feed |

### Status

[OK] **Completed**

---

## Session 5: cfhost hosts 写入韧性 (TEMP 优先 + rename 重试)

**Date**: 2026-10-05
**Task**: 10-05-cfhost-hosts-write
**Branch**: `main`

### Summary

菜包机器实测发现 Windows 杀软 (Defender/火绒过滤驱动) 对 System32\drivers\etc 目录新建文件的扫描句柄与 cfhost 毫秒级 CreateTemp→rename 竞态, rename 稳定 Access denied; 且写失败传播为致命错误导致 RunLoop 退出, 服务当日被杀两次 (SCM 无恢复, 永久停摆). 菜包拍板: tmp 优先写系统 TEMP 少过 etc 杀软闸 (知知原方案同目录+重试被推翻); 知知补工程配套: 跨卷回退同目录保原子性, rename 锁类错误 200ms×5 退避重试, 耗尽按本轮跳过守护不死. check 抓出 syscall.ERROR_SHARING_VIOLATION 不存在的交叉编译错误 (改 x/sys/windows), 补 GOOS=windows 构建进验证. spec cfhost.md 与 PRD F-025 同步. 待菜包发 v1.2.2.

### Git Commits

| Hash | Message |
|------|---------|
| `5bc84c2` | fix: cfhost hosts write resilience with temp-first staging and rename retry |
| `2b28644` | chore(task): archive 10-05-cfhost-hosts-write |

### Status

[OK] **Completed**
