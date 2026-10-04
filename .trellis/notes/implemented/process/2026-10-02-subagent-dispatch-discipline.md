# Agent Note: subagent dispatch discipline

Status: implemented
Scope: .trellis/tasks/archive/2026-10/10-02-cfdoh-impl, implement.jsonl

## Problem

本仓库的实现任务按 Trellis 流程经 pi subagent 派遣 trellis-implement / trellis-check. 批 1-3 期间子代理多次零输出失败 (根因: 继承父会话模型 + thinking high, 动笔轮 thinking 全量推演撞输出上限 stopReason=length); 且大块派遣 (多包一批) 在 5 小时限流处中断, 产出不可控.

## Decision

派遣纪律五条, 主会话执行:

1. 单次派遣交付物要小: 一次一个包 (或一个可独立验证的文件组); 批次清单仅作进度参照.
2. 派遣前重写 implement.jsonl 为当批条目 — 子代理读全 jsonl 且被 trellis 扩展注入, 旧条目会污染上下文.
3. prompt 固定结构: Active task 首行 → 递归禁令 → 执行纪律 (限定读取面, 读完即写) → 交付物路径级 → 读取面 → 钉死语义 (浓缩到可逐条核对) → 测试要求 → 约束 (禁 .trellis 写, 禁 git, 禁 refer/, 仅允许依赖, 签名逐字) → 交付格式 (质量门完整输出 + 偏离清单).
4. 子代理返回后主会话必复验: fresh 跑 go build/vet/test, grep 签名对照 arch, 抽检关键语义; 自报不可信.
5. 失败处理: 一句话终止/截断 → 先读扩展 debug 日志 (~/.pi/agent/extensions/pi-subagents/logs/debug.jsonl) 再决定; 连续两次失败 → 缩小任务重派.

## Alternatives considered

- 主会话直写全部实现: 输给并行度与上下文经济 — 主会话保留复验与决策, 体力活下放.
- 拆小任务解决零输出: 已证伪 (最小任务照爆, 根因在输出上限不在任务体量); 用户侧调大 maxTokens 后配合本纪律一次通过.
- 降低 thinking 档位省 token: 被否决, 影响实现质量.

## Consequences

- 批 2-5 的 8 次派遣全部一次或缩小一次通过; 复验抓住过真实缺陷 (stale 不轮转, 改写门控缺失, cmd 落穿), 证明自报不可信的假设成立.
- 纪律的成本是 prompt 组装时间与复验时间; 对单包小改动净收益为负时, 主会话直做 (cfhost.md 语义钉死与批 6 交付资产即如此处理).
