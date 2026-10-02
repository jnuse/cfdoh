---
name: agent-notes
owner: Jnuse
description: 当做出或推翻影响代码库的持久决策、需要记录决策理由、回答"这段代码为什么是这样"、新 Agent Note 触发取代审计、或判定旧 note 归档与删除时使用。
---

# Agent Notes 写入与检索

Agent Notes 是决策记录: 为什么, 与放弃了什么. 树在 `.trellis/notes/`, 契约在 `.trellis/notes/README.md`, 工具是 `.trellis/scripts/notes.py`. 所有操作走 CLI, 不手写文件, 不手工移动目录.

## 写入

触发有两类, 缺一不可:

- **语义触发**: 本次变更包含代码, 测试与现有文档解释不了的持久决策理由 (架构, 行为语义, 流程, 取舍). 机械性局部改动豁免.
- **流程触发 (必经, 不靠自觉)**: 三重锚点 — 即时询问 (决策产生当回合由 workflow-state 面包屑触发, 一次性询问是否落盘, 可推迟), 任务收口 (workflow 3.3 Knowledge capture 的 notes 侧) 与会话收口 (`/trellis-finish-work` 的 session decision sweep). 即时落盘的在途决策建 `proposed/`, 收口锚点负责生命周期迁移; 两个收口锚点列出本次全部裁决, 逐条判断是否已记录, 缺则补录.

**跨仓协作**: 决策发生地与 notes 树不在同一仓库时 (会话在 A 仓, 决策属于 B 仓), 直接调用 B 仓的 `notes.py create` 回填 — CLI 是脚本, 不依赖本 skill 被会话加载.

流程:

1. **先查拥有者**: `notes.py search <主题词>` — 已有 note 拥有该决策时更新它, 不建重复. 已归档的旧 note 不算拥有者.
2. **脚手架**: `notes.py create <lifecycle> <class> <标题> --scope <逗号分隔路径>`; 直接否决的提案用 `create rejected ... --reason "<一句话理由>"`.
3. **填骨架**: 替换全部 `<!-- 提示 -->`; `## Problem` 独立成立; `## Alternatives considered` 只记真实候选与输掉原因 — 没有对手记录的决策邀请翻案.
4. **Supersession 审计**: 每条新 note 必触发 — 搜活动树中覆盖同一决策/机制的旧 note; 完全取代的 implemented note 同变更归档, 部分取代的保留并交叉链接 (相对 markdown 链接).
5. **门禁**: 收尾前 `notes.py verify` 必须通过.

## 检索

- 回答 "这个模块/文件为什么是这样" → `notes.py history <路径>` (Scope 前缀双向匹配, 按日期排出决策史, 含 rejected 与 archived).
- 浏览某类决策 → `notes.py list --lifecycle <L> --class <C>`.
- 单条全貌 → `notes.py show <文件名前缀>`; 全文找词 → `notes.py search <词>`.
- archived 命中是冻结历史, 不是当前权威; 当前权威是 implemented 树.

## 生命周期迁移

- 提案上线: `notes.py move <note> implemented`, 按 CLI 提示完成机械重写 (Proposal → 现在时 Decision, Acceptance criteria/Risks 折入 Consequences), verify 过才算完成.
- 提案否决: `notes.py move <note> rejected --reason "<理由>"` — 冻结, 不改正文.
- 决策完结且理由不再指导未来工作: `notes.py move <note> archived` — 封存写 manifest, CLI 报告的入站链接同变更修复.

## 判据

- 归档与否看**未来决策价值**, 不看字数, 年龄, 配额: 候选方案, 所有权边界, 否定性保证, 线上语义, 安全规则, 重新引入条件仍 useful 就保持活动.
- rejected 只在其理由仍能阻止一个可信的实质性错误时保留, 否则整条删除.
- note 永不编辑成另一个决策 — 用新 note 取代并交叉链接; 完全取代可合并删除, 但须保留全部独特理由, 且不得依赖 git 历史作为理由的唯一副本.

## 禁止

- 不绕过 CLI 手写 note 文件或手工移动目录 (门禁会拦, 但别制造噪音).
- 不编辑, 重排版, "更新" 任何 archived 文件.
- 不创建任何 INDEX / 汇总 / 派生索引文件 — 树即库存, 搜索即发现.
