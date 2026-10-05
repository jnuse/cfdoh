# Agent Note: 审查修复三裁决: 交错限段强于 refer, ParseRelaxed 豁免收编, low-info 对齐原则

Status: implemented
Scope: internal/pool/rank.go, internal/wire/parse.go, .trellis/spec

## Problem

2026-10-04 全仓审查出 37 条发现 (high 2 / medium 11 / low 15 / info 9). 其中三处无法由 "对齐 refer 或对齐 PRD" 单独定案: M4 的交错合并限段在 PRD 验收原句与 refer 行为间直接冲突; M10 的 ParseRelaxed 尾随豁免是代码已存在但 spec 未登记的解析语义分叉; 其余 low/info 缺一条统一的修/不修判准. 菜包当日拍板三条裁决, 需要持久记录理由与放弃面, 否则未来 "改齐 refer" 的清理会再次翻开同一争论.

## Decision

1. M4 交错合并同受每 /24 (v6 /48) ≤ 2 约束 — 修码补限段, pool.md 扩展规则登记 "强于 refer (refer 交错无此限), 有意强化: 防单探针垄断单 /24". PRD 验收原句为准, refer 的无限制段行为被放弃.
2. M10 ParseRelaxed 尾随豁免收编入 wire.md 防御性检查清单 — 仅上游应答四面 (upstream 校验链, resolver 刷新, ech 源域) 允许尾随字节, 入站查询与缓存存取保持严格 Parse. 不改码, spec 承认为互操作容错豁免.
3. low/info 统一判准 "对齐 refer, 除非 PRD 明文或行为更正确且登记偏差" — L4 TTL 0 属后者: PRD F-004 补 "TTL 0 的记录视为不可缓存, 不钳入区间", 行为保留; I1 qtype 错型属前者: 修齐 refer 永不匹配.

## Alternatives considered

- M4 改 PRD 验收措辞向 refer 妥协 (交错不限段) — 输掉: 限段规则是防污染核心, 单探针独占 /24 时优选多样性归零恰是该规则要防的场景; 宁强于 refer.
- M10 改码让上游应答路径走严格 Parse — 输掉: 真实上游 (含互操作容错) 存在带尾随字节的应答, 严格化会把合法应答弃掉; 登记豁免优于制造解析拒绝.
- low/info 逐条拍板不立原则 — 输掉: 24 条逐条裁决成本高且不一致; 一条判准 + 两个例外 (L4, I1) 可审计可复制.

## Consequences

- 交错路径与共识路径共用 addressBlock/maxPerBlock, 未来改限段参数只动一处; 单测 TestCombineRankingsInterleavePerBlockCap 钉住.
- wire 解析出现两种受控语义 (Parse / ParseRelaxed), 边界固定为 "上游应答四面", 新增上游应答消费点沿用 ParseRelaxed 需落在该登记面内.
- H2 同期裁决 Windows 服务安装参数保持 "run" 不改 (兼容已发布 v1.0.0/v1.1.0 服务), 入口补 "run" 分支与无参数同路径 — 属一次性兼容修复, 未单独立裁决 note.
- 三条裁决的结论真源在 spec (pool.md, wire.md, prd F-004), 本 note 只保存理由与放弃面.
