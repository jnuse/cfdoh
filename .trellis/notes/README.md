# Agent Notes

一种设计文档住在这里. **Agent Note** 记录影响本代码库的决策或提案 — *为什么* 与 *放弃了什么*, 代码， 测试与普通文档装不下的部分. 本文件定义 Agent Notes 住在哪， 何时写一条， 以及文件内格式. 增删改查与校验统一走 CLI:

```bash
python3 .trellis/scripts/notes.py <command>   # create / list / show / search / history / move / verify
```

## 布局与命名

每条 Agent Note 有两个轴， 都编码在**路径**里 — `{lifecycle}/{class}/yyyy-mm-dd-topic-title.md`:

- **Lifecycle** (顶层目录) 是 note 的状态， 状态改变 = 移动目录:
  - `proposed/` — 尚未实施的提案 (或只建了一部分).
  - `implemented/` — 决策已上线. 文件记录决定了什么， 否决了什么， 并**与实际发布保持同步**： 代码后来移动了文件， 改了包名， 换了默认值时， 同一变更内更新该 note 以匹配 (只跟事实 — 路径， 名字， 结构 — 不改决策本身).
  - `rejected/` — 提案被考虑后否决. 只在其理由仍能阻止一个诱人的实质性错误时保留； 否则整条删除.
  - `archived/` — 低未来决策价值的 implemented note 的冻结快照, 只进不改.
- **Class** (嵌套目录) 是决策的种类， 见 [分类](#分类).

文件名里的日期是议题**首次提出**的日期; 生命周期迁移不改文件名. git 记其余一切， Status 行不带日期.

note 之间的交叉引用用相对 markdown 链接 (`[topic](../implemented/architecture/2026-….md)`), 不用裸文字或编号 — 链接可被机械校验， 且迁移目录后可修复.

活动树就是工作库存： 翻目录或跑 `list` / `search` / `history`. **不建中央 `INDEX.md`** — 生成索引是维护负担, 树 + 搜索已覆盖发现需求.

## 分类

每条 note 属于一个路径编码的 class, 封闭集如下； 门禁拒绝其他目录. 新增一个 class 是刻意行为： 同时改 CLI 里的集合与本表.

| Class | 覆盖范围 |
|---|---|
| `feature` | 新的用户或模型可感知的能力. |
| `bug-fix` | 修正缺陷, 或关闭 postmortem 暴露的缺口. |
| `simplification` | 删代码， 删行为， 删表面积， 不加能力. |
| `architecture` | 关于**交付源码**的结构决策 — 包如何关联， 运行时词汇是什么. |
| `process` | 代码**周边**的工具， 策略与流程 — 门禁， 包管理器 — 不是运行时行为. |
| `testing` | 测试基础设施与策略. |

`architecture` / `process` 分界： architecture 关于交付的源码； process 关于周边的工具与流程. (`refactor` 刻意缺席 — 它与 simplification 重叠， 后者的判别式 “可观测行为变了吗” 已覆盖.)

## Scope 字段

头块的 `Scope:` 行声明本 note 管辖的代码路径 — 逗号分隔的仓库根相对路径， 正斜杠. **必填**： 写作时强迫想清影响面; 纯流程决策写最贴近的目录 (如 `.trellis/`).

- 查询: `notes.py history <路径>` 找出 Scope 覆盖该路径的全部 note (互为前缀匹配)， 按日期排出该模块的决策史.
- 同步: implemented note 的 Scope 随事实同步 — 模块改名时同变更更新， 否则 history 会漏.

## 何时写一条

只在代码， 测试与现有文档解释不了的**持久决策理由**出现时， 同一变更内新增或更新 note. 实质性未来工作的提案从 `proposed/` 开始； 已定的决策直接从 `implemented/` 开始. 选对 class 目录.

已有 note 拥有该决策时， 更新它即满足规则， **不建重复**. 机械性或局部改动 (含本地 UI 表现与交互调整) 豁免. note 永远不被编辑成*另一个决策*： 用新 note 取代， 两条交叉链接， 除非旧 note 之后按下面的规则被完全合并.

被完全取代的 implemented note 可合并进当前拥有者并删除. 删除前， 拥有者必须保留全部独特理由， 候选， 后果与必要验证； 修复所有入站链接. 部分取代不满足合并条件： 两条都保留并交叉链接， 更新仍成立的事实. 合并不得把旧文件改写成它的反面， 也不得依赖 git 历史作为理由的唯一副本.

## 同步分级

note 与现实 (代码, 上游演进) 的同步按事件性质分级, 判别式: 事件发生后, 未来读者会不会问 "为什么".

- **指向修正** — 代码改路径, 改名, 改结构, note 跟着改指向: 纯同步, git diff 足够, 无需叙事.
- **语义演进** — 机制行为变化: 在原 note 内联自含的因果链 (日期, 变了什么, 为什么), 读者单条读完不依赖外部仓库与 git 历史; 留裸 provenance 指针不达标.
- **本项目自己的新裁决** — 开新 note, 不编辑旧决策.
- **决策被推翻** — 新 note + supersession, 旧 note 归档.

骑线事件按语义演进从严处理.

## Supersession 检查

**每条新 note 触发一次.** 在活动树中搜索覆盖同一决策或机制的旧 note (`search <主题词>`), 分类完全取代或部分取代； 完全取代的 implemented note 同一变更内归档， 部分取代的保留并交叉链接. 这防止决策记录本身变成新的羊皮卷.

## 归档与删除

implemented note 的已发布决策完结， 且其理由不太可能指导未来工作时归档. 以下情形保持活动： 候选方案， 所有权边界， 否定性保证， 持久或线上语义， 安全规则， 重新引入条件仍然有用. **绝不归档 proposed note** — 过时提案走 rejected. rejected note 只在其仍能阻止一个可信的错误时保留， 否则删除.

判据是**未来决策价值**, 不是字数， 年龄或配额. 归档 = `notes.py move <note> archived`:

- 移入 `archived/{class}/`, 原文件名不变， `Status: implemented` 保持;
- 头块插入 `Archived: YYYY-MM-DD` 行 (Scope 行之后);
- manifest.json 追加该文件的 sha256 — **append-only**: 封存后永不编辑， 移动或删除， 永不作为当前行为的权威. 活动文档仍可有意引用历史时链入归档 note.

## 文件格式

`notes.py verify` 逐行门禁 (树结构 + 格式 + 归档密封 + note 间链接), 提交前跑.

### 头块

每条 note 的头部固定 (归档行仅 archived 有):

```markdown
# Agent Note: <标题>

Status: <status>
Scope: <路径1>, <路径2>
Archived: YYYY-MM-DD        ← 仅归档文件

## Problem
```

`Status:` 三种合法取值， 必须与所在目录一致， 门禁交叉检查:

- `Status: proposed`
- `Status: implemented`
- `Status: rejected — <一句话理由>`

理由只出现在 rejected 的 Status 行上 — 被否 note 的裁决就是读者要来看的事实. Status 行全文唯一， 不带日期与括号补充.

### 正文骨架

每条 note 以 `## Problem` 开篇 — 动机独立成立， 不依赖解法. 其后按生命周期:

**`proposed/`**

```markdown
## Problem
## Proposal
…自由的技术章节…
## Alternatives considered
## Acceptance criteria
## Risks
```

`## Proposal` 是意图的变更， 可以合法用将来时 — 计划， 迁移步骤与开放问题在未建造时属于这里. `## Acceptance criteria` 说清什么可观测状态算完成. `## Risks` 覆盖可能出什么错与该变更明知放弃什么.

**`implemented/`**

```markdown
## Problem
## Decision
…自由的技术章节…
## Alternatives considered
## Consequences
```

`## Decision` 用现在时描述已发布的现实. 提案腔标题在这里被门禁拒绝： `## Proposal`, `## Plan`, `## Migration plan`, `## Acceptance criteria` 不得出现在 implemented note 中 (折入 Decision / Consequences / Testing). `## Testing`, `## Deferred`, `## Related` 陈述现在时事实时合法.

**`rejected/`**

被否的 note 就是冻结的提案： 保留提案期的全部章节 (含 `## Acceptance criteria`, `## Plan`), 裁决活在 `Status:` 行上. 门禁只要求 `## Problem` 开篇， `## Proposal` 存在， 与下面的 Alternatives 强制项.

### Alternatives considered — 强制

每条 note 必有 `## Alternatives considered`: 每个真实候选与它输掉的原因， 一个候选一段 (粗体引导) 或每个有争议的候选一个 `### Why not <X>?` 小节. **没有记录对手的决策邀请翻案** — 这正是 Agent Notes 要防止的失败. 候选只记录， 不发明.

### 生命周期迁移

迁移 = 更新 Status 行 + 同一变更内满足目标目录的骨架， 门禁不过则迁移未完成. 具体： `proposed → implemented` 把 `## Proposal` 重写为现在时 `## Decision`, `## Acceptance criteria` 与 `## Risks` 折入 `## Consequences` (或现在时的 `## Testing` / `## Verification`), 删计划， 写实际发布了什么 — CLI `move` 会列出重写清单. `proposed → rejected` 只在 Status 行加理由并冻结文件.

## 与 deepseek-harness 的关系

本体系基于 deepseek-harness 的 Agent Notes 实践版本 (四生命周期， 六类别， 格式骨架， alternatives 强制， 迁移机械重写， supersession 检查， 冻结归档， 无索引原则). 两处刻意扩展:

1. **Scope 字段** — 头块声明管辖路径， 支撑按模块的决策史查询 (`history`).
2. **CLI 工具化** — 建立基于模板骨架， 查询 (list/show/search/history), 迁移与封存， 三合一门禁全部脚本化， 而非依赖手写文件与手工移动.

一处环境差异： deepseek 维护 en/zh/sidecar 三语三件套 (其翻译流水线配套); 本模板 note 为单文件单语言， manifest 与哈希封存机制不受影响.
