# Agent 定义文件编写指南

本目录存放本仓的 pi 子代理定义 (trellis-implement / trellis-check / trellis-research), 也接受项目自定义 agent. 本文档说明如何编写可发现、可执行、权限边界清晰的 agent 定义文件.

格式实现权威是 pi-subagents 扩展 (真源: 该扩展仓的 `AGENT_DEFINITION.md`); 本文档为随模板分发的副本, 与扩展行为不一致时以扩展实际行为为准.

## 1. 文件位置

### 项目级 agent

放在当前项目的 `.pi/agents/` 目录:

```text
<project-root>/.pi/agents/<name>.md
```

pi-subagents 会从当前工作目录向上查找第一个包含 `.pi` 目录的祖先, 将它作为项目根目录.

### 用户级 agent

放在用户 agent 目录:

```text
~/.pi/agent/agents/<name>.md
```

用户级 agent 可被多个项目复用.

### 直接路径

也可以通过 `path` 直接指定任意位置的定义文件, 不要求文件位于上述两个目录:

```json
{
  "path": "/absolute/path/to/auditor.md",
  "prompt": "Audit the changed files and report concrete findings."
}
```

相对路径相对当前工作目录解析. 推荐仍使用 `.md` 扩展名.

### 同名覆盖

项目级定义优先于用户级定义. 两个目录中存在相同 `name` 时, 项目级版本生效.

## 2. 最小文件结构

```markdown
---
name: scout
description: Inspect code and report relevant facts
tools:
  - read
  - grep
  - find
---

You are a focused code reconnaissance agent.

Responsibilities:
- Inspect only the files relevant to the delegated task.
- Cite concrete file paths and line-level evidence when available.
- Do not modify files.

Return a concise report with findings, evidence, and remaining uncertainty.
```

文件必须有 YAML frontmatter, 并且必须包含非空的 `name`. 缺少 `name` 的文件会被忽略 (本 README 因此不会被注册为 agent).

frontmatter 结束标记必须是单独一行的 `---`. 结束标记之后的正文是 agent 的稳定角色提示词.

## 3. Frontmatter 字段

### `name`, 必填

agent 的调用名称:

```yaml
name: scout
```

通过名称调用时使用该值:

```json
{
  "agent": "scout",
  "prompt": "Inspect the authentication flow."
}
```

名称应简短、稳定、具有角色含义. 文件名不决定调用名称, frontmatter 中的 `name` 才是唯一来源.

### `description`, 推荐

用于列出已发现 agent 时的简短说明. 它不是 agent 的 system prompt:

```yaml
description: Review code for correctness and security risks
```

建议写成一句可检索的职责描述, 不要放长篇工作流程.

### `model`, 可选

指定该 agent 的模型. 可以包含 thinking 后缀:

```yaml
model: provider/model
```

```yaml
model: provider/model:high
```

实际模型名称必须是当前 Pi 环境可用的名称. 委派工具输入中的 `model` 优先于定义文件中的 `model`.

### `thinking`, 可选

可用值:

```text
off, minimal, low, medium, high, xhigh, max
```

示例:

```yaml
thinking: medium
```

优先级从高到低为:

1. 委派工具输入中的 `thinking`.
2. 委派工具输入中 `model` 的 thinking 后缀.
3. agent 定义中的 `thinking`.
4. agent 定义中 `model` 的 thinking 后缀.
5. 父会话继承的 thinking 设置.

### `tools`, 可选

限制子代理可使用的工具. 支持逗号字符串和 YAML 数组, 推荐使用数组:

```yaml
tools:
  - read
  - grep
  - find
```

也可以写成:

```yaml
tools: read, grep, find
```

工具名称会被去除首尾空格并转换为小写. 只声明任务确实需要的工具:

- 只读分析: `read`, `grep`, `find`, `ls`
- 需要执行命令: 在此基础上增加 `bash`
- 需要修改文件: 明确增加 `edit` 或 `write`

`tools` 只控制子代理可用的 Pi 工具, 不会改变权限系统对具体调用的审批结果.

## 4. 正文怎么写

正文是长期稳定的角色定义, 委派时传入的 `prompt` 是当前任务. 不要把一次性任务写进 agent 定义.

正文至少应明确以下内容:

1. 角色: agent 是审查者、实现者、测试者还是资料收集者.
2. 目标: 它要产出什么结果.
3. 工作范围: 允许查看或修改哪些对象.
4. 操作边界: 是否禁止写文件、禁止联网、禁止执行命令等.
5. 输出格式: 例如按严重程度列出问题, 或输出结论、证据、风险.
6. 证据要求: 要求引用文件路径、命令结果或测试结果, 避免无依据推测.

推荐把稳定约束放在定义文件, 把具体文件、问题和验收标准放在委派 prompt:

```markdown
---
name: reviewer
description: Review implementation changes for bugs and missing tests
tools:
  - read
  - grep
  - find
---

You are a code reviewer.

Review the delegated change for:
- correctness and behavioral regressions;
- security and permission boundary violations;
- missing or ineffective tests.

Do not modify files. Report findings first, ordered by severity. Every finding must
include a file path, a precise explanation, and a practical fix direction. If there
are no findings, state the remaining test gaps and residual risk.
```

## 5. 权限和安全边界

子代理通过独立的、无 UI 的 Pi 子进程运行. 当它请求需要审批的操作时, 权限系统可以把请求转发到父会话.

特别注意:

- `bash` 允许执行命令, 权限范围明显大于只读工具.
- 访问工作目录之外的路径可能触发 `external_directory` 审批.
- 不要为了省事给所有 agent 声明 `bash`, `edit`, `write`.
- 需要修改代码的 agent 应明确写出修改范围和验证要求.
- 无 UI 子代理不能自行显示审批窗口, 它的审批请求依赖父会话转发.
- agent 正文中的限制不能替代权限配置. 需要防止实际访问时, 同时收紧 `tools` 和权限策略.

## 6. 常用调用方式

按名称发现并运行:

```json
{
  "agent": "scout",
  "prompt": "Find all callers of resolvePermission and summarize their contracts."
}
```

使用单次直接路径:

```json
{
  "path": ".pi/agents/reviewer.md",
  "prompt": "Review the current uncommitted changes. Do not edit files."
}
```

并行委派:

```json
{
  "agent": "scout",
  "mode": "parallel",
  "prompts": [
    "Inspect the data model and report inconsistencies.",
    "Inspect the tests and report missing coverage."
  ]
}
```

链式委派时, 后一个任务会收到前一个任务的输出, 适合先收集事实再进行综合判断.

## 7. 编写后检查

- [ ] 文件位于 `.pi/agents/`, `~/.pi/agent/agents/`, 或通过 `path` 可访问的位置.
- [ ] frontmatter 有非空 `name`.
- [ ] `description` 能准确概括职责.
- [ ] `thinking` 使用允许值.
- [ ] `tools` 只包含实际需要的工具.
- [ ] 正文定义了角色、范围、边界和输出格式.
- [ ] 一次性任务放在委派 `prompt`, 没有硬编码进角色定义.
- [ ] 需要外部目录、命令或写入时, 已准备父会话审批和验证步骤.
- [ ] 用真实 Pi 子进程运行一次, 确认 agent 被发现、工具可用、输出符合预期.

## 8. 常见问题

### agent 没有被发现

依次检查:

1. 文件扩展名是否为 `.md`.
2. 文件是否位于正确的 `.pi/agents/` 或 `~/.pi/agent/agents/` 目录.
3. frontmatter 是否存在.
4. 是否缺少非空 `name`.
5. 是否被同名的项目级 agent 覆盖.

### agent 被发现但行为不对

检查正文是否把稳定角色和一次性任务混在一起, 以及委派 prompt 是否明确写出了输入对象、禁止事项和成功标准.

### 子代理无法执行命令

确认定义中的 `tools` 包含 `bash`, 并检查父会话是否处理了权限转发弹窗. `tools` 声明和权限策略是两层独立控制.

### `model` 或 `thinking` 没生效

检查委派输入是否显式覆盖了定义文件, 以及 `model` 的 thinking 后缀是否拼写为允许值. 例如 `provider/model:high` 中的 `high` 才会被识别.
