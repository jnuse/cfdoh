# Agent Note: subagent dispatch discipline

Status: proposed
Scope: .trellis/tasks/10-02-cfdoh-impl, implement.jsonl

## Problem
<!-- the motivation, written to stand without the solution -->

## Proposal
<!-- the intended change; future tense is legitimate here -->

## Alternatives considered
<!-- each genuine alternative and why it lost -->

## Acceptance criteria
<!-- what observable state means done -->

## Risks
<!-- what could go wrong and what the change knowingly gives up -->

## 补充 (第二次失败复盘)

implement.jsonl 必须按批裁剪, 只留本批交付物直接依赖的 spec 文件; 全任务清单会耗尽子代理轮次 (第一次失败根因: 22 文件 jsonl + prompt 重复清单, 轮次全花在读上, 零代码产出即终止). 每批 dispatch 前主会话重写 implement.jsonl 为当批条目.
