---
name: subagent-dispatch
description: "Use when dispatching any sub-agent via the subagent tool — deciding whether and how to dispatch, choosing agent and mode, composing the dispatch prompt, or handling sub-agent failure and iteration. The Trellis section applies only with an active task."
---

# Sub-agent Dispatch

The subagent tool spawns an isolated pi sub-process. Three platform facts shape every rule below:

1. The sub-agent inherits **no main-session context** — not the conversation, not injected state.
2. There is **no turn limit** — it runs until the model stops calling tools; the only external stop is abort.
3. Output is only as trustworthy as its verifiable artifacts.

## Pre-dispatch gate

Run before any dispatch. If any check fails, fix the cause (plan more, persist to files) — do not dispatch.

- [ ] **Net gain** — the dispatch must buy something the main session cannot do directly: parallelism, tool/model isolation, or a fresh context window. If the deliverable is already fully converged in main-session context (e.g. transcribing a settled decision into files), write it in the main session. Dispatching a context-poor copy of work you already hold is pure loss.
- [ ] **Decidable goal** — done criteria + verification command, one line each. Open-ended goals have no natural stopping point; with no turn limit that means drift, not completion.
- [ ] **Self-contained information** — everything the sub-agent needs is in the dispatch prompt or in files it can deterministically find (artifacts, specs, code). Anything that lives only in main-session conversation memory does not exist for the sub-process.
- [ ] **Capability match** — the agent's tools, model, and environment cover the task; verification commands must actually run in the sub-process cwd.
- [ ] **Verifiable process** — the deliverable lands on disk (files, command output), not in a prose self-report.

Planning is the pre-engineering of dispatch: Trellis Phase 1 artifacts exist to satisfy this gate for Phase 2 dispatches. A failed gate check means planning is not done — not that the dispatch should be attempted anyway.

## General contract (every dispatch)

### Agent resolution

- By `agent` name: project `.pi/agents/` first, then user `~/.pi/agent/agents/`.
- Or `path` pointing at any agent definition file.
- Per-dispatch overrides: `model` (supports `provider/model:thinking`), `thinking`.

### Dispatch prompt anatomy

In order:

1. **Task** — one bounded deliverable with a scope slice (files/area), not the whole plan.
2. **Context pointers** — paths the sub-agent must read. Never content dumps; if you are tempted to paste file contents into the prompt, the pointer chain is broken — fix the files instead.
3. **Done criteria** — what "finished" means, checkable.
4. **Verification commands** — run before reporting.
5. **Constraints** — what not to do (e.g. no git commit).

### Sizing

- No turn limit means no external brake: one dispatch = one bounded deliverable.
- Split large plans into ordered chunks; dispatch sequentially, verify between chunks.

### Mode selection

- `single` (default) — one deliverable.
- `parallel` (≤ 6 prompts) — only for mutually independent prompts: read-only work, or writes to disjoint targets. Never parallel writes into the same repo.
- `chain` — only when step N's output genuinely feeds step N+1. A dependency known at planning time belongs in `implement.md`, not in a chain.

### Result handling

- Never trust a sub-agent's self-report; re-check via files and command output in the main session.
- On failure: summarize the error into a re-dispatch, or take over manually. A looping sub-agent has no automatic stop — abort it.

## Trellis overlay (only with an active task)

### Prompt prefix

- First line: `Active task: <path from task.py current>`.
- Second line: role guard — "You are already the trellis-X sub-agent; do NOT spawn another trellis-implement / trellis-check."

### Routing

| Situation | Agent |
|---|---|
| Phase 2.1 — implement reviewed artifacts | `trellis-implement` |
| Phase 2.2 — verify after each implement chunk; final pass full-scope before commit | `trellis-check` |
| Phase 1.2 research or mid-flight unknowns | `trellis-research` (artifacts into `{TASK_DIR}/research/`) |

### Context division

Sub-agents self-load their context: jsonl manifests -> `prd.md` -> `design.md` -> `implement.md`. The dispatch prompt carries the scope slice and pointers only.

### Iteration protocol

- Small findings -> `trellis-check` fixes them directly.
- Large findings -> summarize into a re-dispatch to `trellis-implement`.
- Requirement defect -> back to Phase 1; fix artifacts; re-dispatch.
- Mid-flight research question -> dispatch `trellis-research` first, list the artifact in the re-dispatch.

### When not to dispatch (Trellis)

Documentation-only edits whose content is already converged in main-session context: write them directly. The implement -> check alternation guards code changes; transcribing settled text is not a code change.
