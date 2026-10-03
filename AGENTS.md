<!-- TRELLIS:START -->
# Trellis Instructions

These instructions are for AI assistants working in this project.

This project is managed by Trellis. The working knowledge you need lives under `.trellis/`:

- `.trellis/workflow.md` — development phases, when to create tasks, skill routing
- `.trellis/spec/` — package- and layer-scoped coding guidelines (read before writing code in a given layer)
- `.trellis/workspace/` — per-developer journals and session traces
- `.trellis/tasks/` — active and archived tasks (PRDs, research, jsonl context)

If a Trellis command is available on your platform (e.g. `/trellis:finish-work`, `/trellis:continue`), prefer it over manual steps. Not every platform exposes every command.

If you're using Codex or another agent-capable tool, additional project-scoped helpers may live in:
- `.agents/skills/` — reusable Trellis skills
- `.codex/agents/` — optional custom subagents

## Session Start Protocol

Run this before your first substantive reply in a session:

1. Establish the session goal from the user's opening request. If the goal is unclear, ask before doing anything else.
2. Read the context that goal touches: the relevant spec layer indexes (`.trellis/spec/{prd,arch,cdd}/index.md` plus the documents they list) and past decisions (`python3 .trellis/scripts/notes.py search <keyword>`).
3. Only after this background is collected, continue the conversation with the user.

Files are the source of truth; conversation memory is not. Do not answer, plan, or edit from what a previous session may have said — re-read the files.

Managed by Trellis. Edits outside this block are preserved; edits inside may be overwritten by a future `trellis update`.

<!-- TRELLIS:END -->
