# Finish Work

Wrap up the current session: archive the active task (and any other completed-but-unarchived tasks the user wants to clean up) and record the session journal. Code commits are NOT done here — those happen in workflow Phase 3.4 before you invoke this command.

## Step 1: Survey current state

```bash
python3 ./.trellis/scripts/get_context.py --mode record
```

This prints:

- **My active tasks** — review whether any besides the current one are actually done (code merged, AC met) and should be archived this round.
- **Git status** — quick visual on what's dirty.
- **Recent commits** — you'll need their hashes in Step 5 for `--commit`.

If `--mode record` surfaces other completed tasks not tied to the current session, surface them to the user with a one-shot confirmation: "These N tasks look done — archive them too in this round? [y/N]". Default is no; the current active task is always archived in Step 4 regardless.

## Step 2: Session decision sweep

Before archiving, sweep the whole session for durable decisions — including ones made outside any task (design discussions, user verdicts, overturned proposals), plus any the user deferred from mid-session immediate offers. This is the session-level write anchor; task-level capture already happened in workflow Phase 3.3.

1. List what the session decided or overturned. For each, check whether it is recorded:
   ```bash
   python3 ./.trellis/scripts/notes.py list --all
   ```
2. Missing ones: `python3 ./.trellis/scripts/notes.py create <lifecycle> <class> <title> --scope <paths>` and fill the skeleton per the `agent-notes` skill (`.agents/skills/agent-notes/SKILL.md`). Decisions made in a different repository than the notes tree: record them here anyway with the target repo's CLI — do not skip cross-repo decisions.
3. Verify: `python3 ./.trellis/scripts/notes.py verify`.
4. Commit the notes as one batch: `docs(notes): record session decisions`.

If the sweep found nothing to record, say so and continue — the judgment must happen, the write is conditional.

## Step 3: Sanity check — classify dirty paths

Run:

```bash
git status --porcelain
```

Filter out paths under `.trellis/workspace/` and `.trellis/tasks/` — those are managed by `add_session.py` and `task.py archive` auto-commits and will appear dirty as part of this skill's own work.

For each remaining dirty path, decide whether it belongs to **the current task** or to **other parallel work** (e.g., another terminal window editing the same repo). Heuristics:

- Paths referenced in the current task's `prd.md` / `implement.jsonl` / `check.jsonl` → current task
- Paths in code areas matching the task's stated scope, or that you remember editing this session → current task
- Paths in unrelated areas you have no recollection of touching this session → other parallel work

Then route:

- **Any remaining path looks like current-task work** — bail out with:
  > "Working tree has uncommitted code changes from this task: `<list>`. Return to workflow Phase 3.4 to commit them before running `/trellis-finish-work`."

  Do NOT run `git commit` here. Do NOT prompt the user to commit. The user goes back to Phase 3.4 and the AI drives the batched commit there.
- **All remaining paths look unrelated** (other parallel-window work) — report them once and continue to Step 4:
  > "FYI, dirty files outside this task's scope — leaving them for the other window: `<list>`."
- **Genuinely unsure** — ask the user once: "Are `<list>` this task's work I forgot to commit, or another window's? (commit / ignore)" — then route per their answer.

## Step 4: Archive task(s)

```bash
python3 ./.trellis/scripts/task.py archive <task-name>
```

At minimum: the current active task (if any). Plus any extra tasks the user confirmed in Step 1. Each archive produces a `chore(task): archive ...` commit via the script's auto-commit.

If there is no active task and the user did not confirm any cleanup archives, skip this step.

## Step 5: Record session journal

```bash
python3 ./.trellis/scripts/add_session.py \
  --title "Session Title" \
  --commit "hash1,hash2" \
  --summary "Brief summary"
```

Use the work-commit hashes produced in Phase 3.4 (visible in Step 1's `Recent commits` list, or via `git log --oneline`) for `--commit`. Do not include the archive commit hashes from Step 4. This produces a `chore: record journal` commit.

Final git log order: `<work commits from 3.4>` → `docs(notes): record session decisions` (if any) → `chore(task): archive ...` (one or more) → `chore: record journal`.
