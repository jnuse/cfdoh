#!/usr/bin/env python3
"""Agent Notes CLI for .trellis/notes/.

Agent Notes are durable proposals and decision records: the *why* and
*what we gave up* that code, tests, and docs cannot carry. The tree is
the single source of truth — this tool never writes a derived index.

Commands: create / list / show / search / history / move / verify
Contract: .trellis/notes/README.md
"""

import argparse
import hashlib
import json
import re
import sys
from datetime import date
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
NOTES_ROOT = SCRIPT_DIR.parent / "notes"

ARCHIVE = "archived"
LIFECYCLES = ["proposed", "implemented", "rejected"]
CLASSES = ["feature", "bug-fix", "simplification", "architecture", "process", "testing"]
ALLOWED_ROOT_FILES = {"README.md"}
ALLOWED_ARCHIVE_ROOT_FILES = {"manifest.json"}

FILENAME_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2})-([a-z0-9\u4e00-\u9fff]+(?:-[a-z0-9\u4e00-\u9fff]+)*)\.md$"
)
STATUS_GRAMMAR = {
    "proposed": re.compile(r"^Status: proposed$"),
    "implemented": re.compile(r"^Status: implemented$"),
    "rejected": re.compile(r"^Status: rejected \u2014 .+$"),
}
SCOPE_LINE_RE = re.compile(r"^Scope: (.+)$")
ARCHIVED_LINE_RE = re.compile(r"^Archived: (\d{4}-\d{2}-\d{2})$")
REQUIRED_SECTIONS = {
    "proposed": ["## Proposal", "## Acceptance criteria", "## Risks"],
    "implemented": ["## Decision", "## Consequences"],
    "rejected": ["## Proposal"],
}
BANNED_IMPLEMENTED_RE = re.compile(
    r"^## (?:Proposal|Plan|Migration plan|Acceptance criteria)\b", re.IGNORECASE
)
MD_LINK_RE = re.compile(r"\]\(([^)#\s]+)(?:#[^)\s]*)?\)")

SKELETONS = {
    "proposed": [
        ("Problem", "the motivation, written to stand without the solution"),
        ("Proposal", "the intended change; future tense is legitimate here"),
        ("Alternatives considered", "each genuine alternative and why it lost"),
        ("Acceptance criteria", "what observable state means done"),
        ("Risks", "what could go wrong and what the change knowingly gives up"),
    ],
    "implemented": [
        ("Problem", "the motivation, written to stand without the solution"),
        ("Decision", "what shipped, present tense; kept current with facts (paths, names, structure)"),
        ("Alternatives considered", "each genuine alternative and why it lost"),
        ("Consequences", "what the trade-off cost and bought"),
    ],
    # A rejected note is the proposal, frozen. REQUIRED_SECTIONS only asks for
    # Problem + Proposal, but a fresh one gets the full proposal skeleton.
    "rejected": [
        ("Problem", "the motivation, written to stand without the solution"),
        ("Proposal", "the proposal, frozen as proposed"),
        ("Alternatives considered", "each genuine alternative and why it lost"),
        ("Acceptance criteria", "what done would have meant"),
        ("Risks", "what was at stake"),
    ],
}


def fail(msg: str) -> None:
    print(f"notes.py: {msg}", file=sys.stderr)
    sys.exit(1)


# ── Tree walking ────────────────────────────────────────────────────────

def note_files(include_archived: bool = True) -> list[Path]:
    """Return every .md file under lifecycle/class/ (and archived/class/)."""
    out: list[Path] = []
    roots = list(LIFECYCLES)
    if include_archived:
        roots.append(ARCHIVE)
    for lc in roots:
        base = NOTES_ROOT / lc
        if not base.is_dir():
            continue
        for p in sorted(base.rglob("*.md")):
            if p.name in ("AGENTS.md",):
                continue
            out.append(p)
    return out


def parse_note(path: Path) -> dict | None:
    """Return note metadata if the filename grammar matches, else None."""
    m = FILENAME_RE.match(path.name)
    if not m:
        return None
    lifecycle = path.relative_to(NOTES_ROOT).parts[0]
    return {
        "path": path,
        "rel": path.relative_to(NOTES_ROOT).as_posix(),
        "lifecycle": lifecycle,
        "class_dir": path.parent.name,
        "date": m.group(1),
        "slug": m.group(2),
    }


def title_of(path: Path) -> str:
    try:
        first = path.read_text(encoding="utf-8").split("\n", 1)[0]
    except OSError:
        return "?"
    return first.removeprefix("# Agent Note: ").strip()


def read_prose(path: Path) -> list[str]:
    """File lines with fenced code blocks removed (format tokens in
    fenced examples are not document structure)."""
    lines = path.read_text(encoding="utf-8").split("\n")
    prose, in_fence = [], False
    for line in lines:
        if line.startswith("```"):
            in_fence = not in_fence
            continue
        if not in_fence:
            prose.append(line)
    return prose


def scope_paths(path: Path) -> list[str]:
    """Parse the Scope: header line into repo-relative paths."""
    m = SCOPE_LINE_RE.match(path.read_text(encoding="utf-8").split("\n")[3])
    if not m:
        return []
    return [p.strip().strip("/") for p in m.group(1).split(",") if p.strip()]


def find_note(key: str) -> Path:
    """Resolve a note by path, filename, or unique filename-prefix."""
    cand = Path(key)
    if cand.is_file():
        return cand.resolve()
    matches = [p for p in note_files() if p.name == key or p.stem.startswith(key)]
    if not matches:
        inside = [p for p in note_files() if key.lower() in p.name.lower()]
        if inside:
            matches = inside
    if not matches:
        fail(f"no Agent Note matches {key!r}")
    if len(matches) > 1:
        for p in matches:
            print(f"  {p.relative_to(NOTES_ROOT).as_posix()}")
        fail(f"{key!r} is ambiguous ({len(matches)} matches) — refine the prefix")
    return matches[0]


# ── create ──────────────────────────────────────────────────────────────

def slugify(title: str) -> str:
    out = []
    for ch in title.strip().lower():
        if ch.isascii() and ch.isalnum():
            out.append(ch)
        elif "\u4e00" <= ch <= "\u9fff":
            out.append(ch)
        else:
            out.append("-")
    return re.sub(r"-+", "-", "".join(out)).strip("-")


def cmd_create(args: argparse.Namespace) -> None:
    if args.lifecycle not in LIFECYCLES:
        fail(f"unknown lifecycle {args.lifecycle!r} (allowed: {', '.join(LIFECYCLES)})")
    if args.cls not in CLASSES:
        fail(f"unknown class {args.cls!r} (allowed: {', '.join(CLASSES)})")
    if args.lifecycle == "rejected" and not args.reason:
        fail("creating directly in rejected/ requires --reason (the verdict readers come for)")
    scopes = [s.strip() for s in args.scope.split(",") if s.strip()]
    if not scopes or any("\\" in s for s in scopes):
        fail("--scope must be a non-empty comma-separated list of repo-relative paths with forward slashes")

    title = " ".join(args.title).strip()
    slug = slugify(title)
    if not slug:
        fail("title produces an empty filename slug")
    name = f"{date.today().isoformat()}-{slug}.md"
    path = NOTES_ROOT / args.lifecycle / args.cls / name
    if path.exists():
        fail(f"{path.relative_to(NOTES_ROOT).as_posix()} already exists")

    status = {"proposed": "Status: proposed", "implemented": "Status: implemented"}.get(
        args.lifecycle, f"Status: rejected \u2014 {args.reason}"
    )
    lines = [f"# Agent Note: {title}", "", status, f"Scope: {', '.join(scopes)}", ""]
    for section, hint in SKELETONS[args.lifecycle]:
        lines += [f"## {section}", f"<!-- {hint} -->", ""]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines).rstrip("\n") + "\n", encoding="utf-8")

    print(f"created {path.relative_to(NOTES_ROOT).as_posix()}")
    print("next: fill every section (replace the <!-- hints), keep the header block as is.")
    print("supersession check: search the active tree for older notes covering the same")
    print(f"decision — e.g. `notes.py search <topic>` — and archive/cross-link as needed.")


# ── list / show / search / history ─────────────────────────────────────

def cmd_list(args: argparse.Namespace) -> None:
    rows = []
    for p in note_files(include_archived=args.all):
        note = parse_note(p)
        if not note:
            continue
        if args.lifecycle and note["lifecycle"] != args.lifecycle:
            continue
        if args.cls and note["class_dir"] != args.cls:
            continue
        if args.pattern and args.pattern.lower() not in p.name.lower():
            continue
        rows.append(note)
    if not rows:
        print("no Agent Notes match")
        return
    for n in sorted(rows, key=lambda x: x["rel"]):
        print(f"{n['rel']}  \u2014  {title_of(n['path'])}")


def cmd_show(args: argparse.Namespace) -> None:
    path = find_note(args.note)
    sys.stdout.write(path.read_text(encoding="utf-8"))


def cmd_search(args: argparse.Namespace) -> None:
    needle = args.text.lower()
    hits = 0
    for p in note_files():
        for i, line in enumerate(p.read_text(encoding="utf-8").split("\n"), 1):
            if needle in line.lower():
                text = line.strip()
                print(f"{p.relative_to(NOTES_ROOT).as_posix()}:{i}: {text[:120]}")
                hits += 1
    if not hits:
        print(f"no Agent Note mentions {args.text!r}")


def cmd_history(args: argparse.Namespace) -> None:
    q = args.path.strip().strip("/")
    rows = []
    for p in note_files():
        note = parse_note(p)
        if not note:
            continue
        for s in scope_paths(p):
            if s == q or s.startswith(q + "/") or q.startswith(s + "/"):
                rows.append(note)
                break
    if not rows:
        print(f"no Agent Note covers {q!r} (checked Scope lines across the whole tree)")
        return
    for n in sorted(rows, key=lambda x: (x["date"], x["slug"])):
        print(f"{n['date']}  {n['lifecycle']:<11}  {n['rel']}  \u2014  {title_of(n['path'])}")
    print(f"\narchived entries are frozen history, not current authority.")


# ── move ────────────────────────────────────────────────────────────────

ALLOWED_MOVES = {
    ("proposed", "implemented"),
    ("proposed", "rejected"),
    ("implemented", ARCHIVE),
}


def manifest_path() -> Path:
    return NOTES_ROOT / ARCHIVE / "manifest.json"


def load_manifest() -> dict:
    p = manifest_path()
    if not p.is_file():
        return {"version": 1, "files": {}}
    return json.loads(p.read_text(encoding="utf-8"))


def save_manifest(data: dict) -> None:
    manifest_path().parent.mkdir(parents=True, exist_ok=True)
    manifest_path().write_text(
        json.dumps(data, indent=1, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def sha256_of(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def inbound_links(target: Path) -> list[str]:
    """Active+archived notes whose markdown links resolve to target."""
    out = []
    for p in note_files():
        if p.resolve() == target.resolve():
            continue
        text = p.read_text(encoding="utf-8")
        for link in MD_LINK_RE.findall(text):
            if (p.parent / link).resolve() == target.resolve():
                out.append(p.relative_to(NOTES_ROOT).as_posix())
                break
    return out


def cmd_move(args: argparse.Namespace) -> None:
    path = find_note(args.note)
    note = parse_note(path)
    if not note:
        fail(f"{path.name!r} does not match the yyyy-mm-dd-topic.md filename grammar")
    src, dst = note["lifecycle"], args.target
    if (src, dst) not in ALLOWED_MOVES:
        fail(f"move {src} -> {dst} is not allowed (allowed: "
             + ", ".join(f"{a} -> {b}" for a, b in ALLOWED_MOVES) + ")")

    lines = path.read_text(encoding="utf-8").split("\n")

    if dst == "implemented":
        lines[2] = "Status: implemented"
        dest = NOTES_ROOT / "implemented" / note["class_dir"] / path.name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text("\n".join(lines), encoding="utf-8")
        path.unlink()
        print(f"moved to {dest.relative_to(NOTES_ROOT).as_posix()} — the format gate now fails")
        print("until the body is rewritten mechanically:")
        print("  - rewrite `## Proposal` into a present-tense `## Decision`")
        print("  - fold `## Acceptance criteria` and `## Risks` into `## Consequences`")
        print("  - drop plans in favor of what shipped")
        print("run `notes.py verify` when done.")

    elif dst == "rejected":
        if not args.reason:
            fail("rejecting a proposal requires --reason (one line, goes on the Status line)")
        lines[2] = f"Status: rejected \u2014 {args.reason}"
        dest = NOTES_ROOT / "rejected" / note["class_dir"] / path.name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text("\n".join(lines), encoding="utf-8")
        path.unlink()
        print(f"moved to {dest.relative_to(NOTES_ROOT).as_posix()} — proposal frozen,")
        print("verdict recorded on the Status line. No body rewrite is required.")

    else:  # implemented -> archived
        manifest = load_manifest()
        rel_in_archive = f"{note['class_dir']}/{path.name}"
        if rel_in_archive in manifest["files"]:
            fail(f"{rel_in_archive} is already in the frozen manifest (append-only)")
        lines.insert(4, f"Archived: {date.today().isoformat()}")
        dest = NOTES_ROOT / ARCHIVE / note["class_dir"] / path.name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text("\n".join(lines), encoding="utf-8")
        manifest["files"][rel_in_archive] = sha256_of(dest)
        save_manifest(manifest)
        path.unlink()
        print(f"sealed {dest.relative_to(NOTES_ROOT).as_posix()} — manifest updated, file frozen.")
        links = inbound_links(dest)
        if links:
            print("inbound links pointing at the old location — repair them in the same change:")
            for l in links:
                print(f"  {l}")


# ── verify ──────────────────────────────────────────────────────────────

def verify_structure(errors: list[str]) -> list[dict]:
    notes: list[dict] = []
    if not NOTES_ROOT.is_dir():
        errors.append(f"structure: {NOTES_ROOT} does not exist")
        return notes
    for entry in sorted(NOTES_ROOT.iterdir()):
        if entry.name == "INDEX.md":
            errors.append("structure: INDEX.md — centralized Agent Note indexes are forbidden; "
                          "browse the lifecycle/class tree or run notes.py list/search/history")
            continue
        if entry.is_dir() and entry.name not in LIFECYCLES + [ARCHIVE]:
            errors.append(f"structure: {entry.name}/ — unknown lifecycle folder "
                          f"(allowed: {', '.join(LIFECYCLES)}, plus {ARCHIVE}/)")
        if entry.is_file() and entry.name not in ALLOWED_ROOT_FILES:
            errors.append(f"structure: {entry.name} — unexpected file at the notes root")
    tree_roots = {lc: NOTES_ROOT / lc for lc in LIFECYCLES}
    tree_roots[ARCHIVE] = NOTES_ROOT / ARCHIVE
    for root_name, base in tree_roots.items():
        if not base.is_dir():
            continue
        allowed = ALLOWED_ARCHIVE_ROOT_FILES if root_name == ARCHIVE else set()
        for entry in sorted(base.iterdir()):
            if entry.name == ".gitkeep":
                continue
            if entry.is_file() and entry.name in allowed:
                continue
            if not entry.is_dir() or entry.name not in CLASSES:
                errors.append(f"structure: {root_name}/{entry.name} — unknown class folder "
                              f"(allowed: {', '.join(CLASSES)})")
                continue
            for p in sorted(entry.rglob("*")):
                if p.is_dir():
                    continue
                if p.name == ".gitkeep":
                    continue
                rel = p.relative_to(NOTES_ROOT).as_posix()
                if len(p.relative_to(base).parts) != 2 or p.suffix != ".md":
                    errors.append(f"structure: {rel} — notes live exactly at "
                                  f"{root_name}/<class>/yyyy-mm-dd-topic.md")
                    continue
                note = parse_note(p)
                if not note:
                    errors.append(f"structure: {rel} — filename must be yyyy-mm-dd-topic-title.md "
                                  "(date first, lowercase slug)")
                    continue
                notes.append(note)
    return notes


def verify_format(note: dict, errors: list[str]) -> None:
    rel = note["rel"]
    fail_msg = lambda msg: errors.append(f"format: {rel} — {msg}")  # noqa: E731
    lines = note["path"].read_text(encoding="utf-8").split("\n")
    prose = read_prose(note["path"])
    lifecycle = "implemented" if note["lifecycle"] == ARCHIVE else note["lifecycle"]

    if not re.match(r"^# Agent Note: \S", lines[0]):
        fail_msg("line 1 must be `# Agent Note: <title>`")
    if lines[1] != "":
        fail_msg("line 2 must be blank")
    grammar = STATUS_GRAMMAR[lifecycle]
    if not grammar.match(lines[2]):
        fail_msg(f"line 3 must match the {lifecycle} status grammar ({grammar.pattern})")
    if not SCOPE_LINE_RE.match(lines[3]):
        fail_msg("line 4 must be `Scope: <comma-separated repo-relative paths>`")
    else:
        for s in [x.strip() for x in SCOPE_LINE_RE.match(lines[3]).group(1).split(",")]:
            if not s:
                fail_msg("Scope has an empty entry")
            elif "\\" in s:
                fail_msg(f"Scope entry {s!r} must use forward slashes")
    if note["lifecycle"] == ARCHIVE:
        m = ARCHIVED_LINE_RE.match(lines[4])
        if not m:
            fail_msg("line 5 must be `Archived: YYYY-MM-DD`")
        elif lines[5] != "":
            fail_msg("line 6 must be blank")
    elif lines[4] != "":
        fail_msg("line 5 must be blank")

    header_tokens = ("Status:", "Scope:", "Archived:")
    for tok in header_tokens:
        occurrences = [l for l in prose if l.startswith(tok)]
        expected = 1 + (1 if tok == "Archived:" and note["lifecycle"] == ARCHIVE else 0)
        if len(occurrences) > expected:
            fail_msg(f"`{tok}` must appear only in the header block")

    h2s = [l for l in prose if l.startswith("## ")]
    if not h2s or h2s[0].rstrip() != "## Problem":
        fail_msg(f"the first section must be `## Problem` (got {h2s[0] if h2s else '<none>'!r})")
    for required in REQUIRED_SECTIONS[lifecycle]:
        if required not in h2s:
            fail_msg(f"missing the required `{required}` section")
    if lifecycle == "implemented":
        for h2 in h2s:
            if BANNED_IMPLEMENTED_RE.match(h2):
                fail_msg(f"`{h2}` is a proposal-era heading; an implemented Agent Note states "
                         "what is (fold it into Decision/Consequences/Testing)")
    if "## Alternatives considered" not in h2s:
        fail_msg("missing `## Alternatives considered` — a decision recorded without what "
                 "it beat invites re-litigation")


def verify_manifest(errors: list[str]) -> None:
    p = manifest_path()
    if not p.is_file():
        errors.append("archive: manifest.json is missing under archived/")
        return
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        errors.append(f"archive: manifest.json is not valid JSON ({e})")
        return
    if data.get("version") != 1:
        errors.append("archive: manifest.json version must be 1")
    files = data.get("files", {})
    actual: dict[str, str] = {}
    base = NOTES_ROOT / ARCHIVE
    if base.is_dir():
        for f in sorted(base.rglob("*.md")):
            if len(f.relative_to(base).parts) == 2:
                actual[f.relative_to(base).as_posix()] = sha256_of(f)
    for key in sorted(set(files) - set(actual)):
        errors.append(f"archive: {key} is in the manifest but missing on disk — frozen "
                      "files are append-only, never deleted")
    for key in sorted(set(actual) - set(files)):
        errors.append(f"archive: {key} is not sealed in the manifest — move it with "
                      "`notes.py move <note> archived`")
    for key in sorted(set(files) & set(actual)):
        if files[key] != actual[key]:
            errors.append(f"archive: {key} content hash mismatch — frozen files are never edited")


def verify_links(notes: list[dict], errors: list[str]) -> None:
    known = {n["path"].resolve() for n in notes}
    for note in notes:
        if note["lifecycle"] == ARCHIVE:
            continue  # frozen snapshots: outbound links rot as targets move on; the archive is one-way
        text = note["path"].read_text(encoding="utf-8")
        for link in MD_LINK_RE.findall(text):
            if not link.endswith(".md"):
                continue
            target = (note["path"].parent / link).resolve()
            if NOTES_ROOT.resolve() not in target.parents:
                continue  # link leaves the notes tree; not our gate
            if target not in known and not target.is_file():
                errors.append(f"link: {note['rel']} — `]({link})` does not resolve")


def cmd_verify(_: argparse.Namespace) -> None:
    errors: list[str] = []
    notes = verify_structure(errors)
    for note in notes:
        verify_format(note, errors)
    verify_manifest(errors)
    verify_links(notes, errors)
    if errors:
        print("verify: violations found:")
        for e in errors:
            print(f"  {e}")
        sys.exit(1)
    print(f"verify: {len(notes)} Agent Note(s) checked — tree, format, archive seal, "
          "and cross-links all conform to .trellis/notes/README.md")


# ── entry ───────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(prog="notes.py", description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("create", help="scaffold a note from the lifecycle skeleton")
    p.add_argument("lifecycle", choices=LIFECYCLES)
    p.add_argument("cls", metavar="class", choices=CLASSES)
    p.add_argument("title", nargs="+", help="note title (used for the filename slug)")
    p.add_argument("--scope", required=True, help="comma-separated repo-relative paths")
    p.add_argument("--reason", help="one-line verdict, required for rejected")
    p.set_defaults(fn=cmd_create)

    p = sub.add_parser("list", help="browse the tree")
    p.add_argument("pattern", nargs="?", help="substring filter on the filename")
    p.add_argument("--lifecycle", choices=LIFECYCLES + [ARCHIVE])
    p.add_argument("--class", dest="cls", choices=CLASSES)
    p.add_argument("--all", action="store_true", help="include archived/")
    p.set_defaults(fn=cmd_list)

    p = sub.add_parser("show", help="print one note")
    p.add_argument("note", help="filename, filename prefix, or path")
    p.set_defaults(fn=cmd_show)

    p = sub.add_parser("search", help="full-text search across the tree")
    p.add_argument("text")
    p.set_defaults(fn=cmd_search)

    p = sub.add_parser("history", help="all notes whose Scope covers a path, by date")
    p.add_argument("path", help="repo-relative path (prefix match, both directions)")
    p.set_defaults(fn=cmd_history)

    p = sub.add_parser("move", help="migrate a note between lifecycles")
    p.add_argument("note", help="filename, filename prefix, or path")
    p.add_argument("target", choices=LIFECYCLES + [ARCHIVE])
    p.add_argument("--reason", help="one-line verdict, required for proposed -> rejected")
    p.set_defaults(fn=cmd_move)

    p = sub.add_parser("verify", help="run all gates (tree, format, archive seal, links)")
    p.set_defaults(fn=cmd_verify)

    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
