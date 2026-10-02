#!/usr/bin/env python3
"""Spec gates for the project-level layers (prd / arch / cdd).

Philosophy: the gate guards the skeleton, templates guide the flesh.
- Hard (machine-checked): each layer's index.md — required sections, the
  document inventory (registry ↔ actual files, both directions), and the
  two-tense word lists over every .md and .md.template.
- Soft (template-guided): body-document shape, including the arch module
  map. Writers follow the *.md.template files placed next to the
  documents; the gate does NOT enforce field syntax, ordering, ids,
  cross-references, or table shapes in bodies.

Gates:
- layer structure: index.md exists with its required sections; flat layout
  (subdirectories are rejected loudly, not ignored)
- inventory: registered files ↔ actual files, both directions; every
  inventory line is `- path — note`
- word lists: no past-tense debris (history lives in .trellis/notes/),
  no meta-talk filler; scans every layer .md plus .md.template

Unknown shapes fail loudly; nothing is silently skipped. The readable
contract lives in each layer's index.md (## 文档格式); this script only
executes it. Exit code 1 on any violation.
"""

import re
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
SPEC_ROOT = SCRIPT_DIR.parent / "spec"

LAYERS = ["prd", "arch", "cdd"]
INDEX_REQUIRED_SECTIONS = ["文档清单", "Pre-Development Checklist", "文档格式"]
PLACEHOLDER = "本层暂无文档."
INV_RE = re.compile(r"^-\s+(\S+\.md)(?:\s+(?:—|-)\s*.*)?$")

# Past-tense debris: history lives in .trellis/notes/, spec is present tense.
PAST_TENSE_WORDS = [
    "曾经", "原先", "早先", "后来", "改为", "变更为", "重命名为", "历史上",
    "遗留", "旧版", "旧的", "used to", "previously", "formerly", "originally",
    "was renamed", "used to be",
]
# Meta-talk filler: self-referential throat-clearing and praise.
META_WORDS = [
    "本文档旨在", "本文将", "本文旨在", "值得注意的是", "需要注意的是",
    "需要强调的是", "总而言之", "综上所述", "众所周知", "不难看出",
    "优雅", "强大",
]


def read_lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").split("\n")


def strip_code_fences(lines: list[str]) -> list[str]:
    out, in_fence = [], False
    for line in lines:
        if line.startswith("```"):
            in_fence = not in_fence
            continue
        if not in_fence:
            out.append(line)
    return out


def section(lines: list[str], heading: str) -> list[str] | None:
    """Lines of the first `## heading` section (heading exclusive), or None."""
    start = None
    for i, line in enumerate(lines):
        if line.strip() == f"## {heading}":
            start = i + 1
            break
    if start is None:
        return None
    end = len(lines)
    for i in range(start, len(lines)):
        if lines[i].startswith("## "):
            end = i
            break
    return lines[start:end]


def layer_dir(layer: str) -> Path:
    return SPEC_ROOT / layer


def body_docs(layer: str) -> list[Path]:
    d = layer_dir(layer)
    if not d.is_dir():
        return []
    return sorted(p for p in d.glob("*.md") if p.name != "index.md")


def template_files(layer: str) -> list[Path]:
    d = layer_dir(layer)
    if not d.is_dir():
        return []
    return sorted(d.glob("*.md.template"))


# ── layer structure ─────────────────────────────────────────────────────

def gate_structure(layer: str, errors: list[str]) -> None:
    d = layer_dir(layer)
    index = d / "index.md"
    if not index.is_file():
        errors.append(f"{layer}: index.md is missing — the layer has no checkpoint")
        return
    lines = strip_code_fences(read_lines(index))
    for heading in INDEX_REQUIRED_SECTIONS:
        if section(lines, heading) is None:
            errors.append(f"{layer}/index.md: missing the required `## {heading}` section")
    for entry in sorted(d.iterdir()):
        if entry.is_dir():
            errors.append(f"{layer}/{entry.name}/: subdirectories are not supported — "
                          "keep documents flat and register them in index.md")


# ── inventory (the registry) ────────────────────────────────────────────

def gate_inventory(layer: str, errors: list[str]) -> dict[str, Path]:
    """Return {filename: path} for registered body documents."""
    index = layer_dir(layer) / "index.md"
    registry: dict[str, Path] = {}
    inv = section(strip_code_fences(read_lines(index)), "文档清单") or []
    entries: set[str] = set()
    has_placeholder = False
    for raw in inv:
        line = raw.strip()
        if not line:
            continue
        if line.lstrip("- ").strip() == PLACEHOLDER:
            has_placeholder = True
            continue
        m = INV_RE.match(line)
        if not m:
            errors.append(f"{layer}/index.md: inventory line not parseable: {line!r} "
                          "(expected `- path — note`)")
            continue
        entries.add(m.group(1))
    if has_placeholder and entries:
        errors.append(f"{layer}/index.md: placeholder `{PLACEHOLDER}` coexists with entries")
    actual = {p.name for p in body_docs(layer)}
    for name in sorted(entries - actual):
        errors.append(f"{layer}/index.md: inventory lists {name} but the file does not exist")
    for name in sorted(actual - entries):
        errors.append(f"{layer}/index.md: {name} exists but is not in the inventory")
    for name in sorted(entries & actual):
        registry[name] = layer_dir(layer) / name
    # Free-form .md mentions outside the inventory block are prose, not registry.
    return registry


# ── word lists ──────────────────────────────────────────────────────────

def gate_word_lists(layer: str, errors: list[str]) -> None:
    docs = [layer_dir(layer) / "index.md", *body_docs(layer), *template_files(layer)]
    for path in docs:
        if not path.is_file():
            continue
        for i, line in enumerate(strip_code_fences(read_lines(path)), 1):
            low = line.lower()
            for w in PAST_TENSE_WORDS:
                if w in line or w in low:
                    errors.append(f"{layer}/{path.name}:{i}: past-tense debris {w!r} — "
                                  "history belongs in .trellis/notes/")
                    break
            for w in META_WORDS:
                if w in line:
                    errors.append(f"{layer}/{path.name}:{i}: meta-talk {w!r} — "
                                  "state the fact, drop the filler")
                    break


def main() -> None:
    errors: list[str] = []
    if not SPEC_ROOT.is_dir():
        print("verify_spec: .trellis/spec/ does not exist")
        sys.exit(1)
    checked = 0
    for layer in LAYERS:
        if not layer_dir(layer).is_dir():
            continue
        gate_structure(layer, errors)
        gate_inventory(layer, errors)
        gate_word_lists(layer, errors)
        checked += 1 + len(body_docs(layer)) + len(template_files(layer))
    if errors:
        print("verify_spec: violations found:")
        for e in errors:
            print(f"  {e}")
        sys.exit(1)
    print(f"verify_spec: {checked} document(s) checked across prd/arch/cdd — "
          "structure, inventory, and word lists all conform")


if __name__ == "__main__":
    main()
