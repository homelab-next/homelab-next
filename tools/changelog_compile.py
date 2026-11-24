#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: changelog-compile
#   kind: tool
#   purpose: Fold the per-PR fragments in changelog.d/ into the [Unreleased] section of CHANGELOG.md and delete them.
#   owner: maintainers
#   trigger: [make:changelog-compile]
#   inputs: the fragment files of the changelog.d directory, and CHANGELOG.md
#   outputs: the updated CHANGELOG.md; the folded fragments are removed; one line per fragment on stdout
#   exit:
#     "0": folded (or nothing to fold), or --check found every fragment well formed
#     "1": a fragment is malformed or CHANGELOG.md has no [Unreleased] section; nothing was changed
#     "2": a path cannot be read or written
"""Fold changelog fragments into CHANGELOG.md.

A PR adds ``changelog.d/<slug>.md`` instead of editing CHANGELOG.md, so two PRs never touch the
same lines. A fragment is one entry: optional front matter ``group: Added|Changed|Fixed|Breaking``
(default ``Added``), then the entry text (a leading ``- `` is optional). Whoever cuts a release
runs this first; the entries land at the top of their group in ``## [Unreleased]`` (oldest slug
first, so the newest fragment name ends up lowest of the batch and existing entries stay below),
and the fragments are deleted. ``--check`` only validates them.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHANGELOG_NAME = "CHANGELOG.md"
GROUPS = ("Added", "Changed", "Fixed", "Breaking")
_FRONT = re.compile(r"\A---\n(.*?)\n---\n", re.S)


class FragmentError(Exception):
    """A fragment is malformed (exit 1)."""


def parse_fragment(name: str, text: str) -> tuple[str, str]:
    """Return (group, entry) for one fragment, or raise FragmentError naming it."""
    group = "Added"
    m = _FRONT.match(text)
    if m:
        for line in m.group(1).splitlines():
            key, _, value = line.partition(":")
            if key.strip() != "group":
                raise FragmentError(f"{name}: unknown front-matter key {key.strip()!r}")
            group = value.strip()
        text = text[m.end() :]
    if group not in GROUPS:
        raise FragmentError(f"{name}: group {group!r} is not one of {', '.join(GROUPS)}")
    body = text.strip()
    if not body:
        raise FragmentError(f"{name}: empty entry")
    if "\n## " in "\n" + body or "\n### " in "\n" + body:
        raise FragmentError(f"{name}: an entry must not contain headings")
    if not body.startswith("- "):
        body = "- " + body
    return group, body


def fragments(root: Path) -> list[Path]:
    d = root / "changelog.d"
    if not d.is_dir():
        return []
    return sorted(p for p in d.glob("*.md") if p.is_file() and not p.is_symlink())


def fold(changelog: str, entries: dict[str, list[str]]) -> str:
    """Insert each group's entries at the top of that group inside [Unreleased]."""
    start = changelog.find("## [Unreleased]")
    if start < 0:
        raise FragmentError("CHANGELOG.md has no [Unreleased] section")
    nxt = re.search(r"^## \[", changelog[start + 1 :], re.M)
    end = start + 1 + nxt.start() if nxt else len(changelog)
    section = changelog[start:end]
    for group in GROUPS:
        items = entries.get(group)
        if not items:
            continue
        block = "\n".join(items) + "\n"
        head = f"### {group}\n"
        i = section.find("\n" + head)
        if i >= 0:
            at = i + 1 + len(head)
            section = section[:at] + block + section[at:]
        else:
            line_end = section.index("\n") + 1
            section = section[:line_end] + f"\n{head}{block}" + section[line_end:]
    return changelog[:start] + section + changelog[end:]


def write_text(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def main(argv: list[str] | None = None, root: Path = ROOT) -> int:
    args = sys.argv[1:] if argv is None else argv
    check_only = "--check" in args
    paths = [a for a in args if not a.startswith("--")]
    changelog_path = Path(paths[0]) if paths else root / CHANGELOG_NAME
    files = fragments(root)
    entries: dict[str, list[str]] = {}
    try:
        for p in files:
            group, entry = parse_fragment(p.name, p.read_text(encoding="utf-8"))
            entries.setdefault(group, []).append(entry)
        if not files:
            print("changelog-compile: no fragments")
            return 0
        if check_only:
            print(f"changelog-compile: {len(files)} fragment(s) well formed")
            return 0
        new = fold(changelog_path.read_text(encoding="utf-8"), entries)
    except FragmentError as exc:
        print(f"changelog-compile: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"changelog-compile: {exc}", file=sys.stderr)
        return 2
    try:
        write_text(changelog_path, new)
        for p in files:
            p.unlink()
            print(f"changelog-compile: folded {p.name}")
    except OSError as exc:
        print(f"changelog-compile: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
