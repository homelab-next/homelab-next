#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: licence-check
#   kind: check
#   purpose: Fail when a pinned Python package or a compose image has no reviewed licence entry, or a linked one is copyleft.
#   owner: maintainers
#   trigger: [ci:ci/schemas, make:licence-check]
#   inputs: constraints/*.txt, compose/**/docker-compose*.yml and tools/licences.yml
#   outputs: one line per problem; a summary line
#   exit:
#     "0": every pin and image listed, none refused
#     "1": an unlisted pin or image, a stale or malformed entry, or a copyleft linked package
#     "2": the register cannot be read
"""Gate: ADR-0011's licence rule, checked against what is pinned and deployed.

Every package ``constraints/*.txt`` pins (``name==version``) and every image a compose stack
under ``compose/`` runs (its repository, less tag and digest) must have an entry in
``tools/licences.yml``: its licence as an SPDX expression and its ``kind``.  A ``linked``
package may not be copyleft (GPL, AGPL or SSPL in every alternative of its expression; LGPL and
MPL are allowed unmodified); a ``tool`` or ``service`` may be, and says why in its ``reason``.
An entry that nothing pins any more is stale and fails too, so the register is exactly what is
in use.  CI's dependency review reads the licence of each dependency a pull request changes;
this gate covers what is already pinned and the images, which that review does not see.

Usage: python tools/licence_check.py [--root DIR]
Exit: 0 clean, 1 problems, 2 the register cannot be read.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
REGISTER = "tools/licences.yml"
#: the copyleft families ADR-0011 decision 4 refuses for linked code (LGPL is not one of them)
REFUSED = ("GPL", "AGPL", "SSPL")
KINDS = {"python": ("linked", "tool"), "images": ("service",)}
_PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==", re.M)
_IMAGE = re.compile(r"^\s*image:\s*['\"]?([^'\"\s#]+)", re.M)
_TERM = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+-]*$")


def normalise(name: str) -> str:
    """A Python distribution name as PEP 503 compares them."""
    return re.sub(r"[-_.]+", "-", name).lower()


def pins(root: Path) -> set[str]:
    return {
        normalise(m[1])
        for f in sorted((root / "constraints").glob("*.txt"))
        for m in _PIN.finditer(f.read_text(encoding="utf-8"))
    }


def repository(ref: str) -> str:
    """An image reference less its digest and tag: ``host/name:tag@sha256:...`` -> ``host/name``."""
    ref = ref.split("@", 1)[0]
    head, _, last = ref.rpartition("/")
    return f"{head}/{last.split(':', 1)[0]}" if head else last.split(":", 1)[0]


def images(root: Path) -> dict[str, str]:
    """Each image repository a compose stack runs -> the first file that names it."""
    out: dict[str, str] = {}
    for f in sorted((root / "compose").glob("**/docker-compose*.yml")):
        for m in _IMAGE.finditer(f.read_text(encoding="utf-8")):
            out.setdefault(m[1], f.relative_to(root).as_posix())
    return out


def alternatives(expr: str) -> list[list[str]] | None:
    """An SPDX expression as its OR-alternatives, each a list of AND-ed ids (None: malformed)."""
    if not isinstance(expr, str) or "(" in expr or ")" in expr:
        return None
    alts = [[t.strip() for t in alt.split(" AND ")] for alt in expr.split(" OR ")]
    if any(not _TERM.match(t) for alt in alts for t in alt):
        return None
    return alts


def copyleft(expr: str) -> bool:
    """True when every alternative of ``expr`` holds a refused copyleft licence."""
    alts = alternatives(expr) or []
    return bool(alts) and all(
        any(re.match(rf"^{fam}-", t) for t in alt for fam in REFUSED) for alt in alts
    )


def check(root: Path) -> list[str]:
    reg = yaml.safe_load((root / REGISTER).read_text(encoding="utf-8")) or {}
    if not isinstance(reg, dict) or set(reg) - set(KINDS):
        raise ValueError(f"{REGISTER}: the top level holds only {', '.join(KINDS)}")
    used = {"python": dict.fromkeys(pins(root), "constraints/"), "images": {}}
    for ref, where in images(root).items():
        if "$" in ref:
            used["images"][ref] = where  # reported below: an interpolated image cannot be listed
        else:
            used["images"][repository(ref)] = where
    out = []
    for section, kinds in KINDS.items():
        entries = reg.get(section) or {}
        if not isinstance(entries, dict):
            raise ValueError(f"{REGISTER}: {section} must be a mapping")
        for name, where in sorted(used[section].items()):
            if "$" in name:
                out.append(f"{where}: image {name} is interpolated; name it literally")
            elif name not in entries:
                out.append(f"{section}: {name} ({where}) has no entry in {REGISTER}")
        for name, entry in sorted(entries.items()):
            label = f"{REGISTER}: {section}.{name}"
            if name not in used[section]:
                out.append(f"{label}: nothing pins or runs it; remove the entry")
                continue
            if not isinstance(entry, dict) or set(entry) - {"spdx", "kind", "reason"}:
                out.append(f"{label}: must be {{spdx, kind, reason}}")
                continue
            kind, spdx = entry.get("kind"), entry.get("spdx")
            if kind not in kinds:
                out.append(f"{label}: kind must be one of {', '.join(kinds)}")
            if alternatives(spdx) is None:
                out.append(f"{label}: spdx {spdx!r} is not ids joined by AND or OR")
            elif kind == "linked" and copyleft(spdx):
                out.append(
                    f"{label}: {spdx} is copyleft, which ADR-0011 refuses for linked code; "
                    "replace it, or (if it only ever runs as its own program) make it a tool"
                )
            if kind != "linked" and not str(entry.get("reason") or "").strip():
                out.append(f"{label}: a {kind} needs a reason")
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", type=Path, default=REPO_ROOT)
    args = ap.parse_args(argv)
    try:
        problems = check(args.root)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        print(f"licence_check: {exc}", file=sys.stderr)
        return 2
    for p in problems:
        print(f"licence_check: {p}", file=sys.stderr)
    if problems:
        return 1
    n = len(pins(args.root)), len({repository(r) for r in images(args.root)})
    print(f"licence_check: {n[0]} pinned packages and {n[1]} images, each with a reviewed licence")
    return 0


if __name__ == "__main__":
    sys.exit(main())
