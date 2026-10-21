# SPDX-License-Identifier: Apache-2.0
"""Roadmap: the build-order phases and steps, each with its checklist criteria and their live
state.

Sources of truth: ``docs/build-order.md`` (the phase tables, PUBLIC-NOW or SERVER by the section
they sit in; each phase's ``Checklist`` cell names its criteria; the step tables, ``P9.1`` under
``P9``), ``docs/checklist.md`` (every criterion row: id, statement, tag) and, when given, an
invariants results file (``hnx invariants run --out``, e.g. ``build/invariants/results.json``
from ``make invariants``): pass, fail, error or skip per criterion; a criterion with no result is
``untested``.  Both Markdown files are read with :mod:`.mdtables`, never copied.

A ``Checklist`` cell is a comma-separated list of: a section letter (``Q``: that section's rows
with the phase's own tag), a row id (``X-03``: that row, whatever its tag) or a range
(``F-09-F-11``).  A token that names no checklist row is reported, not dropped.  Every row no
phase names is listed as unphased, so the map cannot hide a criterion.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from . import svg
from .mdtables import parse_tables

STATES = ("pass", "fail", "error", "skip", "untested")
TAGS = ("PUBLIC-NOW", "SERVER")
_ID = re.compile(r"^([A-Z])-(\d{2})$")
_RANGE = re.compile(r"^([A-Z])-(\d{2})-([A-Z])-(\d{2})$")
_SECTION = re.compile(r"^([A-Z])\s+-\s+(.*)$")


def checklist_rows(text: str) -> list[dict[str, Any]]:
    """Every criterion row of ``docs/checklist.md``: id, section, statement, tag."""
    out = []
    for t in parse_tables(text):
        if not t.header or t.header[0] != "ID" or "Tag" not in t.header:
            continue
        m = _SECTION.match(t.heading)
        for r in t.records():
            if not _ID.match(r["ID"]):
                continue
            out.append(
                {
                    "id": r["ID"],
                    "section": r["ID"][0],
                    "section_title": m.group(2) if m else t.heading,
                    "statement": r.get("Must be true", ""),
                    "tag": r["Tag"],
                }
            )
    return out


def _tag_of(headings: Sequence[str]) -> str | None:
    for h in reversed(headings):
        for tag in TAGS:
            if tag in h:
                return tag
    return None


def _expand(
    cell: str, tag: str | None, rows: Sequence[Mapping[str, Any]]
) -> tuple[list[str], list[str]]:
    """(criterion ids, unknown tokens) for one ``Checklist`` cell."""
    ids, bad = [], []
    known = {r["id"] for r in rows}
    for raw in re.split(r"[,;]", cell):
        tok = raw.strip().strip("`").strip()
        if not tok or tok in ("-", "none"):
            continue
        if re.fullmatch(r"[A-Z]", tok):
            got = [
                r["id"] for r in rows if r["section"] == tok and (tag is None or r["tag"] == tag)
            ]
        elif _ID.match(tok):
            got = [tok] if tok in known else []
        elif m := _RANGE.match(tok):
            a, lo, b, hi = m.group(1), int(m.group(2)), m.group(3), int(m.group(4))
            got = [
                r["id"]
                for r in rows
                if a == b and r["section"] == a and lo <= int(r["id"][2:]) <= hi
            ]
        else:
            got = []
        if got:
            ids += got
        else:
            bad.append(tok)
    return list(dict.fromkeys(ids)), bad


def _status(results: Mapping[str, Any] | None, cid: str) -> str:
    if not results:
        return "untested"
    r = (results.get("results") or {}).get(cid)
    s = r.get("status") if isinstance(r, Mapping) else None
    return s if s in STATES else "untested"


def _counts(statuses: Sequence[str]) -> dict[str, int]:
    return {"total": len(statuses), **{s: statuses.count(s) for s in STATES}}


def build(
    build_order: str, checklist: str, results: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    """The roadmap view-model from the two Markdown texts and an optional results document."""
    rows = checklist_rows(checklist)
    by_id = {r["id"]: r for r in rows}
    tables = parse_tables(build_order)
    steps: dict[str, list[dict[str, str]]] = {}
    for t in tables:
        if t.header and t.header[0] == "Step":
            for r in t.records():
                sid = r["Step"]
                steps.setdefault(sid.split(".", 1)[0], []).append(
                    {
                        "id": sid,
                        "deliverable": r.get("Deliverable", ""),
                        "exit": r.get("Exit criterion", ""),
                    }
                )
    phases, problems, named = [], [], set()
    for t in tables:
        if not t.header or t.header[0] != "Phase":
            continue
        tag = _tag_of(t.headings)
        for r in t.records():
            pid = r["Phase"]
            ids, bad = _expand(r.get("Checklist", ""), tag, rows)
            problems += [f"{pid}: {tok!r} names no checklist row" for tok in bad]
            if "Checklist" not in r:
                problems.append(f"{pid}: the phase table has no Checklist column")
            named |= set(ids)
            crit = [
                {
                    **{k: by_id[i][k] for k in ("id", "statement", "tag")},
                    "status": _status(results, i),
                }
                for i in ids
            ]
            phases.append(
                {
                    "id": pid,
                    "tag": tag,
                    "goal": r.get("Goal", ""),
                    "steps": steps.get(pid, []),
                    "criteria": crit,
                    "counts": _counts([c["status"] for c in crit]),
                }
            )
    unphased = [
        {**{k: r[k] for k in ("id", "statement", "tag")}, "status": _status(results, r["id"])}
        for r in rows
        if r["id"] not in named
    ]
    return {
        "phases": phases,
        "unphased": unphased,
        "unphased_counts": _counts([c["status"] for c in unphased]),
        "results": None if results is None else {"last_run": results.get("last_run")},
        "problems": problems,
    }


def load_results(path: str | Path | None) -> tuple[dict[str, Any] | None, str | None]:
    """(results document, None) or (None, why it could not be read); (None, None) without one."""
    if not path:
        return None, None
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return None, f"cannot read the invariants results {path}: {exc}"
    if not isinstance(doc, dict) or not isinstance(doc.get("results"), dict):
        return None, f"{path}: not an invariants results document (no results object)"
    return doc, None


def load(root: str | Path, results_path: str | Path | None = None) -> dict[str, Any]:
    """:func:`build` over a checkout (``docs/build-order.md``, ``docs/checklist.md``)."""
    r = Path(root)
    results, err = load_results(results_path)
    vm = build(
        (r / "docs" / "build-order.md").read_text(encoding="utf-8"),
        (r / "docs" / "checklist.md").read_text(encoding="utf-8"),
        results,
    )
    if err:
        vm["problems"].insert(0, err)
    return vm


# ------------------------------------------------------------------------------------ render
LABEL_W, BAR_W, ROW_H = 330, 380, 36
_CHIP = {"pass": "ok", "fail": "fail", "error": "unknown", "skip": "stale", "untested": "unknown"}


def _bar_row(y: int, label: str, sub: str, counts: Mapping[str, int]) -> list[str]:
    out = [
        svg.text(8, y + 13, label, width=LABEL_W - 12),
        svg.text(8, y + 26, sub, width=LABEL_W - 12, cls="sub"),
    ]
    x, total = LABEL_W, counts["total"]
    out.append(f'<rect class="track" x="{x}" y="{y + 6}" width="{BAR_W}" height="16" rx="3"/>')
    if total:
        used = 0
        for s in STATES:
            n = counts[s]
            if not n:
                continue
            w = BAR_W * (used + n) // total - BAR_W * used // total
            out.append(
                f"<g><title>{svg.e(f'{label}: {n} {s}')}</title>"
                f'<rect class="f-{s}" x="{x + BAR_W * used // total}" y="{y + 6}" width="{w}" '
                'height="16"/></g>'
            )
            used += n
    done = f"{counts['pass']}/{total} pass" if total else "no criteria named"
    out.append(svg.text(x + BAR_W + 10, y + 19, done, width=150))
    return out


def _bars_svg(vm: Mapping[str, Any]) -> str:
    body, y = [], 6
    for p in vm["phases"]:
        body += _bar_row(y, f"{p['id']} {p['goal']}", p["tag"] or "untagged", p["counts"])
        y += ROW_H
    if vm["unphased"]:
        body += _bar_row(y, "Unphased", "named by no phase", vm["unphased_counts"])
        y += ROW_H
    desc = (
        f"{len(vm['phases'])} build phases, one bar each: the share of the phase's checklist "
        "criteria that pass, fail, error, skip or have no result yet. "
        + (
            "No invariants results were given, so every criterion is untested. "
            if vm["results"] is None
            else ""
        )
        + "The tables below list every criterion and its state."
    )
    width = LABEL_W + BAR_W + 170
    return svg.svg("roadmap", width, y + 6, "Roadmap progress by phase", desc, body)


def _crit_rows(crit: Sequence[Mapping[str, Any]]) -> list[tuple[str, ...]]:
    return [
        (
            svg.code(c["id"]),
            svg.e(c["statement"]),
            svg.e(c["tag"]),
            f'<span class="s {_CHIP[c["status"]]}">{svg.e(c["status"])}</span>',
        )
        for c in crit
    ]


def render(vm: Mapping[str, Any]) -> str:
    res = vm["results"]
    head = (
        f'<p class="muted">invariants results of {svg.e(res.get("last_run") or "an unknown date")}</p>'
        if res is not None
        else '<p class="muted">no invariants results given: every criterion reads untested '
        "(<code>make invariants</code> writes <code>build/invariants/results.json</code>)</p>"
    )
    probs = "".join(f"<li>{svg.e(p)}</li>" for p in vm["problems"])
    parts = [head, f'<ul class="fail">{probs}</ul>' if probs else "", _bars_svg(vm)]
    for p in vm["phases"]:
        c = p["counts"]
        parts.append(
            f"<h3>{svg.e(p['id'])} {svg.e(p['goal'])} "
            f'<span class="muted">{svg.e(p["tag"] or "")} &middot; {c["pass"]}/{c["total"]} pass</span></h3>'
        )
        if p["steps"]:
            parts.append(
                svg.table(
                    f"{p['id']} steps",
                    ("Step", "Deliverable", "Exit criterion"),
                    [
                        (svg.code(s["id"]), svg.e(s["deliverable"]), svg.e(s["exit"]))
                        for s in p["steps"]
                    ],
                )
            )
        parts.append(
            svg.table(
                f"{p['id']} criteria",
                ("Criterion", "Must be true", "Tag", "State"),
                _crit_rows(p["criteria"]),
            )
        )
    if vm["unphased"]:
        parts.append("<h3>Unphased criteria</h3>")
        parts.append(
            svg.table(
                "Criteria no phase names",
                ("Criterion", "Must be true", "Tag", "State"),
                _crit_rows(vm["unphased"]),
            )
        )
    return "".join(parts)
