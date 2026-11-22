# SPDX-License-Identifier: Apache-2.0
"""Load, check and render the cutover ledger.

A ledger is a directory of record files, ``<root>/<uid>.md`` (YAML front matter validated by
``schemas/registers/cutover_row.schema.json``; the body is free prose), each with an optional
``<uid>.events/`` sidecar of ``transition`` events (``register_event``).  A row's state is NOT a
field: it is the fold of its transition events, starting at ``old``; a transition whose ``from`` is
not the current state is a problem (ADR-0043 decision 2).

What this module checks (``check_ledger``) is the part of ADR-0043 decision 4 that needs no
decider: schema, uid = file name, an ``old`` name claimed by two rows, a dangling or cyclic
``requires``, a state that is impossible for the row (``new-primary`` or ``old-retired`` of a
``carry``/``replace`` row without its data and consumer checks, ``new-primary`` while a ``requires``
row is not), and ``gate: none-yet`` on a row past ``new-shadow``.  It does not apply transitions or
review them: the decider gates (ADR-0043 step 5) are the follow-up, and until then every ledger
change is operator-merged.

Derived, never stored: ``soaking`` (old side stopped, ``soak_ends`` still ahead), and the
``blockers`` of a row (what stands between it and the next state).
"""

from __future__ import annotations

import datetime as dt
import json
import pathlib
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

import yaml

from homelabnext._yaml import UniqueKeyLoader
from homelabnext.registers import events as ev

STATES = ("old", "new-shadow", "new-primary", "old-retired")
#: transitions the state machine allows (decision 2): the rollback and the close included
ALLOWED = {
    ("old", "new-shadow"),
    ("new-shadow", "new-primary"),
    ("new-primary", "old-retired"),
    ("new-primary", "new-shadow"),  # rollback
    ("old", "old-retired"),  # close (drop or retire only)
}
REPORT_SCHEMA = "homelabnext.cutover.report/1"
_FRONT = re.compile(r"\A---\n(.*?)\n---\n?(.*)\Z", re.S)


@dataclass
class Row:
    uid: str
    path: pathlib.Path
    doc: dict[str, Any]
    state: str = "old"
    history: list[tuple[str, str, str]] = field(default_factory=list)  # (date, from, to)
    problems: list[str] = field(default_factory=list)

    def get(self, key: str, default=None):
        return self.doc.get(key, default)

    @property
    def disposition(self) -> str:
        return str(self.doc.get("disposition"))

    def check_status(self, name: str) -> str:
        return str((self.doc.get("checks") or {}).get(name, {}).get("status", "pending"))

    def soaking(self, today: dt.date) -> bool:
        end = self.doc.get("soak_ends")
        return bool(end) and self.state in ("new-primary", "old-retired") and _date(end) > today

    def blockers(self, today: dt.date) -> list[str]:
        """What stands between this row and being finished (old-retired, or a settled decision)."""
        out: list[str] = []
        d = self.disposition
        if d == "undecided":
            out.append("undecided: no disposition recorded")
        if self.doc.get("hold"):
            out.append("held: " + str(self.doc["hold"].get("reason")))
        if self.doc.get("gate") == "none-yet":
            out.append("gate none-yet: the capability has no conformance suite")
        if d in ("carry", "replace"):
            for name in ("data_verified", "consumers_repointed"):
                if self.state != "old-retired" and self.check_status(name) not in ("pass", "na"):
                    out.append(f"{name}: {self.check_status(name)}")
        if self.soaking(today):
            out.append(f"soaking until {self.doc['soak_ends']}")
        if self.state != "old-retired" and d != "undecided":
            out.append(f"state {self.state}: old side not yet retired")
        return out


@dataclass
class Ledger:
    root: pathlib.Path
    rows: dict[str, Row]
    problems: list[str]


def _date(v) -> dt.date:
    return v if isinstance(v, dt.date) else dt.date.fromisoformat(str(v))


def _split(text: str, name: str) -> tuple[dict, str]:
    m = _FRONT.match(text)
    if not m:
        raise ValueError(f"{name}: no YAML front matter")
    doc = yaml.load(m.group(1), Loader=UniqueKeyLoader)
    if not isinstance(doc, dict):
        raise ValueError(f"{name}: front matter must be a mapping")
    return json.loads(json.dumps(doc, default=str)), m.group(2)


def _validator():
    from homelabnext.schema_registry import validator

    return validator("registers", "cutover_row.schema.json")


def fold_state(events: Iterable[ev.Event], base: str = "old") -> tuple[str, list, list[str]]:
    """The state after every transition event, in order, with the history and any problem."""
    state, hist, problems = base, [], []
    for e in sorted(events, key=lambda e: e.sort_key()):
        if e.kind != "transition":
            continue
        frm, to = str(e.data.get("from")), str(e.data.get("to"))
        if frm != state:
            problems.append(f"{e.name}: transition from {frm!r} but the row is {state!r}")
            continue
        if to not in STATES:
            problems.append(f"{e.name}: {to!r} is not a cutover state ({', '.join(STATES)})")
            continue
        if (frm, to) not in ALLOWED:
            problems.append(f"{e.name}: {frm} -> {to} is not an allowed transition")
            continue
        hist.append((str(e.data.get("date")), frm, to))
        state = to
    return state, hist, problems


def load_ledger(root) -> Ledger:
    root = pathlib.Path(root)
    rows: dict[str, Row] = {}
    problems: list[str] = []
    if not root.is_dir():
        return Ledger(root, rows, [f"{root}: no such ledger directory"])
    v = _validator()
    for p in sorted(root.glob("*.md")):
        try:
            doc, _ = _split(p.read_text(encoding="utf-8"), p.name)
        except ValueError as exc:
            problems.append(str(exc))
            continue
        row = Row(uid=str(doc.get("uid")), path=p, doc=doc)
        for e in sorted(v.iter_errors(doc), key=lambda e: list(map(str, e.absolute_path))):
            row.problems.append(
                f"{p.name}: {'/'.join(map(str, e.absolute_path)) or '$'}: {e.message}"
            )
        if row.uid != p.stem:
            row.problems.append(f"{p.name}: uid {row.uid!r} is not the file name")
        if row.uid in rows:
            row.problems.append(f"{p.name}: uid {row.uid} is claimed by two files")
        ev_problems: list[str] = []
        events = ev.read_events(ev.events_dir(p), ev_problems)
        row.problems += [f"{p.name}: {x}" for x in ev_problems]
        row.state, row.history, st_problems = fold_state(events)
        row.problems += [f"{p.name}: {x}" for x in st_problems]
        rows[row.uid] = row
    return Ledger(root, rows, problems)


def _cycle(rows: dict[str, Row]) -> list[str]:
    seen: dict[str, int] = {}
    out: list[str] = []

    def visit(u: str, trail: list[str]) -> None:
        seen[u] = 1
        for r in rows[u].get("requires", []) or []:
            if r not in rows:
                continue
            if seen.get(r) == 1:
                out.append(" -> ".join([*trail, u, r]))
            elif r not in seen:
                visit(r, [*trail, u])
        seen[u] = 2

    for u in rows:
        if u not in seen:
            visit(u, [])
    return out


def check_ledger(ledger: Ledger, today: dt.date | None = None) -> list[str]:
    """Every problem with the ledger as a whole (an empty list is a clean ledger)."""
    out = list(ledger.problems)
    rows = ledger.rows
    for r in rows.values():
        out += r.problems
    claimed: dict[str, str] = {}
    for r in rows.values():
        for name in r.get("old", []) or []:
            if name in claimed and claimed[name] != r.uid:
                out.append(f"old name {name!r} is claimed by two rows: {claimed[name]}, {r.uid}")
            claimed[name] = r.uid
    for r in rows.values():
        for q in r.get("requires", []) or []:
            if q not in rows:
                out.append(f"{r.uid}: requires {q}, which is not a row")
            elif r.state in ("new-primary", "old-retired") and rows[q].state not in (
                "new-primary",
                "old-retired",
            ):
                out.append(f"{r.uid}: {r.state} while required row {q} is {rows[q].state}")
    out += [f"requires cycle: {c}" for c in _cycle(rows)]
    for r in rows.values():
        d = r.disposition
        if d in ("carry", "replace") and r.state in ("new-primary", "old-retired"):
            for name in ("data_verified", "consumers_repointed"):
                if r.check_status(name) not in ("pass", "na"):
                    out.append(f"{r.uid}: {r.state} but {name} is {r.check_status(name)}")
        if d == "undecided" and r.state != "old":
            out.append(f"{r.uid}: undecided but state is {r.state}")
        if (
            d in ("carry", "replace")
            and r.state == "old-retired"
            and r.history[-1:]
            and (r.history[-1][1] == "old")
        ):
            out.append(f"{r.uid}: closed from old: close is only for drop or retire rows")
        if (
            r.get("gate") == "none-yet"
            and r.state in ("new-primary", "old-retired")
            and d != "drop"
        ):
            out.append(f"{r.uid}: {r.state} with gate none-yet (no conformance suite)")
    return sorted(dict.fromkeys(out))


def _group(rows: Iterable[Row]) -> dict[str, int]:
    c = dict.fromkeys(STATES, 0)
    for r in rows:
        c[r.state] += 1
    return c


def plane_gate(ledger: Ledger, plane: str, today: dt.date) -> list[str]:
    """Rows of ``plane`` that are not finished: the pm200 power-off gate for a plane.

    A row passes when it is ``new-primary`` or ``old-retired`` with nothing undecided, held or
    unproven, or when it is a drop, retire or archive row with its decision cited and ``old-retired``.
    An empty plane fails (a gate that names no rows measures nothing).
    """
    rows = [r for r in ledger.rows.values() if r.get("plane") == plane]
    if not rows:
        return [f"plane {plane!r}: no rows (the gate measures nothing)"]
    out = []
    for r in sorted(rows, key=lambda r: r.get("title")):
        d = r.disposition
        ok = r.state in ("new-primary", "old-retired") and d in ("carry", "replace")
        ok = ok or (r.state == "old-retired" and d in ("drop", "retire", "archive"))
        bad = [
            b
            for b in r.blockers(today)
            if not b.startswith("state ") and not b.startswith("soaking")
        ]
        if not ok or bad or r.soaking(today):
            why = "; ".join(bad) or f"state {r.state}"
            out.append(f"{r.uid} {r.get('title')}: {r.state}, {d}: {why}")
    return out


def _display(r: Row, today: dt.date) -> str:
    return f"{r.state} (soaking)" if r.soaking(today) else r.state


def render_json(ledger: Ledger, today: dt.date | None = None) -> dict:
    today = today or dt.date.today()
    rows = []
    for r in sorted(ledger.rows.values(), key=lambda r: (r.get("plane") or "", r.get("title"))):
        rows.append(
            {
                "uid": r.uid,
                "title": r.get("title"),
                "kind": r.get("kind"),
                "plane": r.get("plane"),
                "old": r.get("old"),
                "new": r.get("new"),
                "disposition": r.disposition,
                "state": r.state,
                "display_state": _display(r, today),
                "checks": {
                    k: r.check_status(k) for k in ("data_verified", "consumers_repointed", "soak")
                },
                "soak_ends": r.get("soak_ends"),
                "hold": (r.get("hold") or {}).get("reason"),
                "decision": r.get("decision"),
                "audit": r.get("audit") or [],
                "links": r.get("links") or [],
                "blockers": r.blockers(today),
            }
        )
    return {
        "schema": REPORT_SCHEMA,
        "as_of": today.isoformat(),
        "counts": _group(ledger.rows.values()),
        "undecided": sum(1 for r in ledger.rows.values() if r.disposition == "undecided"),
        "rows": rows,
    }


def render_markdown(ledger: Ledger, today: dt.date | None = None) -> str:
    rep = render_json(ledger, today)
    lines = [
        f"# Cutover ledger ({rep['as_of']})",
        "",
        "States: "
        + ", ".join(f"{k} {v}" for k, v in rep["counts"].items())
        + f"; undecided {rep['undecided']}",
        "",
        "| plane | title | old | new | disposition | state | data | consumers | soak | blockers |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for r in rep["rows"]:
        c = r["checks"]
        lines.append(
            "| {plane} | {title} | {old} | {new} | {disp} | {state} | {d} | {c} | {s} | {b} |".format(
                plane=r["plane"] or "",
                title=r["title"],
                old=", ".join(r["old"]),
                new=r["new"] or "",
                disp=r["disposition"],
                state=r["display_state"],
                d=c["data_verified"],
                c=c["consumers_repointed"],
                s=c["soak"],
                b="; ".join(r["blockers"]).replace("|", "/"),
            )
        )
    return "\n".join(lines) + "\n"
