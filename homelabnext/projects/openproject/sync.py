# SPDX-License-Identifier: Apache-2.0
"""One-way strategy sync: the repository's strategy records -> the read-only Strategy project.

``hnx projects sync-strategy --target openproject --dry-run|--apply``.  The repository is the
source of truth (ADR-0020); OpenProject shows the records so execution work can relate to them.

* **Upsert by uid.** Each record is the work package whose External key is the record's uid
  (:mod:`homelabnext.projects.strategy`): found -> ``PATCH`` with its ``lockVersion``, not found ->
  ``POST``.  The type is the record's type (SO ... MOE, RFI), the status the record's status.
* **Cascade and links.** ``parent`` is the work package parent (parents are written first; a
  measure's parent is its objective); ``supports``/``serves``/``raised_by`` are ``relates`` relations with the edge name
  in the relation's description.  Stale relations are deleted only when both ends are strategy
  work packages; a relation to execution work is never touched.
* **Content hash.** The hash of what the sync writes is kept in the ``hnx state`` field.  Equal
  to the record's hash and to what OpenProject shows -> nothing is written (an unchanged
  repository makes zero writes and no journal noise).
* **Repo wins.** When what OpenProject shows no longer hashes to the stored hash, someone edited a
  mirrored record there: the sync writes the repository's version back and reports it as
  ``reverted`` (a finding, never a merge).
* **Never closes on its own.** Statuses come from the records only.  A record that disappeared
  from the repository is reported as an ``orphan`` and left as it is; completion of execution
  work never moves an objective (achievement is a reviewed transition in the repository).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from ..strategy import StrategyRecord
from .backend import API, _link_id, _raw, wp_href, wp_id
from .client import OpenProjectClient, all_work_packages, filters
from .setup import OpenProjectConfig, Setup

__all__ = ["BANNER", "SyncReport", "sync_strategy"]

BANNER = "Mirrored from the strategy repository: edits made here are overwritten by the next sync."
#: parents before children: the order records are written in
_ORDER = {t: n for n, t in enumerate(("SO", "OO", "TO", "TT", "CCIR", "FFIR", "PIR", "MOE", "MOP", "RFI"))}  # fmt: skip


@dataclass
class SyncReport:
    created: list[str] = field(default_factory=list)
    updated: list[str] = field(default_factory=list)
    unchanged: list[str] = field(default_factory=list)
    reverted: list[str] = field(default_factory=list)  # edited in OpenProject, written back
    orphans: list[str] = field(default_factory=list)  # in OpenProject, gone from the repository
    relations_added: list[str] = field(default_factory=list)
    relations_removed: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    applied: bool = False

    @property
    def writes(self) -> int:
        return (
            len(self.created) + len(self.updated) + len(self.reverted)
            + len(self.relations_added) + len(self.relations_removed)
        )  # fmt: skip

    def as_dict(self) -> dict[str, Any]:
        return dict(self.__dict__.items())

    def lines(self) -> list[str]:
        out = [f"{'applied' if self.applied else 'dry run'}: {self.writes} write(s)"]
        for name in ("created", "updated", "reverted", "orphans", "relations_added",
                     "relations_removed", "problems"):  # fmt: skip
            for x in getattr(self, name):
                out.append(f"  {name.replace('_', ' ')}: {x}")
        out.append(f"  unchanged: {len(self.unchanged)}")
        return out


def _number(label: str) -> tuple[int, ...]:
    """``OO 1.10`` -> (1, 10): parents sort before their children."""
    tail = label.rsplit(" ", 1)[-1]
    return tuple(int(p) if p.isdigit() else 0 for p in tail.split("."))


def _shown(wp: Mapping[str, Any], fields: Mapping[str, str]) -> dict[str, Any]:
    """What a strategy work package shows of the fields the sync owns."""
    return {
        "subject": str(wp.get("subject") or ""),
        "description": _raw(wp.get("description")).strip(),
        "type": _link_id(wp, "type"),
        "status": _link_id(wp, "status"),
        "parent": _link_id(wp, "parent"),
        "key": wp.get(fields["external_key"]),
    }


def _hash(shown: Mapping[str, Any]) -> str:
    return hashlib.sha256(json.dumps(shown, sort_keys=True).encode()).hexdigest()[:32]


def _description(rec: StrategyRecord) -> str:
    head = f"_{BANNER}_\n\n**{rec.label or rec.type}**"
    return f"{head}\n\n{rec.text}".rstrip() if rec.text else head


def sync_strategy(
    client: OpenProjectClient,
    cfg: OpenProjectConfig,
    setup: Setup,
    records: Iterable[StrategyRecord],
    *,
    apply: bool = False,
) -> SyncReport:
    """Mirror ``records`` into the Strategy project (``apply=False``: plan only, no write)."""
    rep = SyncReport(applied=apply)
    ext, state_cf = setup.fields["external_key"], setup.fields["state"]
    pid = setup.strategy_project
    existing: dict[str, dict[str, Any]] = {}
    for wp in all_work_packages(client, pid):  # closed records too, or each sync re-creates them
        key = wp.get(ext)
        if key:
            existing[str(key)] = wp
    recs = sorted(records, key=lambda r: (_ORDER.get(r.type, 99), _number(r.label), r.uid))
    wp_of = {k: int(w["id"]) for k, w in existing.items()}
    for rec in recs:
        if rec.type not in setup.types:
            rep.problems.append(f"{rec.label}: no work package type {rec.type!r}")
            continue
        status = cfg.strategy_statuses.get(rec.status)
        if status not in setup.statuses:
            rep.problems.append(f"{rec.label}: no status for {rec.status!r}")
            continue
        parent = wp_of.get(rec.parent_uid or "")
        if rec.parent_uid and parent is None and apply:
            rep.problems.append(f"{rec.label}: its parent is not mirrored")
            continue
        want = {
            "subject": rec.title[:255],
            "description": _description(rec).strip(),
            "type": setup.types[rec.type],
            "status": setup.statuses[status],
            "parent": parent,
            "key": rec.uid,
        }
        h = _hash(want)
        body = {
            "subject": want["subject"],
            "description": {"format": "markdown", "raw": want["description"]},
            ext: rec.uid,
            state_cf: {"format": "markdown", "raw": json.dumps({"hash": h})},
            "_links": {
                "type": {"href": f"{API}/types/{want['type']}"},
                "status": {"href": f"{API}/statuses/{want['status']}"},
                "parent": {"href": wp_href(parent) if parent else None},
            },
        }
        cur = existing.get(rec.uid)
        label = f"{rec.label} ({rec.uid})"
        if cur is None:
            rep.created.append(label)
            if apply:
                wp_of[rec.uid] = int(client.post(f"{API}/projects/{pid}/work_packages", body)["id"])
            continue
        try:
            stored = json.loads(_raw(cur.get(state_cf)) or "{}").get("hash")
        except ValueError:
            stored = None
        shown = _hash(_shown(cur, setup.fields))
        if shown == h and stored == h:
            rep.unchanged.append(label)
            continue
        (rep.reverted if shown != stored else rep.updated).append(label)
        if apply:
            client.patch(
                wp_href(int(cur["id"])), {**body, "lockVersion": cur.get("lockVersion", 0)}
            )
    rep.orphans = sorted(f"wp:{w['id']} ({k})" for k, w in existing.items() if k not in {r.uid for r in recs})  # fmt: skip
    _sync_links(client, setup, recs, wp_of, rep, apply)
    return rep


def _sync_links(client, setup, recs, wp_of, rep: SyncReport, apply: bool) -> None:
    ids = sorted(wp_of.values())
    strategy_wps = set(ids)
    have: dict[tuple[int, int, str], int] = {}
    if ids:
        for rel in client.collect(f"{API}/relations", filters=filters(involved=("=", ids))):
            ln = rel.get("_links") or {}
            a = wp_id((ln.get("from") or {}).get("href"))
            b = wp_id((ln.get("to") or {}).get("href"))
            if rel.get("type") == "relates" and a in strategy_wps and b in strategy_wps:
                have[(a, b, str(rel.get("description") or ""))] = int(rel["id"])
    want: set[tuple[int, int, str]] = set()
    for rec in recs:
        for label, target in rec.links:
            a, b = wp_of.get(rec.uid), wp_of.get(target)
            if a is None or b is None:
                if apply:
                    rep.problems.append(f"{rec.label}: {label} target not mirrored")
                else:
                    rep.relations_added.append(f"{rec.label} {label} {target}")
                continue
            want.add((a, b, label))
    for a, b, label in sorted(want - set(have)):
        rep.relations_added.append(f"wp:{a} {label} wp:{b}")
        if apply:
            body = {"type": "relates", "description": label, "_links": {"to": {"href": wp_href(b)}}}
            client.post(f"{wp_href(a)}/relations", body)
    for key in sorted(set(have) - want):
        a, b, label = key
        rep.relations_removed.append(f"wp:{a} {label} wp:{b}")
        if apply:
            client.delete(f"{API}/relations/{have[key]}")
