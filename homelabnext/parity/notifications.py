# SPDX-License-Identifier: Apache-2.0
"""Notification parity: the new path must page for the same problems, with the same urgency.

Feed the same observations to the old and the new notification path (each with a recording
``FakeSender``) and compare what was sent. A *missing* page is a lost alert and always fails; an
*extra* page is noise and fails too (pages are budgeted).
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass

from homelabnext.notify.core import Message

from .report import Check, ParityReport


@dataclass(frozen=True)
class NotifyRules:
    compare_body: bool = False  # bodies often embed engine-specific text
    compare_tags: bool = True
    compare_routing: bool = True  # topic / email


def _ws(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


def _ident(m: Message) -> tuple[str, str, str]:
    return (m.key, m.title, m.level)


def compare_notifications(
    old: Sequence[Message], new: Sequence[Message], rules: NotifyRules | None = None
) -> ParityReport:
    rules = rules or NotifyRules()
    rep = ParityReport("notifications", meta={"old": len(old), "new": len(new)})
    co, cn = Counter(_ident(m) for m in old), Counter(_ident(m) for m in new)
    missing, extra = co - cn, cn - co
    rep.add(
        Check(
            "pages",
            not (missing or extra),
            "same set of pages"
            if not (missing or extra)
            else f"{sum(missing.values())} lost, {sum(extra.values())} extra",
            {
                "missing": [list(k) for k in sorted(missing)],
                "extra": [list(k) for k in sorted(extra)],
            },
        )
    )
    seq_o: dict[str, list[str]] = {}
    seq_n: dict[str, list[str]] = {}
    for m in old:
        seq_o.setdefault(m.key, []).append(m.title)
    for m in new:
        seq_n.setdefault(m.key, []).append(m.title)
    bad = sorted(
        k
        for k in seq_o
        if k in seq_n and seq_o[k] != seq_n[k] and Counter(seq_o[k]) == Counter(seq_n[k])
    )
    rep.add(
        Check(
            "problem-recovery-order",
            not bad,
            "problem/recovery order matches" if not bad else f"order differs for {bad[:5]}",
            {"keys": bad},
        )
    )

    by_old: dict[tuple, list[Message]] = {}
    for m in old:
        by_old.setdefault(_ident(m), []).append(m)
    by_new: dict[tuple, list[Message]] = {}
    for m in new:
        by_new.setdefault(_ident(m), []).append(m)
    diffs: dict[str, list[list[str]]] = {"priority": [], "tags": [], "routing": [], "body": []}
    for ident in sorted(set(by_old) & set(by_new)):
        for a, b in zip(by_old[ident], by_new[ident], strict=False):
            if a.effective_priority != b.effective_priority:
                diffs["priority"].append([*ident])
            if rules.compare_tags and sorted(a.tags) != sorted(b.tags):
                diffs["tags"].append([*ident])
            if rules.compare_routing and (a.topic, a.email) != (b.topic, b.email):
                diffs["routing"].append([*ident])
            if rules.compare_body and _ws(a.body) != _ws(b.body):
                diffs["body"].append([*ident])
    for name, found in diffs.items():
        if name == "body" and not rules.compare_body:
            continue
        if name == "tags" and not rules.compare_tags:
            continue
        if name == "routing" and not rules.compare_routing:
            continue
        rep.add(
            Check(
                name,
                not found,
                f"{name} identical" if not found else f"{len(found)} pages differ in {name}",
                {"pages": found[:20]},
            )
        )
    return rep
