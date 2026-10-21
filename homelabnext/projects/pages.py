# SPDX-License-Identifier: Apache-2.0
"""The Projects page of the status hub: server-rendered, no script, the hub's own stylesheet.

``/projects`` (``hnx status serve --projects DIR [--strategy DIR]``; menu panel ``projects``):

* **Open projects** with their step progress (done of all, cancelled not counted against) and
  each step's state, date and one-line result;
* **Blocked** steps and tasks, with what blocks them;
* **Work by objective**: for each strategy objective, the steps, tasks and projects linked to it
  (any relation), by the record's computed display number when the strategy tree is given.

Each request reads the item files only (it never writes), and every value is escaped.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Callable, Mapping
from typing import Any

from homelabnext.status.agents.pages import _table
from homelabnext.status.render import _e, nav_html, shell_html

from . import markdown_store, rules
from .model import TERMINAL, WorkItem
from .strategy import strategy_records

__all__ = ["ROUTES", "ProjectsSite"]

Response = tuple[int, str, bytes]
HTML = "text/html; charset=utf-8"
ROUTES = ("/projects",)
_CLASS = {
    "open": "ok",
    "done": "ok",
    "closed": "ok",
    "in_progress": "warn",
    "todo": "unknown",
    "blocked": "fail",
    "cancelled": "unknown",
}


def _badge(state: str) -> str:
    return f'<span class="s {_CLASS.get(state, "unknown")}">{_e(state)}</span>'


def _short(uid: str) -> str:
    """A computed display handle: the uid's last 8 hex digits (uids are the identity)."""
    return uid.rsplit("-", 1)[-1][-8:]


class ProjectsSite:
    """The ``/projects`` route of ``hnx status serve`` over one projects directory."""

    def __init__(self, root, *, strategy=None, clock: Callable[[], float]):
        self.root, self.strategy, self.clock = root, strategy, clock

    def handle(self, route: str, query: str, doc: Mapping[str, Any]) -> Response | None:
        if route != "/projects":
            return None
        store = markdown_store(self.root, strategy=self.strategy, create=False)
        items = store.list()
        records = {r.uid: r for r in strategy_records(self.strategy)} if self.strategy else {}
        now = dt.datetime.fromtimestamp(self.clock(), dt.UTC)
        main = self._page(items, records, now)
        html = shell_html(doc, "Projects", main, nav=nav_html(doc, live=True))
        return 200, HTML, html.encode("utf-8")

    def _page(self, items: list[WorkItem], records: Mapping[str, Any], now: dt.datetime) -> str:
        by_uid = {i.uid: i for i in items}

        def name(uid: str) -> str:
            it = by_uid.get(uid)
            if it is not None:
                return f"{_e(it.title)} <code>{_e(_short(uid))}</code>"
            rec = records.get(uid)
            return (
                f"<code>{_e(rec.label)}</code> {_e(rec.title)}"
                if rec
                else f"<code>{_e(uid)}</code>"
            )

        parts = [
            "<h2>Projects</h2>",
            f'<p class="muted">Read from the project files at '
            f"{_e(now.strftime('%Y-%m-%dT%H:%M:%SZ'))}; uids are the identity, the short codes "
            "are their last digits.</p>",
            "<h3>Open projects</h3>",
        ]
        open_projects = [i for i in items if i.kind == "project" and i.status == "open"]
        for p in open_projects:
            steps = rules.steps_of(items, p.uid)
            counted = [s for s in steps if s.status != "cancelled"]
            done = sum(1 for s in counted if s.status == "done")
            pct = f" ({100 * done // len(counted)}%)" if counted else ""
            rows = [
                (
                    _e(s.order),
                    _badge(s.status),
                    _e(s.title),
                    _e(s.closed_on or ""),
                    _e(s.result or ""),
                    _e(s.assignee or ""),
                )
                for s in steps
            ]
            links = ", ".join(f"{_e(lk.relation)} {name(lk.target)}" for lk in p.links)
            parts.append(
                f'<div class="pane"><h3>{_e(p.title)} <code>{_e(_short(p.uid))}</code></h3>'
                f"<p>{_badge(p.status)} {done} of {len(counted)} steps done{pct}"
                + (f' <span class="muted">due {_e(p.due)}</span>' if p.due else "")
                + "</p>"
                + (f'<p class="muted">{links}</p>' if links else "")
                + _table(("#", "State", "Step", "Date", "Result", "Assignee"), rows)
                + "</div>"
            )
        if not open_projects:
            parts.append('<p class="muted">no open project</p>')
        blocked = [i for i in items if i.status == "blocked"]
        blockers = {
            i.uid: [
                b
                for b in items
                if any(lk.relation == "blocks" and lk.target == i.uid for lk in b.links)
                and b.status not in TERMINAL
            ]
            for i in blocked
        }
        parts.append("<h3>Blocked</h3>")
        parts.append(
            _table(
                ("Item", "Kind", "Project", "Blocked by"),
                [
                    (
                        name(i.uid),
                        _e(i.kind),
                        name(i.project) if i.project else "-",
                        ", ".join(name(b.uid) for b in blockers[i.uid]) or "-",
                    )
                    for i in blocked
                ],
            )
        )
        parts.append("<h3>Work by objective</h3>")
        targets = sorted({lk.target for i in items for lk in i.links if lk.target not in by_uid})
        rows = []
        for t in targets:
            linked = [i for i in items if t in i.linked()]
            done = sum(1 for i in linked if i.status in TERMINAL)
            rows.append(
                (
                    name(t),
                    "<br>".join(f"{_badge(i.status)} {_e(i.kind)}: {name(i.uid)}" for i in linked),
                    f"{done} of {len(linked)} finished",
                )
            )
        parts.append(_table(("Record", "Linked work", "Progress"), rows))
        return "".join(parts)
