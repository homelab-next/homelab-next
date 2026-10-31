# SPDX-License-Identifier: Apache-2.0
"""The strategy pages of the status hub: server-rendered, no script, the hub's own stylesheet.

=================== ===============================================================================
``/strategy``       mission, intent, end state, priorities of work, assumptions, constraints
``/requirements``   the requirements board: three columns, CCIR / FFIR / PIR; each card shows what
                    it supports and serves, its cadence, LTIOV and state
``/objectives``     the SO -> OO -> TO -> TT tree; each node's rollup and each MOP/MOE's grade
                    with its value and time (from the recorded readings)
``/rfis``           open RFIs by triage (collection, production), what expires soon, the closed
=================== ===============================================================================

``hnx status serve --strategy DIR`` serves them; the menu entries are ``views.yml`` page panels
(``strategy``, ``requirements``, ``objectives``, ``rfis``).  Each request reads the record files
and their events only -- it never runs a measurement -- and every value is escaped.  The
stylesheet is the hub's one inline style, so the CSP hash ``hnx status serve`` sends covers
these pages unchanged.  Records are shown by their computed display numbers (``OO 1.2``; the
uid in the element's title), numbered afresh on every request (ADR-0019); a ``[[<uid>]]`` link
in a record's prose is shown as the number of the record it names.
"""

from __future__ import annotations

import datetime as dt
import re
from collections.abc import Callable, Mapping
from typing import Any

from homelabnext.identity.uid import UID_PATTERN
from homelabnext.status.agents.pages import _table
from homelabnext.status.render import _e, nav_html, shell_html

from .doctrine import load_doctrine
from .measure import Grade, grade_all, rollup
from .records import Tree, load_tree
from .rfis import expiring
from .rules import _active

__all__ = ["ROUTES", "StrategySite"]

Response = tuple[int, str, bytes]
HTML = "text/html; charset=utf-8"
ROUTES = ("/strategy", "/requirements", "/objectives", "/rfis")
#: grade -> the hub's state class (its colours)
_CLASS = {
    "green": "ok",
    "amber": "warn",
    "red": "fail",
    "unmeasured": "fail",
    "baseline": "unknown",
    "pending": "unknown",
    "active": "ok",
    "open": "warn",
}


def _badge(state: str) -> str:
    return f'<span class="s {_CLASS.get(state, "unknown")}">{_e(state)}</span>'


_WIKI = re.compile(rf"\[\[({UID_PATTERN})(?:\|[^\]]*)?\]\]")


def _ref(tree: Tree, uid: Any) -> str:
    """A record reference as its display number, the uid in the title."""
    uid = str(uid)
    return f'<span class="ref" title="{_e(uid)}">{_e(tree.label(uid))}</span>'


def _p(text: Any, tree: Tree | None = None) -> str:
    def para(s: str) -> str:
        if tree is None:
            return _e(s)
        out, pos = [], 0
        for m in _WIKI.finditer(s):  # escape around the links, render each as its number
            out += [_e(s[pos : m.start()]), _ref(tree, m[1])]
            pos = m.end()
        return "".join(out) + _e(s[pos:])

    return "".join(f"<p>{para(par)}</p>" for par in str(text or "").split("\n\n") if par.strip())


def _ul(items) -> str:
    rows = "".join(f"<li>{x}</li>" for x in items)
    return f"<ul>{rows}</ul>" if rows else '<p class="muted">none</p>'


class StrategySite:
    """The strategy routes of ``hnx status serve`` over one strategy directory."""

    def __init__(self, root, *, clock: Callable[[], float]):
        self.root = root
        self.clock = clock

    def handle(self, route: str, query: str, doc: Mapping[str, Any]) -> Response | None:
        """The response for a strategy route, or None when ``route`` is not one."""
        pages = {
            "/strategy": self._strategy,
            "/requirements": self._requirements,
            "/objectives": self._objectives,
            "/rfis": self._rfis,
        }
        if route not in pages:
            return None
        tree = load_tree(self.root)
        now = dt.datetime.fromtimestamp(self.clock(), dt.UTC)
        title, main = pages[route](tree, now)
        html = shell_html(doc, title, main, nav=nav_html(doc, live=True, private=True))
        return 200, HTML, html.encode("utf-8")

    # ---------------------------------------------------------------- pages
    def _strategy(self, tree: Tree, now: dt.datetime) -> tuple[str, str]:
        s = tree.strategy or {}
        prio = "".join(f"<li>{_e(p)}</li>" for p in s.get("priorities") or ())
        rows = [
            (_e(c.get("rule")), f"<code>{_e(c.get('owner'))}</code>")
            for c in s.get("constraints") or ()
        ]
        main = (
            f"<h2>{_e(s.get('title', 'Strategy'))}</h2>"
            f'<div class="split"><div class="pane"><h3>Mission</h3>{_p(s.get("mission"), tree)}'
            f"<h3>Intent</h3>{_p(s.get('intent'), tree)}<h3>End state</h3>{_p(s.get('end_state'), tree)}</div>"
            f'<div class="pane"><h3>Priorities of work</h3><ol>{prio}</ol>'
            f"<h3>Assumptions</h3>{_ul(_e(a) for a in s.get('assumptions') or ())}</div></div>"
            f"<h3>Constraints</h3>{_table(('Rule', 'Owner'), rows)}"
        )
        return "Strategy", main

    def _requirements(self, tree: Tree, now: dt.datetime) -> tuple[str, str]:
        cols = []
        for rtype, what in (
            ("CCIR", "what the owner needs to know"),
            ("FFIR", "what the lab needs to know about itself"),
            ("PIR", "what we need to know about the environment and adversary"),
        ):
            cards = []
            for k in tree.ordered("requirements"):
                r = tree.of("requirements")[k]
                if r.get("type") != rtype:
                    continue
                num = tree.label(k).partition(" ")[2]
                sirs = "".join(
                    f"<li>SIR {_e(num)}.{n} {_e(s)}</li>"
                    for n, s in enumerate(r.get("sirs") or (), 1)
                )
                facts = (
                    ("Supports", ", ".join(_ref(tree, x) for x in r.get("supports") or ())),
                    ("Serves", ", ".join(_ref(tree, x) for x in r.get("serves") or ()) or "-"),
                    ("Cadence", _e(r.get("cadence"))),
                    ("LTIOV", _e(r.get("ltiov"))),
                    ("Consumer", f"<code>{_e(r.get('consumer'))}</code>"),
                    ("SIRs", f"<ul>{sirs}</ul>" if sirs else ""),
                )
                dl = "".join(f"<dt>{_e(a)}</dt><dd>{b}</dd>" for a, b in facts if b)
                cards.append(
                    f'<div class="tile {_CLASS.get(str(r.get("status")), "unknown")}">'
                    f'<h3 title="{_e(k)}">{_e(tree.label(k))}</h3>'
                    f"{_badge(str(r.get('status')))} {_e(r.get('title'))}"
                    f"<dl>{dl}</dl></div>"
                )
            body = "".join(cards) or '<p class="muted">none</p>'
            cols.append(f'<div><h3>{rtype}</h3><p class="muted">{_e(what)}</p>{body}</div>')
        return "Requirements", f'<h2>Requirements</h2><div class="tiles">{"".join(cols)}</div>'

    def _objectives(self, tree: Tree, now: dt.datetime) -> tuple[str, str]:
        grades = grade_all(tree, load_doctrine(tree.root), now)
        states = rollup(tree, grades)
        objs = tree.of("objectives")

        def measure(m: str) -> str:
            g: Grade = grades[m]
            v = "-" if g.value is None else f"{g.value:g}"
            more = [x for x in (g.trend and f"trend {g.trend}", g.thin and f"thin: {g.thin}") if x]
            more += ["self-measured: capped"] if g.capped else []
            more += [g.finding] if g.finding else []
            note = f' <span class="muted">{_e("; ".join(more))}</span>' if more else ""
            return (
                f'<li>{_badge(g.state)} <code title="{_e(m)}">{_e(tree.label(m))}</code> '
                f"{_e(tree.of('measures')[m].get('title'))}: <b>{_e(v)}</b> "
                f'<span class="muted">at {_e(g.observed_at or "never")}, '
                f"confidence {_e(g.confidence)}</span>{note}</li>"
            )

        def node(k: str) -> str:
            o, s = objs[k], states[k]
            ms = "".join(measure(m) for m in s["measures"])
            kids = "".join(node(c) for c in s["children"])
            return (
                f'<li>{_badge(s["state"])} <b title="{_e(k)}">{_e(tree.label(k))}</b> '
                f"{_e(o.get('title'))} "
                f'<span class="muted">owner {_e(o.get("owner"))}</span>'
                f"<ul>{ms}{kids}</ul></li>"
            )

        roots = [k for k in tree.ordered("objectives", states) if objs[k].get("type") == "SO"]
        tree_html = "".join(node(k) for k in roots)
        main = (
            '<h2>Objectives</h2><p class="muted">The rollup is the worst of an objective\'s MOEs '
            "and child objectives (its MOPs when none has a grade); readings are the recorded "
            f"value events, graded at {_e(now.strftime('%Y-%m-%dT%H:%M:%SZ'))}.</p>"
            f"<ul>{tree_html}</ul>"
        )
        return "Objectives", main

    def _rfis(self, tree: Tree, now: dt.datetime) -> tuple[str, str]:
        doctrine = load_doctrine(tree.root)
        rfis = tree.of("rfis")

        def rows(keys):
            return [
                (
                    _badge(str(rfis[k].get("status"))),
                    f'<code title="{_e(k)}">{_e(tree.label(k))}</code>',
                    _e(rfis[k].get("title")),
                    _ref(tree, rfis[k].get("raised_by")),
                    _e(rfis[k].get("ltiov")),
                    _e(rfis[k].get("resolution") or ""),
                )
                for k in keys
            ]

        head = ("State", "RFI", "Question", "Raised by", "LTIOV", "Resolution")
        parts = ["<h2>RFIs</h2>"]
        for triage, what in (
            ("collection", "collection requirements: the answer needs data the lab does not hold"),
            ("production", "production requirements: the lab holds the data, the answer is owed"),
        ):
            keys = [
                k
                for k in tree.ordered("rfis")
                if _active(rfis[k]) and rfis[k].get("triage") == triage
            ]
            parts.append(f'<h3>Open: {triage}</h3><p class="muted">{_e(what)}</p>')
            parts.append(_table(head, rows(keys)))
        soon = expiring(tree, now.date(), doctrine.expiring_soon_days)
        parts.append(f"<h3>Expiring within {doctrine.expiring_soon_days} days</h3>")
        parts.append(_table(head, rows(k for k, _ in soon)))
        closed = [k for k in tree.ordered("rfis") if not _active(rfis[k])]
        parts.append("<h3>Closed</h3>" + _table(head, rows(closed)))
        return "RFIs", "".join(parts)
