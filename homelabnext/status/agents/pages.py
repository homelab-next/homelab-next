# SPDX-License-Identifier: Apache-2.0
"""The agent pages of the hub: server-rendered, no script, filters in the query string.

Summary tier (every viewer of the hub):

=================== ===============================================================================
``/agents``          sessions with state badges; filter chips by runtime, state, project
``/agents/session``  one session (``?id=``): its facts and the timeline of its summary events
``/activity``        the event stream, newest first, refreshing every 15 s (a meta refresh, no
                     script); filters by runtime, outcome, kind, session; ``?event=`` opens the
                     inspector pane beside the list; ``/activity.csv`` and ``/activity.jsonl``
                     export the same selection (summary tier only)
``/agent-analytics`` counts by outcome, runtime, model, tool and day
=================== ===============================================================================

Private tier (only through the trusted front door, :mod:`.auth`; every view is access-logged):
``/private/sessions``, ``/private/session?id=``, ``/private/event?id=``, ``/private/access-log``.

Everything is rendered as escaped text: a prompt or a tool output is put in a ``<pre>`` after
``html.escape``, never interpreted as HTML or markdown, and nothing here sends detail content
anywhere but the authorized response.
"""

from __future__ import annotations

import csv
import io
import json
import re
import time
import urllib.parse
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from ..render import _e, nav_html, shell_html
from .auth import AccessLog, Decision, authorize
from .config import FrontDoor
from .model import DETAIL_TEXT, SESSION_STATES, state_counts
from .store import ActivityStore

Response = tuple[int, str, bytes]
HTML = "text/html; charset=utf-8"
_VALUE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}$")
_SUMMARY_COLUMNS = (
    "time", "event_id", "session_id", "parent_session_id", "runtime", "surface", "host",
    "project", "model", "agent", "kind", "tool", "outcome", "tokens_in", "tokens_out", "cost_usd",
)  # fmt: skip
STREAM_LIMIT = 200
EXPORT_LIMIT = 10000
REFRESH_S = 15


def _q(query: str) -> dict[str, str]:
    """Single-valued, shape-checked query parameters (anything else is ignored)."""
    out = {}
    for k, vals in urllib.parse.parse_qs(query, keep_blank_values=False).items():
        if len(vals) == 1 and _VALUE_RE.match(vals[0]):
            out[k] = vals[0]
    return out


def _href(path: str, **params: str | None) -> str:
    q = urllib.parse.urlencode({k: v for k, v in params.items() if v})
    return f"{path}?{q}" if q else path


def _badge(state: str) -> str:
    return f'<span class="s {_e(state)}">{_e(state)}</span>'


def _chips(path: str, current: Mapping[str, str], key: str, values: Sequence[str]) -> str:
    """Filter links for ``key``: one per value plus ``all``; the active one is bold."""
    if not values:
        return ""
    others = {k: v for k, v in current.items() if k not in (key, "event")}
    parts = [f'<span class="muted">{_e(key)}:</span> ']
    for v in ("", *values):
        label = v or "all"
        if current.get(key, "") == v:
            parts.append(f"<b>{_e(label)}</b>")
        else:
            parts.append(
                f'<a href="{_e(_href(path, **{**others, key: v or None}))}">{_e(label)}</a>'
            )
    return f'<div class="chips">{"".join(parts)}</div>'


def _table(head: Sequence[str], rows: Sequence[Sequence[str]]) -> str:
    """``rows`` hold already-escaped cell HTML."""
    if not rows:
        return '<p class="muted">nothing to show</p>'
    th = "".join(f"<th>{_e(h)}</th>" for h in head)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows)
    return f"<table><thead><tr>{th}</tr></thead><tbody>{body}</tbody></table>"


def _n(v: Any) -> str:
    return "" if v is None else _e(v)


def _csv_cell(v: Any) -> str:
    """CSV value that a spreadsheet will not run as a formula."""
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


class AgentSite:
    """The agent routes of ``hnx status serve`` over one :class:`ActivityStore`."""

    def __init__(
        self,
        store: ActivityStore,
        *,
        front_door: FrontDoor | None = None,
        clock: Callable[[], float] = time.time,
    ):
        self.store = store
        self.front_door = front_door
        self.clock = clock
        self.access_log = AccessLog(front_door.access_log, clock=clock) if front_door else None

    # ---------------------------------------------------------------- helpers
    def authorize(self, client: str | None, headers: Any) -> Decision:
        return authorize(self.front_door, client, headers)

    def summary(self, now: float | None = None) -> dict[str, Any]:
        """``status.json``'s ``agents`` block: sessions (summary tier) and counts by state."""
        sessions = self.store.sessions(now)
        return {"sessions": sessions, "counts": state_counts(sessions)}

    def _page(self, doc, title, main, decision, *, refresh=False) -> Response:
        nav = nav_html(doc, live=True, private=decision.allowed)
        html = shell_html(doc, title, main, nav=nav, refresh_s=REFRESH_S if refresh else None)
        return 200, HTML, html.encode("utf-8")

    def handle(
        self, route: str, query: str, doc: Mapping[str, Any], client: str | None, headers: Any
    ) -> Response | None:
        """The response for an agent route, or None when ``route`` is not one."""
        q = _q(query)
        if route.startswith("/private/") or route == "/private":
            return self._private(route, q, doc, client, headers)
        decision = self.authorize(client, headers)
        pages = {
            "/agents": self._sessions,
            "/agents/session": self._session,
            "/activity": self._activity,
            "/agent-analytics": self._analytics,
        }
        if route in pages:
            return pages[route](q, doc, decision)
        if route in ("/activity.csv", "/activity.jsonl"):
            return self._export(route.rsplit(".", 1)[1], q)
        return None

    # ---------------------------------------------------------------- summary pages
    def _sessions(self, q, doc, decision) -> Response:
        all_rows = self.store.sessions()
        rows = [
            s
            for s in all_rows
            if all(s.get(k) == q[k] for k in ("runtime", "state", "project") if k in q)
        ]
        counts = state_counts(all_rows)
        head = " ".join(f"{_badge(st)} {counts[st]}" for st in SESSION_STATES)
        chips = (
            _chips("/agents", q, "state", [s for s in SESSION_STATES if counts[s]])
            + _chips(
                "/agents", q, "runtime", sorted({s["runtime"] for s in all_rows if s["runtime"]})
            )
            + _chips(
                "/agents", q, "project", sorted({s["project"] for s in all_rows if s["project"]})
            )
        )
        table = _table(
            ("State", "Session", "Runtime", "Where", "Model", "Agent", "Parent", "Last tool",
             "Tools", "Denied", "Approvals", "Tokens", "Cost", "Last event", "Idle"),
            [
                (
                    _badge(s["state"]),
                    f'<a href="{_e(_href("/agents/session", id=s["session_id"]))}"><code>'
                    f"{_e(s['session_id'])}</code></a>",
                    _n(s["runtime"]) + (f" ({_e(s['surface'])})" if s.get("surface") else ""),
                    _e("/".join(x for x in (s.get("host"), s.get("project")) if x)),
                    _n(s["model"]), _n(s["agent"]), _n(s["parent_session_id"]), _n(s["last_tool"]),
                    _n(s["tool_calls"]), _n(s["denials"]), _n(s["approvals"]),
                    _e(f"{s['tokens_in']}/{s['tokens_out']}") if s["tokens_in"] or s["tokens_out"] else "",
                    _n(s["cost_usd"]), _n(s["last_seen"]), _e(f"{s['idle_s']}s"),
                )
                for s in rows
            ],
        )  # fmt: skip
        main = f"<h2>Agents</h2><p>{head}</p>{chips}{table}"
        return self._page(doc, "Agents", main, decision, refresh=True)

    def _session(self, q, doc, decision) -> Response:
        sid = q.get("id")
        events = self.store.events(session=sid, limit=None, oldest_first=True) if sid else []
        if not events:
            return 404, HTML, b"unknown session\n"
        s = next(r for r in self.store.sessions() if r["session_id"] == sid)
        facts = "".join(
            f"<dt>{_e(k)}</dt><dd>{_n(s.get(k))}</dd>"
            for k in ("state", "runtime", "surface", "host", "project", "model", "agent",
                      "parent_session_id", "first_seen", "last_seen", "tool_calls", "denials",
                      "approvals", "errors", "tokens_in", "tokens_out", "cost_usd",
                      "stuck_after_s")
        )  # fmt: skip
        link = ""
        if decision.allowed:
            href = _href("/private/session", id=sid)
            link = f'<p class="private"><a href="{_e(href)}">Private detail of this session</a></p>'
        rows = [
            (
                _n(e["time"]), _n(e["kind"]), _n(e.get("tool")), _n(e.get("outcome")),
                _e(f"{e.get('tokens_in', '')}/{e.get('tokens_out', '')}")
                if e.get("tokens_in") or e.get("tokens_out") else "",
                f'<a href="{_e(_href("/activity", session=sid, event=e["event_id"]))}">'
                f"<code>{_e(e['event_id'])}</code></a>",
            )
            for e in events
        ]  # fmt: skip
        main = (
            f"<h2>Session <code>{_e(sid)}</code> {_badge(s['state'])}</h2>"
            f'<div class="pane"><dl>{facts}</dl></div>{link}<h3>Timeline</h3>'
            + _table(("Time", "Kind", "Tool", "Outcome", "Tokens", "Event"), rows)
        )
        return self._page(doc, f"Session {sid}", main, decision)

    def _selection(self, q: Mapping[str, str], limit: int) -> list[dict[str, Any]]:
        return self.store.events(
            session=q.get("session"),
            runtime=q.get("runtime"),
            outcome=q.get("outcome"),
            kind=q.get("kind"),
            limit=limit,
        )

    def _activity(self, q, doc, decision) -> Response:
        events = self._selection(q, STREAM_LIMIT)
        recent = self.store.events(limit=2000)
        chips = "".join(
            _chips("/activity", q, key, sorted({e[key] for e in recent if e.get(key)}))
            for key in ("runtime", "outcome", "kind")
        )
        if q.get("session"):
            chips += _chips("/activity", q, "session", [q["session"]])
        filters = {k: q.get(k) for k in ("runtime", "outcome", "kind", "session")}
        exports = (
            f'<p class="muted">export: <a href="{_e(_href("/activity.csv", **filters))}">CSV</a> '
            f'&middot; <a href="{_e(_href("/activity.jsonl", **filters))}">JSONL</a> '
            f"(summary tier, newest {EXPORT_LIMIT})</p>"
        )
        rows = [
            (
                _n(e["time"]),
                _n(e["runtime"]),
                f'<a href="{_e(_href("/agents/session", id=e["session_id"]))}">'
                f"<code>{_e(e['session_id'][:12])}</code></a>",
                _n(e["kind"]),
                _n(e.get("tool")),
                _n(e.get("outcome")),
                f'<a href="{_e(_href("/activity", **filters, event=e["event_id"]))}">inspect</a>',
            )
            for e in events
        ]
        listing = _table(("Time", "Runtime", "Session", "Kind", "Tool", "Outcome", ""), rows)
        selected = self.store.event(q["event"]) if q.get("event") else None
        if selected:
            dl = "".join(f"<dt>{_e(k)}</dt><dd>{_n(v)}</dd>" for k, v in sorted(selected.items()))
            extra = ""
            if decision.allowed and selected.get("has_detail"):
                href = _href("/private/event", id=selected["event_id"])
                extra = f'<p class="private"><a href="{_e(href)}">Private detail</a></p>'
            inspector = f'<div class="pane"><h3>Event</h3><dl>{dl}</dl>{extra}</div>'
        else:
            inspector = '<div class="pane muted">Pick an event to inspect it.</div>'
        main = (
            f"<h2>Activity</h2>{chips}{exports}"
            f'<div class="split"><div>{listing}</div>{inspector}</div>'
        )
        return self._page(doc, "Activity", main, decision, refresh=not selected)

    def _export(self, fmt: str, q: Mapping[str, str]) -> Response:
        events = self._selection(q, EXPORT_LIMIT)
        if fmt == "jsonl":
            body = "".join(json.dumps(e, sort_keys=True) + "\n" for e in events)
            return 200, "application/x-ndjson; charset=utf-8", body.encode("utf-8")
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator="\n")
        w.writerow(_SUMMARY_COLUMNS)
        for e in events:
            w.writerow([_csv_cell(e.get(c)) for c in _SUMMARY_COLUMNS])
        return 200, "text/csv; charset=utf-8", buf.getvalue().encode("utf-8")

    def _analytics(self, q, doc, decision) -> Response:
        events = self.store.events(limit=None)

        def counts(title: str, key: Callable[[Mapping[str, Any]], Any], top: int = 25) -> str:
            c = Counter(k for k in map(key, events) if k)
            rows = [(_e(k), _e(n)) for k, n in c.most_common(top)]
            return f"<h3>{_e(title)}</h3>" + _table((title.split()[-1], "Events"), rows)

        days: dict[str, Counter] = {}
        for e in events:
            days.setdefault(e["time"][:10], Counter())[e.get("outcome") or "none"] += 1
        outcomes = ("success", "error", "denied", "pending", "approved", "info", "none")
        day_rows = [
            (_e(d), *(_e(days[d][o]) for o in outcomes), _e(sum(days[d].values())))
            for d in sorted(days, reverse=True)[:30]
        ]
        sessions = self.store.sessions()
        st = state_counts(sessions)
        main = (
            "<h2>Agent analytics</h2>"
            f"<p>{len(events)} events in {len(sessions)} sessions &middot; "
            + " ".join(f"{_badge(k)} {v}" for k, v in st.items())
            + "</p>"
            + counts("By outcome", lambda e: e.get("outcome"))
            + counts("By runtime", lambda e: e.get("runtime"))
            + counts("By model", lambda e: e.get("model"))
            + counts("By tool", lambda e: e.get("tool"))
            + "<h3>By day</h3>"
            + _table(("Day", *outcomes, "Total"), day_rows)
        )
        return self._page(doc, "Agent analytics", main, decision)

    # ---------------------------------------------------------------- private tier
    def _private(self, route, q, doc, client, headers) -> Response:
        decision = self.authorize(client, headers)
        if not decision.allowed or self.access_log is None:
            return 403, "text/plain; charset=utf-8", b"forbidden: private view\n"
        user = decision.user or ""
        if route == "/private/sessions":
            self.access_log.append(user, "sessions")
            rows = [
                (
                    _badge(s["state"]),
                    f'<a href="{_e(_href("/private/session", id=s["session_id"]))}">'
                    f"<code>{_e(s['session_id'])}</code></a>",
                    _n(s["runtime"]), _n(s["project"]), _n(s["last_seen"]),
                )
                for s in self.store.sessions()
            ]  # fmt: skip
            main = '<h2 class="private">Private: sessions</h2>' + _table(
                ("State", "Session", "Runtime", "Project", "Last event"), rows
            )
            return self._page(doc, "Private sessions", main, decision)
        if route == "/private/session" and q.get("id"):
            sid = q["id"]
            events = self.store.events(session=sid, limit=None, oldest_first=True)
            if not events:
                return 404, HTML, b"unknown session\n"
            self.access_log.append(user, "session", session=sid)
            details = self.store.details(sid)
            blocks = "".join(self._event_block(e, details.get(e["event_id"])) for e in events)
            main = f'<h2 class="private">Private: session <code>{_e(sid)}</code></h2>{blocks}'
            return self._page(doc, f"Private session {sid}", main, decision)
        if route == "/private/event" and q.get("id"):
            ev = self.store.event(q["id"])
            if ev is None:
                return 404, HTML, b"unknown event\n"
            self.access_log.append(user, "event", session=ev["session_id"], event=ev["event_id"])
            main = '<h2 class="private">Private: event</h2>' + self._event_block(
                ev, self.store.detail(ev["event_id"])
            )
            return self._page(doc, "Private event", main, decision)
        if route == "/private/access-log":
            self.access_log.append(user, "access-log")
            rows = [
                (_n(a.get("at")), _n(a.get("user")), _n(a.get("view")), _n(a.get("session")),
                 _n(a.get("event")))
                for a in self.access_log.entries()
            ]  # fmt: skip
            main = '<h2 class="private">Private: access log</h2>' + _table(
                ("When", "Who", "View", "Session", "Event"), rows
            )
            return self._page(doc, "Private access log", main, decision)
        return 404, HTML, b"not found\n"

    @staticmethod
    def _event_block(ev: Mapping[str, Any], detail: Mapping[str, Any] | None) -> str:
        head = " ".join(
            _e(x) for x in (ev["time"], ev["kind"], ev.get("tool"), ev.get("outcome")) if x
        )
        parts = [f'<div class="pane"><h3>{head}</h3>']
        if not detail:
            parts.append('<p class="muted">no detail recorded</p>')
        else:
            for k in DETAIL_TEXT:
                if detail.get(k):
                    parts.append(f"<h4>{_e(k)}</h4><pre>{_e(detail[k])}</pre>")
            appr = detail.get("approval") or {}
            if appr:
                parts.append(f"<h4>approval: {_n(appr.get('decision'))}</h4>")
                if appr.get("payload"):
                    parts.append(f"<pre>{_e(appr['payload'])}</pre>")
            notes = []
            if detail.get("truncated"):
                notes.append("truncated: " + ", ".join(detail["truncated"]))
            red = {k: v for k, v in (detail.get("redactions") or {}).items() if v}
            if red:
                notes.append("redacted: " + ", ".join(f"{k} x{v}" for k, v in sorted(red.items())))
            if notes:
                parts.append(f'<p class="muted">{_e("; ".join(notes))}</p>')
        parts.append("</div>")
        return "".join(parts)
