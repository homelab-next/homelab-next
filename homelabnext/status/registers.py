# SPDX-License-Identifier: Apache-2.0
"""The register pages of the status hub: Kanban, Lessons, Runbooks and Invariants.

``hnx status serve --registers DIR`` serves four read-only, server-rendered pages (no script,
the hub's own stylesheet) from YAML register files in ``DIR``:

======================  ==================  ======================================================
``/kanban``             ``kanban.yml``      cards by column (projects with their steps, step cards,
                                            blocked, to do, in progress); ``?status=done`` is the
                                            archive
``/lessons``            ``lessons.yml``     the lessons-learned register: symptom, root cause,
                                            controls, status, recurrences, systems
``/runbooks``           ``runbooks.yml``    checklists whose every step has its own verify, plus the
                                            lessons sharing the runbook's systems
``/invariants``         ``invariants.yml``  statement, observable, expected, with the live
                                            pass/fail of ``invariants.results.json``
======================  ==================  ======================================================

``meta.json`` (``{"commit", "fetched_at"}``) says which git commit the files are a snapshot of
and when they were fetched; every page shows both and a loud STALE banner when the snapshot is
older than :data:`STALE_AFTER_S`.  The pages are withheld (ADR-0033 decision 8): private group,
``red``, only through the trusted front door; they are in no public view.

Filters are query-string only (the console's CSP allows no form and no script): ``?q=`` text
search, ``?status=`` (the column on Kanban, the kind on Runbooks, the verdict on Invariants),
``?system=`` (Lessons, Runbooks), ``?pillar=`` (Invariants), ``?id=`` (one record, opened), and
``?page=``.  A page holds at most :data:`PAGE_SIZE` records.

Reading: each file is parsed once with the repository's budgeted unique-key loader (a file above
:data:`MAX_FILE_BYTES` is refused unread) and cached by (mtime, size, inode); a request never
re-parses an unchanged file.  A file that is missing or malformed gives *its* page an error
banner and nothing else a failure.  Every value is HTML-escaped; the inline markup the registers
carry in prose (``<code>``, ``<strong>``) is re-allowed by a fixed tag list, and everything else,
links included, is shown as text.
"""

from __future__ import annotations

import datetime as dt
import html
import json
import re
import threading
import urllib.parse
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from homelabnext._yaml import UniqueKeyStrDateLoader

from .render import _e, nav_html, shell_html

__all__ = ["MAX_FILE_BYTES", "PAGE_SIZE", "ROUTES", "STALE_AFTER_S", "RegistersSite"]

Response = tuple[int, str, bytes]
HTML = "text/html; charset=utf-8"
ROUTES = ("/kanban", "/lessons", "/runbooks", "/invariants")
FILES = {
    "/kanban": "kanban.yml",
    "/lessons": "lessons.yml",
    "/runbooks": "runbooks.yml",
    "/invariants": "invariants.yml",
}
RESULTS_FILE = "invariants.results.json"
META_FILE = "meta.json"
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_META_BYTES = 64 * 1024
#: a snapshot older than this is shown with a loud STALE banner
STALE_AFTER_S = 2 * 3600
PAGE_SIZE = 25
KANBAN_PAGE_SIZE = 40
MAX_TEXT = 20_000
MAX_Q = 100
_VALUE = re.compile(r"[A-Za-z0-9._:/@ -]{1,64}")
_ALLOWED_TAG = re.compile(r"</?(?:code|strong|b|em|i)>")
_STRIP_TAG = re.compile(r"</?a\b[^>]*>", re.IGNORECASE)
_CLASS = {
    "controlled": "ok", "partial": "warn", "open": "fail", "retired": "unknown",
    "grandfathered": "unknown", "pass": "ok", "fail": "fail", "error": "warn",
    "untested": "unknown", "deferred": "unknown", "done": "ok", "blocked": "fail",
    "progress": "warn", "todo": "unknown"
}  # fmt: skip
INVARIANT_STATUSES = ("pass", "fail", "error", "untested", "deferred")
DEFAULT_COLUMNS = (
    ("rfi", "Open RFIs/Tasks"), ("blocked", "Blocked"), ("todo", "To Do"),
    ("progress", "In Progress"), ("partial", "Projects (partial)"), ("done", "Archive"),
)  # fmt: skip


# --- text helpers ----------------------------------------------------------------------------


def _t(v: Any, limit: int = MAX_TEXT) -> str:
    """Any YAML value as bounded plain text."""
    if v is None:
        return ""
    if isinstance(v, str):
        s = v
    elif isinstance(v, (list, tuple)):
        s = "\n".join(_t(x, limit) for x in v)
    elif isinstance(v, Mapping):
        s = "; ".join(f"{k}: {_t(x, limit)}" for k, x in v.items())
    else:
        s = str(v)
    return s if len(s) <= limit else s[:limit] + " ... (truncated)"


def _inline(v: Any) -> str:
    """Escaped text that keeps a fixed list of formatting tags (``<code>`` ``<strong>`` ``<b>``
    ``<em>`` ``<i>``, no attributes); links lose their tag and keep their text, and every other
    tag or character is escaped.  Entities already in the source (``&amp;``) are read first so
    they are not escaped twice."""
    s = _STRIP_TAG.sub("", html.unescape(_t(v)))
    out, pos = [], 0
    for m in _ALLOWED_TAG.finditer(s):
        out.append(html.escape(s[pos : m.start()]))
        out.append(m.group(0))
        pos = m.end()
    out.append(html.escape(s[pos:]))
    return _balance("".join(out))


def _balance(s: str) -> str:
    """Close any allowed tag left open and drop a close with no open, so one card's stray tag
    cannot reshape the page around it."""
    stack: list[str] = []
    out, pos = [], 0
    for m in re.finditer(r"<(/?)(code|strong|b|em|i)>", s):
        out.append(s[pos : m.start()])
        pos = m.end()
        closing, name = m.group(1) == "/", m.group(2)
        if not closing:
            stack.append(name)
            out.append(m.group(0))
        elif name in stack:
            while stack:
                top = stack.pop()
                out.append(f"</{top}>")
                if top == name:
                    break
    out.append(s[pos:])
    out.extend(f"</{n}>" for n in reversed(stack))
    return "".join(out)


def _paras(v: Any) -> str:
    """Escaped plain text as paragraphs (a blank line splits, a newline breaks)."""
    s = _t(v).strip()
    if not s:
        return '<p class="muted">not recorded</p>'
    return "".join(
        "<p>" + "<br>".join(_e(line) for line in block.split("\n")) + "</p>"
        for block in re.split(r"\n\s*\n", s)
    )


def _list(v: Any) -> list[Any]:
    return v if isinstance(v, list) else ([] if v is None else [v])


def _badge(text: str, cls: str | None = None) -> str:
    return f'<span class="s {_CLASS.get(cls or text, "unknown")}">{_e(text)}</span>'


def _field(label: str, body_html: str) -> str:
    return f"<h4>{_e(label)}</h4>{body_html}"


def _ul(items: Sequence[Any], render: Callable[[Any], str] = _inline) -> str:
    return "<ul>" + "".join(f"<li>{render(i)}</li>" for i in items) + "</ul>" if items else ""


# --- query -----------------------------------------------------------------------------------


def _params(query: str) -> dict[str, str]:
    """Single-valued, shape-checked parameters; anything else is ignored.  ``q`` is free text
    (bounded, control characters dropped); it is only ever searched and escaped."""
    out: dict[str, str] = {}
    for k, vals in urllib.parse.parse_qs(query, keep_blank_values=False).items():
        if len(vals) != 1:
            continue
        v = vals[0]
        if k == "q":
            v = "".join(c for c in v if c.isprintable())[:MAX_Q].strip()
            if v:
                out["q"] = v
        elif k == "page":
            if v.isdigit() and len(v) <= 6:
                out["page"] = v
        elif k in ("status", "system", "id", "pillar") and _VALUE.fullmatch(v):
            out[k] = v.strip()
    return out


def _href(route: str, params: Mapping[str, str], **change: str | None) -> str:
    merged = {**params, **change}
    q = urllib.parse.urlencode({k: v for k, v in merged.items() if v})
    return f"{route}?{q}" if q else route


def _chips(
    route: str, params: Mapping[str, str], key: str, counts: Mapping[str, int], limit: int = 40
) -> str:
    """Filter links for ``key``: ``all`` and one per value (most frequent first), the active
    one in bold."""
    if not counts:
        return ""
    cur = params.get(key, "")
    parts = [f'<span class="muted">{_e(key)}:</span> ']
    shown = [v for v, _ in Counter(counts).most_common(limit)]
    if cur and cur not in shown:
        shown.append(cur)
    for v in ("", *shown):
        label = f"{v} ({counts[v]})" if v and v in counts else (v or "all")
        if cur == v:
            parts.append(f"<b>{_e(label)}</b>")
        else:
            href = _href(route, params, **{key: v or None, "page": None, "id": None})
            parts.append(f'<a href="{_e(href)}">{_e(label)}</a>')
    return f'<div class="chips">{"".join(parts)}</div>'


def _paginate(rows: list, params: Mapping[str, str], size: int) -> tuple[list, int, int]:
    pages = max(1, -(-len(rows) // size))
    page = min(max(int(params.get("page", "1") or 1), 1), pages)
    return rows[(page - 1) * size : page * size], page, pages


def _pager(route: str, params: Mapping[str, str], page: int, pages: int, total: int, size: int):
    first = (page - 1) * size + 1 if total else 0
    last = min(page * size, total)
    nav = []
    if page > 1:
        nav.append(f'<a href="{_e(_href(route, params, page=str(page - 1)))}">previous</a>')
    if page < pages:
        nav.append(f'<a href="{_e(_href(route, params, page=str(page + 1)))}">next</a>')
    return (
        f'<p class="muted">{total} records, showing {first}-{last} (page {page} of {pages})'
        f"{' &middot; ' if nav else ''}{' &middot; '.join(nav)}</p>"
    )


def _filter_note(route: str, params: Mapping[str, str]) -> str:
    active = {k: v for k, v in params.items() if k in ("q", "status", "system", "id", "pillar")}
    if not active:
        return (
            '<p class="muted">Search: add <code>?q=text</code> to the address (the console '
            "allows no form).</p>"
        )
    shown = ", ".join(f"{_e(k)} = <code>{_e(v)}</code>" for k, v in active.items())
    return f'<p>Filtered by {shown} &middot; <a href="{_e(route)}">clear</a></p>'


# --- reading ---------------------------------------------------------------------------------


class RegisterError(Exception):
    """A register file that cannot be shown; the message is the page's banner."""


@dataclass(frozen=True)
class _Row:
    d: Mapping[str, Any]
    hay: str  # lower-cased text of the record, the ``?q=`` search target


@dataclass(frozen=True)
class _Loaded:
    rows: tuple[_Row, ...]
    extra: Mapping[str, Any]


def _hay(d: Mapping[str, Any]) -> str:
    return _t(d, 8000).lower()


def _read_bounded(path: Path, limit: int) -> bytes:
    try:
        size = path.stat().st_size
        if size > limit:
            raise RegisterError(f"{path.name} is {size} bytes, above the {limit} byte limit")
        with path.open("rb") as fh:
            raw = fh.read(limit + 1)
    except FileNotFoundError:
        raise RegisterError(f"{path.name} not found in the register directory") from None
    except OSError as exc:
        raise RegisterError(f"{path.name} cannot be read: {exc.strerror or 'I/O error'}") from None
    if len(raw) > limit:
        raise RegisterError(f"{path.name} is above the {limit} byte limit")
    return raw


def _parse_yaml(path: Path) -> Any:
    raw = _read_bounded(path, MAX_FILE_BYTES)
    try:
        return yaml.load(raw.decode("utf-8"), Loader=UniqueKeyStrDateLoader)  # budgeted, safe
    except UnicodeDecodeError:
        raise RegisterError(f"{path.name} is not UTF-8 text") from None
    except yaml.YAMLError as exc:
        why = " ".join(str(exc).split())[:300]
        raise RegisterError(f"{path.name} is not valid YAML: {why}") from None
    except RecursionError:
        raise RegisterError(f"{path.name} is nested too deeply") from None


def _records(doc: Any, name: str, key: str, id_key: str = "id") -> tuple[_Row, ...]:
    if not isinstance(doc, Mapping) or not isinstance(doc.get(key), list):
        raise RegisterError(f"{name} has no '{key}' list at its top level")
    rows = []
    for n, rec in enumerate(doc[key], 1):
        if not isinstance(rec, Mapping):
            raise RegisterError(f"{name}: entry {n} of '{key}' is not a mapping")
        rows.append(_Row(rec, _hay(rec)))
    return tuple(rows)


def _load_kanban(path: Path) -> _Loaded:
    doc = _parse_yaml(path)
    rows = _records(doc, path.name, "cards")
    cols = doc.get("columns")
    return _Loaded(rows, {"columns": cols if isinstance(cols, list) else []})


def _load_lessons(path: Path) -> _Loaded:
    return _Loaded(_records(_parse_yaml(path), path.name, "lessons"), {})


def _load_runbooks(path: Path) -> _Loaded:
    return _Loaded(_records(_parse_yaml(path), path.name, "runbooks"), {})


def _load_invariants(path: Path) -> _Loaded:
    doc = _parse_yaml(path)
    rows = _records(doc, path.name, "criteria")
    pillars = [p for p in _list(doc.get("pillars")) if isinstance(p, Mapping)]
    keep = ("version", "definition", "how_to_run", "how_to_read_a_red", "declared_on")
    return _Loaded(rows, {"pillars": pillars, **{k: doc.get(k) for k in keep}})


_LOADERS = {
    "/kanban": _load_kanban,
    "/lessons": _load_lessons,
    "/runbooks": _load_runbooks,
    "/invariants": _load_invariants,
}


class RegistersSite:
    """The register routes of ``hnx status serve`` over one directory of register files.

    Each file is parsed at most once per change (cache keyed by mtime, size and inode, errors
    included, so a malformed file is not re-parsed per request either); a parse holds a lock of
    its own file, so concurrent requests for one page parse it once and the other pages never
    wait."""

    def __init__(self, root: str | Path, *, clock: Callable[[], float]):
        self.root, self.clock = Path(root), clock
        self._locks = {r: threading.Lock() for r in ROUTES}
        self._cache: dict[str, tuple[tuple, _Loaded | RegisterError]] = {}
        self.parses = 0

    # -- cache --

    def _load(self, route: str) -> _Loaded:
        path = self.root / FILES[route]
        try:
            st = path.stat()
        except FileNotFoundError:
            raise RegisterError(f"{path.name} not found in the register directory") from None
        except OSError as exc:
            raise RegisterError(f"{path.name} cannot be read: {exc.strerror or 'I/O'}") from None
        sig = (st.st_mtime_ns, st.st_size, st.st_ino)
        with self._locks[route]:
            hit = self._cache.get(route)
            if hit is None or hit[0] != sig:
                self.parses += 1
                try:
                    value: _Loaded | RegisterError = _LOADERS[route](path)
                except RegisterError as exc:
                    value = exc
                self._cache[route] = hit = (sig, value)
        if isinstance(hit[1], RegisterError):
            raise hit[1]
        return hit[1]

    def _meta(self) -> tuple[dict[str, str], str | None]:
        """The snapshot's ``commit`` and ``fetched_at`` and a problem text, if any."""
        try:
            raw = _read_bounded(self.root / META_FILE, MAX_META_BYTES)
            doc = json.loads(raw.decode("utf-8"))
        except RegisterError as exc:
            return {}, str(exc)
        except (ValueError, UnicodeDecodeError):
            return {}, f"{META_FILE} is not valid JSON"
        if not isinstance(doc, dict):
            return {}, f"{META_FILE} is not a JSON object"
        return {k: _t(doc.get(k), 200) for k in ("commit", "fetched_at")}, None

    def _results(self) -> tuple[dict[str, Any], str, str | None]:
        try:
            doc = json.loads(_read_bounded(self.root / RESULTS_FILE, MAX_FILE_BYTES))
        except RegisterError as exc:
            return {}, "", str(exc)
        except (ValueError, UnicodeDecodeError):
            return {}, "", f"{RESULTS_FILE} is not valid JSON"
        res = doc.get("results") if isinstance(doc, dict) else None
        if not isinstance(res, dict):
            return {}, "", f"{RESULTS_FILE} has no 'results' object"
        return res, _t(doc.get("last_run"), 40), None

    # -- chrome --

    def _snapshot(self) -> str:
        meta, problem = self._meta()
        now = self.clock()
        commit = meta.get("commit", "")
        fetched = meta.get("fetched_at", "")
        age = None
        if fetched:
            try:
                ts = dt.datetime.fromisoformat(fetched.replace("Z", "+00:00"))
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=dt.UTC)
                age = max(0.0, now - ts.timestamp())
            except ValueError:
                age = None
        line = (
            f"Snapshot of git commit <code>{_e(commit[:40]) or 'unknown'}</code>, fetched "
            f"<code>{_e(fetched) or 'unknown'}</code>. Read-only: edit the register in its "
            "repository."
        )
        out = [f'<p class="muted">{line}</p>']
        if age is None:
            why = problem or "meta.json carries no readable fetched_at"
            out.append(
                '<div class="pane private"><b class="s fail">STALE?</b> the age of this '
                f"snapshot is unknown ({_e(why)}); treat it as out of date.</div>"
            )
        elif age > STALE_AFTER_S:
            out.append(
                '<div class="pane private"><b class="s fail">STALE</b> this snapshot was '
                f"fetched {_e(_human_age(age))} ago (limit {STALE_AFTER_S // 3600} hours): the "
                "register may have changed since.</div>"
            )
        return "".join(out)

    def handle(self, route: str, query: str, doc: Mapping[str, Any]) -> Response | None:
        if route not in ROUTES:
            return None
        title = route[1:].capitalize()
        params = _params(query)
        body = ""
        try:
            body = {
                "/kanban": self._kanban,
                "/lessons": self._lessons,
                "/runbooks": self._runbooks,
                "/invariants": self._invariants,
            }[route](route, params)
        except RegisterError as exc:
            body = (
                '<div class="pane private"><b class="s fail">ERROR</b> this register cannot be '
                f"shown: {_e(exc)}</div>"
            )
        except Exception as exc:  # a register must never become a 500 for its page
            body = (
                '<div class="pane private"><b class="s fail">ERROR</b> this register could not '
                f"be rendered ({_e(type(exc).__name__)}).</div>"
            )
        main = f"<h2>{_e(title)}</h2>{self._snapshot()}{body}"
        html_ = shell_html(doc, title, main, nav=nav_html(doc, live=True, private=True))
        return 200, HTML, html_.encode("utf-8")

    # -- kanban --

    def _kanban(self, route: str, params: Mapping[str, str]) -> str:
        loaded = self._load(route)
        cols = [
            (str(c["id"]), _t(c.get("title"), 120) or str(c["id"]))
            for c in loaded.extra["columns"]
            if isinstance(c, Mapping) and c.get("id")
        ] or list(DEFAULT_COLUMNS)
        order = {cid: i for i, (cid, _) in enumerate(cols)}
        titles = dict(cols)
        counts = Counter(_t(r.d.get("column")) or "?" for r in loaded.rows)
        want = params.get("status")
        rows = []
        for r in loaded.rows:
            col = _t(r.d.get("column")) or "?"
            if (want and col != want) or (not want and col == "done"):
                continue
            if "q" in params and params["q"].lower() not in r.hay:
                continue
            if "id" in params and not _kanban_has_id(r.d, params["id"]):
                continue
            rows.append((col, r))
        rows.sort(key=lambda cr: _date_key(cr[1].d), reverse=True)
        rows.sort(key=lambda cr: order.get(cr[0], len(order)))
        total = len(rows)
        page_rows, page, pages = _paginate(rows, params, KANBAN_PAGE_SIZE)
        visible = {c: n for c, n in counts.items() if c != "done"}
        out = [
            _chips(route, params, "status", {**visible, "done": counts.get("done", 0)}),
            _filter_note(route, params),
            '<p class="muted">The RFI column is generated from the task queue and is not part '
            "of this snapshot. Completed cards are the archive: <code>?status=done</code>.</p>",
            _pager(route, params, page, pages, total, KANBAN_PAGE_SIZE),
        ]
        last = None
        for col, r in page_rows:
            if col != last:
                out.append(f"<h3>{_e(titles.get(col, col))}</h3>")
                last = col
            out.append(_card(r.d, col))
        if not page_rows:
            out.append('<p class="muted">no card matches</p>')
        return "".join(out)

    # -- lessons --

    def _lessons(self, route: str, params: Mapping[str, str]) -> str:
        loaded = self._load(route)
        statuses = Counter(_t(r.d.get("status")) or "?" for r in loaded.rows)
        systems = Counter(s for r in loaded.rows for s in _systems(r.d))
        rows = _filter(loaded.rows, params, status_of=lambda d: _t(d.get("status")))
        rows = [r for r in rows if _has_system(r.d, params.get("system"))]
        page_rows, page, pages = _paginate(rows, params, PAGE_SIZE)
        opened = "id" in params
        out = [
            _chips(route, params, "status", statuses),
            _chips(route, params, "system", systems),
            _filter_note(route, params),
            _pager(route, params, page, pages, len(rows), PAGE_SIZE),
        ]
        out += [_lesson(r.d, opened) for r in page_rows]
        if not page_rows:
            out.append('<p class="muted">no lesson matches</p>')
        return "".join(out)

    # -- runbooks --

    def _runbooks(self, route: str, params: Mapping[str, str]) -> str:
        loaded = self._load(route)
        kinds = Counter(_t(r.d.get("kind")) or "?" for r in loaded.rows)
        systems = Counter(s for r in loaded.rows for s in _systems(r.d))
        rows = _filter(loaded.rows, params, status_of=lambda d: _t(d.get("kind")))
        rows = [r for r in rows if _has_system(r.d, params.get("system"))]
        page_rows, page, pages = _paginate(rows, params, PAGE_SIZE)
        opened = "id" in params
        lessons = self._lessons_by_system() if page_rows else {}
        out = [
            '<p class="muted">The status filter here is the runbook kind.</p>',
            _chips(route, params, "status", kinds),
            _chips(route, params, "system", systems),
            _filter_note(route, params),
            _pager(route, params, page, pages, len(rows), PAGE_SIZE),
        ]
        out += [_runbook(r.d, opened, lessons) for r in page_rows]
        if not page_rows:
            out.append('<p class="muted">no runbook matches</p>')
        return "".join(out)

    def _lessons_by_system(self) -> dict[str, list[tuple[str, str, str]]]:
        """``{normalised system: [(id, title, status)]}`` from the lessons register, empty when
        that file cannot be read (the runbook page does not fail for it)."""
        try:
            loaded = self._load("/lessons")
        except RegisterError:
            return {}
        idx: dict[str, list[tuple[str, str, str]]] = {}
        for r in loaded.rows:
            entry = (_t(r.d.get("id"), 40), _t(r.d.get("title"), 200), _t(r.d.get("status"), 40))
            for s in _systems(r.d):
                idx.setdefault(_norm(s), []).append(entry)
        return idx

    # -- invariants --

    def _invariants(self, route: str, params: Mapping[str, str]) -> str:
        loaded = self._load(route)
        results, last_run, problem = self._results()
        merged = [(_merge(r.d, results), r) for r in loaded.rows]
        tally = Counter(m["status"] for m, _ in merged)
        pillars = Counter(_t(r.d.get("pillar")) or "?" for r in loaded.rows)
        live = [m for m, _ in merged if m["status"] != "deferred"]
        broken = [m for m in live if m["status"] != "pass"]
        out = []
        if problem:
            out.append(
                '<div class="pane private"><b class="s fail">NO LIVE RESULTS</b> '
                f"{_e(problem)}: auto criteria show as untested.</div>"
            )
        if live and not broken:
            out.append('<p><b class="s ok">ALL INVARIANTS HOLD</b></p>')
        else:
            out.append(
                f'<p><b class="s fail">{len(broken)} INVARIANT(S) NOT HOLDING</b> '
                f"of {len(live)} live criteria</p>"
            )
        counts = ", ".join(f"{tally.get(s, 0)} {s}" for s in INVARIANT_STATUSES)
        out.append(
            f'<p class="muted">{len(merged)} criteria: {_e(counts)}'
            f"{' &middot; auto checks last run ' + _e(last_run) if last_run else ''}</p>"
        )
        if loaded.extra.get("definition"):
            out.append(f'<div class="pane">{_paras(loaded.extra["definition"])}</div>')
        rows = [
            (m, r)
            for m, r in merged
            if _match(r, params, status=m["status"])
            and ("pillar" not in params or _t(r.d.get("pillar")) == params["pillar"])
        ]
        page_rows, page, pages = _paginate(rows, params, PAGE_SIZE)
        out += [
            _chips(route, params, "status", {s: tally[s] for s in INVARIANT_STATUSES if tally[s]}),
            _chips(route, params, "pillar", pillars),
            _filter_note(route, params),
            _pager(route, params, page, pages, len(rows), PAGE_SIZE),
        ]
        names = {_t(p.get("id")): _t(p.get("name"), 120) for p in loaded.extra["pillars"]}
        out += [_criterion(m, names, "id" in params) for m, _ in page_rows]
        if not page_rows:
            out.append('<p class="muted">no criterion matches</p>')
        return "".join(out)


# --- filtering helpers -----------------------------------------------------------------------


def _match(row: _Row, params: Mapping[str, str], *, status: str = "") -> bool:
    if "id" in params and _t(row.d.get("id")) != params["id"]:
        return False
    if "status" in params and status != params["status"]:
        return False
    return "q" not in params or params["q"].lower() in row.hay


def _filter(rows: Sequence[_Row], params: Mapping[str, str], *, status_of: Callable) -> list[_Row]:
    return [r for r in rows if _match(r, params, status=status_of(r.d))]


def _norm(tag: Any) -> str:
    return str(tag).lower().replace("_", "-")


def _systems(d: Mapping[str, Any]) -> list[str]:
    return [_t(s, 60) for s in _list(d.get("systems")) if _t(s, 60)]


def _has_system(d: Mapping[str, Any], want: str | None) -> bool:
    return not want or _norm(want) in {_norm(s) for s in _systems(d)}


def _date_key(d: Mapping[str, Any]) -> str:
    s = _t(d.get("date"), 20)
    return s if re.fullmatch(r"\d{4}-\d{2}-\d{2}", s) else ""


def _kanban_has_id(card: Mapping[str, Any], want: str) -> bool:
    cid = _t(card.get("id"), 40)
    return cid == want or cid.startswith(want + ".")


def _human_age(seconds: float) -> str:
    h, m = divmod(int(seconds) // 60, 60)
    return f"{h // 24}d {h % 24}h" if h >= 24 else f"{h}h {m}m"


# --- rendering one record --------------------------------------------------------------------


def _card(c: Mapping[str, Any], column: str) -> str:
    cid = _t(c.get("id"), 40)
    steps = [s for s in _list(c.get("steps")) if isinstance(s, Mapping)]
    badge = ""
    if cid:
        done = sum(1 for s in steps if _t(s.get("status")) == "done")
        link = _href(
            "/kanban", {}, id=cid.split(".")[0], status=column if column == "done" else None
        )
        extra = f" &middot; {done}/{len(steps)}" if steps else ""
        badge = f'<a href="{_e(link)}"><code>{_e(cid)}</code></a>{extra} '
    tags = " ".join(
        f'<span class="s unknown">{_e(_t(t.get("text"), 60))}</span>'
        for t in _list(c.get("tags"))
        if isinstance(t, Mapping) and t.get("text")
    )
    parked = f" {_badge('parked', 'unknown')}" if c.get("parked") else ""
    meta = f'<p class="muted">{_e(_t(c.get("date"), 20))}{parked} {tags}</p>'
    body = "".join(f"<p>{_inline(p)}</p>" for p in _list(c.get("body")))
    lines = []
    for s in steps:
        st = _t(s.get("status"), 20)
        tail = ""
        if st == "done" and (s.get("date") or s.get("result")):
            tail = (
                f' <span class="muted">({_e(_t(s.get("date"), 20))}'
                f"{' - ' + _inline(s['result']) if s.get('result') else ''})</span>"
            )
        elif s.get("result"):
            tail = f' <span class="muted">({_inline(s["result"])})</span>'
        lines.append(
            f"{_badge(st or '?', 'done' if st == 'done' else 'todo')} {_e(_t(s.get('n'), 6))}. "
            f"{_inline(s.get('text'))}{tail}"
        )
    return (
        f'<div class="pane"><h4>{badge}{_inline(c.get("title"))}</h4>{meta}{body}'
        f"{_ul(lines, lambda x: x)}</div>"
    )


def _lesson(d: Mapping[str, Any], opened: bool) -> str:
    lid, status = _t(d.get("id"), 40), _t(d.get("status"), 40)
    rec = d.get("recurrences")
    head = (
        f"<summary><code>{_e(lid)}</code> {_badge(status or '?')} {_e(_t(d.get('title'), 300))} "
        f'<span class="muted">{_e(_t(d.get("date"), 20))} &middot; '
        f"{_e(', '.join(_systems(d)))} &middot; bitten {_e(_t(rec, 10) or '?')}x</span></summary>"
    )
    parts = [
        _field("Symptom: what it looks like", _paras(d.get("symptom"))),
        _field("Contributing factors", _ul(_list(d.get("contributing_factors")), _e)),
        _field("Root cause", _paras(d.get("root_cause"))),
        _field("Corrective action", _paras(d.get("corrective_action"))),
        _field("Preventive control", _paras(d.get("preventive_control"))),
        _field("Verification: the falsifiable test", _paras(d.get("verification"))),
    ]
    for key, label in (("retired_by", "Retired by"), ("detection", "Early detection"),
                       ("note", "Note")):  # fmt: skip
        if d.get(key):
            parts.append(_field(label, _paras(d[key])))
    if d.get("severity"):
        parts.append(f'<p class="muted">severity {_e(_t(d["severity"], 20))}</p>')
    return (
        f'<div class="pane" id="{_e(lid)}"><details{" open" if opened else ""}>{head}'
        f"{''.join(parts)}</details></div>"
    )


def _runbook(
    d: Mapping[str, Any], opened: bool, lessons: Mapping[str, list[tuple[str, str, str]]]
) -> str:
    rid, kind = _t(d.get("id"), 40), _t(d.get("kind"), 20)
    head = (
        f"<summary><code>{_e(rid)}</code> {_badge(kind or '?', 'unknown')} "
        f'{_e(_t(d.get("name"), 300))} <span class="muted">{_e(", ".join(_systems(d)))}'
        "</span></summary>"
    )
    steps = []
    for s in _list(d.get("checklist")):
        if isinstance(s, Mapping):
            steps.append(
                f'{_inline(s.get("step"))}<br><span class="muted">verify: '
                f"{_inline(s.get('verify'))}</span>"
            )
    parts = [
        _field("What this is", _paras(d.get("summary"))),
        _field("When to use it", _paras(d.get("when_to_use"))),
        _field("Access", _paras(d.get("access"))),
    ]
    ident = d.get("identity")
    if isinstance(ident, Mapping) and ident:
        parts.append(
            _field(
                "Identity",
                "<dl>"
                + "".join(
                    f"<dt>{_e(k)}</dt><dd><code>{_e(_t(v, 200))}</code></dd>"
                    for k, v in ident.items()
                )
                + "</dl>",
            )
        )
    if d.get("dataflow"):
        parts.append(_field("Dataflow", _paras(d["dataflow"])))
    parts.append(
        _field(
            "Checklist: every step has its own verify",
            "<ol>" + "".join(f"<li>{s}</li>" for s in steps) + "</ol>"
            if steps
            else '<p class="muted">no checklist</p>',
        )
    )
    kf = [k for k in _list(d.get("key_files")) if isinstance(k, Mapping)]
    if kf:
        parts.append(
            _field(
                "Key files",
                _ul(
                    kf,
                    lambda k: f"<code>{_e(_t(k.get('path'), 300))}</code> {_inline(k.get('why'))}",
                ),
            )
        )
    for key, label in (("connections", "Connections"), ("alerts", "Alerts")):
        if d.get(key):
            parts.append(_field(label, _ul(_list(d[key]))))
    parts.append(_field("Done when: the falsifiable check", _paras(d.get("verification"))))
    for key, label in (("rollback", "Rollback"), ("references", "References")):
        if d.get(key):
            parts.append(_field(label, _paras(d[key])))
    aids = d.get("aids")
    if isinstance(aids, Mapping) and aids:
        flat = [(k, v) for k, vs in aids.items() for v in _list(vs)]
        parts.append(
            _field("Aids", _ul(flat, lambda kv: f"{_e(kv[0])}: <code>{_e(_t(kv[1], 300))}</code>"))
        )
    applied: dict[str, tuple[str, str]] = {}
    for s in _systems(d):
        for lid, title, status in lessons.get(_norm(s), []):
            applied[lid] = (title, status)
    if applied:
        shown = sorted(applied.items())[:30]
        more = len(applied) - len(shown)
        items = [
            f'<a href="{_e(_href("/lessons", {}, id=lid))}"><code>{_e(lid)}</code></a> '
            f"{_badge(st or '?')} {_e(title)}"
            for lid, (title, st) in shown
        ]
        if more > 0:
            items.append(f'<span class="muted">and {more} more: filter /lessons by system</span>')
        parts.append(_field("Lessons that apply here: read before you touch this",
                            _ul(items, lambda x: x)))  # fmt: skip
    return (
        f'<div class="pane" id="{_e(rid)}"><details{" open" if opened else ""}>{head}'
        f"{''.join(parts)}</details></div>"
    )


def _merge(d: Mapping[str, Any], results: Mapping[str, Any]) -> dict[str, Any]:
    """An invariant with its live verdict: an ``auto`` criterion takes status and evidence from
    the results file (``untested`` without a result), a manual one keeps the register's stamp."""
    out = dict(d)
    if _t(d.get("evidence")) == "auto":
        r = results.get(_t(d.get("id"))) if isinstance(results, Mapping) else None
        r = r if isinstance(r, Mapping) else {}
        out["status"] = _t(r.get("status")) or (
            "deferred" if d.get("status") == "deferred" else "untested"
        )
        out["evidence_text"] = _t(r.get("evidence"))
        out["checked_at"] = _t(r.get("checked_at"), 40)
    else:
        out["status"] = _t(d.get("status")) or "untested"
        out["evidence_text"] = _t(d.get("evidence_note"))
        out["checked_at"] = _t(d.get("last_checked"), 40)
    if out["status"] not in INVARIANT_STATUSES:
        out["status"] = "error"
    return out


def _criterion(m: Mapping[str, Any], pillars: Mapping[str, str], opened: bool) -> str:
    cid, status = _t(m.get("id"), 40), m["status"]
    pillar = _t(m.get("pillar"), 20)
    head = (
        f"<summary><code>{_e(cid)}</code> {_badge(status.upper(), status)} "
        f'{_inline(m.get("statement"))} <span class="muted">{_e(pillar)} '
        f"{_e(pillars.get(pillar, ''))} &middot; {_e(_t(m.get('evidence'), 20))}"
        f"{' &middot; slow' if m.get('slow') else ''} &middot; "
        f"{_e(m['checked_at'][:10])}</span></summary>"
    )
    parts = [
        _field("Observable", _paras(m.get("observable"))),
        _field("Expected", _paras(m.get("expected"))),
    ]
    if m.get("evidence_text"):
        parts.append(_field("Evidence", f"<pre>{_e(_t(m['evidence_text'], 4000))}</pre>"))
    if m.get("check"):
        parts.append(_field("Check", f"<pre>{_e(_t(m['check'], 4000))}</pre>"))
    if m.get("remediation"):
        parts.append(_field("What to do", _paras(m["remediation"])))
    elif status in ("fail", "error"):
        parts.append(
            '<p><b class="s fail">No remediation recorded</b> this criterion is red and does '
            "not say what to do about it.</p>"
        )
    if m.get("note"):
        parts.append(_field("Note", _paras(m["note"])))
    # a red or errored criterion is open by default: it is what the page is for
    is_open = opened or status in ("fail", "error")
    return (
        f'<div class="pane" id="{_e(cid)}"><details{" open" if is_open else ""}>{head}'
        f"{''.join(parts)}</details></div>"
    )
