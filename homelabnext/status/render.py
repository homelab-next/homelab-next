# SPDX-License-Identifier: Apache-2.0
"""The static shell: one self-contained HTML page (inline CSS, no script, no CDN) plus
``status.json``, both rendered from the status document alone (``homelabnext.status.views``).

Layout: a left menu (every view of ``views.yml``, external entries marked and linked out) and a
main area holding one section per panel view.  Switching views needs no JavaScript: each menu
entry is an ``#view-<id>`` anchor and CSS ``:target`` shows that section; with no fragment the
main view shows.  Every value is HTML-escaped.  Same document in, same bytes out.

Logical links (``svc:x``, ``cap:x``, ``inv:X-01``, ``status:x``) are shown as text with the page
they resolve to linked through ``docs_base`` (default ``docs``, a path relative to where the page
is served): the hub links to the documentation and to the approval path, it never acts.
"""

from __future__ import annotations

import base64
import hashlib
import html
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .views import GENERATED_PANELS, PAGE_PANELS, dumps, public_status

_CSS = """
:root{--bg:#f6f7f9;--panel:#fff;--ink:#1d2330;--mute:#5b6475;--line:#d9dde4;
--ok:#1f7a3a;--warn:#9a6700;--fail:#b42318;--unknown:#5b6475;--stale:#6941c6}
@media (prefers-color-scheme:dark){:root{--bg:#12151b;--panel:#1b1f27;--ink:#e6e9ef;
--mute:#9aa3b2;--line:#2c323d;--ok:#4cc38a;--warn:#e3b341;--fail:#f97066;--unknown:#9aa3b2;
--stale:#b692f6}}
*{box-sizing:border-box}body{margin:0;font:15px/1.45 system-ui,sans-serif;background:var(--bg);
color:var(--ink);display:flex;min-height:100vh}
nav{width:15rem;flex:none;background:var(--panel);border-right:1px solid var(--line);padding:1rem}
nav h1{font-size:1.05rem;margin:0 0 .25rem}nav p{margin:0 0 1rem;color:var(--mute);font-size:.8rem}
nav a{display:block;padding:.35rem .5rem;border-radius:.3rem;color:inherit;text-decoration:none}
nav a:hover{background:var(--bg)}nav .ext::after{content:" \\2197";color:var(--mute)}
nav .off{color:var(--mute);padding:.35rem .5rem;display:block}
main{flex:1;padding:1.25rem 1.5rem;min-width:0}
.view{display:none}.view:target{display:block}.view.main{display:block}
.view:target~.view.main{display:none}
h2{margin:0 0 1rem;font-size:1.25rem}
.green{font-size:2.2rem;font-weight:600;color:var(--ok)}.muted{color:var(--mute)}
.tiles{display:grid;grid-template-columns:repeat(auto-fill,minmax(14rem,1fr));gap:.75rem}
.tile{background:var(--panel);border:1px solid var(--line);border-left:.35rem solid var(--unknown);
border-radius:.4rem;padding:.6rem .75rem}
.tile h3{margin:0 0 .25rem;font-size:1rem}.tile ul{margin:.4rem 0 0;padding-left:1rem;font-size:.85rem}
table{border-collapse:collapse;width:100%;background:var(--panel);font-size:.88rem}
th,td{border-bottom:1px solid var(--line);padding:.4rem .5rem;text-align:left;vertical-align:top}
.s{font-weight:600;text-transform:uppercase;font-size:.75rem;letter-spacing:.03em}
.ok{color:var(--ok);border-left-color:var(--ok)}.warn{color:var(--warn);border-left-color:var(--warn)}
.fail{color:var(--fail);border-left-color:var(--fail)}
.unknown{color:var(--unknown);border-left-color:var(--unknown)}
.stale{color:var(--stale);border-left-color:var(--stale)}
.tile.ok,.tile.warn,.tile.fail,.tile.unknown,.tile.stale{color:inherit}
code{font-size:.85em}
nav .grp{margin:.9rem 0 .2rem;padding:0 .5rem;color:var(--mute);font-size:.75rem;
text-transform:uppercase;letter-spacing:.04em}
.chips{margin:0 0 .75rem;font-size:.85rem}.chips a,.chips b{display:inline-block;margin:0 .3rem .3rem 0;
padding:.1rem .5rem;border:1px solid var(--line);border-radius:1rem;color:inherit;text-decoration:none}
.chips b{background:var(--panel)}.split{display:grid;grid-template-columns:minmax(0,3fr) minmax(0,2fr);
gap:1rem}.pane{background:var(--panel);border:1px solid var(--line);border-radius:.4rem;padding:.6rem .75rem;
min-width:0}dl{display:grid;grid-template-columns:max-content 1fr;gap:.2rem .75rem;margin:0}
dt{color:var(--mute)}dd{margin:0;overflow-wrap:anywhere}
pre{white-space:pre-wrap;overflow-wrap:anywhere;background:var(--bg);border:1px solid var(--line);
padding:.5rem;border-radius:.3rem;font-size:.82rem;max-height:30rem;overflow:auto}
.working{color:var(--ok)}.waiting{color:var(--warn)}.stuck{color:var(--stale)}.errored{color:var(--fail)}
.done{color:var(--mute)}.private{border-left:.35rem solid var(--fail);padding-left:.6rem}
.mapwrap{overflow-x:auto;margin:0 0 1rem}.map{display:block;max-width:none;font:12px system-ui,sans-serif}
.map text{fill:var(--ink)}.map .sub,.map .lbl{fill:var(--mute)}
.map .bx{fill:var(--panel);stroke:var(--line)}.map .band{fill:var(--bg);stroke:var(--line)}
.map .zone .bx,.map .transport .bx{stroke:var(--stale);stroke-width:1.5}
.map .unknown .bx,.map .muted .bx{stroke-dasharray:4 3}.map .muted text{fill:var(--mute)}
.map .edge{fill:none;stroke:var(--mute);stroke-width:1.3}.map .edge.dash{stroke-dasharray:5 4}
.map .head{fill:var(--mute)}.map .allow .bx{fill:var(--ok);fill-opacity:.18;stroke:var(--ok)}
.map .deny text,.map .self text{fill:var(--mute)}.map .other .bx{stroke:var(--warn)}
.map .adapter .bx{stroke:var(--ok)}.map .fake .bx{stroke-dasharray:4 3}
.map .track{fill:var(--bg);stroke:var(--line)}.map .f-pass{fill:var(--ok)}
.map .f-fail{fill:var(--fail)}.map .f-error{fill:var(--warn)}.map .f-skip{fill:var(--stale)}
.map .f-untested{fill:var(--unknown);fill-opacity:.35}
.maptable{margin:0 0 1.25rem}.maptable caption{text-align:left;font-weight:600;padding:.3rem 0}
@media (max-width:60rem){.split{grid-template-columns:1fr}}
@media (max-width:40rem){body{display:block}nav{width:auto;border-right:0;
border-bottom:1px solid var(--line)}}
"""


#: logical ids that always have a page (a capability has one only when it is a conformance
#: capability: the module's ``links.contract`` names it then)
def style_hash() -> str:
    """CSP source for the page's one inline ``<style>`` (``hnx status serve`` sends it)."""
    digest = hashlib.sha256(_CSS.encode("utf-8")).digest()
    return "'sha256-" + base64.b64encode(digest).decode("ascii") + "'"


_LOGICAL_PAGES = {
    "svc": "systems/{}.md",
    "status": "status/sources.md#{}",
}
#: which of a module's links a tile shows, in order (``page`` is ``service``'s page again)
_TILE_LINKS = ("service", "contract", "capability")


def _e(v: Any) -> str:
    return html.escape("" if v is None else str(v), quote=True)


def _state(s: str) -> str:
    return f'<span class="s {_e(s)}">{_e(s)}</span>'


def _link(target: str | None, docs_base: str) -> str:
    """A logical id or relative path as escaped HTML: a link when it maps to a page."""
    if not target:
        return ""
    kind, _, rest = target.partition(":")
    if rest and kind in _LOGICAL_PAGES:
        href = f"{docs_base}/{_LOGICAL_PAGES[kind].format(rest)}"
        return f'<a href="{_e(href)}"><code>{_e(target)}</code></a>'
    if not rest and target.startswith("docs/"):
        href = f"{docs_base}/{target[len('docs/') :]}"
        return f'<a href="{_e(href)}"><code>{_e(target)}</code></a>'
    return f"<code>{_e(target)}</code>"


def _rows(rows: Sequence[Mapping[str, Any]], docs_base: str) -> str:
    if not rows:
        return ""
    body = "".join(
        f"<tr><td>{_state(r['state'])}</td><td>{_e(r.get('module'))}</td><td>{_e(r.get('item'))}</td>"
        f"<td>{_e(r.get('summary'))}</td><td>{_link(r.get('link'), docs_base)}</td></tr>"
        for r in rows
    )
    return (
        "<table><thead><tr><th>State</th><th>Module</th><th>Item</th><th>Summary</th>"
        f"<th>Link</th></tr></thead><tbody>{body}</tbody></table>"
    )


def _exceptions(p: Mapping[str, Any], docs_base: str) -> str:
    parts = [f'<p class="green">{p["ok"]} ok</p>']
    if p["total"] != p["ok"]:
        parts.append(f'<p class="muted">of {p["total"]} items</p>')
    if p.get("live"):
        live = "".join(
            f"<li>{_e(r['module'])} / {_e(r['item'])}: {_e(r['summary'])}</li>" for r in p["live"]
        )
        parts.append(f'<h3>Live work</h3><ul class="live">{live}</ul>')
    if p.get("attention"):
        parts.append('<h3>Needs attention</h3><div class="attention">')
        parts.append(_rows(p["attention"], docs_base) + "</div>")
    return "".join(parts)


def _grid(p: Mapping[str, Any], docs_base: str) -> str:
    tiles = []
    for m in p["modules"]:
        c = m["counts"]
        count = ", ".join(f"{c[s]} {s}" for s in ("fail", "stale", "unknown", "warn", "ok") if c[s])
        bad = [i for i in m.get("items", ()) if i["state"] != "ok"]
        items = "".join(
            f"<li>{_state(i['state'])} {_e(i['item'])}: {_e(i['summary'])}</li>" for i in bad
        )
        ml = m.get("links", {})
        links = " ".join(_link(ml[k], docs_base) for k in _TILE_LINKS if k in ml)
        tiles.append(
            f'<div class="tile {_e(m["state"])}"><h3>{_e(m["module"])}</h3>'
            f'{_state(m["state"])} <span class="muted">{_e(count or "no items")}</span>'
            f"{'<ul>' + items + '</ul>' if items else ''}"
            f'<div class="muted">{links}</div></div>'
        )
    return (
        f'<div class="tiles">{"".join(tiles)}</div>'
        if tiles
        else '<p class="muted">nothing selected</p>'
    )


#: the source table's columns: (heading, the field that decides whether the column is shown,
#: the cell); a column whose field no row carries (the public view withdraws them) is left out
_SOURCE_COLUMNS = (
    ("State", "state", lambda s, d: _state(s["state"])),
    ("Source", "id", lambda s, d: _link("status:" + s["id"], d)),
    ("Kind", "kind", lambda s, d: _e(s.get("kind"))),
    ("Module", "module", lambda s, d: _e(s.get("module"))),
    ("Interval / stale after", "interval_s",
     lambda s, d: f"{_e(s.get('interval_s'))}s / {_e(s.get('stale_after_s'))}s"),
    ("Last read", "last_ok", lambda s, d: _e(s.get("last_ok") or "never")),
    ("Error", "error", lambda s, d: _e(s.get("error") or "")),
    ("What", "what", lambda s, d: _e(s.get("what"))),
)  # fmt: skip


def _sources(p: Mapping[str, Any], docs_base: str) -> str:
    rows = p["sources"]
    cols = [c for c in _SOURCE_COLUMNS if c[1] in ("state", "id") or any(c[1] in s for s in rows)]
    head = "".join(f"<th>{_e(h)}</th>" for h, _, _ in cols)
    body = "".join(
        "<tr>" + "".join(f"<td>{cell(s, docs_base)}</td>" for _, _, cell in cols) + "</tr>"
        for s in rows
    )
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


_PANELS = {"exceptions": _exceptions, "grid": _grid, "sources": _sources}


def nav_html(
    doc: Mapping[str, Any], *, live: bool = False, private: bool = False, home: str | None = None
) -> str:
    """The left menu.  ``live``: served by ``hnx status serve`` (page entries link to their live
    pages; in the static file they are marked live-only, except the maps ``hnx status render
    --private-out`` writes as ``<panel>.html``, linked from the private pages beside them).  ``private``: the request passed the trusted front
    door -- only then is the private group rendered at all, and then only its pages that are
    served (the Approvals entry appears only when approvals are configured).  ``home``: the page
    the panel anchors live on, for a static page other than ``index.html``."""
    prefix = "/" if live else (home or "")
    nav, group = [], None
    for m in doc["menu"]:
        if m.get("group") == "private" and not (private and m.get("available", True)):
            continue
        if m.get("group") != group:
            group = m.get("group")
            if group:
                nav.append(f'<div class="grp">{_e(group)}</div>')
        if m["kind"] == "panel":
            nav.append(f'<a href="{prefix}#view-{_e(m["id"])}">{_e(m["title"])}</a>')
        elif m["kind"] == "page":
            if live and m["available"]:  # the public view withdraws href: the path is the code's
                href = m.get("href") or PAGE_PANELS[m["panel"]]
                nav.append(f'<a href="{_e(href)}">{_e(m["title"])}</a>')
            elif m["available"] and m.get("panel") in GENERATED_PANELS:  # written beside index.html
                nav.append(f'<a href="{_e(m["panel"])}.html">{_e(m["title"])}</a>')
            else:
                why = "served live by hnx status serve" if not live else "no activity store"
                nav.append(f'<span class="off" title="{why}">{_e(m["title"])}</span>')
        elif m["available"] and m.get("href"):
            nav.append(
                f'<a class="ext" href="{_e(m["href"])}" rel="noopener noreferrer">{_e(m["title"])}</a>'
            )
        elif m["available"]:  # the public view withdraws a lab service's address
            nav.append(f'<span class="off" title="lab only">{_e(m["title"])}</span>')
        else:
            nav.append(f'<span class="off" title="not registered">{_e(m["title"])}</span>')
    if doc.get("act_via"):
        nav.append(f'<a class="ext" href="{_e(doc["act_via"])}">Make a change</a>')
    s = doc["summary"]
    return (
        f"<nav><h1>{_e(doc['title'])}</h1><p>read-only &middot; {_e(doc['generated_at'])}"
        f"<br>{s['ok']}/{s['total']} ok</p>{''.join(nav)}</nav>"
    )


def shell_html(
    doc: Mapping[str, Any],
    title: str,
    main: str,
    *,
    nav: str,
    refresh_s: int | None = None,
    head: str = "",
    tail: str = "",
    theme: str | None = None,
) -> str:
    """One page of the shell: the menu and ``main`` (already-escaped HTML).  ``head``/``tail``:
    trusted markup before the hub's stylesheet (so a CSP meta comes first) and at the end of
    ``body`` (the interactive maps' own
    stylesheet and script, :mod:`homelabnext.status.maps.assets`); ``theme``: a fixed
    ``data-theme`` on ``<html>`` (those maps start dark)."""
    meta = f'<meta http-equiv="refresh" content="{int(refresh_s)}">' if refresh_s else ""
    attrs = f' data-theme="{_e(theme)}"' if theme else ""
    return (
        "<!doctype html>\n"
        f'<html lang="en"{attrs}><head><meta charset="utf-8">'
        f'<meta name="viewport" content="width=device-width,initial-scale=1">{meta}'
        f"<title>{_e(title)}</title>{head}<style>{_CSS}</style></head><body>"
        f"{nav}<main>{main}</main>{tail}</body></html>\n"
    )


def render_html(
    doc: Mapping[str, Any], *, docs_base: str = "docs", live: bool = False, private: bool = False
) -> str:
    """The page for one status document (deterministic)."""
    sections = []
    titles = {m["id"]: m["title"] for m in doc["menu"]}
    order = sorted(doc["views"], key=lambda v: (v == doc["main"], list(titles).index(v)))
    for vid in order:
        p = doc["views"][vid]
        cls = "view main" if vid == doc["main"] else "view"
        sections.append(
            f'<section id="view-{_e(vid)}" class="{cls}" data-panel="{_e(p["panel"])}">'
            f"<h2>{_e(titles[vid])}</h2>{_PANELS[p['panel']](p, docs_base)}</section>"
        )
    nav = nav_html(doc, live=live, private=private)
    return shell_html(doc, doc["title"], "".join(sections), nav=nav)


def write(
    out: str | Path, doc: Mapping[str, Any], *, docs_base: str = "docs", releases: Any = None
) -> list[Path]:
    """Write ``index.html`` and ``status.json`` into ``out``; returns the paths.  Both are the
    public view, so both are the document through its release transform
    (:func:`homelabnext.status.views.public_status`); ``releases``: the registry (default the
    hub's)."""
    page_doc = public_status(doc, releases)
    data_doc = public_status(doc, releases, contract=True)
    d = Path(out)
    d.mkdir(parents=True, exist_ok=True)
    page, data = d / "index.html", d / "status.json"
    page.write_text(render_html(page_doc, docs_base=docs_base), encoding="utf-8")
    data.write_text(dumps(data_doc), encoding="utf-8")
    return [page, data]
