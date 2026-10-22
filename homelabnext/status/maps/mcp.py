# SPDX-License-Identifier: Apache-2.0
"""MCP servers: every server of the MCP catalog (``homelabnext.mcp.servers``, ADR-0024) with its
owner, origin and pin, transport, capability classes, who is granted it, its review and its
lifecycle.

Built from the catalog and the agent profiles the roster names (``roster.yml``'s ``profiles``,
read by :func:`homelabnext.status.maps.roster.gather`), never from a client config.  An HTTP
server is named by its registry service (``svc:``), never by an address.  Script-free and escaped.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from homelabnext.mcp import servers
from homelabnext.mcp.clients import granted

from . import svg

STATE_CLASS = {"active": "ok", "deprecated": "warn", "draft": "stale", "retired": "unknown"}


def _origin(o: Mapping[str, Any]) -> tuple[str, str, bool]:
    """(what, pin, pinned) of an origin."""
    kind = o.get("kind")
    if kind == "first-party":
        return f"first-party {o.get('path')}", "this repository", True
    if kind == "package":
        what = f"{o.get('ecosystem')} {o.get('package')}"
        pin = o.get("version") or "no version"
        if o.get("sha256"):
            pin += f" sha256:{str(o['sha256'])[:12]}"
        elif o.get("lock"):
            pin += f" (lock {o['lock']})"
        return what, pin, bool(o.get("version") and (o.get("sha256") or o.get("lock")))
    if kind == "image":
        d = o.get("digest")
        return f"image {o.get('image')}", str(d)[:19] if d else "no digest", bool(d)
    if kind == "git":
        c = o.get("commit")
        return f"git {o.get('repo')}", str(c)[:12] if c else "no commit", bool(c)
    return "unknown", "not pinned", False


def _review(rec: Mapping[str, Any]) -> list[str]:
    digest = servers.record_digest(rec)
    roles = sorted(
        {
            str(r.get("role"))
            for r in rec.get("reviews") or ()
            if isinstance(r, Mapping)
            and r.get("verdict") == "pass"
            and digest.startswith(str(r.get("digest", "-")))
        }
    )
    return roles


def build(cat: servers.Catalog, profiles: Iterable[Mapping[str, Any]] = ()) -> dict[str, Any]:
    """The view-model: one row per server (id order), with its grants by profile id."""
    holders: dict[str, list[str]] = {}
    for p in profiles:
        for sid in granted(p):
            holders.setdefault(sid, []).append(str(p.get("id")))
    classes = cat.classes()
    rows = []
    for sid, rec in cat:
        what, pin, pinned = _origin(rec.get("origin") or {})
        t = rec.get("transport") or {}
        tools = rec.get("tools") or []
        rows.append(
            {
                "id": sid,
                "description": rec.get("description", ""),
                "owner": rec.get("owner"),
                "status": rec.get("status"),
                "reason": rec.get("reason"),
                "replaced_by": rec.get("replaced_by"),
                "origin": what,
                "pin": pin,
                "pinned": pinned,
                "transport": t.get("type"),
                "where": (
                    f"{t.get('endpoint')}{t.get('path', '/mcp')}"
                    if t.get("endpoint")
                    else f"{t.get('command')} ({'agent-local' if rec.get('runtime') == 'agent-local' else 'runs on its host'})"
                ),
                "classes": classes.get(sid, []),
                "tools": len(tools),
                "approval": sorted(str(x.get("name")) for x in tools if x.get("approval")),
                "parameters": sorted(rec.get("parameters") or {}),
                "implements": list(rec.get("implements") or ()),
                "data_tier": rec.get("data_tier"),
                "granted_to": sorted(holders.get(sid, [])),
                "reviews": _review(rec),
                "record": cat.rel(sid),
            }
        )
    unknown = sorted(set(holders) - set(cat.servers))
    return {
        "servers": rows,
        "unknown_grants": [{"server": s, "profiles": sorted(holders[s])} for s in unknown],
        "counts": {
            "servers": len(rows),
            "active": sum(1 for r in rows if r["status"] == "active"),
            "unpinned": sum(1 for r in rows if not r["pinned"]),
            "granted": sum(1 for r in rows if r["granted_to"]),
        },
    }


def _codes(items: Iterable[str]) -> str:
    items = list(items)
    return svg.codes(items) if items else '<span class="muted">none</span>'


def _state(r: Mapping[str, Any]) -> str:
    out = f'<span class="s {STATE_CLASS.get(str(r["status"]), "unknown")}">{svg.e(r["status"])}</span>'
    if r["reason"]:
        out += f'<br><span class="muted">{svg.e(r["reason"])}</span>'
    if r["replaced_by"]:
        out += "<br>use " + svg.code(f"mcp:{r['replaced_by']}")
    reviewed = ", ".join(r["reviews"]) or "not reviewed"
    return out + f'<br><span class="muted">current reviews: {svg.e(reviewed)}</span>'


def render(vm: Mapping[str, Any]) -> str:
    c = vm["counts"]
    parts = [
        '<p class="chips">'
        f"<b>{c['servers']} servers</b><b>{c['active']} active</b>"
        f"<b>{c['granted']} granted</b><b>{c['unpinned']} unpinned</b></p>",
        '<p class="muted">The MCP catalog is the one list of MCP servers: every client '
        "configuration, the capability classes and the graph are generated from it. A grant "
        "names a catalog id; draft and retired servers cannot be granted.</p>",
    ]
    if vm["unknown_grants"]:
        parts.append(
            '<p class="s fail">granted but not in the catalog: '
            + "; ".join(
                f"{svg.code('mcp:' + u['server'])} ({svg.e(', '.join(u['profiles']))})"
                for u in vm["unknown_grants"]
            )
            + "</p>"
        )
    parts.append(
        svg.table(
            "MCP servers",
            ("Server", "Origin and pin", "Transport", "Classes and tools", "Granted to", "State"),
            [
                (
                    svg.code(f"mcp:{r['id']}")
                    + f'<br><span class="muted">{svg.e(r["description"])}</span>'
                    + f'<br><span class="muted">owner {svg.e(r["owner"])} &middot; '
                    f"{svg.e(r['record'])}</span>",
                    svg.e(r["origin"])
                    + "<br>"
                    + (
                        svg.e(r["pin"])
                        if r["pinned"]
                        else f'<span class="s fail">{svg.e(r["pin"])}</span>'
                    ),
                    svg.e(r["transport"])
                    + "<br>"
                    + svg.code(r["where"])
                    + f'<br><span class="muted">data {svg.e(r["data_tier"])}</span>',
                    _codes(r["classes"])
                    + f'<br><span class="muted">{r["tools"]} tool(s)'
                    + (f"; approval: {svg.e(', '.join(r['approval']))}" if r["approval"] else "")
                    + (
                        f"; parameters: {svg.e(', '.join(r['parameters']))}"
                        if r["parameters"]
                        else ""
                    )
                    + "</span>"
                    + ("<br>implements " + _codes(r["implements"]) if r["implements"] else ""),
                    _codes(r["granted_to"]),
                    _state(r),
                )
                for r in vm["servers"]
            ],
        )
    )
    return "".join(parts)
