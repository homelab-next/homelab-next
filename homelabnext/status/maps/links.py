# SPDX-License-Identifier: Apache-2.0
"""Links: a directory of every service the registry declares, grouped by zone, each by its
registry name.

Every link is built from the registry the way the hub's external menu entries are
(:func:`homelabnext.status.views.service_href`): a service's public hostname when it has one,
else its capability alias and port.  No address or endpoint is ever written here or read from
anywhere but the registry (``tools/no_raw_endpoints.py``).  An http(s) service is a link (with
its health and MCP endpoints, where it has them); any other protocol is listed by its alias and
port, not linked.

Access is read from the registry too: ``public`` (a public hostname, through the edge) or
``lab only`` (the capability alias, inside the lab); the sign-in (``auth``); and **private
tier** for a service with a ``front_door`` -- it trusts forward-auth identity only on requests
the edge marks, so its private pages open only through the trusted front door (``docs/status.md``).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from homelabnext.registry.model import Registry

from . import svg

AUTH_WORDS = {
    "none": "no sign-in",
    "idp": "sign-in (identity provider)",
    "own": "its own login",
    "mtls": "client certificate",
}
WEB = ("http", "https")


def _alias_url(registry: Registry, svc: Any, path: str = "/") -> str:
    return f"{svc.scheme}://{registry.alias(svc.capability)}:{svc.port}{path}"


def build(registry: Registry) -> dict[str, Any]:
    """The links view-model: one group per registry zone (in the registry's order), each
    service in it ordered by capability then name."""
    from homelabnext.status.views import service_href

    zones = []
    for zname, zone in registry.zones.items():
        rows = []
        mine = [s for s in registry.services.values() if registry.hosts[s.host].zone == zname]
        for svc in sorted(mine, key=lambda s: (s.capability, s.name)):
            web = svc.protocol in WEB
            health = svc.health if isinstance(svc.health, Mapping) else {}
            rows.append(
                {
                    "name": svc.name,
                    "capability": svc.capability,
                    "impl": svc.impl,
                    "version": svc.version,
                    "owner": svc.owner,
                    "description": svc.description,
                    "href": service_href(registry, {"service": svc.name}) if web else None,
                    "endpoint": None if web else _alias_url(registry, svc, ""),
                    "access": "public" if svc.public_hostname else "lab only",
                    "auth": AUTH_WORDS.get(svc.auth, svc.auth),
                    "private_tier": bool(svc.front_door),
                    "health": _alias_url(registry, svc, health["path"])
                    if web and health.get("kind") == "http" and health.get("path")
                    else None,
                    "mcp": {
                        "name": svc.mcp["name"],
                        "transport": svc.mcp.get("transport", "http"),
                        "href": _alias_url(registry, svc, svc.mcp.get("path", "/mcp")),
                    }
                    if svc.mcp
                    else None,
                    "tags": list(svc.tags),
                }
            )
        if rows:
            zones.append({"zone": zname, "description": zone.description, "services": rows})
    every = [r for z in zones for r in z["services"]]
    return {
        "lab": registry.lab_name,
        "zones": zones,
        "counts": {
            "services": len(every),
            "web": sum(1 for r in every if r["href"]),
            "public": sum(1 for r in every if r["access"] == "public"),
            "private_tier": sum(1 for r in every if r["private_tier"]),
        },
    }


def _a(href: str, label: str) -> str:
    return f'<a href="{svg.e(href)}">{svg.e(label)}</a>'


def _open(r: Mapping[str, Any]) -> str:
    if not r["href"]:
        return f'{svg.code(r["endpoint"])} <span class="muted">(not a web UI)</span>'
    extra = []
    if r["health"]:
        extra.append(_a(r["health"], "health"))
    if r["mcp"]:
        extra.append(_a(r["mcp"]["href"], f"MCP {r['mcp']['name']} ({r['mcp']['transport']})"))
    more = f'<br><span class="muted">{" &middot; ".join(extra)}</span>' if extra else ""
    return _a(r["href"], f"open svc:{r['name']}") + more


def _access(r: Mapping[str, Any]) -> str:
    out = f"{svg.e(r['access'])}, {svg.e(r['auth'])}"
    if r["private_tier"]:
        out += ' <span class="s stale">private tier</span>'
    return out


def render(vm: Mapping[str, Any]) -> str:
    c = vm["counts"]
    parts = [
        '<p class="chips">'
        f"<b>{c['services']} services</b><b>{c['web']} web links</b>"
        f"<b>{c['public']} public</b><b>{c['private_tier']} with a private tier</b></p>",
        '<p class="muted">Every link is built from the registry (public hostname, else the '
        "capability alias). <b>public</b>: reachable through the edge; <b>lab only</b>: inside "
        'the lab; <span class="s stale">private tier</span>: its private pages open only '
        "through the trusted front door.</p>",
    ]
    for z in vm["zones"]:
        parts.append(
            f'<h3>{svg.e(z["zone"])} <span class="muted">{svg.e(z["description"])}</span></h3>'
        )
        parts.append(
            svg.table(
                f"Zone {z['zone']}",
                ("Service", "Capability", "Open", "Access", "What it does"),
                [
                    (
                        svg.code(f"svc:{r['name']}")
                        + f'<br><span class="muted">{svg.e(r["impl"])} {svg.e(r["version"])}'
                        f" &middot; {svg.e(r['owner'])}</span>",
                        svg.code(f"cap:{r['capability']}"),
                        _open(r),
                        _access(r),
                        svg.e(r["description"]) or '<span class="muted">-</span>',
                    )
                    for r in z["services"]
                ],
            )
        )
    return "".join(parts)
