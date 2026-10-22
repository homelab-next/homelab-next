# SPDX-License-Identifier: Apache-2.0
"""The customizations register: one static HTML page and one JSON file.

Same style as the other registers: output is a pure function of the inputs plus the supplied
date, no scripts, no external assets. Expired entries are marked loudly; the page summary
counts them. Given the deployment's :class:`~.universe.Universe`, each ``links`` entry is shown
by the record's computed display number (``lesson LL 3``) and resolved to its uid (``linked``
in the JSON; a legacy code through the registers' ``aliases.yml``, see :mod:`.links`); without
one, as written.
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path
from typing import Any

from homelabnext.registers.render import e, page

from .links import resolve_links
from .model import Customization, days_left, extension_points, sort_key
from .universe import Universe

__all__ = ["build_register", "render_register", "state_of"]


def state_of(c: Customization, today: date, enabled: dict[str, list[str]]) -> str:
    left = days_left(c, today)
    if c.schema_errors or (left is None and not c.upstream_maintained):
        return "invalid"
    if left is not None and left < 0:
        return "expired"
    if c.optional and c.id not in enabled:
        return "inactive"
    return "active"


def _linked(c: Customization, u: Universe | None) -> list[dict[str, Any]]:
    """Each link resolved: ``key``, ``ref`` as written, ``uid`` and ``label`` (the record's
    display number) or the ``problem``; empty without a universe holding the registers."""
    if u is None or (u.aliases is None and u.records is None) or c.schema_errors:
        return []
    out = []
    for lk in resolve_links(c.doc, u.aliases, u.records):
        row: dict[str, Any] = {"key": lk.key, "ref": lk.ref, "uid": lk.uid}
        if lk.uid:
            row["label"] = (u.records or {}).get(lk.uid, ("", lk.uid))[1]
        else:
            row["problem"] = lk.problem
        out.append(row)
    return out


def _links_text(r: dict[str, Any]) -> str:
    if not r["linked"]:
        return ", ".join(f"{k} {v}" for k, v in sorted(r["links"].items()))
    return ", ".join(
        f"{x['key']} {x['label']} ({x['uid']})"
        if x["uid"]
        else f"{x['key']} {x['ref']} (unresolved: {x['problem']})"
        for x in r["linked"]
    )


def render_register(
    items: list[Customization],
    today: date,
    enabled: dict[str, list[str]] | None = None,
    universe: Universe | None = None,
) -> tuple[str, dict[str, Any]]:
    enabled = enabled or {}
    rows: list[dict[str, Any]] = []
    for c in sorted(items, key=sort_key):
        d = c.doc
        rows.append(
            {
                "id": c.id,
                "title": d.get("title", ""),
                "kind": c.kind,
                "state": state_of(c, today, enabled),
                "origin": c.origin,
                "owner": d.get("owner", ""),
                "created": d.get("created", ""),
                "review_by": d.get("review_by", ""),
                "days_left": days_left(c, today),
                "upstream_maintained": c.upstream_maintained,
                "upstream": d.get("upstream", ""),
                "contract": d.get("contract", ""),
                "reason": d.get("reason", ""),
                "links": d.get("links", {}),
                "linked": _linked(c, universe),
                "extension_points": extension_points(c) if not c.schema_errors else [],
            }
        )
    counts: dict[str, int] = {}
    for r in rows:
        counts[r["state"]] = counts.get(r["state"], 0) + 1
    summary = {
        "date": today.isoformat(),
        "total": len(rows),
        "by_state": dict(sorted(counts.items())),
    }
    cards = []
    for r in rows:
        cls = {"expired": "fail", "invalid": "fail", "inactive": "skip"}.get(r["state"], "pass")
        links = _links_text(r)
        cards.append(
            f'<article id="{e(r["id"])}"><h2>{e(r["id"])} '
            f'<span class="pill {cls}">{e(r["state"])}</span>'
            + (
                ' <span class="pill pass">maintained upstream</span>'
                if r["upstream_maintained"]
                else ""
            )
            + f"</h2><p>{e(r['title'])}</p><dl>"
            f"<dt>Kind</dt><dd>{e(r['kind'])} ({e(r['origin'])})</dd>"
            f"<dt>Owner</dt><dd>{e(r['owner'])}</dd>"
            + (
                "<dt>Review by</dt><dd>maintained upstream (shipped profile, never expires)</dd>"
                if r["upstream_maintained"]
                else f"<dt>Review by</dt><dd>{e(r['review_by'])} ({e(r['days_left'])} days)</dd>"
            )
            + f"<dt>Upstream</dt><dd>{e(r['upstream'])}</dd>"
            f"<dt>Deviates from</dt><dd><code>{e(r['contract'])}</code></dd>"
            f"<dt>Extension points</dt><dd><code>{e(', '.join(r['extension_points']))}</code></dd>"
            f"<dt>Reason</dt><dd>{e(r['reason'])}</dd>"
            + (f"<dt>Links</dt><dd>{e(links)}</dd>" if links else "")
            + "</dl></article>"
        )
    text = ", ".join(f"{n} {k}" for k, n in summary["by_state"].items()) or "none"
    html = page("Customizations", "".join(cards), f"As of {today.isoformat()}: {text}.")
    return html, {"summary": summary, "customizations": rows}


def build_register(
    items: list[Customization],
    out_dir: Path,
    today: date,
    enabled: dict[str, list[str]] | None = None,
    universe: Universe | None = None,
) -> list[Path]:
    html, data = render_register(items, today, enabled, universe)
    out_dir.mkdir(parents=True, exist_ok=True)
    h, j = out_dir / "customizations.html", out_dir / "customizations.json"
    h.write_text(html, encoding="utf-8")
    j.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return [h, j]
