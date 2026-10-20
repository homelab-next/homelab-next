# SPDX-License-Identifier: Apache-2.0
"""The Baselines page of the status hub: the guest x defense-layer coverage matrix (ADR-0016).

``hnx status serve --guests DIR --guests-site SITE`` serves ``/baselines``; the menu entry is the
``baselines`` page panel of ``views.yml``.  Each request reads the guest files and the baseline
set (the same report as ``hnx guests baselines --json``); it never changes anything, and every
value is escaped.  The stylesheet is the hub's one inline style, so the hub's CSP covers it.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from homelabnext.status.agents.pages import _table
from homelabnext.status.render import _e, nav_html, shell_html

from .baselines import coverage
from .loader import load_fleet
from .model import ComputeError
from .zones import open_site

__all__ = ["ROUTE", "BaselineSite"]

Response = tuple[int, str, bytes]
HTML = "text/html; charset=utf-8"
ROUTE = "/baselines"


def _cell(controls: list[str]) -> str:
    if not controls:
        return '<span class="s fail">none</span>'
    return "<br>".join(f"<code>{_e(c)}</code>" for c in controls)


def _binding(control: str, info: Mapping[str, Any], unplaced: list[str]) -> str:
    """The Role cell: the role, how it applies (ADR-0016 decision 7), or "not bound"."""
    role = (
        f"<code>{_e(info['role'])}</code>"
        if info["role"]
        else '<span class="s warn">not bound</span>'
    )
    if info["apply"] != "central":
        return role
    out = f"{role} central on <code>{_e(info['group'])}</code>"
    if control in unplaced:
        out += f' <span class="s warn">no host in <code>{_e(info["group"])}</code></span>'
    return out


class BaselineSite:
    """The ``/baselines`` route of ``hnx status serve`` over one guest directory."""

    def __init__(self, directory, site, *, baselines_path=None):
        self.directory = directory
        self.site = site
        self.baselines_path = baselines_path

    def handle(self, route: str, query: str, doc: Mapping[str, Any]) -> Response | None:
        """The response for ``/baselines``, or None when ``route`` is not it."""
        if route != ROUTE:
            return None
        title, main = "Baselines", self._main()
        html = shell_html(doc, title, main, nav=nav_html(doc, live=True))
        return 200, HTML, html.encode("utf-8")

    def _main(self) -> str:
        try:
            zones, domain = open_site(self.site)
            fleet = load_fleet(
                self.directory,
                zones,
                domain=domain or "example.internal",
                baselines_path=self.baselines_path,
                require_baselines=False,
            )
        except (ComputeError, OSError, ValueError) as exc:
            return f'<h2>Baselines</h2><p class="s fail">cannot load the guests</p><pre>{_e(exc)}</pre>'
        if fleet.baselines is None:
            return '<h2>Baselines</h2><p class="muted">no baseline set (_baselines.yml)</p>'
        rep = coverage(fleet.sorted(), fleet.baselines)
        rows = []
        for r in rep["guests"]:
            if r["missing"]:
                state = '<span class="s fail">missing</span>'
                cells = ["-"] * len(rep["layers"])
            elif r["exemption"]:
                state = f'<span class="s warn">exempt</span> {_e(r["exemption"]["reason"])}'
                cells = ["-"] * len(rep["layers"])
            else:
                state = ", ".join(_e(b) for b in r["baselines"])
                cells = [_cell(r["by_layer"][x]) for x in rep["layers"]]
            rows.append((f"<code>{_e(r['id'])}</code>", _e(r["kind"]), state, *cells))
        ctrl_rows = [
            (
                f"<code>{_e(c)}</code>",
                _e(info["layer"]),
                _binding(c, info, rep["unplaced"]),
                _e(info["verify"]),
                str(len(info["needed_by"])),
            )
            for c, info in rep["controls"].items()
        ]
        s = rep["summary"]
        summary = (
            f"{s['guests']} guests: {s['with_baseline']} with a baseline, {s['exempt']} exempt, "
            f"{s['missing']} missing; {s['unbound_needed']} needed controls not bound to a role"
        )
        return (
            f'<h2>Baselines</h2><p class="muted">{_e(summary)}</p>'
            + _table(("Guest", "Kind", "Baselines", *rep["layers"]), rows)
            + "<h3>Controls</h3>"
            + _table(("Control", "Layer", "Role", "Verify", "Guests"), ctrl_rows)
        )
