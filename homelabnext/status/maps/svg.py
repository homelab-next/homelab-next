# SPDX-License-Identifier: Apache-2.0
"""The few SVG and table primitives every generated map is drawn with (ADR-0018).

Everything here is a pure function of its arguments and returns escaped markup.  The hub is
script-free and its CSP allows exactly one inline stylesheet, so an SVG never carries a ``style``
attribute: shapes take classes the hub's stylesheet themes (``.map ...`` in
:mod:`homelabnext.status.render`), which is also what makes them legible in light and dark.
Text width is estimated from the character count (no font metrics), so the same model gives the
same bytes everywhere; a label that would not fit is clipped and its full text kept in a
``<title>`` tooltip and in the table every map ships beside its picture.
"""

from __future__ import annotations

import html
from collections.abc import Iterable, Sequence
from typing import Any

#: estimated advance of one character of the 12px map font, in px
CHAR_W = 7
LINE_H = 15
ELLIPSIS = "\u2026"


def e(v: Any) -> str:
    """HTML/SVG-escaped text (None is empty)."""
    return html.escape("" if v is None else str(v), quote=True)


def clip(text: Any, width_px: int) -> str:
    """``text`` cut to what fits in ``width_px`` (an ellipsis marks the cut); not escaped."""
    s = "" if text is None else str(text)
    n = max(1, width_px // CHAR_W)
    return s if len(s) <= n else s[: max(0, n - 1)] + ELLIPSIS


def text(x: int, y: int, value: Any, *, width: int, cls: str = "", anchor: str = "") -> str:
    """One line of text, clipped to ``width``."""
    c = f' class="{e(cls)}"' if cls else ""
    a = f' text-anchor="{e(anchor)}"' if anchor else ""
    return f'<text x="{x}" y="{y}"{c}{a}>{e(clip(value, width))}</text>'


def node(
    x: int,
    y: int,
    w: int,
    h: int,
    lines: Sequence[Any],
    *,
    cls: str = "",
    tip: str | None = None,
) -> str:
    """A labelled box: the first line in ink, the rest muted; ``tip`` is its tooltip (default:
    the lines joined)."""
    tip = tip if tip is not None else " \u00b7 ".join(str(t) for t in lines if t)
    out = [f'<g class="node {e(cls)}"><title>{e(tip)}</title>']
    out.append(f'<rect class="bx" x="{x}" y="{y}" width="{w}" height="{h}" rx="4"/>')
    for i, line in enumerate(lines):
        out.append(text(x + 8, y + 16 + i * LINE_H, line, width=w - 14, cls="sub" if i else ""))
    out.append("</g>")
    return "".join(out)


def band(x: int, y: int, w: int, h: int, cls: str = "") -> str:
    """A background band (a zone column, a transport lane): no text of its own."""
    return f'<rect class="band {e(cls)}" x="{x}" y="{y}" width="{w}" height="{h}" rx="6"/>'


def arrow(points: Iterable[tuple[int, int]], marker: str, *, cls: str = "") -> str:
    """A polyline ending in the ``marker`` arrowhead."""
    pts = " ".join(f"{x},{y}" for x, y in points)
    return f'<polyline class="edge {e(cls)}" points="{pts}" marker-end="url(#{e(marker)})"/>'


def svg(map_id: str, width: int, height: int, title: str, desc: str, body: Iterable[str]) -> str:
    """The whole picture: an accessible image (``title`` and ``desc`` name it for assistive
    technology) with one arrowhead marker, ``<map_id>-arrow``, wrapped so it scrolls rather
    than shrinking past legibility on a narrow screen."""
    mid = e(map_id)
    return (
        f'<div class="mapwrap"><svg class="map" xmlns="http://www.w3.org/2000/svg" '
        f'viewBox="0 0 {width} {height}" width="{width}" height="{height}" role="img" '
        f'aria-labelledby="{mid}-title {mid}-desc"><title id="{mid}-title">{e(title)}</title>'
        f'<desc id="{mid}-desc">{e(desc)}</desc><defs><marker id="{mid}-arrow" viewBox="0 0 8 8" '
        'refX="8" refY="4" markerWidth="8" markerHeight="8" orient="auto">'
        '<path class="head" d="M0,0 L8,4 L0,8 z"/></marker></defs>' + "".join(body) + "</svg></div>"
    )


def table(caption: str, head: Sequence[str], rows: Sequence[Sequence[str]]) -> str:
    """The table alternative of a map; ``rows`` hold already-escaped cell HTML."""
    if not rows:
        return f'<p class="muted">{e(caption)}: nothing to show</p>'
    th = "".join(f'<th scope="col">{e(h)}</th>' for h in head)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows)
    return (
        f'<table class="maptable"><caption>{e(caption)}</caption><thead><tr>{th}</tr></thead>'
        f"<tbody>{body}</tbody></table>"
    )


def code(v: Any) -> str:
    return f"<code>{e(v)}</code>"


def codes(values: Iterable[Any]) -> str:
    return ", ".join(code(v) for v in values) or '<span class="muted">none</span>'
