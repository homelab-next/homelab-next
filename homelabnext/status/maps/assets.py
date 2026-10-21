# SPDX-License-Identifier: Apache-2.0
"""The one script and stylesheet the interactive maps share (Topology and Dataflow, ADR-0018).

The rest of the hub is script-free; these two pages pan, zoom, filter and open a detail panel,
so they carry ``static/maps.js`` and ``static/maps.css`` (packaged files, never generated).  How
they reach the browser, and what the browser is allowed to run:

* served live (``hnx status serve``): the stylesheet inline, pinned by hash, and the script as
  ``/static/maps.js`` (:data:`SCRIPT_ROUTE`) under ``script-src 'self'`` -- a CSP sent only on
  these two routes (:func:`live_csp`); every other page keeps the hub's script-free policy;
* written by ``hnx status render``: both inline, pinned by their sha256 in a CSP ``<meta>``
  (:func:`static_csp`), so the file is self-contained and can be served on its own.

The page's data travels as ``<script type="application/json">`` (:func:`json_script`, which the
CSP does not execute) with ``<``, ``>`` and ``&`` written as JSON escapes, so a hostile name
cannot close the element; the script builds the DOM with ``textContent`` only.  The cards and
tables are server-rendered, escaped HTML, so the page is complete without the script.
"""

from __future__ import annotations

import base64
import hashlib
import json
from functools import cache
from pathlib import Path
from typing import Any

from homelabnext.status.render import _e, style_hash

STATIC = Path(__file__).with_name("static")
SCRIPT_ROUTE = "/static/maps.js"
JS_TYPE = "text/javascript; charset=utf-8"
#: the pages that carry the script (the other maps stay script-free)
INTERACTIVE = frozenset({"topology", "dataflow"})


@cache
def js() -> str:
    return (STATIC / "maps.js").read_text(encoding="utf-8")


@cache
def css() -> str:
    return (STATIC / "maps.css").read_text(encoding="utf-8")


def sha256_source(text: str) -> str:
    """The CSP hash source for an inline element whose content is exactly ``text``."""
    digest = hashlib.sha256(text.encode("utf-8")).digest()
    return "'sha256-" + base64.b64encode(digest).decode("ascii") + "'"


def _styles() -> str:
    return f"{style_hash()} {sha256_source(css())}"


def live_csp() -> str:
    """The CSP header of a served interactive map: the hub's stylesheet and this one by hash,
    scripts from the hub itself only (``/static/maps.js``), nothing else."""
    return (
        f"default-src 'none'; style-src {_styles()}; script-src 'self'; img-src 'self' data:; "
        "frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
    )


def static_csp() -> str:
    """The CSP ``<meta>`` of a written interactive map: both inline elements by hash (a meta
    policy cannot carry ``frame-ancestors``; a server in front should send it)."""
    return (
        f"default-src 'none'; style-src {_styles()}; script-src {sha256_source(js())}; "
        "img-src data:; base-uri 'none'; form-action 'none'"
    )


def json_text(data: Any) -> str:
    """``data`` as JSON safe inside an HTML element: ``<``, ``>`` and ``&`` become ``\\u003c``,
    ``\\u003e`` and ``\\u0026`` (still the same JSON to ``JSON.parse``)."""
    text = json.dumps(data, sort_keys=True, separators=(",", ":"))
    return text.replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e")


def json_script(element_id: str, data: Any) -> str:
    return f'<script type="application/json" id="{_e(element_id)}">{json_text(data)}</script>'


def head(*, live: bool) -> str:
    """What an interactive map adds to ``<head>``: its stylesheet, after the hash-pinned CSP
    meta when the page is written rather than served."""
    style = f"<style>{css()}</style>"
    if live:
        return style
    return f'<meta http-equiv="Content-Security-Policy" content="{_e(static_csp())}">' + style


def tail(*, live: bool) -> str:
    """The script, last in ``<body>``: the served file live, inline (its hash is in the CSP
    meta) when written."""
    if live:
        return f'<script src="{SCRIPT_ROUTE}"></script>'
    return f"<script>{js()}</script>"
