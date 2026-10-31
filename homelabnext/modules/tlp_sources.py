# SPDX-License-Identifier: Apache-2.0
"""``tlp-sources.json``: every selected module's datasets with their TLP declarations (ADR-0033).

The log pipeline labels each event from the dataset its collector input feeds
(:mod:`homelabnext.logpipeline.tlp_labels`).  This is the table it joins on, rendered by
``hnx modules render`` from the site's selection: one source per dataset of every module the site
runs, keyed ``<module>/<dataset>``, with the declaration :func:`rules.dataset_label` reads (``red``
and not honoured where the dataset declares none).  A dataset of a module the site does not run is
not a source, so an event routed to it is ``red``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from homelabnext.logpipeline import tlp_labels
from homelabnext.modules import rules

__all__ = ["FILE", "render", "write"]

FILE = "tlp-sources.json"
Doc = dict[str, Any]


def render(site: Doc, mods: dict[str, Doc]) -> Doc:
    """The ``tlp_sources/v1`` document for the modules ``site`` selects."""
    try:
        sel = rules.selected(site, mods)
    except (KeyError, TypeError, AttributeError) as exc:
        raise tlp_labels.SourceTableError(f"the selection cannot be read: {exc}") from None
    rows = []
    for mid, doc in sel.items():
        for ds in doc.get("data", []):
            label, honour = rules.dataset_label(ds)
            rows.append((f"{mid}/{ds['id']}", label, honour))
    return tlp_labels.table_doc(rows)


def write(doc: Doc, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / FILE).write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
