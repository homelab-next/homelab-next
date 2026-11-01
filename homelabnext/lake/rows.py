# SPDX-License-Identifier: Apache-2.0
"""A log-pipeline event as the lake row its writer stores (ADR-0033 decisions 3 and 5).

The event's ``tlp`` field and the OCSF column are both named ``tlp``, so the obvious writer, one
that maps event fields to columns by name, would store the source's own word (``tlp: clear``) as
the row's label and bypass the pipeline's relabelling.  :func:`row_from_event` is the one mapping:

* the row's ``tlp`` column is the event's ``labels.hnx_tlp``
  (:func:`homelabnext.logpipeline.enrich_tlp`), never the event's ``tlp`` field, which is dropped;
* an event without ``labels.hnx_tlp``, or with one that is not a canonical label, is refused
  (:class:`RowRejected`) for a labelled table, never given a label here: a missing label must
  never read as a looser one;
* every other field is copied by name; ``labels`` (the pipeline's enrichment) is kept only where
  the table has such a column.  The result is still validated by the writer
  (:func:`homelabnext.lake.validate.normalize_rows`) like any other row.
"""

from __future__ import annotations

import copy
from collections.abc import Mapping
from typing import Any

from homelabnext import tlp

from .errors import RowRejected
from .tables import LABEL_COLUMN, TableSchema

__all__ = ["row_from_event"]

#: where the log pipeline puts the label (``labels.hnx_tlp``)
HOLDER = "labels"
PIPELINE_LABEL = "hnx_tlp"


def row_from_event(event: Mapping[str, Any], schema: TableSchema) -> dict[str, Any]:
    """The row to write for ``event``: its ``tlp`` from ``labels.hnx_tlp`` only."""
    if not isinstance(event, Mapping):
        raise RowRejected(schema.name, ["an event is an object"])
    row = {k: copy.deepcopy(v) for k, v in event.items() if k != LABEL_COLUMN}
    holder = event.get(HOLDER)
    if HOLDER not in schema.column_names:
        row.pop(HOLDER, None)
    if not schema.labelled:
        return row
    value = holder.get(PIPELINE_LABEL) if isinstance(holder, Mapping) else None
    if type(value) is not str or value not in tlp.LABELS:
        raise RowRejected(
            schema.name,
            [
                f"{LABEL_COLUMN}: the row's label is the event's {HOLDER}.{PIPELINE_LABEL}, set by "
                f"the log pipeline; got {value!r} (the event's own {LABEL_COLUMN} is never used)"
            ],
        )
    row[LABEL_COLUMN] = value
    return row
