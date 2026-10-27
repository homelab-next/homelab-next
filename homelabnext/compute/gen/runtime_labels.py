# SPDX-License-Identifier: Apache-2.0
"""The log pipeline's runtime table: observed address -> ``hnx_runtime`` label value.

Every guest's address maps to ``model`` when it is a model runtime
(:func:`homelabnext.compute.validate.model_runtime`: ``cap:inference`` or
``cap:codemode-executor``, by capability or inventory group) and to ``none`` otherwise.  The
``log-pipeline`` provider loads it and labels each event by the address the collector saw
(:mod:`homelabnext.logpipeline`), so the detections that match ``labels.hnx_runtime: model`` see
the guest model's answer, never the event's own.
"""

from __future__ import annotations

import json

from homelabnext.compute.model import ComputeError, Fleet
from homelabnext.compute.validate import model_runtime
from homelabnext.logpipeline import TableError, table_doc


def render(fleet: Fleet) -> dict[str, str]:
    rows = []
    for g in fleet.sorted():
        runtime = model_runtime(g)
        rows.append((g.ip, "none" if runtime is None else "model", g.id, runtime or g.capability))
    try:
        doc = table_doc(rows)
    except TableError as exc:
        raise ComputeError(f"runtime-labels: {exc}") from None
    return {"runtime-labels.json": json.dumps(doc, indent=2, ensure_ascii=True) + "\n"}
