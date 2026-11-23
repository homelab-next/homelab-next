# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: vector-log-pipeline-adapter
#   kind: tool
#   purpose: Drive the sidecar's labelling path for the log-pipeline conformance suite.
#   owner: platform
#   trigger: [manual]
#   inputs: the suite's observed addresses and events
#   outputs: the suite's verdict inputs
#   exit:
#     "0": imported
"""The ``log-pipeline`` conformance adapter for the vector module (docs/log-pipeline.md).

It drives the sidecar's own labelling path, not a model of it: the observed address comes from
``sidecar.observed_for`` under the ``peer`` policy (the address the collector saw, here the
suite's ``Observed.observed``), and the two labels from ``sidecar.label_event``, which composes the
library's ``enrich`` and ``enrich_tlp`` exactly as the contract does.  The sidecar's other two
duties (the per-route observed-address policies and the OCSF remap) are proved by the module's own
tests; this adapter is what the shared suite and its mutants hold to the contract.

    hnx conform run log-pipeline --target modules/vector/conformance/target.yml
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from homelabnext.logpipeline import RuntimeTable, SourceTable

from . import sidecar

#: the policy the suite's records are observed under: the peer address, nothing from the event
POLICY = {"kind": "sensor", "observe": "peer"}


class VectorLogPipeline:
    features: frozenset[str] = frozenset()

    def __init__(self) -> None:
        self.runtimes = RuntimeTable()
        self.sources = SourceTable()

    def load_runtimes(self, table: RuntimeTable) -> None:
        self.runtimes = table

    def load_sources(self, table: SourceTable) -> None:
        self.sources = table

    def process(self, records: Sequence[Any]) -> list[Any]:
        out = []
        for r in records:
            observed = sidecar.observed_for(POLICY, {"peer": r.observed}, r.event)
            out.append(sidecar.label_event(r.event, observed, r.route, self.runtimes, self.sources))
        return out


def make(**_: Any) -> VectorLogPipeline:
    return VectorLogPipeline()
