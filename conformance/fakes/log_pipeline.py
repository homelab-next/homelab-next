# SPDX-License-Identifier: Apache-2.0
"""``log-pipeline`` fakes: the library rule behind the pipeline interface, and defective twins."""

from __future__ import annotations

import copy
from collections.abc import Sequence
from typing import Any

from homelabnext.logpipeline import FLAT_KEY, LABEL, RuntimeTable, enrich


class FakeLogPipeline:
    features: frozenset[str] = frozenset()

    def __init__(self) -> None:
        self.table = RuntimeTable()

    def load_runtimes(self, table: RuntimeTable) -> None:
        self.table = table

    def process(self, records: Sequence[Any]) -> list[dict[str, Any]]:
        return [enrich(r.event, r.observed, self.table) for r in records]


class TrustsSelfNonePipeline(FakeLogPipeline):
    """Defect: an event that calls itself ``none`` keeps that label (a runtime opting out)."""

    def process(self, records):
        out = []
        for r in records:
            if (r.event.get("labels") or {}).get(LABEL) == "none":
                out.append(copy.deepcopy(dict(r.event)))
            else:
                out.append(enrich(r.event, r.observed, self.table))
        return out


class KeepsUnknownLabelPipeline(FakeLogPipeline):
    """Defect: an address the table does not hold leaves the event's own label in place."""

    def process(self, records):
        out = []
        for r in records:
            if r.observed is not None and self.table.lookup(r.observed) is None:
                out.append(copy.deepcopy(dict(r.event)))
            else:
                out.append(enrich(r.event, r.observed, self.table))
        return out


class JoinsOnEventSourcePipeline(FakeLogPipeline):
    """Defect: joins on the event's own ``source.ip`` when it has one."""

    def process(self, records):
        out = []
        for r in records:
            src = (r.event.get("source") or {}).get("ip")
            out.append(enrich(r.event, src if src else r.observed, self.table))
        return out


class KeepsFlatKeyPipeline(FakeLogPipeline):
    """Defect: the flat ``"labels.hnx_runtime"`` key the event arrived with survives."""

    def process(self, records):
        out = []
        for r in records:
            e = enrich(r.event, r.observed, self.table)
            if FLAT_KEY in r.event:
                e[FLAT_KEY] = copy.deepcopy(r.event[FLAT_KEY])
            out.append(e)
        return out


class NoMappedV4Pipeline(FakeLogPipeline):
    """Defect: an IPv4-mapped IPv6 peer is looked up as written, so it is never found."""

    def process(self, records):
        out = []
        for r in records:
            obs = r.observed
            if isinstance(obs, str) and obs.lower().startswith("::ffff:"):
                e = enrich(r.event, None, self.table)
            else:
                e = enrich(r.event, obs, self.table)
            out.append(e)
        return out


class StripsPortPipeline(FakeLogPipeline):
    """Defect: ``address:port`` is accepted by dropping the port."""

    def process(self, records):
        out = []
        for r in records:
            obs = r.observed
            if isinstance(obs, str) and obs.count(":") == 1:
                obs = obs.split(":")[0]
            out.append(enrich(r.event, obs, self.table))
        return out


class MissingObservedFromHostPipeline(FakeLogPipeline):
    """Defect: with no observed address, falls back to the event's own ``host.ip``."""

    def process(self, records):
        out = []
        for r in records:
            obs = r.observed
            if obs is None:
                obs = (r.event.get("host") or {}).get("ip")
            out.append(enrich(r.event, obs, self.table))
        return out


class ReplacesLabelsPipeline(FakeLogPipeline):
    """Defect: ``labels`` is replaced by the runtime label alone, losing the event's others."""

    def process(self, records):
        out = []
        for r in records:
            e = enrich(r.event, r.observed, self.table)
            if isinstance(e.get("labels"), dict) and LABEL in e["labels"]:
                e["labels"] = {LABEL: e["labels"][LABEL]}
            out.append(e)
        return out


class MutatesInputPipeline(FakeLogPipeline):
    """Defect: labels the caller's event in place."""

    def process(self, records):
        out = []
        for r in records:
            e = enrich(r.event, r.observed, self.table)
            r.event.clear()
            r.event.update(e)
            out.append(e)
        return out


class ReversesBatchPipeline(FakeLogPipeline):
    """Defect: a batch comes back in reverse order."""

    def process(self, records):
        return list(reversed(super().process(records)))


class MergesTablesPipeline(FakeLogPipeline):
    """Defect: a new table is merged over the old one, so a removed address stays labelled."""

    def load_runtimes(self, table):
        self.table = RuntimeTable({**self.table.values, **table.values})
