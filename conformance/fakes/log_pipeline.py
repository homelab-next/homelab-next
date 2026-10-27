# SPDX-License-Identifier: Apache-2.0
"""``log-pipeline`` fakes: the library rule behind the pipeline interface, and defective twins."""

from __future__ import annotations

import copy
from collections.abc import Mapping, Sequence
from typing import Any

from homelabnext.logpipeline import FLAT_KEY, LABEL, RuntimeTable, enrich


class FakeLogPipeline:
    features: frozenset[str] = frozenset()

    def __init__(self) -> None:
        self.table = RuntimeTable()

    def load_runtimes(self, table: RuntimeTable) -> None:
        self.table = table

    def process(self, records: Sequence[Any]) -> list[Any]:
        return [
            self._label(r)
            if isinstance(r.event, Mapping)
            else enrich(r.event, r.observed, self.table)
            for r in records
        ]

    def _label(self, r: Any) -> dict[str, Any]:
        """One record whose event is an object; the defective twins override this."""
        return enrich(r.event, r.observed, self.table)


class TrustsSelfNonePipeline(FakeLogPipeline):
    """Defect: an event that calls itself ``none`` keeps that label (a runtime opting out)."""

    def _label(self, r):
        if (r.event.get("labels") or {}).get(LABEL) == "none":
            return copy.deepcopy(dict(r.event))
        return enrich(r.event, r.observed, self.table)


class KeepsUnknownLabelPipeline(FakeLogPipeline):
    """Defect: an address the table does not hold leaves the event's own label in place."""

    def _label(self, r):
        if r.observed is not None and self.table.lookup(r.observed) is None:
            return copy.deepcopy(dict(r.event))
        return enrich(r.event, r.observed, self.table)


class JoinsOnEventSourcePipeline(FakeLogPipeline):
    """Defect: joins on the event's own ``source.ip`` when it has one."""

    def _label(self, r):
        src = (r.event.get("source") or {}).get("ip")
        return enrich(r.event, src if src else r.observed, self.table)


class KeepsFlatKeyPipeline(FakeLogPipeline):
    """Defect: the flat ``"labels.hnx_runtime"`` key the event arrived with survives."""

    def _label(self, r):
        e = enrich(r.event, r.observed, self.table)
        if FLAT_KEY in r.event:
            e[FLAT_KEY] = copy.deepcopy(r.event[FLAT_KEY])
        return e


class KeepsCaseVariantPipeline(FakeLogPipeline):
    """Defect: only the exact spellings are dropped; ``Labels.HNX_RUNTIME`` and kin survive."""

    def _label(self, r):
        e = enrich(r.event, r.observed, self.table)
        for key, value in r.event.items():
            if key != FLAT_KEY and key.strip().casefold() == FLAT_KEY:
                e[key] = copy.deepcopy(value)
            elif key.strip().casefold() == "labels" and isinstance(value, dict):
                for k, v in value.items():
                    if k != LABEL and k.strip().casefold() == LABEL:
                        e.setdefault(key, {})[k] = copy.deepcopy(v)
        return e


class DropsNonObjectPipeline(FakeLogPipeline):
    """Defect: a record that is not an object is silently left out of the batch."""

    def process(self, records):
        return [
            enrich(r.event, r.observed, self.table) for r in records if isinstance(r.event, dict)
        ]


class NoMappedV4Pipeline(FakeLogPipeline):
    """Defect: an IPv4-mapped IPv6 peer is looked up as written, so it is never found."""

    def _label(self, r):
        obs = r.observed
        if isinstance(obs, str) and obs.lower().startswith("::ffff:"):
            obs = None
        return enrich(r.event, obs, self.table)


class StripsPortPipeline(FakeLogPipeline):
    """Defect: ``address:port`` is accepted by dropping the port."""

    def _label(self, r):
        obs = r.observed
        if isinstance(obs, str) and obs.count(":") == 1:
            obs = obs.split(":")[0]
        return enrich(r.event, obs, self.table)


class MissingObservedFromHostPipeline(FakeLogPipeline):
    """Defect: with no observed address, falls back to the event's own ``host.ip``."""

    def _label(self, r):
        obs = r.observed
        if obs is None:
            obs = (r.event.get("host") or {}).get("ip")
        return enrich(r.event, obs, self.table)


class ReplacesLabelsPipeline(FakeLogPipeline):
    """Defect: ``labels`` is replaced by the runtime label alone, losing the event's others."""

    def _label(self, r):
        e = enrich(r.event, r.observed, self.table)
        if isinstance(e.get("labels"), dict) and LABEL in e["labels"]:
            e["labels"] = {LABEL: e["labels"][LABEL]}
        return e


class MutatesInputPipeline(FakeLogPipeline):
    """Defect: labels the caller's event in place."""

    def _label(self, r):
        e = enrich(r.event, r.observed, self.table)
        r.event.clear()
        r.event.update(e)
        return e


class ReversesBatchPipeline(FakeLogPipeline):
    """Defect: a batch comes back in reverse order."""

    def process(self, records):
        return list(reversed(super().process(records)))


class MergesTablesPipeline(FakeLogPipeline):
    """Defect: a new table is merged over the old one, so a removed address stays labelled."""

    def load_runtimes(self, table):
        self.table = RuntimeTable({**self.table.values, **table.values})
