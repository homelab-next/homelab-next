# SPDX-License-Identifier: Apache-2.0
"""``log-pipeline`` fakes: the library rule behind the pipeline interface, and defective twins."""

from __future__ import annotations

import copy
from collections.abc import Mapping, Sequence
from typing import Any

from homelabnext import tlp
from homelabnext.logpipeline import FLAT_KEY, LABEL, RuntimeTable, SourceTable, enrich, enrich_tlp
from homelabnext.logpipeline import tlp_labels as tl


class FakeLogPipeline:
    features: frozenset[str] = frozenset()

    def __init__(self) -> None:
        self.table = RuntimeTable()
        self.sources = SourceTable()

    def load_runtimes(self, table: RuntimeTable) -> None:
        self.table = table

    def load_sources(self, table: SourceTable) -> None:
        self.sources = table

    def process(self, records: Sequence[Any]) -> list[Any]:
        return [
            self._tlp(r, self._label(r))
            if isinstance(r.event, Mapping)
            else enrich(r.event, r.observed, self.table)
            for r in records
        ]

    def _label(self, r: Any) -> dict[str, Any]:
        """One record whose event is an object: its runtime label (defective twins override)."""
        return enrich(r.event, r.observed, self.table)

    def _tlp(self, r: Any, event: dict[str, Any]) -> dict[str, Any]:
        """The runtime-labelled event, given the TLP label of the event as it arrived (another
        stage's changes never decide it; defective twins override)."""
        return self._set_tlp(event, tl.label_for(r.event, r.route, self.sources))

    def _set_tlp(self, event: dict[str, Any], label: tlp.Label) -> dict[str, Any]:
        """``event`` with every spelling of the TLP label replaced by ``label``."""
        out = enrich_tlp(event, None, SourceTable())
        out["labels"][tl.LABEL] = str(label)
        return out


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
        out = super().process(records)
        return [e for e, r in zip(out, records, strict=True) if isinstance(r.event, dict)]


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


# ---------------------------------------------------------------- the TLP label's defective twins
class TlpIgnoresDeclarationPipeline(FakeLogPipeline):
    """Defect: an event that carries no label of its own is red whatever its source declares."""

    def _tlp(self, r, event):
        if self.sources.lookup(r.route) is not None and not tl.claims(r.event):
            return self._set_tlp(event, tlp.Label.RED)
        return super()._tlp(r, event)


class TlpNoRouteUnlabelledPipeline(FakeLogPipeline):
    """Defect: an event with no route leaves without a TLP label (an unknown source stays
    unlabelled, as the runtime label does, where the TLP label must be red)."""

    def _tlp(self, r, event):
        if r.route is None:
            out = enrich_tlp(event, None, SourceTable())
            del out["labels"][tl.LABEL]
            return out
        return super()._tlp(r, event)


class TlpNormalisesRoutePipeline(FakeLogPipeline):
    """Defect: the route is trimmed and lower-cased, so a route that is not a table key matches."""

    def _tlp(self, r, event):
        route = r.route if r.route is None else str(r.route).strip().lower()
        return enrich_tlp(event, route, self.sources)


class TlpKeepsSelfSetPipeline(FakeLogPipeline):
    """Defect: an event that arrived with ``labels.hnx_tlp`` keeps it."""

    def _tlp(self, r, event):
        own = (r.event.get("labels") or {}).get(tl.LABEL) if isinstance(r.event, dict) else None
        out = super()._tlp(r, event)
        if own is not None:
            out["labels"][tl.LABEL] = copy.deepcopy(own)
        return out


class TlpDropsStricterClaimPipeline(FakeLogPipeline):
    """Defect: an item label stricter than its source's declaration is dropped."""

    def _tlp(self, r, event):
        entry = self.sources.lookup(r.route)
        out = super()._tlp(r, event)
        if entry is not None and tlp.read(out["labels"][tl.LABEL]) > entry[0]:
            out["labels"][tl.LABEL] = str(entry[0])
        return out


class TlpHonoursEverySourcePipeline(FakeLogPipeline):
    """Defect: every source's item labels are honoured, so a looser one always wins."""

    def _tlp(self, r, event):
        entry = self.sources.lookup(r.route)
        if entry is None:
            return super()._tlp(r, event)
        honoured = SourceTable({r.route: (entry[0], True)})
        return enrich_tlp(event, r.route, honoured)


class TlpNeverHonoursPipeline(FakeLogPipeline):
    """Defect: ``honour_item_labels`` is ignored, so a looser item label never wins."""

    def _tlp(self, r, event):
        entry = self.sources.lookup(r.route)
        if entry is None:
            return super()._tlp(r, event)
        plain = SourceTable({r.route: (entry[0], False)})
        return enrich_tlp(event, r.route, plain)


class TlpMergesSourcesPipeline(FakeLogPipeline):
    """Defect: a new source table is merged over the old one, so a removed route keeps its label."""

    def load_sources(self, table):
        self.sources = SourceTable({**self.sources.sources, **table.sources})
