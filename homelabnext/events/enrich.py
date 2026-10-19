# SPDX-License-Identifier: Apache-2.0
"""Enrich event envelopes with the owner and criticality of the asset they are about.

The asset inventory is built from what the lab already declares -- the service registry
(``services``, ``hosts``) and the guest model (``owners``, ``tags``) -- never from a second,
hand-kept list.  :func:`enrich_event` adds three CloudEvents extension attributes to an envelope
(declared, optional, in ``schemas/events/envelope.schema.json``):

``assetid``           the inventory asset, ``svc:<name>``, ``guest:<name>`` or ``host:<name>``
``assetowner``        its owning team (a slug)
``assetcriticality``  ``low`` | ``medium`` | ``high`` | ``critical``

Which asset an event is about, in order:

1. ``subject`` when it is an asset id (``svc:``/``guest:``/``host:``);
2. otherwise the first ``data.entities`` item of kind ``host`` that is in the inventory;
3. only when the event names **no** target at all (no asset-shaped ``subject``, no host entity),
   its ``source`` -- the emitter is then what the event is about (``task.queued`` from
   ``svc:siem``).

An event that names a target the inventory does not know is left *unenriched*; it is never
attributed to its emitter instead, because "the SIEM team owns this alert about an unknown host"
is a confident wrong answer.  :func:`enrichment_coverage` counts such events against the target
(checklist T-04: >= 95% of live events carry owner and criticality).

Criticality is derived from tags (:data:`DEFAULT_TAG_CRITICALITY`, highest wins, ``low`` for a
known asset with no ranked tag) and can be pinned per asset with ``overrides``.  A host takes the
highest criticality of its guest and of the services it runs.
"""

from __future__ import annotations

import copy
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from .envelope import validate_event

CRITICALITY = ("low", "medium", "high", "critical")  # ascending
ATTRS = ("assetid", "assetowner", "assetcriticality")
DEFAULT_THRESHOLD = 0.95

# tag -> criticality; an asset takes the highest of its tags
DEFAULT_TAG_CRITICALITY: Mapping[str, str] = {
    "secrets": "critical",
    "identity": "critical",
    "core": "high",
    "prod": "high",
    "hypervisor": "high",
    "storage": "high",
    "database": "high",
    "bus": "high",
    "data": "medium",
    "catalog": "medium",
    "query": "medium",
    "compute": "medium",
    "inference": "medium",
    "agents": "medium",
    "edge": "medium",
    "monitoring": "medium",
}

_ASSET_PREFIXES = ("svc:", "guest:", "host:")


@dataclass(frozen=True)
class Asset:
    id: str  # svc:<name> | guest:<name> | host:<name>
    owner: str
    criticality: str


def _rank(c: str) -> int:
    return CRITICALITY.index(c)


def criticality_for(tags: Iterable[str], table: Mapping[str, str] = DEFAULT_TAG_CRITICALITY) -> str:
    """The highest criticality any of ``tags`` maps to (``low`` when none is ranked)."""
    ranked = [table[t] for t in tags if t in table]
    return max(ranked, key=_rank) if ranked else "low"


class AssetInventory:
    """Lookup from an asset key to its :class:`Asset`.

    Keys: ``svc:<name>``, ``guest:<name>``, ``host:<name>``, a bare host name, and
    ``cap:<capability>`` when exactly one service provides that capability.
    """

    def __init__(self, assets: Iterable[Asset], aliases: Mapping[str, str] | None = None):
        self._assets: dict[str, Asset] = {}
        for a in assets:
            if a.criticality not in CRITICALITY:
                raise ValueError(f"{a.id}: criticality {a.criticality!r} not in {CRITICALITY}")
            if not a.id.startswith(_ASSET_PREFIXES):
                raise ValueError(f"{a.id}: asset id must start with one of {_ASSET_PREFIXES}")
            self._assets[a.id] = a
        self._aliases = dict(aliases or {})

    def __len__(self) -> int:
        return len(self._assets)

    def __iter__(self):
        return iter(sorted(self._assets.values(), key=lambda a: a.id))

    def lookup(self, key: str) -> Asset | None:
        if not isinstance(key, str) or not key:
            return None
        key = self._aliases.get(key, key)
        if key in self._assets:
            return self._assets[key]
        if ":" not in key:  # a bare host name
            return self._assets.get(f"host:{key}") or self._assets.get(f"guest:{key}")
        return None

    @classmethod
    def from_models(
        cls,
        registry: Any = None,
        guests: Iterable[Any] = (),
        *,
        tag_criticality: Mapping[str, str] = DEFAULT_TAG_CRITICALITY,
        overrides: Mapping[str, str] | None = None,
    ) -> AssetInventory:
        """Build from a :class:`homelabnext.registry.model.Registry` and/or guest-model guests.

        ``guests`` are :class:`homelabnext.compute.model.Guest` objects (or anything with a
        ``raw`` mapping holding ``id``, ``owners.primary`` and ``tags``).  ``overrides`` pins a
        criticality per asset id.
        """
        overrides = dict(overrides or {})
        assets: dict[str, Asset] = {}
        by_host: dict[str, list[Asset]] = {}
        by_cap: dict[str, list[str]] = {}

        def crit(asset_id: str, tags: Iterable[str]) -> str:
            return overrides.get(asset_id) or criticality_for(tags, tag_criticality)

        for g in guests:
            raw = g.raw if hasattr(g, "raw") else g
            gid = raw["id"]
            owner = (raw.get("owners") or {}).get("primary")
            if owner:
                assets[gid] = Asset(gid, owner, crit(gid, raw.get("tags", ())))
        if registry is not None:
            for name, s in sorted(registry.services.items()):
                sid = f"svc:{name}"
                a = Asset(sid, s.owner, crit(sid, s.tags))
                assets[sid] = a
                by_host.setdefault(s.host, []).append(a)
                by_cap.setdefault(s.capability, []).append(sid)
            for hname in sorted(registry.hosts):
                hid = f"host:{hname}"
                guest = assets.get(f"guest:{hname}")
                svcs = by_host.get(hname, [])
                owners = {a.owner for a in svcs}
                if guest is not None:
                    owner = guest.owner
                elif len(owners) == 1:
                    owner = owners.pop()
                else:
                    owner = registry.owner or ""
                if not owner:
                    continue
                levels = [a.criticality for a in svcs] + ([guest.criticality] if guest else [])
                level = overrides.get(hid) or max(levels or ["low"], key=_rank)
                assets[hid] = Asset(hid, owner, level)
        aliases = {f"cap:{c}": ids[0] for c, ids in by_cap.items() if len(ids) == 1}
        return cls(assets.values(), aliases)


def _named_targets(event: Mapping[str, Any]) -> tuple[list[str], bool]:
    """Candidate asset keys the event names, and whether it names any target at all."""
    keys: list[str] = []
    named = False
    subject = event.get("subject")
    if isinstance(subject, str) and subject.startswith(_ASSET_PREFIXES):
        keys.append(subject)
        named = True
    data = event.get("data")
    ents = data.get("entities") if isinstance(data, Mapping) else None
    for e in ents if isinstance(ents, list) else ():
        if isinstance(e, Mapping) and e.get("kind") == "host" and isinstance(e.get("value"), str):
            keys.append(e["value"])
            named = True
    return keys, named


def resolve_asset(event: Mapping[str, Any], inventory: AssetInventory) -> Asset | None:
    """The asset ``event`` is about (see the module docstring for the order), or None."""
    keys, named = _named_targets(event)
    for k in keys:
        a = inventory.lookup(k)
        if a is not None:
            return a
    if named:
        return None
    return inventory.lookup(event.get("source", ""))


def enrich_event(
    event: Mapping[str, Any], inventory: AssetInventory, *, validate: bool = True
) -> dict[str, Any]:
    """A copy of ``event`` with ``assetid``/``assetowner``/``assetcriticality`` set.

    Values the publisher already set are kept (the closest source wins).  An event whose asset
    cannot be resolved is returned unchanged.  Note that enrichment changes the body, so it runs
    *before* the publisher records the event, never on an id already sent.
    """
    out = copy.deepcopy(dict(event))
    if all(out.get(k) for k in ATTRS):
        return out
    asset = resolve_asset(out, inventory)
    if asset is None:
        return out
    out.setdefault("assetid", asset.id)
    out.setdefault("assetowner", asset.owner)
    out.setdefault("assetcriticality", asset.criticality)
    if validate:
        validate_event(out)
    return out


def is_enriched(event: Mapping[str, Any]) -> bool:
    """True when the event carries a non-empty owner and a known criticality."""
    return bool(event.get("assetowner")) and event.get("assetcriticality") in CRITICALITY


@dataclass(frozen=True)
class Coverage:
    total: int
    enriched: int
    missing_by_type: Mapping[str, int]
    threshold: float = DEFAULT_THRESHOLD

    @property
    def ratio(self) -> float:
        return self.enriched / self.total if self.total else 0.0

    @property
    def ok(self) -> bool:
        """At or above the threshold.  An empty stream is *not* ok: no events is no evidence."""
        return self.total > 0 and self.ratio >= self.threshold

    def render(self) -> str:
        lines = [
            f"enrichment coverage: {self.enriched}/{self.total} = {self.ratio:.2%} "
            f"(threshold {self.threshold:.0%}) -> {'ok' if self.ok else 'BELOW TARGET'}"
        ]
        for t, n in sorted(self.missing_by_type.items(), key=lambda kv: (-kv[1], kv[0])):
            lines.append(f"  missing owner/criticality: {n} x {t}")
        return "\n".join(lines)


def enrichment_coverage(
    events: Iterable[Mapping[str, Any]], *, threshold: float = DEFAULT_THRESHOLD
) -> Coverage:
    """Share of ``events`` that carry owner and criticality (the T-04 metric)."""
    if not 0 < threshold <= 1:
        raise ValueError("threshold must be in (0, 1]")
    total = enriched = 0
    missing: dict[str, int] = {}
    for ev in events:
        total += 1
        if isinstance(ev, Mapping) and is_enriched(ev):
            enriched += 1
        else:
            t = ev.get("type", "?") if isinstance(ev, Mapping) else "?"
            missing[t] = missing.get(t, 0) + 1
    return Coverage(total, enriched, missing, threshold)
