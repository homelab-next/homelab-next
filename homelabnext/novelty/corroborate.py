# SPDX-License-Identifier: Apache-2.0
"""``corroborate``: the one path from novelty to escalation (ADR-0035 decision 6).

A novelty finding is advisory: no deterministic gate escalates on one alone.  ``corroborate``
groups findings by entity within a time window and returns only the entities flagged by at
least two **distinct sources** (a host sensor and a lake profile, say), as candidates for the
decision cascade and the analyst agents.  Two profiles of one source are one source: a single
noisy or compromised source cannot corroborate itself.

A row counts when its ``status`` is ``finding`` or ``unlearned`` (both say "new for this
entity"); a ``high_cardinality`` row says the entity cannot be baselined, which is not a signal.
A candidate's label is the strictest label of the rows behind it.

Entities are matched by ``(entity_kind, entity)``, never by bare text: every source names an
entity in the shared namespace (``ip``, ``host``, ``user``, ...; ADR-0035 decision 7), so an
address and a host whose name is the same text are two entities.  Distinct sources are
distinct writers: each writer writes only its own ``source`` (``engine.write_findings``).
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from homelabnext import tlp

__all__ = ["SIGNALS", "Candidate", "corroborate"]

#: the statuses that count as a novelty signal
SIGNALS = ("finding", "unlearned")


@dataclass(frozen=True)
class Candidate:
    entity_kind: str
    entity: str
    sources: tuple[str, ...]
    profiles: tuple[str, ...]
    findings: int
    label: tlp.Label
    uids: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "entity_kind": self.entity_kind,
            "entity": self.entity,
            "sources": list(self.sources),
            "profiles": list(self.profiles),
            "findings": self.findings,
            "tlp": self.label.value,
            "uids": list(self.uids),
        }


def _in_window(row: Mapping[str, Any], since: datetime | None, until: datetime | None) -> bool:
    if since is None and until is None:
        return True
    t = row.get("time")
    if not isinstance(t, datetime) or t.utcoffset() is None:
        raise ValueError(f"a finding without an aware time cannot be windowed: {row.get('uid')!r}")
    return (since is None or t >= since) and (until is None or t < until)


def corroborate(
    findings: Iterable[Mapping[str, Any]],
    *,
    since: datetime | None = None,
    until: datetime | None = None,
    min_sources: int = 2,
) -> list[Candidate]:
    """Entities with signals from at least ``min_sources`` (>= 2) distinct sources among
    ``findings`` (rows of ``novelty_finding``) whose ``time`` is in ``[since, until)``; with no
    window every row counts (rows already windowed, such as ``count_by`` groups).  A row may
    carry ``rows``, how many findings it stands for (default 1; a ``count_by`` group stands for
    several).  Sorted by number of sources
    (most first), then entity."""
    if type(min_sources) is not int or min_sources < 2:
        raise ValueError("min_sources must be an integer >= 2: one source never corroborates")
    for name, t in (("since", since), ("until", until)):
        if t is not None and (not isinstance(t, datetime) or t.utcoffset() is None):
            raise ValueError(f"{name} must be a timezone-aware datetime")
    Key = tuple[str, str]
    sources: dict[Key, set[str]] = defaultdict(set)
    profiles: dict[Key, set[str]] = defaultdict(set)
    labels: dict[Key, set[tlp.Label]] = defaultdict(set)
    uids: dict[Key, set[str]] = defaultdict(set)
    counts: dict[Key, int] = defaultdict(int)
    for r in findings:
        if r.get("status") not in SIGNALS or not _in_window(r, since, until):
            continue
        kind = r.get("entity_kind")
        if type(kind) is not str or not kind:
            raise ValueError(
                f"a finding without an entity_kind cannot be matched: {r.get('uid')!r}"
            )
        k = (kind, r["entity"])
        sources[k].add(r["source"])
        profiles[k].add(f"{r['source']}/{r.get('profile', '')}")
        labels[k].add(tlp.read_stored(r.get("tlp")))
        counts[k] += int(r.get("rows", 1))
        if r.get("uid"):
            uids[k].add(r["uid"])
    out = [
        Candidate(
            k[0],
            k[1],
            tuple(sorted(sources[k])),
            tuple(sorted(profiles[k])),
            counts[k],
            tlp.strictest(labels[k]),
            tuple(sorted(uids[k])),
        )
        for k in sources
        if len(sources[k]) >= min_sources
    ]
    return sorted(out, key=lambda c: (-len(c.sources), c.entity_kind, c.entity))
