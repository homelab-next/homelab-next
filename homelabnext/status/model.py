# SPDX-License-Identifier: Apache-2.0
"""Status sources (read from the registry) and status observations (what collectors record).

A **source** is one ``status_sources`` entry of a registry service (``schemas/platform/
service.json`` 2.1): what to poll or receive, by registry name, how often, and how its payload
maps to observations.  An **observation** is one reading of one item of one module
(``schemas/status/observation.schema.json``).  Times are epoch seconds inside the package and
RFC 3339 UTC strings (``...Z``) in every document it writes.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import cache
from typing import Any

from homelabnext import paths
from homelabnext.registry.model import Registry

STATES = ("ok", "warn", "fail", "unknown", "stale")
#: worst first: a module or a view takes the worst state of what it holds
SEVERITY = {"fail": 4, "stale": 3, "unknown": 2, "warn": 1, "ok": 0}
KINDS = ("poll-http-json", "poll-file", "push-event", "poll-prometheus")
RESERVED_KINDS = ("poll-prometheus",)  # stage 2: product collectors
OBSERVED_EVENT = "homelabnext.status.observed"
DEFAULT_TIMEOUT_S = 10


def worst(states: list[str] | tuple[str, ...]) -> str:
    """The worst of ``states`` (``unknown`` when there are none)."""
    return max(states, key=lambda s: SEVERITY[s]) if states else "unknown"


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(text: str) -> float:
    dt = datetime.fromisoformat(str(text).replace("Z", "+00:00"))
    return (dt if dt.tzinfo else dt.replace(tzinfo=UTC)).timestamp()


@dataclass(frozen=True)
class SourceSpec:
    """One registered status source, with defaults applied."""

    id: str
    kind: str
    service: str  # the declaring registry service
    capability: str
    interval_s: float
    what: str
    target_service: str | None = None
    path: str | None = None
    file: str | None = None
    stale_after_s: float = 0.0  # 0 -> 3 x interval_s
    timeout_s: float = DEFAULT_TIMEOUT_S
    on_error: str = "unknown"
    mapping: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.kind not in KINDS:
            raise ValueError(f"status source {self.id}: unknown kind {self.kind!r}")
        if not self.stale_after_s:
            object.__setattr__(self, "stale_after_s", 3 * self.interval_s)

    @property
    def module(self) -> str:
        return str(self.mapping.get("module") or self.service)

    @property
    def polled_service(self) -> str:
        return self.target_service or self.service

    @property
    def polled(self) -> bool:
        return self.kind != "push-event"

    @classmethod
    def from_entry(cls, entry: Mapping[str, Any], service: str, capability: str) -> SourceSpec:
        target = entry.get("target") or {}
        return cls(
            id=entry["id"],
            kind=entry["kind"],
            service=service,
            capability=capability,
            interval_s=entry["interval_s"],
            what=entry["what"],
            target_service=target.get("service"),
            path=target.get("path"),
            file=target.get("file"),
            stale_after_s=entry.get("stale_after_s", 0),
            timeout_s=entry.get("timeout_s", DEFAULT_TIMEOUT_S),
            on_error=entry.get("on_error", "unknown"),
            mapping=dict(entry.get("mapping") or {}),
        )

    def describe(self) -> dict[str, Any]:
        """The menu entry (``hnx status sources --json``, the catalog page, status.json)."""
        target: dict[str, Any] = {}
        if self.kind in ("poll-http-json", "poll-prometheus"):
            target = {"service": self.polled_service, "path": self.path}
        elif self.kind == "poll-file":
            target = {"file": self.file}
        mapping = f"builtin {self.mapping['builtin']}" if "builtin" in self.mapping else "selectors"
        return {
            "id": self.id,
            "kind": self.kind,
            "service": self.service,
            "capability": self.capability,
            "module": self.module,
            "target": target,
            "interval_s": self.interval_s,
            "stale_after_s": self.stale_after_s,
            "timeout_s": self.timeout_s,
            "on_error": self.on_error,
            "mapping": mapping if self.kind != "push-event" else "event (observation as published)",
            "reserved": self.kind in RESERVED_KINDS,
            "what": self.what,
        }


def sources_from_registry(registry: Registry) -> list[SourceSpec]:
    """Every status source the registry declares, sorted by id (the menu)."""
    out = [
        SourceSpec.from_entry(entry, svc.name, svc.capability)
        for svc in registry.sorted_services()
        for entry in svc.status_sources
    ]
    return sorted(out, key=lambda s: s.id)


@dataclass(frozen=True)
class Observation:
    source: str
    module: str
    item: str
    state: str
    summary: str
    observed_at: str
    expires_at: str
    link: str | None = None
    value: float | None = None
    work: bool = False

    @property
    def key(self) -> str:
        return f"{self.source}/{self.module}/{self.item}"

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "source": self.source,
            "module": self.module,
            "item": self.item,
            "state": self.state,
            "summary": self.summary,
            "observed_at": self.observed_at,
            "expires_at": self.expires_at,
        }
        if self.link is not None:
            d["link"] = self.link
        if self.value is not None:
            d["value"] = self.value
        if self.work:
            d["work"] = True
        return d

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> Observation:
        return cls(
            source=d["source"],
            module=d["module"],
            item=d["item"],
            state=d["state"],
            summary=d["summary"],
            observed_at=d["observed_at"],
            expires_at=d["expires_at"],
            link=d.get("link"),
            value=d.get("value"),
            work=bool(d.get("work", False)),
        )


@cache
def _validator():
    import jsonschema
    from referencing import Registry as RefRegistry
    from referencing import Resource
    from referencing.jsonschema import DRAFT202012

    refs: RefRegistry = RefRegistry()
    for family, name in (("ids", "common.schema.json"), ("status", "observation.schema.json")):
        doc = json.loads(paths.schema_file(family, name).read_text(encoding="utf-8"))
        refs = refs.with_resource(
            doc["$id"], Resource.from_contents(doc, default_specification=DRAFT202012)
        )
    schema = json.loads(paths.schema_file("status", "observation.schema.json").read_text("utf-8"))
    return jsonschema.Draft202012Validator(schema, registry=refs)


def observation_problems(doc: Any) -> list[str]:
    """Schema problems of one observation document (empty = valid)."""
    errs = sorted(_validator().iter_errors(doc), key=lambda e: [str(p) for p in e.absolute_path])
    return [f"{'/'.join(map(str, e.absolute_path)) or '$'}: {e.message[:200]}" for e in errs]
