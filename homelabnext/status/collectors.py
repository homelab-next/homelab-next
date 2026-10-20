# SPDX-License-Identifier: Apache-2.0
"""Collectors: one per source kind, each turning a registered source into status drafts.

A collector is anything with ``collect(spec, ctx) -> list[Draft]`` (:class:`Collector`).  It may
raise anything: the scheduler runs each one in isolation and turns an exception or a timeout into
that source's error (``homelabnext.status.scheduler``).  Everything a collector touches comes from
the :class:`CollectContext` -- the clock, the HTTP client, the registry-name -> URL resolver, the
root that ``poll-file`` targets are relative to, and an optional broker store -- so every one runs
offline in tests with fakes.

Stage 2 adds product collectors (Uptime Kuma, Prometheus, StackStorm, NiFi, the orchestrator,
an agent dashboard) as more entries of :data:`COLLECTORS` or as declarative mappings over
``poll-http-json``; nothing else changes.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from homelabnext._http import ResponseTooLarge, read_bounded, safe_urlopen
from homelabnext.registry.model import Registry

from .mapping import Draft, MappingError, apply_mapping
from .model import SourceSpec

MAX_PAYLOAD = 4 << 20  # 4 MiB: a status payload larger than this is a defect, not a status


class CollectError(Exception):
    """A source could not be read (transport, shape or configuration)."""


class HttpClient(Protocol):
    def get(self, url: str, timeout: float) -> tuple[int, bytes]:
        """``(status, body)``; raises on a transport failure."""
        ...


class PendingApprovals(Protocol):
    """What the ``broker-pending`` mapper reads in process: requests waiting for approval."""

    def pending(self) -> Iterable[Mapping[str, Any]]: ...


class UrllibClient:
    """The stdlib client: same-origin redirects only, a bounded read (``homelabnext._http``)."""

    def get(self, url: str, timeout: float) -> tuple[int, bytes]:
        import urllib.error
        import urllib.request

        req = urllib.request.Request(url, headers={"Accept": "application/json"}, method="GET")
        try:
            with safe_urlopen(req, timeout=timeout) as resp:
                return resp.status, read_bounded(resp, MAX_PAYLOAD)
        except urllib.error.HTTPError as exc:
            return exc.code, b""


def registry_endpoint(registry: Registry, **resolver_kwargs: Any) -> Callable[[str], str]:
    """Service name -> base URL through the capability resolver (never a literal address)."""
    from homelabnext.registry.resolver import Resolver

    resolver = Resolver(registry, **resolver_kwargs)

    def endpoint(service: str) -> str:
        svc = registry.services.get(service)
        if svc is None:
            raise CollectError(f"service {service!r} is not registered")
        return resolver.resolve(svc.capability).url

    return endpoint


@dataclass
class CollectContext:
    clock: Callable[[], float] = time.time
    http: HttpClient | None = None
    endpoint: Callable[[str], str] | None = None
    root: Path = Path(".")
    broker: PendingApprovals | None = None
    activity: Any = None  # an agents ActivityStore (homelabnext.status.agents.store), optional


class Collector(Protocol):
    def collect(self, spec: SourceSpec, ctx: CollectContext) -> list[Draft]: ...


def _decode_json(body: bytes, what: str) -> Any:
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise CollectError(f"{what}: not JSON ({exc})") from None


def _map(spec: SourceSpec, payload: Any, ctx: CollectContext) -> list[Draft]:
    try:
        return apply_mapping(payload, spec.mapping, now=ctx.clock(), fallback_item=spec.id)
    except MappingError as exc:
        raise CollectError(f"mapping: {exc}") from None


class HttpJsonCollector:
    """``poll-http-json``: GET ``<service alias><path>``, expect 2xx JSON, map it."""

    def collect(self, spec: SourceSpec, ctx: CollectContext) -> list[Draft]:
        if ctx.http is None or ctx.endpoint is None:
            raise CollectError("no HTTP client or endpoint resolver configured")
        url = ctx.endpoint(spec.polled_service).rstrip("/") + (spec.path or "/")
        try:
            status, body = ctx.http.get(url, spec.timeout_s)
        except ResponseTooLarge as exc:
            raise CollectError(str(exc)) from None
        if not 200 <= status < 300:
            raise CollectError(f"{spec.polled_service}{spec.path}: HTTP {status}")
        return _map(spec, _decode_json(body, f"{spec.polled_service}{spec.path}"), ctx)


def _inside(root: Path, rel: str) -> Path:
    base = root.resolve()
    p = (base / rel).resolve()
    if p != base and base not in p.parents:
        raise CollectError(f"{rel}: resolves outside the status root")
    return p


def _load_records(path: Path) -> dict[str, list[dict[str, Any]]]:
    from homelabnext.records import RecordsReader

    reader = RecordsReader(path)
    try:
        return {
            "inbox": [n.frontmatter for n in reader.iter_notes("inbox")],
            "approved": [n.frontmatter for n in reader.iter_notes("decided/approved")],
        }
    except (OSError, ValueError) as exc:
        raise CollectError(f"records: {exc}") from None


class FileCollector:
    """``poll-file``: a JSON or YAML file (or a records directory) under the status root."""

    def collect(self, spec: SourceSpec, ctx: CollectContext) -> list[Draft]:
        if spec.mapping.get("builtin") == "broker-pending" and ctx.broker is not None:
            return _map(spec, [dict(r) for r in ctx.broker.pending()], ctx)
        path = _inside(ctx.root, spec.file or "")
        if spec.mapping.get("builtin") == "records-lanes":
            if not path.is_dir():
                raise CollectError(f"{spec.file}: no records directory")
            return _map(spec, _load_records(path), ctx)
        try:
            if path.stat().st_size > MAX_PAYLOAD:
                raise CollectError(f"{spec.file}: larger than {MAX_PAYLOAD} bytes")
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise CollectError(f"{spec.file}: {exc.strerror or exc}") from None
        if path.suffix in (".yml", ".yaml"):
            import yaml

            try:
                payload = yaml.safe_load(text)
            except yaml.YAMLError as exc:
                raise CollectError(f"{spec.file}: not YAML ({exc})") from None
        else:
            payload = _decode_json(text.encode("utf-8"), spec.file or "")
        return _map(spec, payload, ctx)


class PushCollector:
    """``push-event``: nothing to poll -- readings arrive as ``status.observed`` events
    (:meth:`homelabnext.status.hub.StatusHub.ingest_event`); staleness comes from their silence."""

    def collect(self, spec: SourceSpec, ctx: CollectContext) -> list[Draft]:
        return []


class ReservedCollector:
    """A kind reserved for stage 2 (``poll-prometheus``): reads as unknown until it ships."""

    def collect(self, spec: SourceSpec, ctx: CollectContext) -> list[Draft]:
        raise CollectError(f"{spec.kind} is reserved for stage 2 (no collector yet)")


class AgentActivityCollector:
    """``agent-activity``: drain agent activity into the store and report stuck and errored
    sessions (:mod:`homelabnext.status.agents.sources`)."""

    def collect(self, spec: SourceSpec, ctx: CollectContext) -> list[Draft]:
        from .agents.sources import collect

        return collect(spec, ctx)


COLLECTORS: dict[str, Collector] = {
    "poll-http-json": HttpJsonCollector(),
    "poll-file": FileCollector(),
    "push-event": PushCollector(),
    "poll-prometheus": ReservedCollector(),
    "agent-activity": AgentActivityCollector(),
}
