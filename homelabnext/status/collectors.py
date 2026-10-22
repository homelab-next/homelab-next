# SPDX-License-Identifier: Apache-2.0
"""Collectors: one per source kind, each turning a registered source into status drafts.

A collector is anything with ``collect(spec, ctx) -> list[Draft]`` (:class:`Collector`).  It may
raise anything: the scheduler runs each one in isolation and turns an exception or a timeout into
that source's error (``homelabnext.status.scheduler``).  Everything a collector touches comes from
the :class:`CollectContext` -- the clock, the HTTP client, the registry-name -> URL resolver, the
root that ``poll-file`` targets are relative to, the secret lookup a source's ``auth`` names a
value through, and an optional broker store -- so every one runs offline in tests with fakes.

Stage 2's product collectors (Prometheus, Uptime Kuma, StackStorm, NiFi) are more entries of
:data:`COLLECTORS` (:mod:`.products`); the orchestrator and Agentmetry are built-in mappings over
``poll-http-json`` (:mod:`.mapping`).  ``poll-nut`` (:mod:`.nut`) is the one kind that is not
HTTP: it speaks the NUT network protocol to upsd over a socket.
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
    def get(
        self, url: str, timeout: float, headers: Mapping[str, str] | None = None
    ) -> tuple[int, bytes]:
        """``(status, body)``; raises on a transport failure.  ``headers`` carry a source's
        credential (``auth``) when it has one."""
        ...


class PendingApprovals(Protocol):
    """What the ``broker-pending`` mapper reads in process: requests waiting for approval."""

    def pending(self) -> Iterable[Mapping[str, Any]]: ...


class UrllibClient:
    """The stdlib client: same-origin redirects only, a bounded read (``homelabnext._http``)."""

    def get(
        self, url: str, timeout: float, headers: Mapping[str, str] | None = None
    ) -> tuple[int, bytes]:
        import urllib.error
        import urllib.request

        hdrs = {"Accept": "application/json", **(headers or {})}
        req = urllib.request.Request(url, headers=hdrs, method="GET")
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
    #: ``secret:<name>`` -> its value, or None (``homelabnext.status.agents.config.secret_lookup``)
    secret: Callable[[str], str | None] | None = None


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


def auth_headers(spec: SourceSpec, ctx: CollectContext) -> dict[str, str]:
    """The request header a source's ``auth`` asks for, its value read from the secret store by
    name.  A reference that does not resolve is an error for that source: it is never polled
    without its credential, and the value never appears in an error."""
    if not spec.auth:
        return {}
    ref = str(spec.auth["secret"])
    value = ctx.secret(ref) if ctx.secret is not None else None
    if not value:
        # name the source, not the reference: nothing read for the secret store goes into a message
        raise CollectError(
            f"source {spec.id}: its auth credential did not resolve (environment or --secrets-dir)"
        )
    header = spec.auth.get("header")
    return {str(header): value} if header else {"Authorization": f"Bearer {value}"}


def fetch_json(
    spec: SourceSpec,
    ctx: CollectContext,
    path: str | None = None,
    query: Mapping[str, str] | None = None,
) -> Any:
    """GET ``<the polled service's alias><path>[?query]`` with the source's credential; 2xx JSON
    or :class:`CollectError`.  ``path`` defaults to the source's ``target.path``."""
    from urllib.parse import urlencode

    if ctx.http is None or ctx.endpoint is None:
        raise CollectError("no HTTP client or endpoint resolver configured")
    rel = path or spec.path or "/"
    url = ctx.endpoint(spec.polled_service).rstrip("/") + rel
    if query:
        url += ("&" if "?" in rel else "?") + urlencode(query)
    headers = auth_headers(spec, ctx)
    try:
        if headers:
            status, body = ctx.http.get(url, spec.timeout_s, headers=headers)
        else:
            status, body = ctx.http.get(url, spec.timeout_s)
    except ResponseTooLarge as exc:
        raise CollectError(str(exc)) from None
    if not 200 <= status < 300:
        raise CollectError(f"{spec.polled_service}{rel}: HTTP {status}")
    return _decode_json(body, f"{spec.polled_service}{rel}")


class HttpJsonCollector:
    """``poll-http-json``: GET ``<service alias><path>``, expect 2xx JSON, map it."""

    def collect(self, spec: SourceSpec, ctx: CollectContext) -> list[Draft]:
        return _map(spec, fetch_json(spec, ctx), ctx)


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


#: a last-run record directory: at most this many records, each at most this large
MAX_RECORDS = 4096
MAX_RECORD = 64 << 10


def _load_last_runs(path: Path) -> dict[str, list[Any]]:
    """Every ``*.json`` of a last-run record directory, at its top level and one level down
    (``<dir>/<host>/<job>.json``, one subdirectory per shipped host).  A file that cannot be read
    is listed by name under ``unreadable``, never dropped: it is a job that cannot be seen.
    ``hosts`` names, per record, the host subdirectory it was read from (``None`` at the top
    level): the mapping takes the host from there, so one host's records cannot speak for
    another's."""
    records: list[Any] = []
    hosts: list[str | None] = []
    unreadable: list[tuple[str, str]] = []
    files = sorted([*path.glob("*.json"), *path.glob("*/*.json")])
    if len(files) > MAX_RECORDS:
        raise CollectError(f"{path.name}: more than {MAX_RECORDS} last-run records")
    for f in files:
        name = f.relative_to(path).as_posix()
        try:
            if f.stat().st_size > MAX_RECORD:
                unreadable.append((name, f"larger than {MAX_RECORD} bytes"))
                continue
            records.append(json.loads(f.read_text(encoding="utf-8")))
            hosts.append(f.parent.name if f.parent != path else None)
        except OSError as exc:
            unreadable.append((name, str(exc.strerror or exc)))
        except (UnicodeDecodeError, ValueError):
            unreadable.append((name, "not JSON"))
    return {"records": records, "unreadable": unreadable, "hosts": hosts}


class FileCollector:
    """``poll-file``: a JSON or YAML file (or a records or last-run directory) under the status
    root."""

    def collect(self, spec: SourceSpec, ctx: CollectContext) -> list[Draft]:
        if spec.mapping.get("builtin") == "broker-pending" and ctx.broker is not None:
            return _map(spec, [dict(r) for r in ctx.broker.pending()], ctx)
        path = _inside(ctx.root, spec.file or "")
        if spec.mapping.get("builtin") == "records-lanes":
            if not path.is_dir():
                raise CollectError(f"{spec.file}: no records directory")
            return _map(spec, _load_records(path), ctx)
        if spec.mapping.get("builtin") == "job-last-run" and path.is_dir():
            return _map(spec, _load_last_runs(path), ctx)
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
    "agent-activity": AgentActivityCollector(),
}


def _register_products() -> None:
    # the product collectors build on the helpers above, so they register once those exist
    from .nut import NutCollector
    from .products import PRODUCT_COLLECTORS

    COLLECTORS.update(PRODUCT_COLLECTORS)
    COLLECTORS["poll-nut"] = NutCollector()


_register_products()
