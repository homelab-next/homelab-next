# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: vector-sidecar
#   kind: service
#   purpose: Label and remap every event the Vector aggregator hands over, with the core library's own label rules, and forward the rows.
#   owner: platform
#   trigger: [manual]
#   inputs: the aggregator's events on a local socket and the rendered label tables
#   outputs: labelled OCSF rows on the forward socket and a status file
#   exit:
#     "0": stopped cleanly
"""The enrichment sidecar: every event the aggregator receives is labelled and remapped here.

Vector owns the transport (the listeners, the files it tails, the disk buffer, the object store
writes); this process owns the two things the ``log-pipeline`` contract is about, and it owns them
with the core library's own rules, not a port: ``homelabnext.logpipeline.enrich`` (the runtime
label from the address the collector saw) and ``enrich_tlp`` (the TLP label from the route's
declaration).  The deployment copies ``homelabnext/tlp.py``, ``homelabnext/logpipeline/``
verbatim beside this file (tests prove the copy is byte-identical and its closure complete), so the
rule that runs on the guest is the rule the conformance suite proved.

Envelope (one JSON object per line from Vector, written by its per-input ``remap`` stamp, which
holds only constants and fields the SOURCE component sets, never a field of the event body)::

    {"route": "<module>/<dataset>", "peer": "<address the socket source saw>" | null,
     "line": "<the raw text line>"}   or   {"route": ..., "event": {...}}

Output (one JSON object per line to Vector): ``{"table": T, "row": {...}}``, the labelled raw
event (table ``raw_archive``) and one row per OCSF class the event maps to (``ocsf.map_event``).

The observed address.  Per route, ``observe`` says where the collector's address comes from:
``peer`` (the peer of the connection), ``agent`` (the address the Wazuh manager recorded for the
agent that sent the event, ``agent.ip``: the manager's own record) or ``recorded`` (a service that
writes about its clients, trusted by the route's ``trusted`` addresses for syslog, or by the route
itself for the sensors: the client the router or sensor recorded).  Anything else the event says
about itself is never consulted.

A line that does not parse is archived whole (decoder ``unparsed``), never dropped; an event the
OCSF remap cannot map keeps its raw row and is counted.  The sidecar counts, per route, the
events it left without a runtime label: an unknown address and ``none`` read the same to the
detections, so that count is the only sign of a model runtime seen from an unlisted address.
"""

from __future__ import annotations

import argparse
import contextlib
import copy
import hashlib
import json
import os
import signal
import socket
import sys
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from homelabnext.logpipeline import (  # the library's own rule (verbatim copy on the guest)
    RuntimeTable,
    SourceTable,
    enrich,
)
from homelabnext.logpipeline import tlp_labels as tl

from . import ocsf

CONFIG_SCHEMA = "hnx-vector.enrich/v1"
OBSERVE = ("peer", "agent", "recorded")
KINDS = tuple(ocsf.MAPPERS)
MAX_LINE = 1 << 20  # a line over 1 MiB is archived truncated, never buffered whole


class ConfigError(ValueError):
    """An enrich.json that is not a valid ``hnx-vector.enrich/v1`` document."""


def load_config(doc: Any) -> dict[str, Any]:
    if not isinstance(doc, Mapping) or doc.get("schema") != CONFIG_SCHEMA:
        raise ConfigError(f"schema is not {CONFIG_SCHEMA!r}")
    routes = doc.get("routes")
    if not isinstance(routes, Mapping) or not routes:
        raise ConfigError("routes is not a non-empty object")
    for route, pol in routes.items():
        if tl._route(route) is None:
            raise ConfigError(f"{route!r} is not <module>/<dataset>")
        if not isinstance(pol, Mapping) or set(pol) - {"kind", "observe", "trusted"}:
            raise ConfigError(f"{route}: a policy holds kind, observe and trusted only")
        if pol.get("kind") not in KINDS or pol.get("observe") not in OBSERVE:
            raise ConfigError(f"{route}: kind is one of {KINDS}, observe one of {OBSERVE}")
        if pol.get("kind") != "siem" and pol["observe"] == "agent":
            raise ConfigError(f"{route}: observe agent is for a siem route")
        trusted = pol.get("trusted", [])
        if not isinstance(trusted, list) or any(not isinstance(t, str) for t in trusted):
            raise ConfigError(f"{route}: trusted is a list of addresses")
    ids = doc.get("detection_ids", {})
    if not isinstance(ids, Mapping) or any(
        not isinstance(k, str) or not isinstance(v, str) for k, v in ids.items()
    ):
        raise ConfigError("detection_ids maps rule ids to det: ids")
    return {"routes": {r: dict(p) for r, p in routes.items()}, "detection_ids": dict(ids)}


# --------------------------------------------------------------------------- the rule
def label_event(
    event: Any,
    observed: str | None,
    route: str | None,
    runtimes: RuntimeTable,
    sources: SourceTable,
) -> Any:
    """One event through the two library rules, as the contract composes them: the runtime label
    from ``observed``, then the TLP label decided by the event **as it arrived** (an item label
    the first rule leaves in place still counts) and set over every spelling the event brought."""
    labelled = enrich(event, observed, runtimes)
    if not isinstance(event, Mapping):
        return labelled
    label = tl.label_for(event, route, sources)
    out = tl.enrich_tlp(labelled, None, SourceTable())
    out["labels"][tl.LABEL] = str(label)
    return out


def _bare_ip(value: Any) -> str | None:
    return value if isinstance(value, str) and value.strip() == value and value else None


def observed_for(policy: Mapping[str, Any], envelope: Mapping[str, Any], event: Any) -> str | None:
    """The address the collector saw for this record (see the module doc); None when it saw none."""
    mode = policy["observe"]
    peer = _bare_ip(envelope.get("peer"))
    if mode == "peer":
        return peer
    if mode == "agent":
        agent = event.get("agent") if isinstance(event, Mapping) else None
        return _bare_ip(agent.get("ip")) if isinstance(agent, Mapping) else None
    # recorded: a service that writes about its clients
    kind = policy["kind"]
    if kind == "syslog":
        if peer is None or peer not in policy.get("trusted", []):
            return peer  # not a trusted recorder: only the connection's peer is evidence
        client = (
            ocsf.cef_client(str(event.get("full_log") or ""))
            if isinstance(event, Mapping)
            else None
        )
        return _bare_ip(client) or peer
    if isinstance(event, Mapping):  # a sensor: the client its capture recorded
        return _bare_ip(_first_str(event, ("src_ip", "id.orig_h")))
    return None


def _first_str(event: Mapping[str, Any], keys: Iterable[str]) -> Any:
    for k in keys:
        if k in event:
            return event[k]
    nested = event.get("id")
    return nested.get("orig_h") if isinstance(nested, Mapping) else None


def _parse(
    policy: Mapping[str, Any], envelope: Mapping[str, Any], now: datetime
) -> tuple[Any, bool]:
    """The event of an envelope and whether it parsed."""
    if "event" in envelope and isinstance(envelope["event"], Mapping):
        return copy.deepcopy(dict(envelope["event"])), True
    line = envelope.get("line")
    if not isinstance(line, str):
        return {"full_log": "", "decoder": {"name": "unparsed"}}, False
    line = line[:MAX_LINE]
    if policy["kind"] == "syslog":
        peer = _bare_ip(envelope.get("peer")) or "unknown"
        return {
            "timestamp": now.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "full_log": line.rstrip("\r\n"),
            "location": f"syslog:{peer}",
            "decoder": {"name": "syslog"},
        }, True
    try:
        parsed = json.loads(line)
    except ValueError:
        parsed = None
    if isinstance(parsed, dict):
        return parsed, True
    return {"full_log": line.rstrip("\r\n"), "decoder": {"name": "unparsed"}}, False


class Counters(dict):
    def bump(self, route: str, name: str, n: int = 1) -> None:
        r = self.setdefault(route, {})
        r[name] = r.get(name, 0) + n


def process_envelope(
    envelope: Any,
    cfg: Mapping[str, Any],
    runtimes: RuntimeTable,
    sources: SourceTable,
    now: datetime,
    counters: Counters | None = None,
) -> list[tuple[str, dict[str, Any]]]:
    """One envelope to its rows.  An envelope for a route the configuration does not hold is
    refused (counted under ``refused``), never labelled by a guess."""
    counters = counters if counters is not None else Counters()
    route = envelope.get("route") if isinstance(envelope, Mapping) else None
    policy = cfg["routes"].get(route) if isinstance(route, str) else None
    if policy is None:
        counters.bump("-", "refused")
        return []
    event, parsed = _parse(policy, envelope, now)
    counters.bump(route, "in")
    if not parsed:
        counters.bump(route, "unparsed")
    observed = observed_for(policy, envelope, event)
    labelled = label_event(event, observed, route, runtimes, sources)
    if not (labelled.get("labels") or {}).get("hnx_runtime"):
        counters.bump(route, "unlabelled")
    try:
        rows = ocsf.map_event(labelled, policy["kind"], route, now, cfg["detection_ids"])
    except Exception:
        counters.bump(route, "unmapped")
        rows = ocsf.map_event(
            {k: v for k, v in labelled.items() if k in ("labels",)}
            | {"full_log": json.dumps(event, default=str)[:8192]},
            "sensor",
            route,
            now,
            {},
        )[:1]
    counters.bump(route, "rows", len(rows))
    return rows


def handle_line(
    line: str,
    cfg: Mapping[str, Any],
    runtimes: RuntimeTable,
    sources: SourceTable,
    now: datetime,
    counters: Counters | None = None,
) -> list[str]:
    """One input line to its output lines (JSON text).  A line that is not a JSON object is
    refused and counted, never forwarded."""
    counters = counters if counters is not None else Counters()
    try:
        env = json.loads(line)
    except ValueError:
        env = None
    if not isinstance(env, dict):
        counters.bump("-", "refused")
        return []
    rows = process_envelope(env, cfg, runtimes, sources, now, counters)
    return [
        json.dumps({"table": t, "row": r}, sort_keys=True, separators=(",", ":"), default=str)
        for t, r in rows
    ]


# --------------------------------------------------------------------------- the daemon
def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class Tables:
    """The three tables the sidecar reads (runtime labels, TLP sources, routes), reloaded when
    their file changes.  A file that does not read keeps the table last loaded and is reported
    under ``error`` in the status: the digest in the status is the one in use, so a health check
    that compares it with the deployed file sees a stale or refused table."""

    def __init__(self, directory: Path):
        self.dir = directory
        self.runtimes = RuntimeTable()
        self.sources = SourceTable()
        self.cfg: dict[str, Any] = {"routes": {}, "detection_ids": {}}
        self.digests: dict[str, str] = {}
        self.errors: dict[str, str] = {}
        self._mtimes: dict[str, float] = {}

    def refresh(self) -> bool:
        changed = False
        for name, load in (
            ("runtime-labels.json", lambda p: RuntimeTable.load(p)),
            ("tlp-sources.json", lambda p: SourceTable.load(p)),
            ("enrich.json", lambda p: load_config(json.loads(p.read_text(encoding="utf-8")))),
        ):
            path = self.dir / name
            try:
                mtime = path.stat().st_mtime_ns
            except OSError as exc:
                self.errors[name] = f"unreadable: {exc.strerror}"
                continue
            if self._mtimes.get(name) == mtime and name not in self.errors:
                continue
            self._mtimes[name] = mtime
            try:
                value = load(path)
                digest = _sha(path)
            except Exception as exc:
                self.errors[name] = f"{type(exc).__name__}: {exc}"[:300]
                continue
            self.errors.pop(name, None)
            self.digests[name] = digest
            changed = True
            if name == "runtime-labels.json":
                self.runtimes = value
            elif name == "tlp-sources.json":
                self.sources = value
            else:
                self.cfg = value
        return changed


def write_status(
    path: Path,
    tables: Tables,
    counters: Counters,
    extra: Mapping[str, Any],
    clock: Callable[[], float] = time.time,
) -> None:
    doc = {
        "schema": "hnx-vector.status/v1",
        "time": clock(),
        "tables": tables.digests,
        "errors": tables.errors,
        "counters": counters,
        **extra,
    }
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)  # its final mode, at creation
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(doc, f, sort_keys=True)
    os.replace(tmp, path)


class Sender:
    """The connection to Vector's receiving socket: a line is sent whole or retried until it is
    (at-least-once; the lake's content key makes a replayed line a no-op).  While it cannot
    connect, the sidecar reads no more input, so the pressure lands in Vector's disk buffer."""

    def __init__(self, path: str, sleep: Callable[[float], None] = time.sleep):
        self.path, self.sleep, self.sock = path, sleep, None

    def send(self, data: bytes, stop: Callable[[], bool] = lambda: False) -> bool:
        delay = 0.2
        while not stop():
            try:
                if self.sock is None:
                    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    s.connect(self.path)
                    self.sock = s
                self.sock.sendall(data)
                return True
            except OSError:
                if self.sock is not None:
                    with contextlib.suppress(OSError):
                        self.sock.close()
                self.sock = None
                self.sleep(delay)
                delay = min(delay * 2, 5.0)
        return False


def serve(
    directory: Path,
    listen: str,
    forward: str,
    status: Path,
    interval: float = 5.0,
    stop: threading.Event | None = None,
) -> int:
    tables = Tables(directory)
    counters = Counters()
    stop = stop if stop is not None else threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        with contextlib.suppress(ValueError):  # not the main thread: the caller owns ``stop``
            signal.signal(sig, lambda *_: stop.set())
    tables.refresh()
    with contextlib.suppress(FileNotFoundError):
        os.unlink(listen)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    old_umask = os.umask(0o117)  # the socket is born 0660: owner and group only
    try:
        srv.bind(listen)
    finally:
        os.umask(old_umask)
    srv.listen(4)
    srv.settimeout(1.0)
    sender = Sender(forward)
    last = 0.0
    while not stop.is_set():
        now = time.monotonic()
        if now - last >= interval:
            tables.refresh()
            write_status(status, tables, counters, {"listening": True})
            last = now
        try:
            conn, _ = srv.accept()
        except TimeoutError:
            continue
        conn.settimeout(1.0)
        buf = b""
        with conn:
            while not stop.is_set():
                try:
                    chunk = conn.recv(65536)
                except TimeoutError:
                    if time.monotonic() - last >= interval:
                        tables.refresh()
                        write_status(status, tables, counters, {"listening": True})
                        last = time.monotonic()
                    continue
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    raw, buf = buf.split(b"\n", 1)
                    out = handle_line(
                        raw.decode("utf-8", "replace"),
                        tables.cfg,
                        tables.runtimes,
                        tables.sources,
                        datetime.now(UTC),
                        counters,
                    )
                    if out and not sender.send(("\n".join(out) + "\n").encode(), stop.is_set):
                        break
                if len(buf) > 2 * MAX_LINE:  # no newline in 2 MiB: not our protocol
                    counters.bump("-", "refused")
                    buf = b""
    write_status(status, tables, counters, {"listening": False})
    return 0


def healthcheck(status: Path, max_age: float = 30.0, clock: Callable[[], float] = time.time) -> int:
    """Exit 0 when the status file is fresh and no table is in error."""
    try:
        doc = json.loads(status.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return 1
    if (
        clock() - float(doc.get("time", 0)) > max_age
        or doc.get("errors")
        or not doc.get("listening")
    ):
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--tables", default="/etc/hnx-vector", help="directory of the three tables")
    ap.add_argument("--listen", default="/run/hnx/in.sock")
    ap.add_argument("--forward", default="/run/hnx/out.sock")
    ap.add_argument("--status", default="/run/hnx/status.json")
    ap.add_argument("--healthcheck", action="store_true")
    a = ap.parse_args(argv)
    if a.healthcheck:
        return healthcheck(Path(a.status))
    return serve(Path(a.tables), a.listen, a.forward, Path(a.status))


if __name__ == "__main__":
    sys.exit(main())
