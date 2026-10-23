# SPDX-License-Identifier: Apache-2.0
"""``hnx orchestration``: orchestration telemetry (docs/orchestration-telemetry.md).

    hnx orchestration consume --db FILE --stream S --subject-prefix P [--durable NAME]
                              [--events-user U --events-password-secret secret:NAME]
                              [--events-ca-file F] [--events-allow-plaintext]
    hnx orchestration ingest --db FILE EVENTS.jsonl|-
    hnx orchestration turns --db FILE --turn-source none|MODULE:FACTORY [--gateway-url URL]
                            [--key secret:NAME] [--ca-file F] [--allow-plaintext] [--settle-s N]
    hnx orchestration report --db FILE [--days N]

``consume`` drains ``homelabnext.agent.job.finished`` from the bus (``HNX_ENDPOINT_EVENTS``) into
the store, one pass (a timer runs it); ``ingest`` stores events from a JSON-lines file (one event
per line: a backfill, or a replay of the controller's outbox).  Both count a record that finished
before the retention window as ``expired``: acknowledged, not stored, not an error.  ``turns`` reads the gateway's
per-call log for every job whose turns are not settled, through the turn source ``--turn-source``
names (else ``$HNX_ORCHESTRATION_TURN_SOURCE``): ``none`` (no gateway data: read nothing, settle
nothing) or an adapter factory ``package.module:factory``, the ``adapter:`` form of a conformance
target, called with the adapter options given (``--gateway-url`` as ``base_url``, ``--key`` by
secret name, ``--ca-file``, ``--allow-plaintext``) and returning a
:class:`conformance.protocols.inference.TurnSource`.  Which adapter fills the slot is site
configuration; ``docs/orchestration-telemetry.md`` lists the shipped ones.  ``report`` prints the rollup as JSON
(``homelabnext.orchestration.rollup/1``: the recommendation engine's input).

Exit codes: 0 ok, 1 a record was refused (``ingest``, ``consume``), the bus failed during the
pass (``consume``: what was settled before stays settled) or the gateway could not be read
(``turns``), 2 usage or configuration error (``consume``: the event schemas cannot be loaded, the bus
configuration or the connect), or a store that cannot be opened, or (``consume``) cannot take a
write before the bus is read (SQLite's own error, or two jobs
holding one gateway tag in a store an earlier release wrote: the message says how to fix it).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import Counter
from collections.abc import Callable, Sequence
from pathlib import Path

from conformance.protocols.events import EventsError
from conformance.protocols.inference import TurnSource, TurnSourceError
from homelabnext.events.envelope import EventError

from .model import CONTROLLER_SOURCE
from .store import DEFAULT_RETENTION_DAYS, STORE_ERRORS, TelemetryStore

TURN_SOURCE_ENV = "HNX_ORCHESTRATION_TURN_SOURCE"
#: the controller's service id(s), comma-separated, when --source is not given
SOURCE_ENV = "HNX_ORCHESTRATION_SOURCE"
REPLAY_S = 7 * 86400  # a new durable reads the last week, not only what arrives after it


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="hnx orchestration", description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    def store_opts(p: argparse.ArgumentParser) -> None:
        p.add_argument("--db", required=True, type=Path, help="the telemetry store (SQLite)")
        p.add_argument("--retention-days", type=float, default=DEFAULT_RETENTION_DAYS)
        p.add_argument(
            "--source",
            action="append",
            default=None,
            metavar="svc:NAME",
            help="the controller's service id, the only source of job records (repeatable; "
            f"default: ${SOURCE_ENV}, else {CONTROLLER_SOURCE})",
        )

    p = sub.add_parser("consume", help="drain agent.job.finished from the bus (one pass)")
    store_opts(p)
    p.add_argument("--stream", required=True, help="the JetStream stream the events are in")
    p.add_argument("--subject-prefix", required=True, help="the stream's subject prefix")
    p.add_argument("--durable", default=None, help="the durable consumer's name")
    p.add_argument("--events-user", default=None, help="the consumer's NATS user")
    p.add_argument(
        "--events-password-secret",
        default=None,
        help="the NATS password by secret name (secret:<name>), never a value",
    )
    p.add_argument("--events-ca-file", default=None, help="CA bundle for a tls:// events endpoint")
    p.add_argument(
        "--events-allow-plaintext",
        action="store_true",
        help="allow the NATS password over nats:// to a host that is not loopback (the lab only)",
    )
    p = sub.add_parser("ingest", help="store agent.job.finished events from a JSON-lines file")
    store_opts(p)
    p.add_argument("events", help="the file, or - for stdin")
    p = sub.add_parser("turns", help="read the gateway's per-turn records of unsettled jobs")
    store_opts(p)
    p.add_argument(
        "--turn-source",
        default=None,
        help=f"none, or the adapter as package.module:factory (default: ${TURN_SOURCE_ENV})",
    )
    p.add_argument("--gateway-url", default=None, help="adapter option base_url")
    p.add_argument("--key", default=None, help="adapter option: the key by secret name")
    p.add_argument("--ca-file", default=None, help="adapter option: CA bundle for a private CA")
    p.add_argument(
        "--allow-plaintext",
        action="store_true",
        help="adapter option: allow http to a host that is not loopback (a key would cross in clear)",
    )
    p.add_argument("--settle-s", type=float, default=None, help="re-read a job's turns this long")
    p = sub.add_parser("report", help="the rollup as JSON (the recommendation engine's input)")
    store_opts(p)
    p.add_argument("--days", type=int, default=7)
    return ap


def _ingest(a, store: TelemetryStore) -> int:
    text = sys.stdin.read() if a.events == "-" else Path(a.events).read_text(encoding="utf-8")
    counts: Counter = Counter()
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            counts[store.consume(line).status] += 1
        except EventError as exc:
            counts["refused"] += 1
            print(f"{a.events}:{n}: {str(exc).splitlines()[0]}", file=sys.stderr)
    print(
        "orchestration ingest: "
        + ", ".join(f"{counts[k]} {k}" for k in ("processed", "duplicate", "expired", "refused"))
    )
    return 1 if counts["refused"] else 0


def _consume(a, store: TelemetryStore) -> int:
    from homelabnext.conform.adapters import nats_jetstream
    from homelabnext.events.envelope import load_validator

    from .bus import DURABLE, drain
    from .model import FINISHED_EVENT

    try:
        load_validator(FINISHED_EVENT)  # a broken environment fails here, before the bus is read
        bus = _connect(nats_jetstream, a)
    except Exception as exc:  # the validator, configuration, the endpoint variable, the connect
        print(f"hnx orchestration consume: {exc}", file=sys.stderr)
        return 2
    try:
        counts = drain(bus, store, durable=a.durable or DURABLE)
    except EventsError as exc:  # a fetch or a settle on a bus that went away mid-pass
        print(f"hnx orchestration consume: the bus failed: {exc}", file=sys.stderr)
        return 1
    finally:
        bus.close()
    keys = ("processed", "duplicate", "expired", "quarantined", "retried")
    print("orchestration consume: " + ", ".join(f"{counts[k]} {k}" for k in keys))
    return 1 if counts["quarantined"] or counts["retried"] else 0


def _connect(nats_jetstream, a):
    return nats_jetstream.make(
        scratch=False,
        provision=False,  # read the stream, manage the durable, nothing else
        stream=a.stream,
        subject_prefix=a.subject_prefix,
        ack_wait=30.0,
        replay_s=REPLAY_S,
        user=a.events_user,
        password_secret=a.events_password_secret,
        ca_file=a.events_ca_file,
        allow_plaintext=a.events_allow_plaintext,
        client_name="hnx-orchestration-telemetry",
    )


def turn_source(spec: str, **config):
    """The :class:`~conformance.protocols.inference.TurnSource` that ``spec`` names, or None for
    ``none``: ``package.module:factory`` called with ``config`` (the options that were given).
    :class:`ValueError` for a spec that names no factory or a factory that gives no source."""
    import importlib

    if spec == "none":
        return None
    mod, sep, attr = spec.partition(":")
    if not sep or not mod or not attr:
        raise ValueError(f"--turn-source {spec!r}: none, or an adapter as package.module:factory")
    try:
        factory = getattr(importlib.import_module(mod), attr)
    except (ImportError, AttributeError) as exc:
        raise ValueError(f"--turn-source {spec!r} cannot be imported: {exc}") from None
    try:
        source = factory(**{k: v for k, v in config.items() if v not in (None, False)})
    except TypeError as exc:  # an option the adapter does not take
        raise ValueError(f"--turn-source {spec!r}: {exc}") from None
    if not isinstance(source, TurnSource):
        raise ValueError(f"--turn-source {spec!r} gave no turn source (no turns(start, end, tags))")
    return source


def _turns(a, store: TelemetryStore, clock: Callable[[], float]) -> int:
    from .gateway import SETTLE_S, sync_turns

    spec = a.turn_source or os.environ.get(TURN_SOURCE_ENV, "")
    if not spec:
        print(
            f"hnx orchestration turns: --turn-source or {TURN_SOURCE_ENV} "
            "(none, or an adapter as package.module:factory)",
            file=sys.stderr,
        )
        return 2
    try:
        source = turn_source(
            spec,
            base_url=a.gateway_url,
            key=a.key,
            ca_file=a.ca_file,
            allow_plaintext=a.allow_plaintext,
        )
    except (TurnSourceError, ValueError) as exc:
        print(f"hnx orchestration turns: {exc}", file=sys.stderr)
        return 2
    if source is None:
        print("orchestration turns: no turn source (none): per-job data only, nothing read")
        return 0
    try:
        got = sync_turns(
            store, source, now=clock(), settle_s=SETTLE_S if a.settle_s is None else a.settle_s
        )
    except TurnSourceError as exc:
        print(f"hnx orchestration turns: {exc}", file=sys.stderr)
        return 1
    print(
        f"orchestration turns: {got['turns']} turn(s) for {got['jobs']} job(s), "
        f"{got['settled']} settled"
    )
    return 0


def main(argv: Sequence[str] | None = None, *, clock: Callable[[], float] = time.time) -> int:
    a = _parser().parse_args(argv)
    try:
        sources = a.source or [
            s.strip() for s in os.environ.get(SOURCE_ENV, CONTROLLER_SOURCE).split(",") if s.strip()
        ]
        store = TelemetryStore(a.db, clock=clock, retention_days=a.retention_days, sources=sources)
        if a.cmd == "ingest":
            return _ingest(a, store)
        if a.cmd == "consume":
            return _consume(a, store)
        if a.cmd == "turns":
            return _turns(a, store, clock)
        days = a.days
        if not 1 <= days <= 366:
            print("hnx orchestration report: --days is 1..366", file=sys.stderr)
            return 2
        sys.stdout.write(json.dumps(store.rollup(days=days), indent=1, sort_keys=True) + "\n")
        return 0
    except (ValueError, *STORE_ERRORS) as exc:  # the store (SQLite, the disk), a file, config
        print(f"hnx orchestration {a.cmd}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
