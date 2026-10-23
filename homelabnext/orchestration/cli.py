# SPDX-License-Identifier: Apache-2.0
"""``hnx orchestration``: orchestration telemetry (docs/orchestration-telemetry.md).

    hnx orchestration consume --db FILE --stream S --subject-prefix P [--durable NAME]
                              [--events-user U --events-password-secret secret:NAME]
                              [--events-ca-file F] [--events-allow-plaintext]
    hnx orchestration ingest --db FILE EVENTS.jsonl|-
    hnx orchestration turns --db FILE --turn-source none|MODULE:FACTORY [--gateway-url URL]
                            [--key secret:NAME] [--ca-file F] [--allow-plaintext] [--settle-s N]
                            [--turn-source-namespace PACKAGE]... [--turn-source-option K=V]...
    hnx orchestration report --db FILE [--days N]
    hnx orchestration export --db FILE [--out FILE|-]
    hnx orchestration import --db FILE EXPORT.jsonl|-

``consume`` drains ``homelabnext.agent.job.finished`` from the bus (``HNX_ENDPOINT_EVENTS``) into
the store, one pass (a timer runs it); ``ingest`` stores events from a JSON-lines file (one event
per line: a backfill, or a replay of the controller's outbox).  Both count a record that finished
before the retention window as ``expired``: acknowledged, not stored, not an error.  ``turns`` reads the gateway's
per-call log for every job whose turns are not settled, through the turn source ``--turn-source``
names (else ``$HNX_ORCHESTRATION_TURN_SOURCE``): ``none`` (no gateway data: read nothing, settle
nothing) or an adapter factory ``package.module:factory``, the ``adapter:`` form of a conformance
target, under ``homelabnext.conform.adapters`` or a site package ``--turn-source-namespace``
declares (checked before the import), called with the adapter options given (``--gateway-url`` as ``base_url``, ``--key`` by
secret name, ``--ca-file``, ``--allow-plaintext``, any other as ``--turn-source-option``) and returning a
:class:`conformance.protocols.inference.TurnSource`.  Which adapter fills the slot is site
configuration; ``docs/orchestration-telemetry.md`` lists the shipped ones.  ``report`` prints the rollup as JSON
(``homelabnext.orchestration.rollup/1``: the recommendation engine's input).  ``export`` writes
the whole store as JSON lines (``homelabnext.orchestration.export/1``, :mod:`.export`: every job
as its event, every turn as its record), reading it as the hub does (read-only, nothing purged);
``import`` loads such a file into a store, idempotent by the same ids and refusing a record the
bus consumer would refuse, so a store can be moved, rebuilt or swapped.

Exit codes: 0 ok, 1 a record was refused (``ingest``, ``consume``, ``import``), the export
holds records an import would refuse (``export``: it says how many), the turn source gave
records that are no turn record (``turns``: dropped and counted, the rest stored and settled), the bus failed during the
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
import re
import sys
import time
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

from conformance.protocols.events import EventsError
from conformance.protocols.inference import TurnSource, TurnSourceError
from homelabnext.events.envelope import EventError

from .model import CONTROLLER_SOURCE
from .store import DEFAULT_RETENTION_DAYS, STORE_ERRORS, TelemetryStore

TURN_SOURCE_ENV = "HNX_ORCHESTRATION_TURN_SOURCE"
#: the site packages a turn source may come from, comma-separated, when no
#: --turn-source-namespace is given; the shipped adapters' package is always allowed
NAMESPACES_ENV = "HNX_ORCHESTRATION_TURN_SOURCE_NAMESPACES"
#: the shipped adapters: a turn source is code from here or from a namespace the site declares
ADAPTERS = "homelabnext.conform.adapters"
#: an adapter module's declaration of its turn source factories: ``{name: {"secrets": [option,
#: ...]}}``, ``secrets`` naming the options that hold a secret name (``secret:<name>``)
FACTORIES = "TURN_SOURCES"
_DOTTED = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*")
_OPTION_KEY = re.compile(r"[a-z][a-z0-9_]{0,63}")
#: an option key naming a credential: its value is a secret name, never the secret.  A stem
#: anywhere in the key, or a short one as a whole ``_`` segment (``pass``, ``db_pwd``, ``sig``);
#: no pattern names every credential, so an adapter also declares its own (:data:`FACTORIES`)
_CREDENTIAL = re.compile(
    r"key|token|passw|secret|credential|auth|bearer|cookie|session|private|cert"
    r"|(?:^|_)(?:pwd|pass|passphrase|jwt|otp|sig|dsn|pem)(?:_|$)"
)
#: a URL carrying userinfo (``scheme://user:password@host``, ``scheme://token@host``)
_USERINFO = re.compile(r"://[^/?#]*@")
_SECRET_NAME = re.compile(r"secret:[a-z0-9][a-z0-9/_.-]{0,127}")
#: the options the dedicated flags give
_FLAG_OPTIONS = {
    "base_url": "--gateway-url",
    "key": "--key",
    "ca_file": "--ca-file",
    "allow_plaintext": "--allow-plaintext",
}
#: the controller's service id(s), comma-separated, when --source is not given
SOURCE_ENV = "HNX_ORCHESTRATION_SOURCE"
REPLAY_S = 7 * 86400  # a new durable reads the last week, not only what arrives after it


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="hnx orchestration", description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    def store_opts(p: argparse.ArgumentParser) -> None:
        p.add_argument("--db", required=True, type=Path, help="the telemetry store (SQLite)")
        p.add_argument(
            "--retention-days",
            type=float,
            default=DEFAULT_RETENTION_DAYS,
            help="keep jobs and turns this many days, 1 to 3650 (default: %(default)s)",
        )
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
    p.add_argument(
        "--turn-source-namespace",
        action="append",
        default=None,
        metavar="PACKAGE",
        help="a site package whose adapters --turn-source may name, besides "
        f"{ADAPTERS} (repeatable; default: ${NAMESPACES_ENV}, comma-separated, else none)",
    )
    p.add_argument(
        "--turn-source-option",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="another adapter option (repeatable; true/false are booleans; a key naming a "
        "credential takes only secret:<name>)",
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
    p = sub.add_parser("export", help="the whole store as JSON lines (export/1)")
    store_opts(p)
    p.add_argument("--out", default="-", help="the file to write, or - for stdout (the default)")
    p = sub.add_parser("import", help="load an export (JSON lines) into the store")
    store_opts(p)
    p.add_argument("export", help="the file, or - for stdin")
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


def _export(a, store: TelemetryStore) -> int:
    from .export import export_lines

    refusable: Counter = Counter()
    lines = [f"{line}\n" for line in export_lines(store, refusable)]
    if a.out == "-":
        sys.stdout.writelines(lines)
    else:
        _write_whole(Path(a.out), "".join(lines), store.path)
    print(f"orchestration export: {len(lines) - 1} record(s)", file=sys.stderr)
    if refusable:
        print(
            f"hnx orchestration export: {refusable.total()} an import would refuse: "
            f"{refusable['job']} job(s) without an envelope, {refusable['turn']} turn(s) not a "
            "turn record (a store written before exports; rebuild it from the outbox to move them)",
            file=sys.stderr,
        )
        return 1
    return 0


def _write_whole(out: Path, text: str, db: Path) -> None:
    """Write ``text`` to ``out`` whole: a temporary file in its directory, then
    :func:`os.replace`, so a reader never sees half an export and a failed write leaves the old
    one.  :class:`ValueError` when ``out`` is the store itself (under any spelling) or a symlink
    (replacing it would write wherever it points)."""
    import tempfile

    if out.is_symlink():
        raise ValueError(f"--out {out} is a symlink: name the file itself")
    if out.exists() and os.path.samefile(out, db):
        raise ValueError(f"--out {out} is the store itself: name another file")
    fd, tmp = tempfile.mkstemp(dir=out.parent, prefix=f".{out.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(tmp, out)
    except BaseException:
        os.unlink(tmp)
        raise


def _import(a, store: TelemetryStore) -> int:
    from .export import STATUSES, import_lines

    text = sys.stdin.read() if a.export == "-" else Path(a.export).read_text(encoding="utf-8")
    counts, refused = import_lines(store, text.splitlines())
    for n, why in refused:
        print(f"{a.export}:{n}: {why}", file=sys.stderr)
    parts = [
        f"{kind}s " + ", ".join(f"{counts[(kind, s)]} {s}" for s in STATUSES)
        for kind in ("job", "turn")
    ]
    print(f"orchestration import: {'; '.join(parts)}; {counts['refused']} refused")
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


def turn_source(spec: str, namespaces: Sequence[str] = (), **config):
    """The :class:`~conformance.protocols.inference.TurnSource` that ``spec`` names, or None for
    ``none``: ``package.module:factory`` called with ``config`` (the options, as given).
    The module must be in :data:`ADAPTERS` or in one of ``namespaces`` (the site's own packages;
    never a standard-library or ``homelabnext`` package), checked before anything is imported,
    and the factory must be one the module declares in :data:`FACTORIES` and defines itself
    (``factory.__module__`` is the module), so a flag never calls a helper an adapter happens to
    import.  :class:`ValueError` for a spec outside them, a module whose import fails in any way,
    a factory that is not declared or not its own, takes other options, or gives no source."""
    import importlib

    if spec == "none":
        return None
    for ns in namespaces:
        if not _DOTTED.fullmatch(ns):
            raise ValueError(f"--turn-source-namespace {ns!r:.80}: a package name (a.b.c)")
        top = ns.split(".")[0]
        if top in sys.stdlib_module_names or top == "homelabnext":
            raise ValueError(
                f"--turn-source-namespace {ns}: the site's own package, never the standard "
                f"library or homelabnext (whose adapters are {ADAPTERS}, always allowed)"
            )
    mod, sep, attr = spec.partition(":")
    if not sep or not _DOTTED.fullmatch(mod) or not attr.isidentifier():
        raise ValueError(
            f"--turn-source {spec!r:.120}: none, or an adapter as package.module:factory "
            f"under {ADAPTERS} or a declared site package"
        )
    allowed = (ADAPTERS, *namespaces)
    if not any(mod.startswith(f"{ns}.") for ns in allowed):
        raise ValueError(
            f"--turn-source {spec!r:.120}: a module under {' or '.join(allowed)} "
            f"(declare a site package with --turn-source-namespace or ${NAMESPACES_ENV})"
        )
    try:
        module = importlib.import_module(mod)
    except Exception as exc:  # any failure of the import (its top level ran) is configuration
        raise ValueError(
            f"--turn-source {spec!r:.120} cannot be imported: {type(exc).__name__}: {exc}"
        ) from None
    declared = getattr(module, FACTORIES, None)
    if not isinstance(declared, Mapping) or attr not in declared:
        raise ValueError(
            f"--turn-source {spec!r:.120}: not a declared turn source factory (the module "
            f"names its factories in {FACTORIES})"
        )
    factory = getattr(module, attr, None)
    if not callable(factory) or getattr(factory, "__module__", None) != mod:
        raise ValueError(f"--turn-source {spec!r:.120}: the factory is not defined in {mod}")
    decl = declared[attr] if isinstance(declared[attr], Mapping) else {}
    for name in decl.get("secrets", ()):
        value = config.get(name)
        if value not in (None, False) and not (
            isinstance(value, str) and _SECRET_NAME.fullmatch(value)
        ):
            raise ValueError(
                f"--turn-source {spec!r:.120}: option {name} is a secret the adapter declares: "
                "a secret name (secret:<name>), never a value"
            )
    try:
        source = factory(**config)
    except TypeError as exc:  # an option the adapter does not take
        raise ValueError(f"--turn-source {spec!r:.120}: {exc}") from None
    if not isinstance(source, TurnSource):
        raise ValueError(
            f"--turn-source {spec!r:.120} gave no turn source (no turns(start, end, tags))"
        )
    return source


def turn_source_options(pairs: Sequence[str]) -> dict[str, str | bool]:
    """``--turn-source-option KEY=VALUE`` pairs as adapter options: ``true``/``false`` are
    booleans; a key that names a credential (:data:`_CREDENTIAL`: key, token, password, secret,
    pwd, bearer, cookie, session, jwt, cert, dsn, ...) takes only a secret name
    (``secret:<name>``), and no value may be a URL with userinfo, so no secret value is ever on a
    command line.  The options a factory declares secret are checked again in :func:`turn_source`.
    :class:`ValueError` for a malformed pair, a repeated key or one a dedicated flag sets."""
    out: dict[str, str | bool] = {}
    for pair in pairs:
        key, sep, value = pair.partition("=")
        if not sep or not _OPTION_KEY.fullmatch(key):
            raise ValueError(f"--turn-source-option {pair[:40]!r}: key=value, key a-z0-9_")
        if key in _FLAG_OPTIONS:
            raise ValueError(f"--turn-source-option {key}: give it as {_FLAG_OPTIONS[key]}")
        if key in out:
            raise ValueError(f"--turn-source-option {key}: given twice")
        if _USERINFO.search(value):
            raise ValueError(
                f"--turn-source-option {key}: a URL with userinfo carries a credential; give "
                "the credential as its own option, by secret name"
            )
        if (_CREDENTIAL.search(key) or value.startswith("secret:")) and not _SECRET_NAME.fullmatch(
            value
        ):
            raise ValueError(
                f"--turn-source-option {key}: a credential is a secret name (secret:<name>), "
                "never a value"
            )
        out[key] = {"true": True, "false": False}.get(value, value)
    return out


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
    namespaces = a.turn_source_namespace or [
        n.strip() for n in os.environ.get(NAMESPACES_ENV, "").split(",") if n.strip()
    ]
    try:
        source = turn_source(
            spec,
            namespaces,
            **turn_source_options(a.turn_source_option),
            **{
                k: v
                for k, v in (
                    ("base_url", a.gateway_url),
                    ("key", a.key),
                    ("ca_file", a.ca_file),
                    ("allow_plaintext", a.allow_plaintext),
                )
                if v not in (None, False)  # a flag not given is the adapter's default
            },
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
        f"{got['settled']} settled, {got['refused']} refused (not a turn record: dropped)"
    )
    return 1 if got["refused"] else 0


def main(argv: Sequence[str] | None = None, *, clock: Callable[[], float] = time.time) -> int:
    a = _parser().parse_args(argv)
    try:
        sources = a.source or [
            s.strip() for s in os.environ.get(SOURCE_ENV, CONTROLLER_SOURCE).split(",") if s.strip()
        ]
        store = TelemetryStore(
            a.db,
            clock=clock,
            retention_days=a.retention_days,
            sources=sources,
            read_only=a.cmd == "export",  # an export creates, migrates and purges nothing
        )
        if a.cmd == "export":
            return _export(a, store)
        if a.cmd == "import":
            return _import(a, store)
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
