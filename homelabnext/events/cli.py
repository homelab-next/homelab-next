# SPDX-License-Identifier: Apache-2.0
"""CLI: ``hnx events <cmd>`` (also ``python -m homelabnext.events <cmd>``).

``deploy-changed``   build the what-changed event of a deploy from the changelog (F-15); write it
                     to ``--out`` and/or publish it through ``--forwarder`` with a ``--state`` file;
                     ``--auth secret:<name>`` sends the secret's value as ``Authorization``.
``flush``            resend the pending events of a ``--state`` file through ``--forwarder``.
``requeue``          make the rejected events of a ``--state`` file pending again (then ``flush``).
``enrich-coverage``  the share of events in a JSON-lines file carrying asset owner and
                     criticality (T-04); ``--registry``/``--guests`` enrich them first.
                     Exit 0 at or above ``--min``, 1 below, 100 when there is nothing to measure.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .deploy import ChangelogError, changes_from_changelog, deploy_changed_event
from .enrich import DEFAULT_THRESHOLD, AssetInventory, enrich_event, enrichment_coverage
from .envelope import EventError


def _forwarder(a: argparse.Namespace) -> Any:
    """The HTTP forwarder of ``--forwarder``; ``--auth secret:<name>`` is read per request from the
    environment or ``--secrets-dir`` (never from the command line itself)."""
    from .forwarder import HttpForwarder, MisconfiguredError

    if not getattr(a, "auth", None):
        return HttpForwarder(a.forwarder)
    # SECRET_REF is the canonical reference shape (lowercase segments joined by '/'), as the
    # registry writes it; secret_lookup lives with the status agents' config, the one reader
    from homelabnext.mcp.credentials import SECRET_REF
    from homelabnext.status.agents.config import secret_lookup

    if not SECRET_REF.fullmatch(a.auth):
        raise ValueError(
            "--auth must be secret:<name> (lowercase letters, digits, '_' and '-', "
            "segments joined by '/')"
        )
    lookup = secret_lookup(secrets_dir=a.secrets_dir)
    ref = a.auth

    def auth() -> str:
        try:
            value = lookup(ref)
        except (OSError, UnicodeError) as exc:  # the class only: never the path's content
            raise MisconfiguredError(
                f"secret {ref!r} cannot be read ({type(exc).__name__})"
            ) from None
        if not value:
            raise MisconfiguredError(f"secret {ref!r} is not set")
        return value

    return HttpForwarder(a.forwarder, auth=auth)


def _flush(a: argparse.Namespace) -> int:
    from homelabnext.state import StateStore

    from .publisher import Publisher

    if a.cmd == "requeue":  # no sending: the store alone changes
        ids = Publisher(None, StateStore(a.state)).requeue()  # type: ignore[arg-type]
        print(f"requeue: {len(ids)} rejected event(s) made pending", file=sys.stderr)
        return 0
    pub = Publisher(_forwarder(a), StateStore(a.state), retain_s=a.retain_hours * 3600)
    results = pub.flush()
    for r in results:
        print(f"flush: {r.id} {r.status}", file=sys.stderr)
    return 0 if all(r.ok for r in results) else 1


def _deploy_changed(a: argparse.Namespace) -> int:
    try:
        changes = changes_from_changelog(
            Path(a.changelog).read_text(encoding="utf-8"), a.to_version
        )
        event = deploy_changed_event(
            component=a.component,
            to_version=a.to_version,
            from_version=a.from_version,
            changes=changes,
            source=a.source,
            deploy_id=a.deploy_id,
            environment=a.environment,
            commit=a.commit,
            changelog=Path(a.changelog).as_posix() if not Path(a.changelog).is_absolute() else None,
            time=a.time,
        )
    except (OSError, ChangelogError, EventError, ValueError) as exc:
        print(f"deploy-changed: {exc}", file=sys.stderr)
        return 1
    text = json.dumps(event, indent=2, sort_keys=True) + "\n"
    if a.out:
        Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        Path(a.out).write_text(text, encoding="utf-8")
    if a.forwarder:
        from homelabnext.state import StateStore

        from .publisher import Publisher

        try:
            fwd = _forwarder(a)
        except ValueError as exc:
            print(f"deploy-changed: {exc}", file=sys.stderr)
            return 1
        pub = Publisher(fwd, StateStore(a.state), retain_s=a.retain_hours * 3600)
        res = pub.publish(event)
        print(f"deploy-changed: {res.id} {res.status}", file=sys.stderr)
        if not res.ok:
            return 1
    if not a.out:
        sys.stdout.write(text)
    return 0


def _enrich_coverage(a: argparse.Namespace) -> int:
    events = []
    for n, line in enumerate(Path(a.events).read_text(encoding="utf-8").splitlines(), 1):
        if line.strip():
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as exc:
                print(f"{a.events}:{n}: not JSON ({exc})", file=sys.stderr)
                return 100
    if a.registry or a.guests:
        from homelabnext.compute.loader import load_guests
        from homelabnext.registry.model import load

        guests = load_guests(a.guests)[0] if a.guests else ()
        inv = AssetInventory.from_models(load(a.registry) if a.registry else None, guests)
        events = [
            enrich_event(e, inv, validate=False) if isinstance(e, dict) else e for e in events
        ]
    cov = enrichment_coverage(events, threshold=a.min)
    print(cov.render())
    if cov.total == 0:
        return 100
    return 0 if cov.ok else 1


def _add_auth(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--auth", metavar="secret:NAME", help="its value is sent as the Authorization header"
    )
    p.add_argument("--secrets-dir", help="files named after secret references (else env)")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="hnx events")
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("deploy-changed", help="the what-changed event of a deploy (F-15)")
    d.add_argument("--component", required=True, help="svc:<name>, cap:<name> or pkg:<name>")
    d.add_argument("--to", dest="to_version", required=True)
    d.add_argument("--from", dest="from_version")
    d.add_argument("--changelog", default="CHANGELOG.md")
    d.add_argument("--source", required=True, help="the emitter, e.g. svc:release-pipeline")
    d.add_argument("--deploy-id")
    d.add_argument("--environment")
    d.add_argument("--commit")
    d.add_argument("--time", help="RFC 3339; default now (UTC)")
    d.add_argument("--out", help="write the event JSON here")
    d.add_argument("--forwarder", help="publish to this forwarder URL (needs --state)")
    d.add_argument("--state", help="publisher state file")
    from .publisher import retain_hours  # here: the package imports this module

    d.add_argument(
        "--retain-hours",
        type=retain_hours,
        default=24.0,
        help="keep sent ids this long for de-duplication (at least the bus's duplicate window)",
    )
    _add_auth(d)
    for name, text in (
        ("flush", "resend the pending events of a state file"),
        ("requeue", "make the rejected events of a state file pending again"),
    ):
        f = sub.add_parser(name, help=text)
        f.add_argument("--state", required=True, help="publisher state file")
        if name == "flush":  # requeue sends nothing and prunes nothing: no retention to set
            f.add_argument("--retain-hours", type=retain_hours, default=24.0)
            f.add_argument("--forwarder", required=True, help="forwarder URL")
            _add_auth(f)
    c = sub.add_parser("enrich-coverage", help="owner/criticality coverage of an event stream")
    c.add_argument("events", help="JSON lines, one envelope per line")
    c.add_argument("--registry")
    c.add_argument("--guests")
    c.add_argument("--min", type=float, default=DEFAULT_THRESHOLD)
    a = ap.parse_args(argv)
    if a.cmd == "deploy-changed":
        if a.forwarder and not a.state:
            ap.error("--forwarder needs --state")
        return _deploy_changed(a)
    if a.cmd in ("flush", "requeue"):
        try:
            return _flush(a)
        except ValueError as exc:
            print(f"{a.cmd}: {exc}", file=sys.stderr)
            return 1
    return _enrich_coverage(a)
