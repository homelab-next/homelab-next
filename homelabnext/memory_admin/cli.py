# SPDX-License-Identifier: Apache-2.0
"""``hnx agent memory dependents|retract|lift|purge|restamp``: the operator's memory tools
(ADR-0037 decisions 12 to 14, amended 2026-11-06).  Operator only, and a dry run unless
``--apply``.  Run it through ``sudo``: the agent runtime owns the state file, and the write keeps
that owner.

``dependents SOURCE [--revision all|this] [--include-exposed] [--include-alias UID ...]``
                                                what a retraction of SOURCE would reach: its
                                                alias set (and any ambiguous digest), the cited
                                                and exposed records across owners, and the
                                                confirm digest.
``retract SOURCE --reason R [same options] [--apply --confirm D]``
                                                without ``--apply``, the dry run; with it, deny
                                                every alias first, record what it reached, then
                                                retire the cited entries (and the exposed ones
                                                with ``--include-exposed``).  A rerun with the
                                                same settings completes a retraction already
                                                denied without ``--confirm``.
``lift SOURCE --reason R [--apply]``             lift SOURCE's active retractions.
``purge OWNER TARGET --reason R [--apply]``      blank a value: TARGET is a ``sha256:`` value
                                                digest (OWNER ``*`` for every owner holding it) or
                                                ``<scope>/<key>@<rev>``.
``restamp OWNER --reason R [--apply --expect-now T]``
                                                re-stamp records stamped in the future (the dry
                                                run lists from -> to); ``--expect-now`` is the
                                                UTC time you believe it is (ISO 8601).

Every command takes ``--state FILE`` (the runtime's memory state file), ``--deny FILE`` (its deny
file, default ``<state>.deny.json``) and ``--operators FILE`` (honoured only for root; default
``/etc/homelabnext/memory-operators.yml``, see :mod:`homelabnext.memory_admin.principal`).  The
owner of the state file is refused as an operator, and the deny file must be owned by root or the
operator, writable by no one else.  Output is JSON on stdout.  Exit codes: 0 done (or a dry run),
1 refused (who ran it, the operators file's ownership or content, a stale ``--confirm``, a bad
argument), 2 a usage error or a file that cannot be read.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import UTC, datetime
from typing import Any

from homelabnext.agent.memory import FileBackend, MemoryAccessError, MemoryClockError

from .admin import MemoryAdmin
from .principal import (
    DEFAULT_OPERATORS,
    MemoryAdminError,
    OperatorsUnreadable,
    check_root_owned,
    invoking_operator,
    load_operators,
)


class _Unreadable(Exception):
    pass


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="hnx agent memory", description=__doc__.split("\n\n")[0] if __doc__ else None
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--state", required=True, help="the runtime's memory state file")
        p.add_argument("--deny", help="the deny file (default <state>.deny.json)")
        p.add_argument("--operators", help=f"the operators file (root only; {DEFAULT_OPERATORS})")

    def scope(p: argparse.ArgumentParser) -> None:
        p.add_argument("source")
        p.add_argument("--revision", choices=("all", "this"), default="all")
        p.add_argument("--include-exposed", action="store_true", help="retire exposed entries too")
        p.add_argument("--include-alias", action="append", default=[], metavar="UID",
                       help="also deny a foreign uid an ambiguous digest is paired with")  # fmt: skip

    d = sub.add_parser("dependents", help="what retracting SOURCE would reach (the dry run)")
    scope(d)
    r = sub.add_parser("retract", help="retract SOURCE and everything built on it")
    scope(r)
    r.add_argument("--confirm", help="the dry run's confirm digest")
    lf = sub.add_parser("lift", help="lift SOURCE's active retractions")
    lf.add_argument("source")
    pg = sub.add_parser("purge", help="blank a value in every record that holds it")
    pg.add_argument("owner", help="a profile id, or * (with a value digest) for every owner")
    pg.add_argument("target", help="sha256:<value digest> or <scope>/<key>@<rev>")
    rs = sub.add_parser("restamp", help="re-stamp records stamped in the future")
    rs.add_argument("owner")
    rs.add_argument("--expect-now", help="the UTC time you believe it is (needed with --apply)")
    for p in (d, r, lf, pg, rs):
        common(p)
    for p in (r, lf, pg, rs):
        p.add_argument("--reason", required=True, help="why (one line; kept in the records)")
        p.add_argument("--apply", action="store_true", help="do it (default: a dry run)")
    return ap


def _expect(text: str | None) -> datetime | None:
    if text is None:
        return None
    try:
        t = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        raise MemoryAdminError("--expect-now is an ISO 8601 time") from None
    return t if t.tzinfo else t.replace(tzinfo=UTC)


def _euid() -> int:
    return os.geteuid()


def _owner(path: str) -> int:
    """The uid owning the state file: the agent runtime's, which is refused as an operator."""
    return os.stat(path).st_uid


def _run(args: argparse.Namespace) -> dict[str, Any]:
    if args.operators is not None and _euid() != 0:
        raise MemoryAdminError(
            "--operators is honoured only for root (run through sudo); without it the command "
            f"reads {DEFAULT_OPERATORS}"
        )
    config = load_operators(args.operators or DEFAULT_OPERATORS)
    try:
        state_owner = _owner(args.state)
    except OSError as exc:
        raise _Unreadable(f"no memory state file at {args.state} ({exc.strerror})") from None
    # the runtime owns the state file, and the operators file cannot forge that
    by = invoking_operator(config.refusing([state_owner]))
    backend = FileBackend(args.state, deny_path=args.deny)
    unsafe = [
        p
        for path in (backend.deny.path, backend.deny.lock_path)
        for p in check_root_owned(path, owners=(0, by.uid))
    ]
    if unsafe:
        raise MemoryAdminError(
            "the deny file must be owned by root or the operator and writable by no one else: "
            + "; ".join(unsafe)
        )
    admin = MemoryAdmin(backend)
    scope = {}
    if args.cmd in ("dependents", "retract"):
        scope = {
            "revision": args.revision,
            "include_exposed": args.include_exposed,
            "include_alias": args.include_alias,
        }
    if args.cmd == "dependents":
        return admin.dependents(args.source, by=by, **scope)
    if args.cmd == "retract":
        if not args.apply:
            return {"dry_run": True, **admin.dependents(args.source, by=by, **scope)}
        return admin.retract(args.source, args.reason, by=by, confirm=args.confirm, **scope)
    if args.cmd == "lift":
        return admin.lift(args.source, args.reason, by=by, dry_run=not args.apply)
    if args.cmd == "purge":
        return admin.purge(args.owner, args.target, args.reason, by=by, dry_run=not args.apply)
    return admin.restamp(
        args.owner,
        args.reason,
        by=by,
        dry_run=not args.apply,
        expect_now=_expect(args.expect_now),
    )


def main(argv: list[str]) -> int:
    args = _parser().parse_args(argv)
    try:
        out = _run(args)
    except (OperatorsUnreadable, _Unreadable, OSError) as exc:
        print(f"hnx agent memory {args.cmd}: {exc}", file=sys.stderr)
        return 2
    except (MemoryAdminError, MemoryAccessError, MemoryClockError) as exc:
        print(f"hnx agent memory {args.cmd}: refused: {exc}", file=sys.stderr)
        return 1
    sys.stdout.write(json.dumps(out, indent=2, sort_keys=True) + "\n")
    return 0
