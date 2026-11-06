# SPDX-License-Identifier: Apache-2.0
"""``hnx agent memory dependents|retract|lift|purge|restamp``: the operator's memory tools
(ADR-0037 decisions 12 to 14).  Operator only, and a dry run unless ``--apply``.

``dependents SOURCE [--revision all|this]``      what a retraction of SOURCE would reach: its
                                                alias set, the cited and exposed records across
                                                owners, and the confirm digest.
``retract SOURCE --reason R [--revision all|this] [--include-exposed] [--apply --confirm D]``
                                                without ``--apply``, the dry run (as
                                                ``dependents``); with it, deny every alias of
                                                SOURCE first, record what it reached, then retire
                                                the cited entries (and the exposed ones with
                                                ``--include-exposed``).  ``--confirm`` is the dry
                                                run's digest; a rerun of a retraction already
                                                denied completes it without one.
``lift SOURCE --reason R [--apply]``             lift SOURCE's active retractions (restores
                                                nothing retired).
``purge OWNER TARGET --reason R [--apply]``      blank a value: TARGET is a ``sha256:`` value
                                                digest (OWNER ``*`` for every owner holding it) or
                                                ``<scope>/<key>@<rev>``.
``restamp OWNER --reason R [--apply]``           re-stamp records stamped in the future, after a
                                                host clock that ran ahead was corrected.

Every command takes ``--state FILE`` (the memory store's state file) and ``--operators FILE``
(the reviewed operators file, default ``/etc/homelabnext/memory-operators.yml``; see
:mod:`homelabnext.memory_admin.principal`).  The invoking user must be listed there and must not
be a user the agent runtime or the broker runs as.  Output is JSON on stdout.  Exit codes: 0 done
(or a dry run), 1 refused (who ran it, the operators file, a stale ``--confirm`` or a bad
argument), 2 a usage error or a file that cannot be read.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

from homelabnext.agent.memory import FileBackend, MemoryAccessError, MemoryClockError

from .admin import MemoryAdmin
from .principal import DEFAULT_OPERATORS, MemoryAdminError, invoking_operator, load_operators


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="hnx agent memory", description=__doc__.split("\n\n")[0] if __doc__ else None
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--state", required=True, help="the memory store's state file")
        p.add_argument("--operators", default=DEFAULT_OPERATORS, help="the operators file")

    d = sub.add_parser("dependents", help="what retracting SOURCE would reach (the dry run)")
    d.add_argument("source")
    d.add_argument("--revision", choices=("all", "this"), default="all")
    r = sub.add_parser("retract", help="retract SOURCE and everything built on it")
    r.add_argument("source")
    r.add_argument("--revision", choices=("all", "this"), default="all")
    r.add_argument("--include-exposed", action="store_true", help="retire exposed entries too")
    r.add_argument("--confirm", help="the dry run's confirm digest")
    lf = sub.add_parser("lift", help="lift SOURCE's active retractions")
    lf.add_argument("source")
    pg = sub.add_parser("purge", help="blank a value in every record that holds it")
    pg.add_argument("owner", help="a profile id, or * (with a value digest) for every owner")
    pg.add_argument("target", help="sha256:<value digest> or <scope>/<key>@<rev>")
    rs = sub.add_parser("restamp", help="re-stamp records stamped in the future")
    rs.add_argument("owner")
    for p in (d, r, lf, pg, rs):
        common(p)
    for p in (r, lf, pg, rs):
        p.add_argument("--reason", required=True, help="why (one line; kept in the records)")
        p.add_argument("--apply", action="store_true", help="do it (default: a dry run)")
    return ap


def _run(args: argparse.Namespace) -> dict[str, Any]:
    by = invoking_operator(load_operators(args.operators))
    if not os.path.isfile(args.state):
        raise FileNotFoundError(f"no memory state file at {args.state}")
    admin = MemoryAdmin(FileBackend(args.state))
    if args.cmd == "dependents":
        return admin.dependents(args.source, by=by, revision=args.revision)
    if args.cmd == "retract":
        if not args.apply:
            out = admin.dependents(args.source, by=by, revision=args.revision)
            return {"dry_run": True, **out}
        return admin.retract(
            args.source,
            args.reason,
            by=by,
            confirm=args.confirm,
            revision=args.revision,
            include_exposed=args.include_exposed,
        )
    if args.cmd == "lift":
        return admin.lift(args.source, args.reason, by=by, dry_run=not args.apply)
    if args.cmd == "purge":
        return admin.purge(args.owner, args.target, args.reason, by=by, dry_run=not args.apply)
    return admin.restamp(args.owner, args.reason, by=by, dry_run=not args.apply)


def main(argv: list[str]) -> int:
    args = _parser().parse_args(argv)
    try:
        out = _run(args)
    except OSError as exc:
        print(f"hnx agent memory {args.cmd}: {exc}", file=sys.stderr)
        return 2
    except (MemoryAdminError, MemoryAccessError, MemoryClockError, TypeError) as exc:
        print(f"hnx agent memory {args.cmd}: refused: {exc}", file=sys.stderr)
        return 1
    sys.stdout.write(json.dumps(out, indent=2, sort_keys=True) + "\n")
    return 0
