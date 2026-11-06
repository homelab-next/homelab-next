# SPDX-License-Identifier: Apache-2.0
"""``hnx records``: record identity (``assign-uids|numbers|uid``, :mod:`homelabnext.identity.cli`)
and the operator's records movers (``decide approve|deny|complete``,
:func:`homelabnext.records.decider.main`).

The decider is imported only when ``decide`` is asked for, so this router does not pull the
movers into a process that runs the identity subcommands; nothing in the agent API imports it."""

from __future__ import annotations

import importlib
import sys

HELP = (
    "usage: hnx records {assign-uids,numbers,uid,decide} ...\n"
    "  assign-uids|numbers|uid   record identity (ADR-0019)\n"
    "  decide approve|deny|complete NAME --root DIR --by WHO   the records movers "
    "(run as the decider's OS user)\n"
)


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args[:1] == ["decide"]:
        from . import decider  # operator side; exempted by name in the agent-isolation test

        return decider.main(args[1:])
    if args[:1] in (["-h"], ["--help"]):
        print(HELP, end="")
        return 0
    return importlib.import_module("homelabnext.identity.cli").main(args)
