# SPDX-License-Identifier: Apache-2.0
"""python -m homelabnext.invariants run REGISTER [--root DIR] [--out FILE] [--only A-01,B-02]
[--skip C-01,D-02] [--fast] [--plugins-dir DIR] [--state FILE --notify-cmd CMD | --no-notify]
[--notify-ceiling LABEL] [--baseline]

A page is a notification channel, an egress point (ADR-0033 decision 13): every page goes through
``homelabnext.notify.CeilingSender`` at ``--notify-ceiling`` (default ``red``).  A page carries
criterion evidence, lab data that is ``red`` by default (decision 2), so on a channel below
``red`` it arrives as the fixed withheld notice.
"""

import argparse
import json
import pathlib
import subprocess
import sys

import yaml

from ..notify.ceiling import CeilingSender, ceiling_arg
from ..notify.core import Message
from ..registers.schema import RegisterError, validate_invariants
from . import Context, default_registry, load_directory, load_entry_points, overall_exit
from .runner import page_changes, run_criteria


class _CommandSender:
    """``--notify-cmd`` as a ``notify.Sender``: the command gets TITLE and BODY as argv."""

    def __init__(self, cmd: str) -> None:
        self.argv = cmd.split()

    def send(self, message: Message) -> None:
        subprocess.run([*self.argv, message.title, message.body], check=True)


class _PrintSender:
    def send(self, message: Message) -> None:
        print(f"[page] {message.title}\n{message.body}")


def pager(sender, ceiling):
    """The ``page_changes`` callable: each page a ``Message`` (no claimed label, so ``red``)
    through a :class:`CeilingSender` at ``ceiling``."""
    gate = CeilingSender(sender, ceiling)

    def send(title: str, body: str) -> None:
        recovered = title == "Invariant recovered"
        gate.send(
            Message(
                key="invariants:recovered" if recovered else "invariants:newly-broken",
                title=title,
                body=body,
                level="info" if recovered else "crit",
                tags=("recovered",) if recovered else (),
            )
        )

    return send


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="hnx invariants")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("register")
    r.add_argument("--root", default=".")
    r.add_argument("--out", help="results JSON (default: next to the register)")
    r.add_argument("--only")
    r.add_argument(
        "--skip",
        help="criteria not to run this time (e.g. a main-only property on a pull request)",
    )
    r.add_argument("--fast", action="store_true")
    r.add_argument("--plugins-dir")
    r.add_argument("--state", help="state file for state-diffed paging")
    r.add_argument("--notify-cmd", help="command receiving TITLE and BODY as argv[1], argv[2]")
    r.add_argument("--no-notify", action="store_true")
    r.add_argument(
        "--notify-ceiling",
        type=ceiling_arg,
        default=None,
        metavar="LABEL",
        help="the page channel's TLP ceiling (default red); a page above it is withheld",
    )
    r.add_argument("--baseline", action="store_true", help="record state without paging")
    ns = ap.parse_args(argv)
    reg_path = pathlib.Path(ns.register)
    # a register that is missing or does not parse is bad input (2), never a failed fleet (1)
    try:
        raw = yaml.safe_load(reg_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as ex:
        print(f"[invariants] FATAL: cannot read register {reg_path}: {ex}", file=sys.stderr)
        return 2
    try:
        reg = validate_invariants(raw)
    except RegisterError as ex:
        print(f"[invariants] FATAL: {ex}", file=sys.stderr)
        return 2
    registry = default_registry()
    load_entry_points(registry)
    if ns.plugins_dir:
        load_directory(registry, ns.plugins_dir)
    out = pathlib.Path(ns.out) if ns.out else reg_path.with_name("invariants.results.json")
    try:  # the last results: a truncated file (a full disk, a killed run) is bad input too
        previous = json.loads(out.read_text(encoding="utf-8")) if out.exists() else None
    except (OSError, UnicodeDecodeError, ValueError) as ex:
        print(f"[invariants] FATAL: cannot read previous results {out}: {ex}", file=sys.stderr)
        return 2
    skip = set(ns.skip.split(",")) if ns.skip else set()
    only = set(ns.only.split(",")) if ns.only else None
    doc = run_criteria(
        reg["criteria"],
        Context(ns.root),
        registry,
        only=only,
        fast=ns.fast,
        previous=previous,
        skip=skip,
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
    for i, x in sorted(doc["results"].items()):
        print(f"{x['status']:5s} {i}  {x['evidence'][:100]!r}")
    if ns.state and not ns.no_notify:
        sender = _CommandSender(ns.notify_cmd) if ns.notify_cmd else _PrintSender()
        ceiling = ns.notify_ceiling if ns.notify_ceiling is not None else ceiling_arg("red")
        page_changes(doc, ns.state, pager(sender, ceiling), baseline=ns.baseline)
    # carried-over results of criteria not run this time do not decide the exit code
    return overall_exit(doc, only - skip if only else None)


if __name__ == "__main__":
    sys.exit(main())
