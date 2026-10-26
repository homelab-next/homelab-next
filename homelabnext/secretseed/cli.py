# SPDX-License-Identifier: Apache-2.0
"""``hnx secrets``: list the credentials a lab names, and create the missing ones.

    hnx secrets plan PATH... [--spec lab/secrets.yml] [--json]
    hnx secrets seed PATH... --spec lab/secrets.yml [--vaultwarden] [--ask]
                     [--from-file NAME=FILE ...] [--dry-run] [--yes]

``plan`` reads files only.  ``seed`` writes to OpenBao as the operator (``BAO_ADDR``,
``BAO_TOKEN``, ``BAO_CACERT``) and, with ``--vaultwarden``, to the folder the spec names through
an unlocked ``bw`` (``BW_SESSION``).  Both print names and outcomes, never a value.

``seed`` exits 0 when every secret exists, 1 on any error, and 3 when some still need a value
(an external one not given, or a name no rule classifies), so a bootstrap script cannot mistake an
unfinished run for a finished one.
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from . import (
    NAME,
    UNCLASSIFIED,
    OpenBaoKV,
    Rule,
    SeedError,
    Spec,
    Vaultwarden,
    load_spec,
    scan,
    seed,
)

#: the most a --from-file value may be (a kubeconfig or a key, not a disk image)
MAX_FILE = 64 * 1024


def _ask(name: str, rule: Rule) -> str:
    print(f"secret:{name} is external: {rule.how}", file=sys.stderr)
    value = getpass.getpass(f"value for secret:{name} (empty to skip): ")
    return value if value.strip() else ""


def _given(pairs: Sequence[str]) -> dict[str, str]:
    out = {}
    for pair in pairs:
        name, sep, path = pair.partition("=")
        name = name.removeprefix("secret:")
        if not sep or not NAME.match(name) or not path:
            raise SeedError(f"--from-file {pair!r}: expected NAME=FILE")
        p = Path(path)
        try:
            if p.stat().st_size > MAX_FILE:
                raise SeedError(f"--from-file {name}: {p} is larger than {MAX_FILE} bytes")
            text = p.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise SeedError(
                f"--from-file {name}: cannot read {p}: {exc.__class__.__name__}"
            ) from None
        if not text.strip():
            raise SeedError(f"--from-file {name}: {p} is empty")
        out[name] = text
    return out


def _confirm(n: int, where: str, yes: bool) -> bool:
    if yes:
        return True
    if not sys.stdin.isatty():
        print("hnx secrets: not a terminal: pass --yes to write without asking", file=sys.stderr)
        return False
    answer = input(f"write {n} new secret(s) to {where}? [y/N] ")
    return answer.strip().lower() in ("y", "yes")


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="hnx secrets", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    pl = sub.add_parser("plan", help="list every secret:<name> the files name, and its kind")
    sd = sub.add_parser("seed", help="create the missing secrets in OpenBao (and Vaultwarden)")
    for p in (pl, sd):
        p.add_argument("paths", nargs="+", help="the overlay and the roles you deploy")
    pl.add_argument("--spec", help="secrets.yml: how each name gets its value")
    pl.add_argument("--json", action="store_true")
    sd.add_argument("--spec", required=True, help="secrets.yml: how each name gets its value")
    sd.add_argument("--vaultwarden", action="store_true", help="also copy into Vaultwarden (bw)")
    sd.add_argument("--ask", action="store_true", help="prompt for each missing external secret")
    sd.add_argument(
        "--from-file", action="append", default=[], metavar="NAME=FILE",
        help="the value of NAME is FILE's contents (a key, a kubeconfig); repeatable",
    )  # fmt: skip
    sd.add_argument("--dry-run", action="store_true", help="read only: write nothing anywhere")
    sd.add_argument("--yes", action="store_true", help="write without asking")
    args = ap.parse_args(argv)
    try:
        spec = load_spec(args.spec) if args.spec else Spec()
        found = scan(args.paths)
        for name in spec.also:
            found.setdefault(name, ["the spec's also"])
        found = dict(sorted(found.items()))
        if args.cmd == "plan":
            return _plan(found, spec, args.json)
        given = _given(args.from_file)
        if args.ask and not sys.stdin.isatty():
            print("hnx secrets: --ask needs a terminal; external values are left", file=sys.stderr)
            args.ask = False
        bao = OpenBaoKV.from_env()
        names = list(found)
        if not args.dry_run:
            preview = seed(names, spec, bao, dry_run=True, given=given)
            pending = sum(1 for o in preview if o.openbao == "would-create")
            pending += sum(1 for o in preview if o.openbao == "needs-value") if args.ask else 0
            if pending and not _confirm(pending, bao.base, args.yes):
                return 1
        vault = (
            Vaultwarden(spec.vaultwarden_folder, dry_run=args.dry_run) if args.vaultwarden else None
        )
        out = seed(
            names, spec, bao, vault, dry_run=args.dry_run, ask=_ask if args.ask else None,
            given=given,
        )  # fmt: skip
    except SeedError as exc:
        print(f"hnx secrets: {exc}", file=sys.stderr)
        return 2
    for o in out:
        line = f"{o.openbao:<12} {o.vaultwarden:<12} {o.kind:<12} secret:{o.name}"
        print(line + (f"  {o.detail}" if o.detail else ""))
    errors = sum(1 for o in out if "error" in (o.openbao, o.vaultwarden))
    owed = sum(1 for o in out if o.openbao in ("needs-value", UNCLASSIFIED))
    print(f"{len(out)} secret(s); {errors} error(s); {owed} still need a value or a rule")
    if errors:
        return 1
    return 3 if owed and not args.dry_run else 0


def _plan(found: dict[str, list[str]], spec: Spec, as_json: bool) -> int:
    rows = [
        {
            "name": n,
            "kind": spec.rule(n).kind,
            "by": "rule" if spec.matched(n) else ("default" if spec.default else "none"),
            "named_in": where,
        }
        for n, where in found.items()
    ]
    if as_json:
        print(json.dumps(rows, indent=2))
        return 0
    for r in rows:
        more = len(r["named_in"]) - 1
        also = f" and {more} more" if more else ""
        mark = " (default)" if r["by"] == "default" else ""
        print(f"{r['kind']:<12} secret:{r['name']}{mark}  ({r['named_in'][0]}{also})")
    unclassified = sum(1 for r in rows if r["kind"] == UNCLASSIFIED)
    print(f"{len(rows)} secret(s); {unclassified} unclassified (add a rule; never generated)")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
