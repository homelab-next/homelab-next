# SPDX-License-Identifier: Apache-2.0
"""``hnx swap``: plan, start, status, advance, rollback, record.

Exit codes: 0 success, 1 a gate refused / the record is invalid / a rollback was refused,
2 usage or I/O error.

``advance`` and ``rollback`` use the :class:`ManualBackend`: gates that need a real system are
satisfied by attestation files (``--attest parity=parity.json``, JSON containing ``"ok": true``)
whose hashes go into the evidence; the registry flip and the decommission scan are real.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import record as rec
from .backend import ManualBackend
from .decommission import Retired, load_allow, retired_from_record
from .flip import FlipError, load_doc, plan_flip
from .machine import GateFailed, RollbackRefused, SwapError, SwapRunner, plan_text

USAGE = """usage: hnx swap {plan,start,status,advance,rollback,record} ...

  plan [--record R] [--registry REG --service S --to-host H ...]   show the nine steps (and the flip)
  start --record R --capability cap:X --from A --to B --service S --registry REG --to-host H ...
  status R                                  one-screen state of a swap record
  advance R [--dry-run] [--attest NAME=FILE ...] [--scan-root DIR ...] [--adr docs/adr/NNNN-x.md]
  rollback R --reason TEXT                  restore the prior route (any step before decommission)
  record R [--verify] [--note TEXT] [--anchor SEQ:HASH]
                                            validate a record, show its transition log and head
"""


def _now(args: argparse.Namespace):
    if getattr(args, "now", None):
        t = datetime.fromisoformat(args.now.replace("Z", "+00:00"))
        if t.tzinfo is None:
            raise SystemExit("hnx swap: --now needs a UTC offset")
        return lambda: t
    return lambda: datetime.now(UTC)  # hermetic: allow CLI edge: real clock unless --now


def _add_target(p: argparse.ArgumentParser) -> None:
    p.add_argument("--registry", help="registry YAML holding the service row")
    p.add_argument("--service", help="registry service key to retarget")
    p.add_argument("--to-host")
    p.add_argument("--to-port", type=int)
    p.add_argument("--to-impl")
    p.add_argument("--to-version")


def _add_backend(p: argparse.ArgumentParser) -> None:
    p.add_argument("--attest", action="append", default=[], metavar="NAME=FILE")
    p.add_argument("--registry", help="override the registry path stored in the record")
    p.add_argument("--scan-root", action="append", default=[])
    p.add_argument("--inventory", action="append", default=[])
    p.add_argument("--allow", action="append", default=[], help="file of allow globs")
    for opt in ("host", "alias", "env-var", "unit", "word"):
        p.add_argument(f"--retired-{opt}", action="append", default=[])
    p.add_argument("--now", help="override the clock (RFC 3339 with offset), for rehearsals")
    p.add_argument("--actor", default="operator")
    p.add_argument("--evidence-dir")


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="hnx swap", add_help=True)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("plan")
    p.add_argument("--record")
    _add_target(p)

    p = sub.add_parser("start")
    p.add_argument("--record", required=True)
    p.add_argument("--capability", required=True)
    p.add_argument("--from", dest="from_adapter", required=True)
    p.add_argument("--to", dest="to_adapter", required=True)
    p.add_argument("--swap-id")
    p.add_argument("--soak-hours", type=float, default=168)
    p.add_argument("--rollback-window-hours", type=float, default=168)
    p.add_argument("--max-divergences", type=int, default=0)
    p.add_argument("--min-parity-rows", type=int, default=1)
    p.add_argument("--evidence-dir")
    p.add_argument("--actor", default="operator")
    p.add_argument("--now")
    _add_target(p)

    p = sub.add_parser("status")
    p.add_argument("record")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("advance")
    p.add_argument("record")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--adr")
    p.add_argument("--lesson")
    _add_backend(p)

    p = sub.add_parser("rollback")
    p.add_argument("record")
    p.add_argument("--reason", required=True)
    _add_backend(p)

    p = sub.add_parser("record")
    p.add_argument("record")
    p.add_argument("--verify", action="store_true")
    p.add_argument("--note")
    p.add_argument("--json", action="store_true")
    p.add_argument("--actor", default="operator")
    p.add_argument("--now")
    p.add_argument("--evidence-dir")
    p.add_argument("--anchor", help="SEQ:HASH from an earlier `head`, stored outside the record")
    return ap


def _endpoint(row: dict[str, Any]) -> dict[str, Any]:
    out = {"host": row["host"], "port": row["port"]}
    for k in ("impl", "version"):
        if row.get(k):
            out[k] = row[k]
    return out


def _backend(args: argparse.Namespace, doc: dict[str, Any], rec_path: Path) -> ManualBackend:
    attest = {}
    for a in args.attest:
        name, _, f = a.partition("=")
        if not f:
            raise SystemExit(f"hnx swap: --attest wants NAME=FILE, got {a!r}")
        attest[name] = f
    reg = args.registry or doc["route"].get("registry")
    reg_path = None
    if reg:
        reg_path = Path(reg)
        if not reg_path.is_absolute() and not reg_path.exists():
            reg_path = rec_path.parent / reg
    base = retired_from_record(doc)
    retired = Retired(
        base.name,
        tuple(args.retired_host),
        base.impls,
        tuple(args.retired_alias),
        tuple(args.retired_env_var),
        tuple(args.retired_unit),
        tuple(args.retired_word),
    )
    allow: list[str] = []
    for a in args.allow:
        allow += load_allow(a)
    return ManualBackend(
        attestations=attest,
        registry=reg_path,
        service=doc["service"],
        scan_roots=args.scan_root,
        retired=retired,
        allow=allow,
        inventory=args.inventory,
    )


def _runner(args: argparse.Namespace) -> SwapRunner:
    path = Path(args.record)
    doc = rec.load(path)
    return SwapRunner(
        path,
        _backend(args, doc, path),
        evidence_dir=args.evidence_dir,
        clock=_now(args),
        actor=args.actor,
    )


def _print_gates(gates) -> None:
    for g in gates:
        print(
            f"  [{'ok' if g.passed else 'FAIL'}] {g.phase}:{g.id}"
            + (f" - {g.detail}" if g.detail else "")
        )


def _cmd_plan(args: argparse.Namespace) -> int:
    doc = rec.load(args.record) if args.record else None
    print(plan_text(doc), end="")
    if (
        args.registry
        and args.service
        and any((args.to_host, args.to_port, args.to_impl, args.to_version))
    ):
        plan = plan_flip(
            load_doc(Path(args.registry).read_text(encoding="utf-8")),
            args.service,
            host=args.to_host,
            port=args.to_port,
            impl=args.to_impl,
            version=args.to_version,
        )
        print(
            "\ncutover flip:\n" + plan.diff() + "rollback (inverse):\n" + plan.inverse().diff(),
            end="",
        )
    return 0


def _cmd_start(args: argparse.Namespace) -> int:
    if not (args.registry and args.service):
        raise SystemExit("hnx swap start: --registry and --service are required")
    doc = load_doc(Path(args.registry).read_text(encoding="utf-8"))
    plan = plan_flip(
        doc,
        args.service,
        host=args.to_host,
        port=args.to_port,
        impl=args.to_impl,
        version=args.to_version,
    )
    if plan.empty:
        print(
            "hnx swap start: the target equals the current route; nothing to flip", file=sys.stderr
        )
        return 1
    before = _endpoint(doc["services"][args.service])
    after = dict(before)
    for c in plan.changes:
        after[c.path.rsplit(".", 1)[1]] = c.after
    clock = _now(args)
    swap_id = args.swap_id or f"swap-{args.capability.split(':', 1)[1]}-{clock():%Y%m%d}"
    SwapRunner.create(
        args.record,
        ManualBackend(),
        swap_id=swap_id,
        capability=args.capability,
        from_adapter=args.from_adapter,
        to_adapter=args.to_adapter,
        service=args.service,
        before=before,
        after=after,
        plan={
            "soak_hours": args.soak_hours,
            "rollback_window_hours": args.rollback_window_hours,
            "max_divergences": args.max_divergences,
            "min_parity_rows": args.min_parity_rows,
        },
        registry=args.registry,
        evidence_dir=args.evidence_dir,
        clock=clock,
        actor=args.actor,
    )
    print(f"declared {swap_id} -> {args.record}\n" + plan.diff(), end="")
    return 0


def _cmd_status(args: argparse.Namespace) -> int:
    doc = rec.load(args.record)
    if args.json:
        print(
            json.dumps(
                {
                    "swap_id": doc["swap_id"],
                    "status": doc["status"],
                    "current_step": doc["current_step"],
                    "flipped": doc["route"]["flipped"],
                    "steps": {s["name"]: s["status"] for s in doc["steps"]},
                },
                indent=2,
            )
        )
        return 0
    print(f"{doc['swap_id']}  {doc['capability']}  {doc['from_adapter']} -> {doc['to_adapter']}")
    print(
        f"status: {doc['status']}   current step: {doc['current_step']}   flipped: {doc['route']['flipped']}"
    )
    for i, s in enumerate(doc["steps"], 1):
        print(f"  {i}. {s['name']:<19} {s['status']:<8} attempts={s['attempts']}")
    if doc["rollback"]:
        print(f"rolled back from {doc['rollback']['from_step']}: {doc['rollback']['reason']}")
    return 0


def _cmd_advance(args: argparse.Namespace) -> int:
    runner = _runner(args)
    closure = {"adr_ref": args.adr, "lesson_ref": args.lesson}
    try:
        res = runner.advance(dry_run=args.dry_run, closure=closure)
    except GateFailed as exc:
        print(f"REFUSED step {exc.result.step}:")
        _print_gates(exc.result.gates)
        if exc.result.reverted:
            print("  the previous route was restored")
        return 1
    if res.dry_run:
        print(f"dry run: step {res.step} pre-conditions {'pass' if res.passed else 'FAIL'}")
        _print_gates(res.gates)
        for line in res.plan:
            print(f"  {line}")
        return 0 if res.passed else 1
    print(f"step {res.step} passed; next: {res.next_step or 'swap closed'}")
    _print_gates(res.gates)
    print(f"  evidence: {res.evidence_ref}")
    return 0


def _cmd_rollback(args: argparse.Namespace) -> int:
    runner = _runner(args)
    try:
        doc = runner.rollback(args.reason)
    except RollbackRefused as exc:
        print(f"ROLLBACK REFUSED: {exc}", file=sys.stderr)
        return 1
    print(
        f"rolled back from {doc['rollback']['from_step']}; route restored: {doc['rollback']['restored_route']}"
    )
    for a in doc["rollback"]["actions"]:
        print(f"  {a}")
    return 0


def _cmd_record(args: argparse.Namespace) -> int:
    path = Path(args.record)
    try:
        doc = rec.load(path)
    except rec.RecordError as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return 1
    if args.note:
        SwapRunner(path, ManualBackend(), clock=_now(args), actor=args.actor).note(args.note)
        doc = rec.load(path)
    bad: list[str] = []
    if args.verify:
        ev = (
            Path(args.evidence_dir)
            if args.evidence_dir
            else path.parent / (doc["swap_id"] + ".evidence")
        )
        bad = rec.verify_evidence(doc, ev)
    if args.anchor:
        seq, _, want = args.anchor.partition(":")
        if not seq.isdigit() or not want:
            raise SystemExit("--anchor must be SEQ:HASH (as printed after 'head:')")
        bad += rec.verify_anchor(doc, {"seq": int(seq), "hash": want})
    if args.json:
        print(rec.dumps(doc), end="")
    else:
        keyed = (doc.get("chain") or {}).get("alg") == "hmac-sha256"
        print(
            f"{doc['swap_id']}: valid ({len(doc['transitions'])} transitions, "
            f"{'keyed ' if keyed else ''}hash chain consistent)"
        )
        h = rec.head(doc)
        print(f"  head: {h['seq']}:{h['hash']}")
        for t in doc["transitions"]:
            print(
                f"  {t['seq']:>3} {t['at']} {t['event']:<16} {t['step'] or '-':<19} {t['note'][:70]}"
            )
    for b in bad:
        print(f"{'ANCHOR' if b.startswith('anchor:') else 'EVIDENCE'}: {b}", file=sys.stderr)
    return 1 if bad else 0


def main(argv: list[str] | None = None) -> int:
    args_in = list(sys.argv[1:] if argv is None else argv)
    if not args_in or args_in[0] in ("-h", "--help"):
        print(USAGE, end="")
        return 0 if args_in else 2
    try:
        args = _parser().parse_args(args_in)
        handler = {
            "plan": _cmd_plan,
            "start": _cmd_start,
            "status": _cmd_status,
            "advance": _cmd_advance,
            "rollback": _cmd_rollback,
            "record": _cmd_record,
        }[args.cmd]
        return handler(args)
    except SystemExit as exc:
        if isinstance(exc.code, str):
            print(exc.code, file=sys.stderr)
            return 2
        return int(exc.code or 0)
    except rec.RecordError as exc:
        print(f"INVALID RECORD: {exc}", file=sys.stderr)
        return 1
    except (FlipError, SwapError, OSError) as exc:
        print(f"hnx swap: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
