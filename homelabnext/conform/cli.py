# SPDX-License-Identifier: Apache-2.0
"""``hnx conform``: list suites, run one against a target, export the coverage report.

    hnx conform list [--all] [--json]      (also: hnx conform --list)
    hnx conform run CAPABILITY|all [--target NAME] [--check ID ...] [--strict] [--json] [--out FILE]
    hnx conform mutants [CAPABILITY|all] [--all] [--json]   (--all: the extended suites too)
    hnx conform report [--target NAME] [--json] [--out FILE] [--no-mutants]

Exit codes: 0 ok, 1 a check failed, too few checks executed (or a capability has no passing
test), 2 misconfiguration (including an unknown ``--check`` id), 100 the run could not be
measured (a subject could not be built).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .registry import CAPABILITIES, EXTENDED, ConformError, load_suite, names
from .report import build_report, render_human
from .runner import CapabilityRun, mutation_runs, run_capability

__all__ = ["main"]


def _print_json(doc: Any) -> None:
    print(json.dumps(doc, indent=2, sort_keys=True))


def _cmd_list(args: argparse.Namespace) -> int:
    rows = []
    for cap in names(args.all):
        row: dict[str, Any] = {
            "capability": cap,
            "tier": "core" if cap in CAPABILITIES else "extended",
        }
        try:
            suite = load_suite(cap, args.root)
            row["summary"] = suite.summary
            row["checks"] = {
                "must": sum(s.severity == "must" for s in suite.specs),
                "should": sum(s.severity == "should" for s in suite.specs),
            }
        except ConformError as exc:
            row["error"] = str(exc)
        rows.append(row)
    if args.json:
        _print_json({"capabilities": rows})
    else:
        for row in rows:
            c = row.get("checks")
            n = f"{c['must']}+{c['should']} checks" if c else "no suite"
            print(f"{row['capability']:<18} {n:<14} {row.get('summary', row.get('error', ''))}")
    return 0


def _human_run(run: CapabilityRun, verbose: bool) -> str:
    # could-not-measure (exit 100) is neither a pass nor a failure (docs/conformance.md)
    verdict = "COULD NOT MEASURE" if run.error else ("PASS" if run.ok else "FAIL")
    lines = [f"{verdict}  {run.capability}  target={run.target}  {len(run.executed)} executed"]
    if run.error:
        lines.append(f"  ERROR {run.error}")
    if run.too_few:
        lines.append(f"  FAIL {run.too_few}")
    for r in run.results:
        if r.status == "pass" and not verbose:
            continue
        tag = {
            "pass": "ok",
            "fail": "FAIL",
            "skip": "skip",
            "waived": "waived",
            "untested": "UNTESTED",
        }[r.status]
        sev = "" if r.severity == "must" else " (should)"
        lines.append(f"  [{tag}] {r.check}{sev}: {r.evidence}")
    return "\n".join(lines)


def _cmd_run(args: argparse.Namespace) -> int:
    caps = list(CAPABILITIES) if args.capability == "all" else [args.capability]
    selection: dict[str, list[str] | None] = dict.fromkeys(caps)
    if args.check:
        wanted = list(dict.fromkeys(args.check))
        known = {c: set(load_suite(c, args.root).ids()) for c in caps}
        unknown = [i for i in wanted if not any(i in ids for ids in known.values())]
        if unknown:
            raise ConformError(f"unknown check id(s) for {args.capability}: {', '.join(unknown)}")
        selection = {c: [i for i in wanted if i in known[c]] for c in caps}
        selection = {c: ids for c, ids in selection.items() if ids}
    runs = [run_capability(c, args.target, args.root, only=ids) for c, ids in selection.items()]
    if args.json or args.out:
        doc = {"target": args.target, "runs": [r.to_dict() for r in runs]}
        if args.out:
            Path(args.out).write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
        if args.json:
            _print_json(doc)
    if not args.json:
        for r in runs:
            print(_human_run(r, args.verbose))
    failed = any(not (r.ok_strict() if args.strict else r.ok) for r in runs if r.error is None)
    if failed:
        return 1
    return 100 if any(r.error for r in runs) else 0


def _cmd_mutants(args: argparse.Namespace) -> int:
    if args.all and args.capability not in (None, "all"):
        raise ConformError("--all runs every suite; name no capability with it")
    if args.capability in (None, "all"):
        caps = [*CAPABILITIES, *(EXTENDED if args.all else ())]
    else:
        caps = [args.capability]
    rows = [m for c in caps for m in mutation_runs(c, args.root)]
    if args.json:
        _print_json(
            {
                "mutants": [
                    {
                        "capability": m.capability,
                        "name": m.name,
                        "expected_check": m.expected,
                        "failed": m.failed,
                        "detected": m.detected,
                    }
                    for m in rows
                ]
            }
        )
    else:
        for m in rows:
            print(
                f"{'caught' if m.detected else 'MISSED'}  {m.capability}/{m.name}: "
                f"expected {m.expected!r}, failed {m.failed or 'nothing'}"
            )
    return 0 if all(m.detected for m in rows) else 1


def _cmd_report(args: argparse.Namespace) -> int:
    rep = build_report(args.root, args.target, mutants=False if args.no_mutants else None)
    if args.out:
        Path(args.out).write_text(json.dumps(rep, indent=2, sort_keys=True) + "\n")
    if args.json:
        _print_json(rep)
    else:
        print(render_human(rep))
    if rep["capabilities_without_passing_test"]:
        return 100 if rep["measurement_errors"] and not _any_fail(rep) else 1
    return 0


def _any_fail(rep: dict[str, Any]) -> bool:
    return any(e.get("failed_must") for e in rep["capabilities"].values())


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="hnx conform", description="Capability conformance harness.")
    p.add_argument("--root", help="source checkout holding conformance/ (default: this checkout)")
    sub = p.add_subparsers(dest="cmd", required=True)
    ls = sub.add_parser("list", help="list capability suites")
    ls.add_argument("--all", action="store_true", help="include extended (non-core) suites")
    ls.add_argument("--json", action="store_true")
    rn = sub.add_parser("run", help="run a suite against a target")
    rn.add_argument("capability", help="a capability name, or 'all'")
    rn.add_argument("--target", default="fake", help="fake | broken[:MUTANT] | file or name")
    rn.add_argument("--check", action="append", help="run only this check id (repeatable)")
    rn.add_argument("--strict", action="store_true", help="a failing SHOULD check fails the run")
    rn.add_argument("--json", action="store_true")
    rn.add_argument("--out", help="also write the JSON result to this file")
    rn.add_argument("-v", "--verbose", action="store_true", help="show passing checks too")
    mu = sub.add_parser("mutants", help="prove the suites catch their deliberately broken fakes")
    mu.add_argument("capability", nargs="?", help="a capability name or 'all' (default)")
    mu.add_argument("--all", action="store_true", help="the extended suites too")
    mu.add_argument("--json", action="store_true")
    rp = sub.add_parser("report", help="capabilities without a passing conformance test")
    rp.add_argument("--target", default="fake")
    rp.add_argument("--json", action="store_true")
    rp.add_argument("--out", help="also write the JSON report to this file")
    rp.add_argument("--no-mutants", action="store_true", help="skip the mutation requirement")
    return p


def main(argv: list[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    if raw[:1] == ["--list"]:  # the spelling used in docs/interfaces.md
        raw[0] = "list"
    args = _parser().parse_args(raw)
    handler = {"list": _cmd_list, "run": _cmd_run, "mutants": _cmd_mutants, "report": _cmd_report}
    try:
        return handler[args.cmd](args)
    except ConformError as exc:
        print(f"hnx conform: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
