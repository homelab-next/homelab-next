# SPDX-License-Identifier: Apache-2.0
"""``hnx golden``: run a golden suite against a model-role alias; check model pins (G-11).

``hnx golden pins check``  every binding is pinned, every role is evaluated, and the stored
                           evaluation report is current and passing (a fake report must also
                           reproduce exactly).  Exit 0 pass, 1 fail.
``hnx golden pins report`` (re)generate the evaluation report: against the deterministic fake by
                           default, or live (``--registry``) through the model-role resolver.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from homelabnext.registry import load as load_registry
from homelabnext.registry.models import ModelResolver, RoleTable

from .runner import client_completer, run_suite
from .tasks import load_suite


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="hnx golden", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    run = sub.add_parser("run", help="run SUITE.yml against an alias")
    run.add_argument("suite")
    run.add_argument("--registry", required=True)
    run.add_argument("--roles", required=True, help="model role table (JSON)")
    run.add_argument("--role", help="alias to test (default: the suite's role)")
    run.add_argument("--json", action="store_true")
    pins = sub.add_parser("pins", help="model pins and their evaluation report (G-11)")
    pins.add_argument("action", choices=("check", "report"))
    pins.add_argument("--roles", required=True, help="pinned model role table (JSON)")
    pins.add_argument("--report", required=True, help="evaluation report (JSON)")
    pins.add_argument("--suite", action="append", type=Path, help="golden suite (repeatable)")
    pins.add_argument("--registry", help="report: run live against this service registry")
    args = ap.parse_args(argv)
    if args.cmd == "pins":
        return _pins(args)
    suite = load_suite(args.suite)
    role = args.role or suite.role
    if not role:
        ap.error("no alias: pass --role or set 'role' in the suite")
    resolver = ModelResolver(load_registry(args.registry), RoleTable.load(args.roles))
    completer, model_id = client_completer(resolver, role)
    rep = run_suite(suite, completer, role=role, model_id=model_id)
    if args.json:
        print(json.dumps(rep.to_dict(timing=True), indent=2, sort_keys=True))
    else:
        print(rep.render_text(), end="")
    return 0 if rep.ok else 1


def _pins(args: argparse.Namespace) -> int:
    from . import pins

    table = RoleTable.load(args.roles)
    suites = args.suite or list(pins.DEFAULT_SUITES)
    if args.action == "report":
        if args.registry:
            factory, tiers, name = _live(args.registry, table)
            rep = pins.run_eval(table, suites, factory, model_name=name, replay_tiers=tiers)
        else:
            rep = pins.run_eval(table, suites, pins.fake_factory, model_name="fake-golden")
        pins.dump_report(rep, args.report)
        print(f"golden pins: wrote {args.report} (ok={rep['summary']['ok']})")
        return 0 if rep["summary"]["ok"] else 1
    try:
        stored = pins.load_report(args.report)
    except (OSError, ValueError) as exc:
        print(f"golden pins: cannot read {args.report}: {exc}", file=sys.stderr)
        return 1
    problems = pins.check_report(stored, table, suites)
    model = stored.get("model", {}).get("name") if isinstance(stored, dict) else None
    if not problems and model == "fake-golden":
        fresh = pins.run_eval(table, suites, pins.fake_factory, model_name="fake-golden")
        if fresh != stored:
            problems.append("stored fake report does not reproduce; regenerate it")
    for p in problems:
        print(f"golden pins: {p}")
    print(f"golden pins: {len(table.roles)} role(s), {len(problems)} problem(s)")
    return 1 if problems else 0


def _live(registry: str, table: RoleTable):  # pragma: no cover - needs a real model server
    from homelabnext.decide.evalset import EXAMPLES
    from homelabnext.decide.spec import LABELS, load_spec
    from homelabnext.decide.tiers import ModelTier
    from homelabnext.registry.models import ModelClient

    resolver = ModelResolver(load_registry(registry), table)
    spec = load_spec(EXAMPLES / "decision_spec.yml")
    tiers = {}
    for t in spec.tiers:
        if t.model_role:
            client = ModelClient(resolver.resolve(t.model_role))
            tiers[t.name] = ModelTier(
                t.name, lambda m, c=client: c.chat(m), spec.question_set, LABELS
            )
    return (lambda role: client_completer(resolver, role)), tiers, "live"


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
