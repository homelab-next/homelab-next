# SPDX-License-Identifier: Apache-2.0
"""``hnx golden``: run a golden suite against a model-role alias; check model pins (G-11).

``hnx golden pins check``  every binding is pinned, every role is evaluated, and the stored
                           evaluation report is current and passing, with a valid egress canary
                           for every binding (a fake report must also reproduce exactly);
                           ``--require-live`` also fails a canary that ran against the fake,
                           and without it a table other than the shipped example whose
                           canaries are all fake fails.
                           Exit 0 pass, 1 fail.
``hnx golden pins report`` (re)generate the evaluation report: against the deterministic fake by
                           default, or live (``--registry``) through the model-role resolver.
``hnx golden codemode``    the Code Mode golden suites (CM-6): every task in classic MCP mode and
                           in Code Mode, the G-02 corpus inside tool results, against the scripted
                           fake model behind the fake inference server and the fake broker world;
                           ``--check REPORT`` fails unless the committed report is current and
                           passing, ``--out REPORT`` (re)writes it.  Exit 0 pass, 1 fail.
``hnx golden canary``      the egress canary (docs/compute-model.md, "The egress canary"): live
                           against every binding of a role (``--registry`` and ``--roles``), or
                           against a scripted fake (``--fake benign|incident``).  Exit 0 pass,
                           1 a finding, 2 usage.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

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
    pins.add_argument(
        "--require-live",
        action="store_true",
        help="check: fail a canary entry that ran against the fake (an overlay with real models)",
    )
    cm = sub.add_parser(
        "codemode", help="Code Mode vs classic MCP mode suites against the fakes (CM-6)"
    )
    cm.add_argument("--suite", action="append", type=Path, help="tool-using suite (repeatable)")
    cm.add_argument("--fake", choices=("fence", "naive"), default="fence")
    out = cm.add_mutually_exclusive_group()
    out.add_argument("--out", type=Path, help="write the report here")
    out.add_argument("--check", type=Path, help="fail unless this committed report is current")
    cm.add_argument(
        "--in-process", action="store_true", help="call the fake model directly, not over HTTP"
    )
    cm.add_argument("--json", action="store_true", help="print the report as JSON")
    can = sub.add_parser("canary", help="the egress canary against a role or a scripted fake")
    can.add_argument("--suite", type=Path, help="canary suite (default: the shipped one)")
    can.add_argument("--role", help="role to test (live)")
    can.add_argument("--registry", help="service registry (live)")
    can.add_argument("--roles", help="model role table (JSON, live)")
    can.add_argument("--fake", choices=("benign", "incident"), help="a scripted fake model")
    can.add_argument("--samples", type=int, help="samples per task (default: the suite's)")
    can.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    if args.cmd == "canary":
        return _canary(args)
    if args.cmd == "pins":
        return _pins(args)
    if args.cmd == "codemode":
        return _codemode(args)
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
            factory, tiers, canary_for, name = _live(args.registry, table)
            rep = pins.run_eval(
                table,
                suites,
                factory,
                model_name=name,
                replay_tiers=tiers,
                canary_factory=canary_for,
            )
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
    problems = pins.check_report(stored, table, suites, require_live=args.require_live)
    if not args.require_live and (guard := pins.fake_canary_on_a_real_table(stored, table)):
        problems.append(guard)
    model = stored.get("model", {}).get("name") if isinstance(stored, dict) else None
    if not problems and model == "fake-golden":
        fresh = pins.run_eval(table, suites, pins.fake_factory, model_name="fake-golden")
        if fresh != stored:
            problems.append("stored fake report does not reproduce; regenerate it")
    for p in problems:
        print(f"golden pins: {p}")
    print(f"golden pins: {len(table.roles)} role(s), {len(problems)} problem(s)")
    return 1 if problems else 0


def _canary(args: argparse.Namespace) -> int:
    from . import canary

    live = (args.role, args.registry, args.roles)
    if bool(args.fake) == any(live) or (not args.fake and not all(live)):
        print(
            "golden canary: pass --fake benign|incident, or --role, --registry and --roles",
            file=sys.stderr,
        )
        return 2
    try:
        suite = canary.load_suite(args.suite or canary.DEFAULT_SUITE)
    except (OSError, ValueError) as exc:
        print(f"golden canary: {exc}", file=sys.stderr)
        return 2
    runs: list[tuple[Any, str, str]] = []
    if args.fake:
        completer: Any = canary.IncidentModel() if args.fake == "incident" else canary.benign_model
        runs.append((completer, "fake", f"fake-{args.fake}"))
    else:  # pragma: no cover - needs a real model server
        table = RoleTable.load(args.roles)
        resolver = ModelResolver(load_registry(args.registry), table)
        canary_for = _binding_completer(resolver)
        for b in table.get(args.role).bindings:  # every binding, not the first that resolves
            runs.append((canary_for(args.role, b)[0], args.role, b.model_id))
    reports = []
    try:
        for completer, role, model_id in runs:
            reports.append(
                canary.run_canary(
                    suite, completer, role=role, model_id=model_id, samples=args.samples
                )
            )
    except canary.CanaryError as exc:
        print(f"golden canary: {exc}", file=sys.stderr)
        return 2
    if args.json:
        doc: Any = reports[0] if len(reports) == 1 else reports
        print(json.dumps(doc, indent=2, sort_keys=True))
    else:
        for rep in reports:
            print(canary.render_report(rep), end="")
    return 0 if all(r["summary"]["ok"] for r in reports) else 1


def _binding_completer(resolver: ModelResolver):  # pragma: no cover - needs a real model server
    """``(role, binding) -> (completer, "live")``: the canary's completer for one binding, which
    returns the whole ChatResult so the canary sees ``finish_reason``."""
    from homelabnext.registry.models import ModelClient

    def canary_for(role: str, binding: Any) -> tuple[Any, str]:
        client = ModelClient(resolver.resolve_binding(role, binding))
        return (lambda messages, params: client.chat(messages, **params)), "live"

    return canary_for


def _codemode(args: argparse.Namespace) -> int:
    from .agentic import HarnessError, check_report, render_report
    from .fakes import DEFAULT_SUITES, ScriptError, fake_report
    from .tasks import TaskError

    if (args.check or args.out) and args.fake != "fence":
        print(
            "golden codemode: --check and --out are for the fence fake's report (the committed "
            "one); run --fake naive alone",
            file=sys.stderr,
        )
        return 2
    try:
        rep = fake_report(
            args.suite or DEFAULT_SUITES, fake=args.fake, via_server=not args.in_process
        )
    except (HarnessError, ScriptError, TaskError, OSError) as exc:
        print(f"golden codemode: {exc}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(rep, indent=2, sort_keys=True))
    else:
        print(render_report(rep), end="")
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(rep, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"golden codemode: wrote {args.out}")
    if args.check:
        try:
            stored = json.loads(args.check.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            print(f"golden codemode: cannot read {args.check}: {exc}", file=sys.stderr)
            return 1
        problems = check_report(stored, rep)
        for p in problems:
            print(f"golden codemode: {p}")
        print(f"golden codemode: {args.check}: {len(problems)} problem(s)")
        return 1 if problems else 0
    return 0 if rep["summary"]["ok"] else 1


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

    def factory(role: str):
        return client_completer(resolver, role)

    return factory, tiers, _binding_completer(resolver), "live"


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
