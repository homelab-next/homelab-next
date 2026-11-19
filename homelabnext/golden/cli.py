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
``hnx golden run``         a golden suite against a role, through the LLM gateway (the
                           ``llm-gateway`` capability, the role as the model, the key in
                           ``--key-env``): what a consumer calls.  A decision suite
                           (``kind: decision``) asks its noul questions on
                           ``POST /v1/systemone`` (``ModelClient.decide``).  ``--direct`` resolves the
                           role's backend instead (host-side; ``--key-env`` then names the
                           backend's key; the key goes over plain http to a non-loopback host
                           only with ``--allow-plaintext``).  Exit 0 pass, 1 fail, 2 usage.
``hnx golden canary``      the egress canary (docs/compute-model.md, "The egress canary"): live
                           against every binding of a role (``--registry`` and ``--roles``), or
                           against a scripted fake (``--fake benign|incident``).  Exit 0 pass,
                           1 a finding, 2 usage.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from typing import Any

from homelabnext.registry import load as load_registry
from homelabnext.registry.models import (
    GatewayResolver,
    ModelResolver,
    NonPrimaryBinding,
    ResolvedModel,
    RoleTable,
    normalize_role,
)
from homelabnext.registry.resolver import ResolutionError

from .runner import client_completer, client_decider, run_decision_suite, run_suite
from .tasks import load_suite


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="hnx golden", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    run = sub.add_parser("run", help="run SUITE.yml against an alias")
    run.add_argument("suite")
    run.add_argument("--registry", required=True)
    run.add_argument("--roles", required=True, help="model role table (JSON)")
    run.add_argument("--role", help="alias to test (default: the suite's role)")
    run.add_argument(
        "--direct",
        action="store_true",
        help="call the role's backend, not the gateway (host-side checks of a binding only)",
    )
    _key_env(run, "the gateway key (with --direct: the backend's key)")
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
    _key_env(pins, "report, live: the backends' key (each binding is called directly)")
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
    _key_env(can, "live: the backend's key (each binding is called directly)")
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
    client = _client(args)
    how = ModelResolver if args.direct else GatewayResolver
    resolver = how(load_registry(args.registry), RoleTable.load(args.roles))
    if suite.kind == "decision":
        decider, model_id = client_decider(resolver, role, **client)
        rep = run_decision_suite(suite, decider, role=role, model_id=model_id)
    else:
        completer, model_id = client_completer(resolver, role, **client)
        rep = run_suite(suite, completer, role=role, model_id=model_id)
    if args.json:
        print(json.dumps(rep.to_dict(timing=True), indent=2, sort_keys=True))
    else:
        print(rep.render_text(), end="")
    return 0 if rep.ok else 1


def _key_env(p: argparse.ArgumentParser, what: str) -> None:
    p.add_argument("--key-env", metavar="VAR", help=f"environment variable holding {what}")
    p.add_argument(
        "--allow-plaintext",
        action="store_true",
        help="send the key over plain http to a non-loopback host (lab only)",
    )
    p.add_argument(
        "--timeout",
        type=_seconds,
        default=DEFAULT_CLIENT_TIMEOUT,
        metavar="SECONDS",
        help="live: how long one model call may take (default %(default)s); a role with a large "
        "output budget (params.max_tokens) needs it to cover a whole reply",
    )


#: ModelClient's own default; a live run with a large output budget passes a longer one
DEFAULT_CLIENT_TIMEOUT = 30.0


def _seconds(text: str) -> float:
    """A positive, finite number of seconds (``--timeout``)."""
    import math

    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not a number of seconds") from None
    if not math.isfinite(value) or value <= 0:
        raise argparse.ArgumentTypeError(f"{text!r}: a positive number of seconds")
    return value


def _client(args: argparse.Namespace) -> dict[str, Any]:
    """The ``ModelClient`` keywords the key options name: ``api_key``, ``allow_plaintext`` and
    ``timeout``. The timeout is not a report input: it decides how long the harness waits, not
    what a reply is judged to be (a call that times out is an error and fails its sample)."""
    return {
        "api_key": _api_key(args),
        "allow_plaintext": args.allow_plaintext,
        "timeout": args.timeout,
    }


def _api_key(args: argparse.Namespace) -> str | None:
    """The key named by ``--key-env`` (never on the command line, so not in a process list)."""
    import os

    if not args.key_env:
        return None
    value = os.environ.get(args.key_env)
    if not value:
        print(
            f"golden {args.cmd}: --key-env {args.key_env}: the variable is not set", file=sys.stderr
        )
        raise SystemExit(2)  # usage
    return value


def _pins(args: argparse.Namespace) -> int:
    from . import pins

    table = RoleTable.load(args.roles)
    suites = args.suite or list(pins.DEFAULT_SUITES)
    if args.action == "report":
        if args.registry:
            live = _live(args.registry, table, _client(args))
            rep = pins.run_eval(
                table,
                suites,
                live["factory"],
                model_name="live",
                replay_tiers=live["tiers"],
                canary_factory=live["canary"],
                decider_factory=live["decider"],
                decision_canary_factory=live["decision_canary"],
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
    from . import canary, pins

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
    runs: list[tuple[Any, Any, str, str]] = []
    if args.fake:
        completer: Any = canary.IncidentModel() if args.fake == "incident" else canary.benign_model
        runs.append((canary.run_canary, completer, "fake", f"fake-{args.fake}"))
    else:  # pragma: no cover - needs a real model server
        table = RoleTable.load(args.roles)
        resolver = ModelResolver(load_registry(args.registry), table)
        if table.get(args.role).kind == "decision":  # asked on POST /v1/systemone
            run = canary.run_decision_canary
            one = _binding_completer(resolver, _client(args), decision=True)
        else:
            run, one = canary.run_canary, _binding_completer(resolver, _client(args))
            # the role's own output budget, as the pins report runs it (pins.canary_budget)
            try:
                suite = replace(suite, max_tokens=pins.canary_budget(table.get(args.role), suite))
            except ValueError as exc:
                print(f"golden canary: mdl:{args.role}: {exc}", file=sys.stderr)
                return 2
        for b in table.get(args.role).bindings:  # every binding, not the first that resolves
            runs.append((run, one(args.role, b)[0], args.role, b.model_id))
    reports = []
    try:
        for run_one, completer, role, model_id in runs:
            reports.append(
                run_one(suite, completer, role=role, model_id=model_id, samples=args.samples)
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


class EvaluationResolver(ModelResolver):
    """A :class:`ModelResolver` for EVALUATION runs: ``resolve`` also reaches a role binding that
    names an ``eval`` row (by its row name, never through its capability), so ``hnx golden pins
    report`` can run the golden suites against the lab's own backend that the gateway fronts,
    exactly as the egress canary already does (:func:`_binding_completer`).  Each of the role's own bindings goes
    through :meth:`ModelResolver.resolve_binding` with ``allow_eval=True``, which reaches an
    ``eval`` row only (never ``retiring`` or ``legacy``) and resolves a primary as always.

    It is built only by :func:`_live`.  The serving path, the gateway render and ``hnx golden
    run`` keep :class:`ModelResolver`, whose ``resolve`` raises :class:`NonPrimaryBinding` on a
    non-primary binding (ADR-0039 decision 3); it is not in the report's ``code`` inputs, so
    adding it leaves the committed reports current."""

    def resolve(self, role: str) -> ResolvedModel:
        """The first binding of ``role`` itself that resolves.  An evaluation never walks to the
        role's ``fallback``: that would report another role's model under this role's name."""
        asked = normalize_role(role)
        trail: list[str] = []
        for b in self.table.get(asked).bindings:
            try:
                got = self.resolve_binding(asked, b, allow_eval=True)
            except NonPrimaryBinding:
                raise  # a retiring or legacy row: never skipped to the next binding
            except ResolutionError as exc:
                trail.append(f"{asked}: svc:{b.backend} unresolved ({str(exc)[:80]})")
                continue
            return replace(got, trail=tuple(trail))
        raise ResolutionError(
            f"mdl:{asked}", "no binding resolved (an evaluation has no fallback)", trail
        )


def _binding_completer(
    resolver: ModelResolver,
    client_kwargs: Mapping[str, Any] | None = None,
    *,
    decision: bool = False,
):  # pragma: no cover - needs a real model server
    """``(role, binding) -> (completer, "live")``: the canary's completer for one binding, which
    returns the whole ChatResult so the canary sees ``finish_reason``; with ``decision``, a
    decision binding's decider instead (the same client on ``POST /v1/systemone``).  This is the
    egress canary runner, the one caller that passes ``allow_eval`` (ADR-0039 decision 3): the
    canary vets a candidate ``eval`` row before its switch."""
    from homelabnext.registry.models import ModelClient

    def canary_for(role: str, binding: Any) -> tuple[Any, str]:
        resolved = resolver.resolve_binding(role, binding, allow_eval=True)
        client = ModelClient(resolved, **(client_kwargs or {}))
        if decision:
            from .runner import ClientDecider

            return ClientDecider(client), "live"
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


def _live(
    registry: str, table: RoleTable, client_kwargs: Mapping[str, Any] | None = None
):  # pragma: no cover - needs a real model server
    from homelabnext.decide.evalset import EXAMPLES
    from homelabnext.decide.spec import load_spec
    from homelabnext.decide.tiers import ModelTier
    from homelabnext.registry.models import ModelClient

    from .pins import _replay_roles

    resolver = EvaluationResolver(load_registry(registry), table)
    spec = load_spec(EXAMPLES / "decision_spec.yml")
    chat_roles = _replay_roles(table)  # the cascade's roles the table has as chat roles
    tiers = {}
    for t in spec.tiers:  # a tier whose role the table lacks, or holds as decision, stays simulated
        if t.model_role and t.model_role.removeprefix("mdl:") in chat_roles:
            client = ModelClient(resolver.resolve(t.model_role), **(client_kwargs or {}))
            tiers[t.name] = ModelTier(
                t.name, lambda m, c=client: c.chat(m), spec.question_set, spec.answer_labels
            )

    def factory(role: str):
        return client_completer(resolver, role, **(client_kwargs or {}))

    def decider(role: str):
        return client_decider(resolver, role, **(client_kwargs or {}))

    return {
        "factory": factory,
        "tiers": tiers,
        "canary": _binding_completer(resolver, client_kwargs),
        "decider": decider,
        "decision_canary": _binding_completer(resolver, client_kwargs, decision=True),
    }


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
