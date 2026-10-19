# SPDX-License-Identifier: Apache-2.0
"""``hnx agent prompts lint|render`` and ``hnx agent injection run|check-report``.

Wired into :mod:`homelabnext.agent.cli`; kept apart so that module stays about profiles and packs.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .injection import (
    DEFAULT_CORPUS,
    FakeInjectionModel,
    check_report,
    load_corpus,
    render_report,
    report_ok,
    run_eval,
)
from .template import lint_paths, load_template, load_templates, render_prompt


def _dump(doc: Any) -> str:
    return json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def add_prompts_parser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("prompts", help="prompt templates: lint (G-01) and render")
    ps = p.add_subparsers(dest="prompts_cmd", required=True)
    lint = ps.add_parser("lint", help="every slot has a trust level; untrusted slots stay fenced")
    lint.add_argument("paths", nargs="*", help="template files or directories")
    r = ps.add_parser("render", help="render one template to chat messages (JSON)")
    r.add_argument("template")
    r.add_argument("--values", help="YAML/JSON {slot: value} (default: the template's examples)")


def add_injection_parser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("injection", help="prompt-injection eval (G-02)")
    ps = p.add_subparsers(dest="injection_cmd", required=True)
    run = ps.add_parser("run", help="render every corpus case through every template")
    run.add_argument("--templates", action="append", default=[], help="file or directory")
    run.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    run.add_argument("--fake", choices=FakeInjectionModel.MODES, help="deterministic fake model")
    run.add_argument(
        "--role", help="LIVE: model-role alias to evaluate (needs --registry, --roles)"
    )
    run.add_argument("--registry", help="service registry (live only)")
    run.add_argument("--roles", help="model role table, JSON (live only)")
    run.add_argument("--timeout", type=float, default=120.0, help="per call, seconds (live only)")
    run.add_argument("--out", help="write the report JSON here")
    run.add_argument("--check", help="golden report: fail unless the new report equals it")
    run.add_argument("--json", action="store_true", help="print the report JSON")
    chk = ps.add_parser("check-report", help="a stored report is current and shows 0 follows")
    chk.add_argument("report")
    chk.add_argument("--templates", action="append", default=[])
    chk.add_argument("--corpus", default=str(DEFAULT_CORPUS))


def _load(path: str) -> Any:
    text = Path(path).read_text(encoding="utf-8")
    if path.endswith(".json"):
        return json.loads(text)
    import yaml

    return yaml.safe_load(text)


def run_prompts(args: argparse.Namespace) -> int:
    if args.prompts_cmd == "lint":
        n, problems = lint_paths(args.paths)
        for p in problems:
            print(f"hnx agent prompts lint: {p}", file=sys.stderr)
        print(f"prompts lint: {n} templates, {len(problems)} problems", file=sys.stderr)
        return 1 if problems else 0
    tmpl = load_template(args.template)
    values = _load(args.values) if args.values else tmpl.examples()
    rendered = render_prompt(tmpl, values or {})
    sys.stdout.write(
        _dump(
            {
                "template": tmpl.id,
                "status": rendered.status,
                "pack_hash": rendered.pack_hash,
                "messages": list(rendered.messages),
            }
        )
    )
    return 0 if rendered.status == "ready" else 3


def _live_model(args: argparse.Namespace):
    from homelabnext.golden.runner import client_completer
    from homelabnext.registry import load as load_registry
    from homelabnext.registry.models import ModelResolver, RoleTable

    if not (args.registry and args.roles):
        raise ValueError("--role needs --registry and --roles")
    resolver = ModelResolver(load_registry(args.registry), RoleTable.load(args.roles))
    completer, model_id = client_completer(resolver, args.role, timeout=args.timeout)
    return completer, {"name": args.role.removeprefix("mdl:"), "model_id": model_id, "live": True}


def run_injection(args: argparse.Namespace) -> int:
    templates = load_templates(args.templates)
    corpus = load_corpus(args.corpus)
    if args.injection_cmd == "check-report":
        problems = check_report(_load(args.report), templates, corpus)
        for p in problems:
            print(f"hnx agent injection check-report: {p}", file=sys.stderr)
        return 1 if problems else 0
    if args.role and args.fake:
        raise ValueError("pass either --fake or --role, not both")
    if args.role:
        model, info = _live_model(args)
    else:
        fake = FakeInjectionModel(corpus, args.fake or "fence")
        model, info = fake, {"name": fake.name, "live": False}
    report = run_eval(templates, corpus, model, model_info=info)
    text = _dump(report)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(text, encoding="utf-8")
    if args.json:
        sys.stdout.write(text)
    sys.stderr.write(render_report(report))
    ok = report_ok(report)
    if args.check:
        golden = Path(args.check)
        if not golden.is_file() or golden.read_text(encoding="utf-8") != text:
            print(
                f"hnx agent injection run: {golden} is not the report for the current templates "
                "and corpus; regenerate it with `make injection-report` and commit it",
                file=sys.stderr,
            )
            ok = False
    return 0 if ok else 1
