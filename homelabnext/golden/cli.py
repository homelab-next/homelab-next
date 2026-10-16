# SPDX-License-Identifier: Apache-2.0
"""``hnx golden run``: run a golden suite against a model-role alias."""

from __future__ import annotations

import argparse
import json

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
    args = ap.parse_args(argv)
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
