# SPDX-License-Identifier: Apache-2.0
"""``hnx agent compile|verify|pack|lint|prompts|injection``.

``compile SPEC --library LIB [--policy POLICY]``  compile a profile spec against a parts library.
``verify PROFILE --policy POLICY [--lock LOCK]``  check a compiled profile against the policy.
``pack MANIFEST --inputs FILE [--denylist FILE]`` assemble a context pack and print its hash.
``lint [PATH ...]``                               readers cannot act: every agent profile and
                                                  context manifest under PATH (default ``.``).
``prompts lint [PATH ...]``                         G-01 template lint (default: shipped templates).
``prompts render TEMPLATE [--values FILE]``         render a template (default: its examples).
``injection run [--fake MODE | --role ROLE ...]``   G-02 injection eval; ``--check`` a golden.
``injection check-report REPORT``                   a stored report is current with 0 follows.

Library file (YAML or JSON): ``{parts: {<logical id>: <path relative to the file>}}``.
Policy file: ``{ceilings: {<profile id>: {mcp, capabilities, tier, budgets}}}``, owned and
reviewed separately from the specs.  Lock file: ``{profiles: {<profile id>: <digest>}}``.
Exit codes: 0 ok, 1 refused (missing part, ceiling, reader or budget violation, bad input; for
``lint``, a reader holding an acting tool or no profile found at all), 3 (``pack`` only) the pack
was assembled but is ``deferred``.  ``prompts lint`` and ``injection`` exit 1 on any problem,
instruction-follow, error or stale report.  ``--classes FILE`` replaces the packaged
capability-class table (``homelabnext/agent/tool_classes.yml``) for ``compile``, ``verify`` and
``lint``.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from homelabnext.ids import MappingResolver

from .compiler import CeilingPolicy, PartsLibrary, compile_profile, verify_profile
from .errors import AgentError
from .pack import assemble_pack
from .prompts_cli import add_injection_parser, add_prompts_parser, run_injection, run_prompts
from .readers import ToolClasses, lint_paths
from .schemas import schema_errors


def _load(path: str) -> Any:
    text = Path(path).read_text(encoding="utf-8")
    if path.endswith(".json"):
        return json.loads(text)
    import yaml

    return yaml.safe_load(text)


def _library(path: str) -> PartsLibrary:
    base = Path(path).resolve().parent
    doc = _load(path)
    mapping = (doc or {}).get("parts")
    if not isinstance(mapping, dict) or not mapping:
        raise AgentError(f"{path}: expected a non-empty 'parts' mapping of logical id -> path")

    def read(locator: str) -> str:
        target = (base / locator).resolve()
        if base not in target.parents:
            raise AgentError(f"part path {locator!r} escapes the library directory")
        return target.read_text(encoding="utf-8")

    return PartsLibrary(MappingResolver("parts", mapping), read)


def _policy(path: str) -> CeilingPolicy:
    return CeilingPolicy.from_mapping(_load(path) or {}, source=path)


def _emit(doc: dict, out: str | None) -> None:
    text = json.dumps(doc, indent=2, sort_keys=True) + "\n"
    if out:
        Path(out).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="hnx agent", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("compile", help="compile a profile spec")
    c.add_argument("spec")
    c.add_argument("--library", required=True)
    c.add_argument("--out")
    c.add_argument(
        "--policy", help="ceiling policy file (without it the spec's own ceiling is used)"
    )
    v = sub.add_parser("verify", help="check a compiled profile against a ceiling policy")
    v.add_argument("profile")
    v.add_argument("--policy", required=True)
    v.add_argument("--lock", help="reviewed digests: {profiles: {<profile id>: <digest>}}")
    for sp in (c, v):
        sp.add_argument("--classes", help="capability-class table (default: the packaged one)")
    li = sub.add_parser("lint", help="readers cannot act: lint every agent profile and manifest")
    li.add_argument("paths", nargs="*", default=["."])
    li.add_argument("--classes", help="capability-class table (default: the packaged one)")
    p = sub.add_parser("pack", help="assemble a context pack")
    p.add_argument("manifest")
    p.add_argument("--inputs", required=True)
    p.add_argument("--out", help="write the pack JSON here (default: stdout)")
    p.add_argument(
        "--denylist", help="deny-list file (one term or re:<regex> per line) redacted from input"
    )
    add_prompts_parser(sub)
    add_injection_parser(sub)
    args = ap.parse_args(argv)
    try:
        if args.cmd == "prompts":
            return run_prompts(args)
        if args.cmd == "injection":
            return run_injection(args)
        classes = ToolClasses.load(args.classes) if getattr(args, "classes", None) else None
        if args.cmd == "lint":
            problems, counts = lint_paths(args.paths, classes)
            for where, prob in problems:
                print(f"hnx agent lint: {where}: {prob}", file=sys.stderr)
            print(
                f"hnx agent lint: {counts['profile']} profile(s), {counts['manifest']} "
                f"manifest(s), {len(problems)} problem(s)",
                file=sys.stderr,
            )
            if not counts["profile"]:
                print("hnx agent lint: no agent profile found (wrong path?)", file=sys.stderr)
                return 1
            return 1 if problems else 0
        if args.cmd == "compile":
            policy = _policy(args.policy) if args.policy else None
            if policy is None:
                print(
                    "hnx agent compile: no --policy; the ceiling comes from the spec itself",
                    file=sys.stderr,
                )
            profile = compile_profile(
                _load(args.spec), _library(args.library), policy=policy, classes=classes
            )
            _emit(profile, args.out)
            print(f"compiled {profile['id']} {profile['digest']}", file=sys.stderr)
            return 0
        if args.cmd == "verify":
            lock = None
            if args.lock:
                lock = (_load(args.lock) or {}).get("profiles")
                if not isinstance(lock, dict):
                    raise AgentError(f"{args.lock}: expected a 'profiles' mapping of id -> digest")
            problems = verify_profile(
                _load(args.profile), policy=_policy(args.policy), lock=lock, classes=classes
            )
            for prob in problems:
                print(f"hnx agent verify: {prob}", file=sys.stderr)
            return 1 if problems else 0
        manifest = _load(args.manifest)
        errs = schema_errors("agent", "context_manifest", manifest)
        if errs:
            print("hnx agent pack: manifest invalid:\n  " + "\n  ".join(errs), file=sys.stderr)
            return 1
        deny = None
        if args.denylist:
            deny = Path(args.denylist).read_text(encoding="utf-8").splitlines()
        pack, digest = assemble_pack(manifest, _load(args.inputs) or {}, denylist=deny)
        _emit({"hash": digest, "pack": pack}, args.out)
        print(f"pack {digest} status={pack['status']}", file=sys.stderr)
        for r in pack["deferred_reasons"]:
            print(f"deferred: {r}", file=sys.stderr)
        return 0 if pack["status"] == "ready" else 3
    except (AgentError, OSError, ValueError) as exc:
        print(f"hnx agent {args.cmd}: {exc}", file=sys.stderr)
        return 1
