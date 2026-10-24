# SPDX-License-Identifier: Apache-2.0
"""``hnx agent compile|verify|pack|terms|keyring|lint|prompts|injection``.

``compile SPEC --library LIB [--policy POLICY]``  compile a profile spec against a parts library.
``verify PROFILE --policy POLICY [--lock LOCK]``  check a compiled profile against the policy.
``pack MANIFEST --inputs FILE [--denylist FILE]`` assemble a context pack and print its hash.
    ``[--profile P --registry R [--runs-on HOST] [--broker M]]`` start a session: the pack gets
                                                  the profile's access block (stable ``access``).
    ``[--root DIR] [--task-path P ...] [--task-text T | --task-file F] [--explain]``
                                                  with a profile that has ``include:`` rules, add
                                                  the linked knowledge from the graph of the
                                                  checkout at DIR (default ``.``); ``--explain``
                                                  prints what was included and excluded and why.
``terms [--check | --write] [PATH]``               the project's terms (the reserved ``terms``
                                                  section of every session pack): print them, or
                                                  check / regenerate PATH (default
                                                  ``docs/terms.md``).
``keyring build|check SOURCES``                   generate the keyring from its sources, or fail
                                                  when the committed one has drifted (M-12).
``lint [PATH ...]``                               readers cannot act: every agent profile and
                                                  context manifest under PATH (default ``.``).
``prompts lint [PATH ...]``                         G-01 template lint (default: shipped templates).
``prompts render TEMPLATE [--values FILE]``         render a template (default: its examples).
``injection run [--fake MODE | --role ROLE ...]``   G-02 injection eval; ``--check`` a golden.
``injection check-report REPORT``                   a stored report is current with 0 follows.

Library file (YAML or JSON): ``{parts: {<logical id>: <path relative to the file>}}``.
Policy file: ``{ceilings: {<profile id>: {mcp, capabilities, tier, budgets, reads_untrusted,
data_tier, model_role}}}``, owned and reviewed separately from the specs (``data_tier`` and
``model_role`` are attested there: a profile must match, and only an attested ``local-only``
profile is granted a local-only MCP server).  Lock file: ``{profiles: {<profile id>: <digest>}}``.
Exit codes: 0 ok, 1 refused (missing part, ceiling, reader or budget violation, an invalid spec,
policy, lock, manifest or inputs document; for ``lint``, a reader holding an acting tool or no
profile found at all), 2 a usage error or a spec, library, policy, lock, manifest, inputs,
profile or broker file that cannot be read or parsed, 3 (``pack`` only) the pack was assembled
but is ``deferred``.  ``prompts lint`` and ``injection`` exit 1 on any problem,
instruction-follow, error or stale report.  ``--classes FILE`` replaces the packaged
capability-class table (``homelabnext/agent/tool_classes.yml``) for ``compile``, ``verify`` and
``lint``; its ``mcp`` section is always the MCP catalog's (a table with its own is refused).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from homelabnext.ids import MappingResolver
from homelabnext.registry import RegistryError

from .access import start_session
from .compiler import CeilingPolicy, PartsLibrary, compile_profile, verify_profile
from .errors import AgentError
from .pack import assemble_pack
from .prompts_cli import add_injection_parser, add_prompts_parser, run_injection, run_prompts
from .readers import ToolClasses, lint_paths
from .schemas import schema_errors


class _Unreadable(Exception):
    """An input document cannot be read or parsed: bad input, exit 2 (docs/interfaces.md)."""


def _load(path: str) -> Any:
    import yaml

    try:
        text = Path(path).read_text(encoding="utf-8")
        if path.endswith(".json"):
            return json.loads(text)
        return yaml.safe_load(text)
    except (OSError, UnicodeDecodeError, ValueError, yaml.YAMLError) as exc:
        raise _Unreadable(f"cannot read {path}: {exc}") from None


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


def _keyring(action: str, sources: str, classes: ToolClasses | None) -> int:
    from .keyring import build_from_sources, drift

    text, out = build_from_sources(sources, classes)
    if action == "build":
        out.write_text(text, encoding="utf-8")
        print(f"hnx agent keyring: wrote {out}", file=sys.stderr)
        return 0
    problems = drift(text, out.read_text(encoding="utf-8") if out.is_file() else None)
    for prob in problems:
        print(f"hnx agent keyring check: {out}: {prob}", file=sys.stderr)
    if problems:
        print(f"rebuild it: hnx agent keyring build {sources}", file=sys.stderr)
        return 1
    print(f"hnx agent keyring check: {out} matches its sources", file=sys.stderr)
    return 0


def _terms(args: argparse.Namespace) -> int:
    from . import terms

    if not (args.check or args.write):
        sys.stdout.write(terms.terms_text())
        return 0
    path = Path(args.path)
    if args.write:
        path.write_text(terms.render_doc(), encoding="utf-8")
        print(f"hnx agent terms: wrote {path}", file=sys.stderr)
        return 0
    problems = terms.check_doc(path)
    for prob in problems:
        print(f"hnx agent terms check: {prob}", file=sys.stderr)
    return 1 if problems else 0


def _knowledge(profile: dict, args: argparse.Namespace) -> Any:
    """The profile's knowledge selection over a fresh graph of ``--root``."""
    from homelabnext.graph import build

    from .knowledge import select_knowledge

    text = args.task_text
    if args.task_file:
        text = (text + "\n" if text else "") + Path(args.task_file).read_text(encoding="utf-8")
    graph, _ = build(args.root)
    return select_knowledge(profile, graph, args.root, task_paths=args.task_path, task_text=text)


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
    p.add_argument("--profile", help="compiled profile: start a session with its access block")
    p.add_argument("--registry", help="service registry (with --profile)")
    p.add_argument("--runs-on", help="registry host the agent runs on (default: agent-runtime)")
    p.add_argument("--broker", help="broker manifest, to list the profile's broker actions")
    p.add_argument("--root", default=".", help="checkout whose graph feeds include: rules")
    p.add_argument("--task-path", action="append", default=[], help="file the task edits")
    p.add_argument("--task-text", default="", help="task text (seeds for from: task)")
    p.add_argument("--task-file", help="read the task text from this file")
    p.add_argument(
        "--explain",
        action="store_true",
        help="print the included and excluded knowledge and why (the pack goes to --out only)",
    )
    t = sub.add_parser("terms", help="the project's terms: print, or check/write docs/terms.md")
    mode = t.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="fail when PATH has drifted")
    mode.add_argument("--write", action="store_true", help="regenerate PATH")
    t.add_argument("path", nargs="?", default="docs/terms.md")
    k = sub.add_parser("keyring", help="generate the keyring from its sources, or check drift")
    k.add_argument("action", choices=("build", "check"))
    k.add_argument("sources", help="sources file: {registry, profiles, broker, out}")
    k.add_argument("--classes", help="capability-class table (default: the packaged one)")
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
            notes: list[tuple[str, str]] = []
            problems, counts = lint_paths(args.paths, classes, notes)
            for where, prob in problems:
                print(f"hnx agent lint: {where}: {prob}", file=sys.stderr)
            for where, note in notes:
                print(f"hnx agent lint: note: {where}: {note}", file=sys.stderr)
            print(
                f"hnx agent lint: {counts['profile']} profile(s), {counts['manifest']} "
                f"manifest(s), {len(problems)} problem(s)",
                file=sys.stderr,
            )
            if not counts["profile"]:
                print("hnx agent lint: no agent profile found (wrong path?)", file=sys.stderr)
                return 1
            return 1 if problems else 0
        if args.cmd == "terms":
            return _terms(args)
        if args.cmd == "keyring":
            return _keyring(args.action, args.sources, classes)
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
        if args.profile or args.registry:
            if not (args.profile and args.registry):
                raise AgentError("--profile and --registry go together")
            from homelabnext.registry import load as load_registry

            profile = _load(args.profile)
            knowledge = None
            if profile.get("include") or args.explain:
                from .knowledge import explain

                knowledge = _knowledge(profile, args)
                if args.explain:
                    sys.stdout.write(explain(knowledge))
            pack, digest = start_session(
                manifest,
                _load(args.inputs) or {},
                profile,
                load_registry(args.registry),
                runs_on=args.runs_on,
                broker=_load(args.broker) if args.broker else None,
                denylist=deny,
                knowledge=knowledge,
            )
        else:
            if args.explain:
                raise AgentError("--explain needs --profile and --registry")
            pack, digest = assemble_pack(manifest, _load(args.inputs) or {}, denylist=deny)
        if args.out or not args.explain:
            _emit({"hash": digest, "pack": pack}, args.out)
        print(f"pack {digest} status={pack['status']}", file=sys.stderr)
        for r in pack["deferred_reasons"]:
            print(f"deferred: {r}", file=sys.stderr)
        return 0 if pack["status"] == "ready" else 3
    except _Unreadable as exc:
        print(f"hnx agent {args.cmd}: {exc}", file=sys.stderr)
        return 2
    except (AgentError, OSError, ValueError, RegistryError) as exc:
        print(f"hnx agent {args.cmd}: {exc}", file=sys.stderr)
        return 1
