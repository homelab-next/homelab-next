# SPDX-License-Identifier: Apache-2.0
"""``hnx``: the single console entry point.

This module only dispatches.  Each subcommand lives in the package that owns it and keeps its
own ``main(argv) -> int``; they are imported lazily so ``hnx --help`` works with the core
install and a missing optional dependency only affects the subcommand that needs it.

New subcommands register themselves by adding one row to ``COMMANDS``.
"""

from __future__ import annotations

import importlib
import importlib.util
import sys
from collections.abc import Callable, Sequence

Main = Callable[[list[str]], int]


def _registry(argv: list[str]) -> int:
    from homelabnext.registry.cli import main

    return main(argv)


def _new(argv: list[str]) -> int:
    from homelabnext.scaffold import main

    return main(["new", *argv])


def _detections(argv: list[str]) -> int:
    from homelabnext.detections.cli import main

    return main(argv)


def _registers(argv: list[str]) -> int:
    from homelabnext.registers.__main__ import main

    return main(argv)


def _invariants(argv: list[str]) -> int:
    from homelabnext.invariants.__main__ import main

    return main(argv)


def _ids(argv: list[str]) -> int:
    from homelabnext.registers.idcli import main

    return main(argv)


def _site(argv: list[str]) -> int:
    from homelabnext.network.cli import main

    return main(argv)


def _guests(argv: list[str]) -> int:
    from homelabnext.compute.cli import main

    return main(argv)


def _schema_check(argv: list[str]) -> int:
    from homelabnext import paths

    try:
        path = paths.checkout_tool("schema_check.py", feature="hnx schema-check")
    except paths.NotACheckout as exc:
        print(exc, file=sys.stderr)
        return 2
    spec = importlib.util.spec_from_file_location("hnx_schema_check", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod  # dataclasses need the module registered
    spec.loader.exec_module(mod)
    return mod.main(argv)


GEN_USAGE = """usage: hnx gen {registry,check,fleet-units,gateway,list} ...

  registry REGISTRY OUT_DIR [--only NAME]   render every generator from a service registry
  check REGISTRY OUT_DIR [--only NAME]      fail on drift between the registry and OUT_DIR
  fleet-units SPEC OUT_DIR                  render systemd units from a fleet_units spec
  gateway render SPEC OUT_DIR [--check]     LiteLLM + Bifrost config from the model-role table
  gateway provision KEYS_JSON               create LiteLLM virtual keys on a running proxy
  gateway homes --roles ROLES HOME...       no HERMES_HOME names an IP or an engine model id
  list                                      list generator names
"""


def _gen(argv: list[str]) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        print(GEN_USAGE, end="")
        return 0 if argv else 2
    sub, rest = argv[0], argv[1:]
    if sub == "registry":
        return _registry(["generate", *rest])
    if sub == "check":
        return _registry(["check", *rest])
    if sub == "list":
        return _registry(["list-generators"])
    if sub == "fleet-units":
        from homelabnext.generators.fleet_units import main

        return main(rest)
    if sub == "gateway":
        from homelabnext.generators.llm_gateway import main as gateway_main

        return gateway_main(rest)
    print(f"hnx gen: unknown generator command {sub!r}\n{GEN_USAGE}", file=sys.stderr, end="")
    return 2


# name -> (one-line help, handler).  Order is the order shown in --help.
COMMANDS: dict[str, tuple[str, Main]] = {
    "registry": (
        "the service registry: validate|resolve|generate|check|list-generators",
        _registry,
    ),
    "new": ("scaffold a component: hnx new role|capability|detection|schema NAME", _new),
    "gen": ("run generators: registry|check|fleet-units|gateway|list", _gen),
    "detections": (
        "detections-as-code: lint|run|map|coverage|lint-ids|compile|validate-techniques",
        _detections,
    ),
    "registers": (
        "lessons/runbooks/invariants: build pages, split|join record files, links blocks, review, "
        "summaries lint, events (migrate|add), decide transitions",
        _registers,
    ),
    "invariants": ("run the standing invariants (invariants run)", _invariants),
    "strategy": (
        "strategy to task: check|links|measure|rollup|rfis|decide|index (docs/strategy.md)",
        lambda a: importlib.import_module("homelabnext.strategy.cli").main(a),
    ),
    "projects": (
        "projects, steps and tasks: new|list|show|move|close|link|check|feed|doctor|sync-strategy "
        "(docs/projects.md)",
        lambda a: importlib.import_module("homelabnext.projects.cli").main(a),
    ),
    "records": (
        "record identity (uids, computed numbers): assign-uids (the migration)|numbers|uid",
        lambda a: importlib.import_module("homelabnext.identity.cli").main(a),
    ),
    "orchestration": (
        "orchestration telemetry: consume|ingest|turns|report|export|import "
        "(docs/orchestration-telemetry.md)",
        lambda a: importlib.import_module("homelabnext.orchestration.cli").main(a),
    ),
    "reviews": (
        "the shared review model (records, system pages): digest",
        lambda a: importlib.import_module("homelabnext.reviews").main(a),
    ),
    "ids": (
        "register keys: check-lost|check-dupes|check-uids (records are identified by uids)",
        _ids,
    ),
    "decide": (
        "decision specs and cascade: eval|scan|lint|safety",
        lambda a: importlib.import_module("homelabnext.decide.cli").main(a),
    ),
    "models": (
        "the model store and serving plan: store validate|check|list, serving render|check "
        "(docs/model-serving.md)",
        lambda a: importlib.import_module("homelabnext.models.cli").main(a),
    ),
    "golden": (
        "golden tasks and model pins: run|pins check|pins report|codemode (Code Mode against "
        "classic MCP mode, both against the fakes; CM-6)",
        lambda a: importlib.import_module("homelabnext.golden.cli").main(a),
    ),
    "site": ("the site/network model: validate|plan|render|ir|adapters", _site),
    "guests": ("validate/render/plan the guest (compute) model; baselines coverage", _guests),
    "schema-check": ("check schemas, examples, negatives and frozen baselines", _schema_check),
    "secrets": (
        "the credentials a lab names: plan (list them) | seed (create the missing ones in OpenBao)",
        lambda a: importlib.import_module("homelabnext.secretseed.cli").main(a),
    ),
    "swap": (
        "run the swap procedure (plan|start|status|advance|rollback|record)",
        lambda a: importlib.import_module("homelabnext.swap.cli").main(a),
    ),
    "conform": (
        "capability conformance suites: list|run|mutants|report",
        lambda a: importlib.import_module("homelabnext.conform.cli").main(a),
    ),
    "decommission": (
        "per-guest teardown audit: check|plan NAME (read-only, all planes)",
        lambda a: importlib.import_module("homelabnext.decommission.cli").main(a),
    ),
    "docs": (
        "generate/check docs: systems (one SOP page per service), capabilities (contract reference), index (docs/README.md descriptions from page summaries)",
        lambda a: importlib.import_module("homelabnext.sop.cli").main(a),
    ),
    "agent": (
        "agent profiles, packs, prompts: compile|verify|lint|pack|terms|keyring|prompts|injection",
        lambda a: importlib.import_module("homelabnext.agent.cli").main(a),
    ),
    "workflows": (
        (
            "workflow packs as code: validate (offline, every pack in git)|run|digest"
            "|st2 (render the pinned packs as a StackStorm pack; run its event bridge)"
        ),
        lambda a: importlib.import_module("homelabnext.workflows.cli").main(a),
    ),
    "scripts": (
        "script catalog: catalog [--check]|reality|runner-lint|list",
        lambda a: importlib.import_module("homelabnext.scripts.cli").main(a),
    ),
    "events": (
        "event seam: deploy-changed (what-changed event, F-15)|enrich-coverage (T-04)",
        lambda a: importlib.import_module("homelabnext.events.cli").main(a),
    ),
    "status": (
        "the read-only status hub: sources (the menu)|catalog|views|collect|render|serve|ingest",
        lambda a: importlib.import_module("homelabnext.status.cli").main(a),
    ),
    "graph": (
        "the repository knowledge graph: build|check|related (docs/graph/)",
        lambda a: importlib.import_module("homelabnext.graph.cli").main(a),
    ),
    "mcp": (
        "read-only MCP server over this repository: serve (stdio)|tools|call (docs/mcp.md); the MCP catalog: catalog check|list|classes|render|import (docs/mcp-catalog.md)",
        lambda a: importlib.import_module("homelabnext.mcp.cli").main(a),
    ),
    "broker": (
        "the broker: validate|serve|relay|mcp|actions|call|submit|status|run|cancel|approve|deny|"
        "pending|audit|import-proposals",
        lambda a: importlib.import_module("homelabnext.broker.cli").main(a),
    ),
    "codemode": (
        "Code Mode (ADR-0031): gen (the per-profile stubs and search index; --check for drift)|"
        "mcp (the codemode_search and codemode_describe tools)",
        lambda a: importlib.import_module("homelabnext.codemode.cli").main(a),
    ),
    "modules": (
        "the module loader (ADR-0027): check (every manifest, site, lock and runtime rule)|render "
        "(footprint limits and egress policy for a site)",
        lambda a: importlib.import_module("homelabnext.modules.cli").main(a),
    ),
    "custom": (
        "list|check|plan|register lab/vendor customizations",
        lambda a: importlib.import_module("homelabnext.customization.cli").main(a),
    ),
}


def _usage() -> str:
    width = max(len(n) for n in COMMANDS)
    rows = "\n".join(f"  {n:<{width}}  {h}" for n, (h, _) in COMMANDS.items())
    return (
        "usage: hnx [-h] [--version] COMMAND [ARGS...]\n\n"
        "HomelabNext command line. Run `hnx COMMAND --help` for a command's options.\n\n"
        f"commands:\n{rows}\n"
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in ("-h", "--help"):
        print(_usage(), end="")
        return 0 if args else 2
    if args[0] == "--version":
        from homelabnext import __version__

        print(f"hnx {__version__}")
        return 0
    cmd, rest = args[0], args[1:]
    entry = COMMANDS.get(cmd)
    if entry is None:
        print(f"hnx: unknown command {cmd!r}\n\n{_usage()}", file=sys.stderr, end="")
        return 2
    saved_argv0 = sys.argv[0]
    sys.argv[0] = f"hnx {cmd}"  # argparse derives `prog` from argv[0] for modules that set none
    try:
        code = entry[1](rest)
    except ModuleNotFoundError as exc:
        print(
            f"hnx {cmd}: missing optional dependency {exc.name!r}; "
            "install the matching extra (see pyproject.toml)",
            file=sys.stderr,
        )
        return 2
    except SystemExit as exc:  # argparse --help / usage errors inside a subcommand
        if isinstance(exc.code, int) or exc.code is None:
            return exc.code or 0
        print(exc.code, file=sys.stderr)
        return 1
    finally:
        sys.argv[0] = saved_argv0
    return int(code or 0)


if __name__ == "__main__":
    sys.exit(main())
