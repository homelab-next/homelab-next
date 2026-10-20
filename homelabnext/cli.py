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


GEN_USAGE = """usage: hnx gen {registry,check,fleet-units,list} ...

  registry REGISTRY OUT_DIR [--only NAME]   render every generator from a service registry
  check REGISTRY OUT_DIR [--only NAME]      fail on drift between the registry and OUT_DIR
  fleet-units SPEC OUT_DIR                  render systemd units from a fleet_units spec
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
    print(f"hnx gen: unknown generator command {sub!r}\n{GEN_USAGE}", file=sys.stderr, end="")
    return 2


# name -> (one-line help, handler).  Order is the order shown in --help.
COMMANDS: dict[str, tuple[str, Main]] = {
    "registry": (
        "the service registry: validate|resolve|generate|check|list-generators",
        _registry,
    ),
    "new": ("scaffold a component: hnx new role|capability|detection|schema NAME", _new),
    "gen": ("run generators: registry|check|fleet-units|list", _gen),
    "detections": (
        "detections-as-code: lint|run|map|coverage|lint-ids|compile|validate-techniques",
        _detections,
    ),
    "registers": (
        "lessons/runbooks/invariants: build pages, split|join record files, links blocks",
        _registers,
    ),
    "invariants": ("run the standing invariants (invariants run)", _invariants),
    "ids": (
        "register ids: alloc|resolve|check-lost|check-dupes|check-placeholders",
        _ids,
    ),
    "decide": (
        "decision specs and cascade: eval|scan|lint|safety",
        lambda a: importlib.import_module("homelabnext.decide.cli").main(a),
    ),
    "golden": (
        "golden tasks and model pins: run|pins check|pins report",
        lambda a: importlib.import_module("homelabnext.golden.cli").main(a),
    ),
    "site": ("the site/network model: validate|plan|render|ir|adapters", _site),
    "guests": ("validate/render/plan the guest (compute) model", _guests),
    "schema-check": ("check schemas, examples, negatives and frozen baselines", _schema_check),
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
        "generate/check docs: systems (one SOP page per service), capabilities (contract reference)",
        lambda a: importlib.import_module("homelabnext.sop.cli").main(a),
    ),
    "agent": (
        "agent profiles, packs, prompts: compile|verify|lint|pack|keyring|prompts|injection",
        lambda a: importlib.import_module("homelabnext.agent.cli").main(a),
    ),
    "workflows": (
        "workflow packs as code: validate (offline, every pack in git)|run|digest",
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
