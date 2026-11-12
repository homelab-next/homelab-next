# SPDX-License-Identifier: Apache-2.0
"""``hnx guests``: validate, render and plan the guest (compute) model; report baseline coverage.

Exit codes: 0 ok, 1 an invalid guest set (or a failed ``baselines --check``), 2 a usage error or an
input that cannot be read or parsed (the site, the guest directory or a guest, policies, nodes,
keys or baselines file), 3 ``plan --exit-code`` found changes (as ``hnx site plan --exit-code``)."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from .baselines import coverage, coverage_text
from .loader import load_fleet, load_registry_for, registry_placement
from .model import ComputeError, ComputeUnreadable
from .plan import plan as make_plan
from .plan import read_tree
from .render import TARGETS, render
from .zones import site_facts


def _common(p: argparse.ArgumentParser) -> None:
    p.add_argument("directory", help="directory of guest files (one <name>.yml per guest)")
    p.add_argument("--site", required=True, help="site model file that defines the zones")
    p.add_argument(
        "--policies", help="backup policy file (default: DIRECTORY/_backup_policies.yml)"
    )
    p.add_argument(
        "--baselines",
        help="baseline set file (default: DIRECTORY/_baselines.yml; without one no guest "
        "needs a baseline)",
    )
    p.add_argument("--keys", help="file mapping ssh key names to public keys (optional)")
    p.add_argument(
        "--nodes",
        help="node firewall file (default: DIRECTORY/_nodes.yml; nodes not listed run a firewall)",
    )
    p.add_argument(
        "--domain", help="DNS domain (default: the site's domain, else example.internal)"
    )
    p.add_argument(
        "--registry",
        help="service registry the guests are judged against (default: services.yml next to "
        "the site file, when there is one): a guest may declare a capability a row on its host "
        "serves, and validate also holds each guest's address, zone and capability to it",
    )


def _fleet(args: argparse.Namespace):
    facts = site_facts(args.site)  # one read (and one SOPS decryption) of the site file
    # every subcommand reads the same registry, so render and plan accept what validate accepts
    args.registry_doc = load_registry_for(args.site, args.registry)
    return load_fleet(
        args.directory,
        facts["zones"],
        domain=args.domain or facts["domain"] or "example.internal",
        policies_path=args.policies,
        keys_path=args.keys,
        nodes_path=args.nodes,
        baselines_path=args.baselines,
        # the coverage report lists guests without a baseline instead of refusing to load
        require_baselines=args.cmd != "baselines",
        flows=facts["flows"],
        power=facts["power"],
        deploy=facts["deploy"],
        site_addresses=facts["site_addresses"],
        delegated6=facts["delegated6"],
        placement=registry_placement(args.registry_doc),
    )


def _node_arg(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--node",
        help="render only the guests placed on this node (validation still covers every guest): "
        "a standalone hypervisor's Terraform must not carry another node's guests",
    )


def _on_node(fleet, node: str | None):
    """The fleet narrowed to one node's guests, after the whole set validated.  A node no guest
    and no ``_nodes.yml`` entry names is refused: a typo must not render an empty, harmless-looking
    plan (Terraform would then destroy everything that state still holds)."""
    if node is None:
        return fleet
    import dataclasses

    guests = tuple(g for g in fleet.guests if g.node == node)
    if not guests and node not in fleet.nodes:
        raise ComputeError(
            f"--node {node!r}: no guest is placed on it and _nodes.yml lists no such node"
        )
    return dataclasses.replace(fleet, guests=guests)


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="hnx guests", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("validate", help="schema and semantic validation")
    _common(v)
    r = sub.add_parser("render", help="render one target")
    _common(r)
    r.add_argument("--target", required=True, choices=sorted(TARGETS))
    _node_arg(r)
    r.add_argument("--out", help="write files here (default: print a file list)")
    r.add_argument(
        "--prune",
        action="store_true",
        help="delete files in --out that this command generated but no longer renders (a removed "
        "guest's vm-*.tf, an old <vmid>.fw); hand-written files are never touched",
    )
    pl = sub.add_parser("plan", help="diff a fresh render against a previous render directory")
    _common(pl)
    pl.add_argument("--target", required=True, choices=sorted(TARGETS))
    _node_arg(pl)
    pl.add_argument("--against", required=True, help="directory holding the previous render")
    pl.add_argument("--exit-code", action="store_true", help="exit 3 when there are changes")
    b = sub.add_parser("baselines", help="guest x defense-layer baseline coverage")
    _common(b)
    b.add_argument("--json", action="store_true", help="print the report as JSON")
    b.add_argument(
        "--check",
        action="store_true",
        help="exit 1 when there is no baseline set or a guest has neither a baseline nor an "
        "exemption",
    )
    b.add_argument(
        "--require-bound",
        action="store_true",
        help="like --check, and also exit 1 when a control some guest needs has no role yet, or "
        "is applied centrally on a group that holds no guest",
    )
    return ap


def _baselines(args: argparse.Namespace, fleet) -> int:
    if fleet.baselines is None:
        print(
            f"hnx guests baselines: no baseline set in {args.directory} "
            "(_baselines.yml or --baselines)",
            file=sys.stderr,
        )
        return 1 if (args.check or args.require_bound) else 0
    report = coverage(fleet.sorted(), fleet.baselines)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(coverage_text(report), end="")
    if not (args.check or args.require_bound):
        return 0
    bad = [r["id"] for r in report["guests"] if r["missing"]]
    if bad:
        print(f"hnx guests baselines: no baseline or exemption: {', '.join(bad)}", file=sys.stderr)
    if args.require_bound and report["unbound"]:
        print(
            "hnx guests baselines: needed controls not bound to a role: "
            + ", ".join(report["unbound"]),
            file=sys.stderr,
        )
        bad.append("unbound")
    if args.require_bound and report["unplaced"]:
        print(
            "hnx guests baselines: central controls whose group holds no guest (nowhere to run): "
            + ", ".join(f"{c} ({report['controls'][c]['group']})" for c in report["unplaced"]),
            file=sys.stderr,
        )
        bad.append("unplaced")
    if not bad:
        print("baselines: ok")
    return 1 if bad else 0


def _registry_problems(args: argparse.Namespace, fleet) -> list[str]:
    """The registry's disagreements with the guests (none without a registry): an address or a
    zone, or a capability or capability group the registry does not place on the guest's host
    (ADR-0039 decision 7).  The registry is the one :func:`_fleet` read."""
    from homelabnext.registry.model import STANDINGS

    from .gen.registry_hosts import capability_problems, registry_problems

    reg = args.registry_doc
    if reg is None:
        return []
    return registry_problems(fleet, reg.hosts) + capability_problems(
        fleet, reg.rows(*STANDINGS), reg.hosts
    )


def _key_problems(fleet) -> list[str]:
    from .validate import unresolved_keys

    return [
        f"{gid}: cloudinit.ssh_authorized_keys names not in the keys file: {', '.join(names)}"
        for gid, names in unresolved_keys(fleet).items()
    ]


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(list(argv) if argv is not None else None)
    try:
        fleet = _fleet(args)
        problems = _registry_problems(args, fleet) if args.cmd == "validate" else []
        if args.cmd == "validate" and args.keys:
            problems += _key_problems(fleet)
        if args.cmd in ("render", "plan"):
            fleet = _on_node(fleet, args.node)
    except ComputeUnreadable as exc:  # docs/interfaces.md: bad input is 2, a failed check 1
        print(f"hnx guests: {exc}", file=sys.stderr)
        return 2
    except ComputeError as exc:
        print(f"hnx guests: {exc}", file=sys.stderr)
        return 1
    if args.cmd == "baselines":
        return _baselines(args, fleet)
    if args.cmd == "validate":
        if problems:
            print("\n".join(f"error: {p}" for p in problems), file=sys.stderr)
            print(f"hnx guests: validation failed ({len(problems)} errors)")
            return 1
        iac = len(fleet.iac())
        print(f"ok: {len(fleet.guests)} guests ({iac} rendered, {len(fleet.manual())} manual)")
        from .validate import usage_lines

        for line in usage_lines(fleet):
            print(f"  {line}")
        return 0
    files = render(fleet, args.target)
    if args.cmd == "render":
        if args.out:
            from pathlib import Path

            if args.target == "cloudinit" and (missing := _key_problems(fleet)):
                # a placeholder in written user-data boots a VM nobody can log in to
                print("\n".join(f"error: {m}" for m in missing), file=sys.stderr)
                print(
                    "hnx guests: refusing --out with unresolved ssh key names "
                    "(pass --keys with every name; stdout render keeps the placeholder)",
                    file=sys.stderr,
                )
                return 1

            from homelabnext.network.plan import stale, write_rendered

            from .gen._text import HEADER

            out, markers = Path(args.out), (HEADER,)
            left = [] if args.prune else stale(files, out, markers)
            touched = write_rendered(files, out, prune=args.prune, markers=markers)
            removed = sorted(set(touched) - set(files))
            print(f"wrote {len(files)} files to {args.out}")
            if removed:
                print(f"pruned {len(removed)} stale files: {', '.join(removed)}")
            if left:
                # a stale vm-*.tf keeps a removed guest under terraform, and an old <vmid>.fw
                # applies to whatever guest takes the vmid next
                print(
                    f"hnx guests: warning: {len(left)} generated files in {args.out} are no "
                    f"longer rendered ({', '.join(left)}); --prune deletes them",
                    file=sys.stderr,
                )
        else:
            for name in sorted(files):
                print(f"==> {name} <==")
                print(files[name], end="")
        return 0
    p = make_plan(read_tree(args.against), files)
    print(f"plan: {p.summary()}")
    print(p.diff, end="")
    # 3, not 2: 2 is an input that cannot be read, which must never read as "changes pending"
    return 3 if (args.exit_code and not p.empty) else 0


if __name__ == "__main__":
    sys.exit(main())
