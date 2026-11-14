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
from .render import SELECTION_TARGETS, TARGETS, render
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


#: targets whose output belongs to one hypervisor node, so ``--node`` may narrow them to it: the
#: hypervisor's IaC (one provider endpoint, one state), its ``virt-install`` scripts, the seeds of
#: the VMs it runs, the ``.fw`` files its firewall directory reads, its own traffic mirror and its
#: notification target.
#: Each generator module says so itself (``PER_NODE = True``); every other target is fleet-wide.
PER_NODE_TARGETS = frozenset(
    name for name, fn in TARGETS.items() if getattr(sys.modules[fn.__module__], "PER_NODE", False)
)
#: per-node targets whose output is made of the node's guests (node-mirror is made of the node's
#: ``_nodes.yml`` entry): rendered for a node with none, they are empty, and an empty Terraform
#: render applied to that node's state destroys everything in it
GUEST_TARGETS = frozenset(
    name
    for name in PER_NODE_TARGETS
    if getattr(sys.modules[TARGETS[name].__module__], "RENDERS_GUESTS", True)
)


def _node_arg(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--node",
        help="render only what belongs to this node (validation still covers every guest): a "
        "standalone hypervisor's Terraform must not carry another node's guests.  Only for the "
        f"per-node targets ({', '.join(sorted(PER_NODE_TARGETS))}); the fleet-wide targets "
        "render without it",
    )
    p.add_argument(
        "--allow-empty",
        action="store_true",
        help="with --node, render a node that no guest is placed on (an empty Terraform render "
        "destroys everything in that node's state; refused without this flag)",
    )


def _selection_arg(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--selection",
        help="a module selection (lab/modules.yml, checked by hnx modules check): the inventory "
        "target adds a mod_<module>_<host role> group per placed host role, holding the guest "
        "its selection host references (docs/modules/apply.md).  Inventory only",
    )


def _group_vars_arg(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--group-vars",
        metavar="DIR",
        help="the overlay's group variables (one <group>.yml per group, e.g. "
        "mod_<module>_<host role>.yml): carried into the render as group_vars/, beside "
        "hosts.yml, where Ansible reads them; a file for a group the inventory does not hold is "
        "refused.  Inventory only",
    )


def _selection(path: str | None) -> dict | None:
    """The module selection named by ``--selection``, schema-valid, or None.  Unreadable is
    :class:`ComputeUnreadable` (exit 2), schema-invalid a :class:`ComputeError` (exit 1)."""
    if path is None:
        return None
    from homelabnext.modules import loader as ld

    try:
        doc = ld.load_input(path, ld.Budget())
    except ld.Unreadable as exc:
        raise ComputeUnreadable(f"--selection {path}: {exc}") from None
    errs = ld._errors(ld._schema("platform", "module_selection.schema.json"), doc)
    if errs:
        raise ComputeError(f"--selection {path}: schema: {errs[0]}")
    return doc


def _dropped_module_groups(out, files: dict[str, str]) -> list[str]:
    """The module groups (``mod_*``, ``modhost_*``) the ``hosts.yml`` already in ``out`` holds and
    the one about to be written there does not: what an inventory render WITHOUT ``--selection``
    (or with another selection) would silently delete, and with it every module play's hosts
    (``ansible-playbook`` on an empty group matches no host and exits 0).  An existing file that
    cannot be read as an inventory is :class:`ComputeUnreadable` (exit 2): it may hold groups, and
    the guard must not fail open."""
    import yaml

    from homelabnext._yaml import safe_load
    from homelabnext.modules.apply import GROUP_PREFIX, HOST_GROUP_PREFIX

    def groups(text: str) -> set[str]:
        node = safe_load(text)
        for key in (
            "all",
            "children",
        ):  # an empty level holds no groups; a non-mapping is no inventory
            if node is None:
                return set()
            if not isinstance(node, dict):
                raise ValueError(f"{key} is not under a mapping")
            node = node.get(key)
        if node is None:
            return set()
        if not isinstance(node, dict):
            raise ValueError("all.children is not a mapping")
        return {g for g in node if str(g).startswith((GROUP_PREFIX, HOST_GROUP_PREFIX))}

    existing = out / "hosts.yml"
    if not existing.is_file():
        return []
    try:
        old = groups(existing.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError, ValueError, AttributeError) as exc:
        raise ComputeUnreadable(
            f"{existing} cannot be read as an inventory ({exc.__class__.__name__}), so the module "
            "groups it may hold cannot be checked: fix or remove it, or pass --drop-module-groups"
        ) from None
    return sorted(old - groups(files.get("hosts.yml", "")))


def _node_usage(args: argparse.Namespace) -> str | None:
    """Why ``--node``/``--allow-empty``/``--selection`` cannot be used as given (a usage error),
    or None."""
    if getattr(args, "selection", None) is not None and args.target not in SELECTION_TARGETS:
        return f"--selection is for the inventory target; {args.target} does not take it"
    if getattr(args, "drop_module_groups", False) and (
        args.cmd != "render" or args.target != "inventory" or not args.out
    ):
        return "--drop-module-groups is for `render --target inventory --out`"
    if getattr(args, "group_vars", None) is not None and args.target != "inventory":
        return f"--group-vars is for the inventory target; {args.target} does not take it"
    if args.node is None:
        return "--allow-empty needs --node" if args.allow_empty else None
    if args.target not in PER_NODE_TARGETS:
        return (
            f"--node is for the per-node targets ({', '.join(sorted(PER_NODE_TARGETS))}); "
            f"{args.target} is fleet-wide (one inventory, registry, policy or playbook for every "
            "node): render it without --node"
        )
    return None


def _on_node(fleet, node: str | None, target: str, allow_empty: bool = False):
    """The fleet narrowed to one node (its guests, and its own ``_nodes.yml`` entry), after the
    whole set validated.  A node that no guest and no ``_nodes.yml`` entry names is refused: a
    typo must not render an empty, harmless-looking plan.  So is a known node that holds none of
    the guests ``target`` renders, unless ``allow_empty``: Terraform would read that render as
    "destroy everything this node's state holds"."""
    if node is None:
        return fleet
    import dataclasses

    guests = tuple(g for g in fleet.guests if g.node == node)
    if not guests and node not in fleet.nodes:
        raise ComputeError(
            f"--node {node!r}: no guest is placed on it and _nodes.yml lists no such node"
        )
    nodes = {node: fleet.nodes[node]} if node in fleet.nodes else {}
    narrowed = dataclasses.replace(fleet, guests=guests, nodes=nodes)
    if target in GUEST_TARGETS and not narrowed.iac() and not allow_empty:
        raise ComputeError(
            f"--node {node!r}: no guest this target renders is placed on it, so the render "
            "would be empty (applied, an empty Terraform render destroys everything in the "
            "node's state); pass --allow-empty if that is what you mean"
        )
    return narrowed


def _print_user_data(fleet, user_data_guests, file: str) -> None:
    """The VMs whose plan needs a ``cloudinit_user_data`` entry, with each user-data's digest."""
    rows = user_data_guests(fleet)
    if not rows:
        return
    print(f"{len(rows)} VMs need a cloudinit_user_data snippet ({file}):")
    for g, digest in rows:
        shown = f"sha256 {digest}" if digest else "unresolved key names: render with --keys"
        print(f"  {g.name} (node {g.node}): {shown}")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="hnx guests", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("validate", help="schema and semantic validation")
    _common(v)
    r = sub.add_parser("render", help="render one target")
    _common(r)
    r.add_argument("--target", required=True, choices=sorted(TARGETS))
    _node_arg(r)
    _selection_arg(r)
    _group_vars_arg(r)
    r.add_argument("--out", help="write files here (default: print a file list)")
    r.add_argument(
        "--drop-module-groups",
        action="store_true",
        help="inventory --out: let this render delete the mod_*/modhost_* groups the hosts.yml "
        "already in --out holds and this render lacks (it is refused otherwise: render without "
        "--selection, or from another one, would silently drop every module's hosts)",
    )
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
    _selection_arg(pl)
    _group_vars_arg(pl)
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
    if args.cmd in ("render", "plan") and (usage := _node_usage(args)):
        print(f"hnx guests: {usage}", file=sys.stderr)
        return 2
    try:
        fleet = _fleet(args)
        problems = _registry_problems(args, fleet) if args.cmd == "validate" else []
        if args.cmd == "validate" and args.keys:
            problems += _key_problems(fleet)
        if args.cmd in ("render", "plan"):
            fleet = _on_node(fleet, args.node, args.target, args.allow_empty)
            selection = _selection(args.selection)
            if selection is not None:
                # a placement the inventory cannot hold is a failed check (1), never a traceback
                files = render(fleet, args.target, selection)
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
    if getattr(args, "selection", None) is None:
        files = render(fleet, args.target)
    if getattr(args, "group_vars", None) is not None:
        from .gen.inventory import group_vars

        try:
            files.update(group_vars(args.group_vars, files["hosts.yml"]))
        except ComputeUnreadable as exc:
            print(f"hnx guests: {exc}", file=sys.stderr)
            return 2
        except ComputeError as exc:
            print(f"hnx guests: {exc}", file=sys.stderr)
            return 1
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

            try:
                dropped = (
                    []
                    if args.target != "inventory" or args.drop_module_groups
                    else _dropped_module_groups(Path(args.out), files)
                )
            except ComputeUnreadable as exc:
                print(f"hnx guests: refusing --out {args.out}: {exc}", file=sys.stderr)
                return 2
            if dropped:
                print(
                    f"hnx guests: refusing --out {args.out}: its hosts.yml holds module groups "
                    f"this render lacks ({', '.join(dropped)}); a render without the "
                    "--selection that made them would delete them, and every module play "
                    "then matches no host.  Pass the same --selection, or "
                    "--drop-module-groups to drop them on purpose",
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
            gen = sys.modules[TARGETS[args.target].__module__]
            if hasattr(gen, "user_data_guests"):  # the hypervisor IaC target
                _print_user_data(fleet, gen.user_data_guests, gen.USER_DATA_FILE)
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
