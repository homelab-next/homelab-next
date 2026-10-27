# SPDX-License-Identifier: Apache-2.0
"""The core's own fleet units (docs/modules.md, "What the loader checks"): read from what
installs them (the core roles' tasks and the generators), never from a list kept for the check.
A running ``hnx-*`` unit that is neither a module's nor the core's is a problem, and no module
may declare a unit named like a core one."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

import pytest

from homelabnext.compute.gen import node_mirror
from homelabnext.modules import cli as mcli
from homelabnext.modules import egress
from homelabnext.modules import loader as ld

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "examples" / "modules"
ROLES_DIR = ROOT / "ansible" / "roles"
SLOTS = ld.load_yaml(EXAMPLES / "slots.yml")["slots"]
ROLES = json.loads((ROOT / "examples" / "model_roles.json").read_text())["roles"]
NOT_GATHERED = ["rows", "mcp_servers", "agents", "tables"]

#: a fleet unit named anywhere: ``hnx-<name>.service`` / ``.timer``, or a family
#: ``hnx-<prefix>-{{ ... }}`` (a template instance, ``hnx-<name>@``, is not a fleet unit)
NAMED = re.compile(r"hnx-([a-z0-9][a-z0-9-]*)\.(?:service|timer)\b")
FAMILY = re.compile(r"hnx-([a-z0-9][a-z0-9-]*-)\{\{")


def core_from(roles_dir: Path) -> ld.CoreNames:
    names, families, problems = ld.core_units(roles_dir)
    assert problems == []
    core, found = ld.core_names(None, units=(names, families))
    assert found == []
    return core


CORE = core_from(ROLES_DIR)


def unaccounted(tree: Path, suffixes: tuple[str, ...], core: ld.CoreNames) -> list[str]:
    """Every fleet unit a file under ``tree`` names that is not one of ``core``'s."""
    out = []
    for f in sorted(tree.rglob("*")):
        if not f.is_file() or f.suffix not in suffixes or "__pycache__" in f.parts:
            continue
        text = f.read_text(errors="replace")
        rel = f.relative_to(tree).as_posix()
        out += [f"{rel}: {n}" for n in NAMED.findall(text) if not core.is_unit(n)]
        out += [f"{rel}: {p}*" for p in FAMILY.findall(text) if p not in core.unit_families]
    return out


def write_role(roles: Path, name: str, tasks: str) -> None:
    d = roles / name / "tasks"
    d.mkdir(parents=True)
    (d / "main.yml").write_text(tasks)


# ----------------------------------------------------------------------------- the source


def test_every_unit_a_core_role_or_generator_names_is_a_core_unit():
    """The guard on the derivation: a unit a role installs or enables some other way than a
    ``dest:`` the loader reads (a handler, a command, a template), or one a generator writes
    without its ``UNIT``, fails here until the loader reads it."""
    assert unaccounted(ROLES_DIR, (".yml", ".yaml", ".j2", ".sh", ".py", ""), CORE) == []
    assert unaccounted(ROOT / "homelabnext", (".py",), CORE) == []


def test_the_generators_units_are_core_units():
    assert CORE.units_known
    assert egress.UNIT in CORE.units and node_mirror.UNIT in CORE.units


def test_the_guard_fails_on_a_unit_the_loader_does_not_read(tmp_path):
    """A role that enables a unit it never installs through a ``dest:`` (here a loop of
    ``systemctl`` arguments) is a unit the derivation misses: the guard names it."""
    roles = tmp_path / "roles"
    write_role(roles, "alpha", "- ansible.builtin.command: systemctl enable hnx-alpha.timer\n")
    core = core_from(roles)
    assert "alpha" not in core.units
    assert unaccounted(roles, (".yml",), core) == ["alpha/tasks/main.yml: alpha"]


def test_a_role_installs_units_and_families_through_dest(tmp_path):
    roles = tmp_path / "roles"
    write_role(
        roles,
        "alpha",
        "- ansible.builtin.template:\n"
        "    src: 'scan.{{ item }}.j2'\n"
        '    dest: "{{ alpha_unit_dir }}/hnx-alpha.{{ item }}"\n'
        "  loop: [service, timer]\n"
        "- ansible.builtin.copy:\n"
        "    dest: /etc/systemd/system/hnx-beta.service\n",
    )
    write_role(
        roles,
        "gamma",
        "- ansible.builtin.template:\n"
        '    dest: "{{ gamma_unit_dir }}/hnx-gamma-{{ item.name }}.service"\n',
    )
    core = core_from(roles)
    assert {"alpha", "beta"} <= core.units
    assert core.unit_families == {"gamma-"}
    assert core.is_unit("gamma-one") and not core.is_unit("gamma-")
    assert not core.is_unit("delta")


def test_an_unreadable_roles_tree_is_a_registry_problem(tmp_path):
    real = tmp_path / "real"
    write_role(real, "alpha", "- {}\n")
    linked = tmp_path / "linked"
    linked.symlink_to(real)
    assert ld.core_units(linked)[2] == [
        ld.Problem("registry", "the core's roles linked/ is not a directory")
    ]
    fifo_roles = tmp_path / "fifo"
    (fifo_roles / "alpha" / "tasks").mkdir(parents=True)
    os.mkfifo(fifo_roles / "alpha" / "tasks" / "main.yml")
    problems = ld.core_units(fifo_roles)[2]
    assert [p.where for p in problems] == ["registry"] and "alpha/main.yml" in str(problems[0])


# ----------------------------------------------------------------------------- the check


def run(units, *, empty=True, core=CORE, site=None):
    tree, _ = ld.discover(ROOT / "modules", EXAMPLES, None)
    inventory = {"schema_version": "1.0", "units": units, "not_gathered": NOT_GATHERED}
    report = ld.check(
        tree, slots=SLOTS, roles=ROLES, in_tree_roots=(ROOT / "modules", EXAMPLES), core=core,
        site=site, inventory=inventory, empty_selection=empty,
    )  # fmt: skip
    return [str(p) for p in report.problems if p.where == "running"], report.notes


@pytest.mark.parametrize("empty", [True, False])
def test_a_running_unit_of_no_module_and_not_the_cores_is_a_problem(empty):
    site = None if empty else ld.load_yaml(EXAMPLES / "sites" / "small-lab.yml")
    family = next(iter(CORE.unit_families))
    got, _ = run([egress.UNIT, family + "one", "backdoor"], empty=empty, site=site)
    assert "running: units backdoor runs but is no module's or the core's" in got
    assert not any(egress.UNIT in g or family + "one" in g for g in got)


def test_without_the_cores_units_a_unit_of_no_module_is_noted_not_judged():
    got, notes = run(["backdoor"], core=ld.CoreNames())
    assert got == []
    assert any("the core's own units were not read" in n for n in notes)


def test_a_module_may_not_declare_a_unit_named_like_a_core_unit():
    tree, _ = ld.discover(fixtures=EXAMPLES)
    core = ld.CoreNames(unit_families=frozenset({"publishing-"}), units_known=True)
    report = ld.check(tree, slots=SLOTS, roles=ROLES, in_tree_roots=(EXAMPLES,), core=core)
    assert "publishing: unit publishing-run is a core unit" in [str(p) for p in report.problems]


# ----------------------------------------------------------------------------- the command


def test_a_deploy_without_the_cores_roles_is_a_registry_problem(tmp_path, capsys):
    """``--root`` is the pinned checkout the deploy runs from: without its roles the core's units
    cannot be read, which a deploy refuses (a plain check notes it)."""
    root = tmp_path / "root"
    root.mkdir()
    for part in ("modules", "examples", "schemas"):
        (root / part).symlink_to(ROOT / part)
    lab = tmp_path / "overlay" / "lab"
    lab.mkdir(parents=True)
    missing = "registry: the core's roles (ansible/roles under --root) are missing"
    args = ["check", "--root", str(root), "--overlay", str(lab.parent), "--json"]
    assert mcli.main([*args, "--deploy"]) == 1
    doc = json.loads(capsys.readouterr().out)
    assert any(p.startswith(missing) for p in doc["problems"]), doc
    mcli.main(args)
    doc = json.loads(capsys.readouterr().out)
    assert not any(p.startswith(missing) for p in doc["problems"]), doc
    assert any("the core's own units were not read" in n for n in doc["notes"]), doc
