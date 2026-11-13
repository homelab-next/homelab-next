# SPDX-License-Identifier: Apache-2.0
"""The module apply path (docs/modules/apply.md): from a checked selection, the inventory groups
``mod_<module>_<host role>`` (``hnx guests render --target inventory --selection``) and the
playbooks ``hnx modules render`` writes (``modules.yml``, ``checks/<module>.yml``).

Goldens pin both renders; each refusal (a stand-in host, an unknown guest, a group-name clash, a
requirement cycle, a role the module does not contribute) is shown on a planted defect; the
playbooks pass ``ansible-playbook --syntax-check`` and run against real role directories, and
every play targets a module group only (``role_lint`` PB001)."""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from homelabnext import cli as hnx
from homelabnext.compute import load_fleet, render
from homelabnext.compute.plan import read_tree
from homelabnext.compute.zones import site_facts
from homelabnext.modules import apply
from homelabnext.modules import cli as mcli
from homelabnext.modules import loader as ld
from homelabnext.modules.rules import selected

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
EXAMPLES = ROOT / "examples" / "modules"
GOLDEN = HERE / "golden" / "apply"
SITE = HERE / "fixtures" / "selection.guest-hosts.yml"
GUESTS = HERE / "fixtures" / "guests"
COMPUTE = ROOT / "tests" / "compute"
FLEET = COMPUTE / "fleet"
FLEET_SELECTION = COMPUTE / "selection.modules.yml"
#: how the golden playbooks reach the example modules (a render's relative module directory)
DIRS_PREFIX = "../examples/modules"


@pytest.fixture(scope="module")
def tree():
    tree, found = ld.discover(fixtures=EXAMPLES)
    assert found == []
    return tree


def _dirs(sel) -> dict[str, str]:
    return {m: f"{DIRS_PREFIX}/{m}" for m in sel}


def _limits(site, tree) -> dict[str, str]:
    from homelabnext.modules import limits

    return limits.render(site, tree.mods, ld.units_fn(ld.inputs(tree)))


def _books(site, tree, with_limits: bool = True) -> dict[str, str]:
    sel = selected(site, tree.mods)
    return apply.render(site, sel, _dirs(sel), _limits(site, tree) if with_limits else None)


@pytest.fixture(scope="module")
def fleet():
    facts = site_facts(str(COMPUTE / "site.yml"))
    return load_fleet(FLEET, facts["zones"], domain=facts["domain"] or "example.internal")


def _golden(name: str, out: dict[str, str]) -> None:
    gdir = GOLDEN / name
    if os.environ.get("HNX_UPDATE_GOLDEN") == "1":
        shutil.rmtree(gdir, ignore_errors=True)
        for rel, text in out.items():
            (gdir / rel).parent.mkdir(parents=True, exist_ok=True)
            (gdir / rel).write_text(text, encoding="utf-8")
    want = read_tree(gdir)
    assert set(out) == set(want), f"file set differs: {set(out) ^ set(want)}"
    for rel in out:
        assert out[rel] == want[rel], f"{name}/{rel} differs from golden"


# ----------------------------------------------------------------------------- goldens


def test_playbooks_match_golden(tree):
    out = _books(ld.load_yaml(SITE), tree)
    assert out == _books(ld.load_yaml(SITE), tree)  # a pure function of its inputs
    _golden("playbooks", out)


def test_inventory_with_a_selection_matches_golden(fleet):
    sel = ld.load_yaml(FLEET_SELECTION)
    out = render(fleet, "inventory", sel)
    assert out == render(fleet, "inventory", sel)
    _golden("inventory", {"hosts.yml": out["hosts.yml"]})
    # only groups are added: the host variables are the inventory's own
    plain = render(fleet, "inventory")
    assert {k: v for k, v in out.items() if k != "hosts.yml"} == {
        k: v for k, v in plain.items() if k != "hosts.yml"
    }
    added = set(yaml.safe_load(out["hosts.yml"])["all"]["children"]) - set(
        yaml.safe_load(plain["hosts.yml"])["all"]["children"]
    )
    assert added == {
        "mod_example_inference_server",
        "mod_example_object_store_store",
        "mod_example_siem_suite_suite",
        "mod_external_collector_receiver",
        # one per lab site host a module is placed on: its limits play's target
        "modhost_bus",
        "modhost_infer",
        "modhost_lake",
    }


def test_two_instances_share_their_group_and_an_external_host_gets_none(fleet):
    groups = yaml.safe_load(render(fleet, "inventory", ld.load_yaml(FLEET_SELECTION))["hosts.yml"])
    kids = groups["all"]["children"]
    assert set(kids["mod_example_object_store_store"]["hosts"]) == {
        "infer-core.example.internal",
        "lake-core.example.internal",
    }
    assert "mod_external_collector_edge" not in kids


# ----------------------------------------------------------------------------- naming


def test_the_group_name_is_the_module_and_host_role_with_underscores():
    assert apply.module_group("web-app", "server") == "mod_web_app_server"
    assert apply.module_group("external-collector", "edge-relay") == (
        "mod_external_collector_edge_relay"
    )


def _site(**placed) -> dict:
    """A selection placing feature ``<module>``'s ``<role>`` on host ``h`` (a guest)."""
    return {
        "profile": "t",
        "hosts": {"h": {"guest": "guest:g"}},
        "slots": {},
        "features": {m: {"placement": {r: "h"}} for m, r in placed.items()},
    }


def test_a_group_name_clash_is_refused():
    site = _site(**{"a-b": "c"})
    site["features"]["a"] = {"placement": {"b-c": "h"}}
    with pytest.raises(apply.ApplyError, match=r"mod_a_b_c: the group of a/b-c and of a-b/c"):
        apply.inventory_groups(site, {"guest:g": "g.example.internal"}.get)


def test_a_module_group_may_not_take_a_guest_model_group_name():
    with pytest.raises(apply.ApplyError, match="mod_x_y: a module group with the name"):
        apply.inventory_groups(
            _site(x="y"), {"guest:g": "g.example.internal"}.get, frozenset({"mod_x_y"})
        )


def test_a_stand_in_host_and_an_unknown_guest_are_refused_by_name():
    site = _site(x="y")
    site["hosts"]["h"] = {"kind": "vm", "capacity": {"cpu": 1, "memory_mb": 512, "disk_gb": 1}}
    with pytest.raises(apply.ApplyError, match=r"x/y: placed on h, a stand-in host"):
        apply.inventory_groups(site, {}.get)
    with pytest.raises(apply.ApplyError, match=r"x/y: hosts.h references guest:g, which is no"):
        apply.inventory_groups(_site(x="y"), {}.get)
    site = _site(x="y")
    site["features"]["x"]["placement"]["y"] = "nowhere"
    with pytest.raises(apply.ApplyError, match="placed on nowhere, which hosts does not define"):
        apply.inventory_groups(site, {}.get)


def test_the_cli_refuses_a_placement_the_inventory_cannot_hold(tmp_path, capsys):
    bad = ld.load_yaml(FLEET_SELECTION)
    bad["hosts"]["lake"] = {"guest": "guest:no-such"}
    p = tmp_path / "sel.yml"
    p.write_text(yaml.safe_dump(bad))
    code = _guests_render("--selection", str(p))
    assert code == 1
    assert "references guest:no-such, which is no guest here" in capsys.readouterr().err


# ----------------------------------------------------------------------------- the guests CLI


def _guests_render(*args: str, target: str = "inventory") -> int:
    return hnx.main(
        ["guests", "render", str(FLEET), "--site", str(COMPUTE / "site.yml"),
         "--target", target, *args]
    )  # fmt: skip


def test_selection_is_for_the_inventory_target_only(capsys):
    assert _guests_render("--selection", str(FLEET_SELECTION), target="cloudinit") == 2
    assert "--selection is for the inventory target" in capsys.readouterr().err


def test_an_unreadable_selection_is_2_and_an_invalid_one_1(tmp_path, capsys):
    assert _guests_render("--selection", str(tmp_path / "missing.yml")) == 2
    p = tmp_path / "sel.yml"
    p.write_text(yaml.safe_dump({"profile": "t", "hosts": {}}))  # no slots
    assert _guests_render("--selection", str(p)) == 1
    assert "schema" in capsys.readouterr().err


def test_the_cli_writes_the_groups_and_plan_takes_the_selection(tmp_path, capsys):
    out = tmp_path / "inv"
    assert _guests_render("--selection", str(FLEET_SELECTION), "--out", str(out)) == 0
    assert "mod_example_siem_suite_suite:" in (out / "hosts.yml").read_text()
    capsys.readouterr()
    code = hnx.main(
        ["guests", "plan", str(FLEET), "--site", str(COMPUTE / "site.yml"), "--target",
         "inventory", "--selection", str(FLEET_SELECTION), "--against", str(out), "--exit-code"]
    )  # fmt: skip
    assert code == 0, capsys.readouterr().out


# ----------------------------------------------------------------------------- install order


def _mod(mid: str, *requires: str, roles=("main",), kind="vm") -> dict:
    """A minimal manifest: one host role ``server`` with roles ``<id_>_<name>``."""
    names = [
        f"{mid.replace('-', '_')}_{r}" if r != "main" else mid.replace("-", "_") for r in roles
    ]
    return {
        "id": mid,
        "kind": "provider",
        "version": "0.1.0",
        "requires": {
            "capabilities": [
                {
                    "cap": f"cap:{c.split('/')[0]}",
                    **({"instance": c.split("/")[1]} if "/" in c else {}),
                }
                for c in requires
            ],
            "hosts": [
                {
                    "role": "server",
                    "kind": kind,
                    "footprint": {},
                    "roles": [f"role:{n}" for n in names],
                }
            ],
        },
        "contributes": {"roles": [{"file": f"roles/{n}"} for n in names]},
    }


def _sel_site(**slots) -> dict:
    """``slot=[(provider, instance), ...]``, each placed on host ``h``."""
    return {
        "profile": "t",
        "hosts": {"h": {"guest": "guest:g"}},
        "slots": {
            s: [{"provider": p, "instance": i, "placement": {"server": "h"}} for p, i in rows]
            for s, rows in slots.items()
        },
    }


def test_a_module_installs_after_the_providers_it_requires():
    sel = {"app": _mod("app", "secrets"), "vault": _mod("vault"), "aaa": _mod("aaa", "notify")}
    site = _sel_site(secrets=[("vault", "v")], notify=[("app", "n")], other=[("aaa", "o")])
    # aaa sorts first but needs app, which needs vault
    assert apply.install_order(site, sel) == ["vault", "app", "aaa"]


def test_an_instance_requirement_orders_only_after_that_instance():
    sel = {"z": _mod("z"), "b": _mod("b"), "c": _mod("c", "notify/second")}
    site = _sel_site(notify=[("z", "first"), ("b", "second")], x=[("c", "c")])
    assert apply.install_order(site, sel) == ["b", "c", "z"]  # c waits for b only
    sel["c"] = _mod("c", "notify")  # no instance: after every provider of the slot
    assert apply.install_order(site, sel) == ["b", "z", "c"]


def test_an_incumbent_or_a_self_requirement_orders_nothing():
    sel = {"z": _mod("z", "secrets", "notify"), "a": _mod("a")}
    site = _sel_site(notify=[("z", "z")], x=[("a", "a")])
    site["incumbents"] = {"secrets": {"service": "vault-core", "why": "served by the core"}}
    assert apply.install_order(site, sel) == ["a", "z"]


def test_a_requirement_cycle_is_refused_naming_its_modules():
    sel = {"a": _mod("a", "y"), "b": _mod("b", "x"), "c": _mod("c")}
    site = _sel_site(x=[("a", "a")], y=[("b", "b")], z=[("c", "c")])
    with pytest.raises(apply.ApplyError, match=r"form a cycle.*: a, b$"):
        apply.install_order(site, sel)


# ----------------------------------------------------------------------------- the playbooks


def test_every_play_targets_its_module_group_in_install_order(tree):
    site = ld.load_yaml(SITE)
    out = _books(site, tree)
    guard, *plays = yaml.safe_load(out[apply.PLAYBOOK])
    sel = selected(site, tree.mods)
    order = apply.install_order(site, sel)
    # the first play refuses an inventory that lacks any group a later play targets
    assert guard["hosts"] == "localhost" and guard["tags"] == ["always"]
    assert guard["tasks"][0]["loop"] == [p["hosts"] for p in plays]
    # every site host's limits play comes before every module play
    lim = [p for p in plays if p["hosts"].startswith(apply.HOST_GROUP_PREFIX)]
    assert lim and plays[: len(lim)] == lim
    assert [p["hosts"] for p in lim] == ["modhost_core", "modhost_data"]
    plays = plays[len(lim) :]
    seen = [p["hosts"] for p in plays]
    assert all(h.startswith("mod_") for h in seen)
    mods = [next(m for m in order if p["tags"][0] == "mod_" + m.replace("-", "_")) for p in plays]
    assert mods == sorted(mods, key=order.index)
    assert all(p["become"] is True for p in plays)
    # the external role is a comment, never a play
    assert "mod_external_collector_edge" not in seen
    assert "external-collector: host role edge: an external role" in out[apply.PLAYBOOK]
    # a check playbook per placed module, readiness before health on each role
    for rel, text in out.items():
        if rel == apply.PLAYBOOK:
            continue
        for play in yaml.safe_load(text)[1:]:
            hooks = [t["ansible.builtin.include_role"]["tasks_from"] for t in play["tasks"]]
            assert hooks == sorted(hooks, key=lambda h: h != "readiness")
            assert play["hosts"].startswith("mod_")


def test_a_role_the_module_does_not_contribute_is_refused():
    sel = {"a": _mod("a")}
    sel["a"]["requires"]["hosts"][0]["roles"].append("role:a_other")
    with pytest.raises(apply.ApplyError, match="role:a_other is not a role the module contributes"):
        apply.render(_sel_site(x=[("a", "a")]), sel, {"a": "../m/a"})


def test_a_placement_on_an_undeclared_host_role_is_refused():
    site = _sel_site(x=[("a", "a")])
    site["slots"]["x"][0]["placement"] = {"worker": "h"}
    with pytest.raises(apply.ApplyError, match="placement names worker"):
        apply.render(site, {"a": _mod("a")}, {"a": "../m/a"})


def test_a_host_role_without_roles_is_a_comment_and_nothing_placed_is_a_no_op():
    sel = {"a": _mod("a", roles=())}
    out = apply.render(_sel_site(x=[("a", "a")]), sel, {"a": "../m/a"})
    assert "module a: host role server: lists no roles" in out[apply.PLAYBOOK]
    assert yaml.safe_load(out[apply.PLAYBOOK]) == [
        {"name": "no module to apply", "hosts": "localhost", "gather_facts": False}
    ]
    assert set(out) == {apply.PLAYBOOK}


def test_the_render_clash_check_matches_the_inventory():
    sel = {"a-b": _mod("a-b"), "a": _mod("a")}
    sel["a"]["requires"]["hosts"][0]["role"] = "b-server"
    site = _sel_site(x=[("a-b", "x")])
    site["slots"]["y"] = [{"provider": "a", "instance": "y", "placement": {"b-server": "h"}}]
    sel["a-b"]["requires"]["hosts"][0]["role"] = "server"
    # a-b/server and a/b-server are both mod_a_b_server
    with pytest.raises(apply.ApplyError, match="mod_a_b_server"):
        apply.render(site, sel, {"a": "../m/a", "a-b": "../m/a-b"})


# ----------------------------------------------------------------------------- the modules CLI


def test_modules_render_writes_the_playbooks_with_relative_role_paths(tmp_path, capsys):
    out = tmp_path / "render"
    code = mcli.main(
        ["render", "--root", str(ROOT), "--examples", "--site", str(SITE), "--guests",
         str(GUESTS), "--out", str(out), "--json"]
    )  # fmt: skip
    doc = json.loads(capsys.readouterr().out)
    assert code == 0, doc
    assert doc["written"]["checks"] == 7
    text = (out / apply.PLAYBOOK).read_text()
    paths = [ln.split('"')[1] for ln in text.splitlines() if "role: " in ln or 'name: ".' in ln]
    assert paths and not any(os.path.isabs(p) for p in paths)  # relative to the render
    want = os.path.relpath(EXAMPLES / "example-object-store", out.resolve())
    assert f'- role: "{want}/roles/example_object_store"' in text
    assert (
        sorted(p.name for p in (out / apply.CHECKS_DIR).iterdir())[0] == "example-agent-runtime.yml"
    )


# ----------------------------------------------------------------------------- ansible itself


def _stub_roles(base: Path, sel: dict) -> dict[str, str]:
    """Real role directories for every role the selected manifests contribute: each hook writes
    one debug line, so a run shows which hooks ran and in what order."""
    for mid, doc in sel.items():
        for e in doc.get("contributes", {}).get("roles", []):
            tasks = base / mid / e["file"] / "tasks"
            tasks.mkdir(parents=True, exist_ok=True)
            name = Path(e["file"]).name
            for hook in ("main", *apply.CHECK_HOOKS):
                (tasks / f"{hook}.yml").write_text(
                    f"- name: {hook}\n  ansible.builtin.debug: {{msg: 'hook {name} {hook}'}}\n"
                    f"  tags: [{hook}]\n"
                )
    return {m: f"../modules/{m}" for m in sel}


def _ansible(tmp_path: Path, *args: str) -> subprocess.CompletedProcess:
    env = dict(os.environ, ANSIBLE_HOME=str(tmp_path / ".ansible"), ANSIBLE_NOCOLOR="1")
    return subprocess.run(
        ["ansible-playbook", *args], capture_output=True, text=True, env=env, cwd=tmp_path,
        timeout=300,
    )  # fmt: skip


@pytest.mark.requires_tool("ansible-playbook")
def test_the_playbooks_run_against_real_roles_on_the_rendered_inventory(tmp_path, tree, fleet):
    site = ld.load_yaml(FLEET_SELECTION)
    sel = selected(site, tree.mods)
    books = apply.render(site, sel, _stub_roles(tmp_path / "modules", sel))
    (tmp_path / "out").mkdir()
    for rel, text in books.items():
        (tmp_path / "out" / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / "out" / rel).write_text(text)
    # the rendered inventory, every guest reached locally
    inv = yaml.safe_load(render(fleet, "inventory", site)["hosts.yml"])
    for name in inv["all"]["children"]["guests"]["hosts"]:
        inv["all"]["children"]["guests"]["hosts"][name] = {
            "ansible_connection": "local", "ansible_python_interpreter": sys.executable,
        }  # fmt: skip
    (tmp_path / "hosts.yml").write_text(yaml.safe_dump(inv))
    pb = str(tmp_path / "out" / apply.PLAYBOOK)
    r = _ansible(tmp_path, "--syntax-check", "-i", "hosts.yml", pb)
    assert r.returncode == 0, r.stdout + r.stderr
    # one module alone, without escalation (the test runs unprivileged)
    r = _ansible(tmp_path, "-i", "hosts.yml", pb, "--tags", "mod_example_inference", "-e",
                 "ansible_become=false")  # fmt: skip
    assert r.returncode == 0, r.stdout + r.stderr
    ran = [ln.split("hook ", 1)[1].rstrip('"') for ln in r.stdout.splitlines() if '"hook ' in ln]
    # its preflight readiness hook (contributes.preflight), then the role
    assert ran == ["example_inference readiness", "example_inference main"], r.stdout
    check = str(tmp_path / "out" / apply.CHECKS_DIR / "example-object-store.yml")
    r = _ansible(tmp_path, "-i", "hosts.yml", check, "-e", "ansible_become=false")
    assert r.returncode == 0, r.stdout + r.stderr
    ran = [ln.split("hook ", 1)[1].rstrip('"') for ln in r.stdout.splitlines() if '"hook ' in ln]
    # two guests hold the group: each runs readiness, then health
    assert ran == ["example_object_store readiness"] * 2 + ["example_object_store health"] * 2
    r = _ansible(tmp_path, "-i", "hosts.yml", check, "--tags", "health", "-e",
                 "ansible_become=false")  # fmt: skip
    assert r.returncode == 0, r.stdout + r.stderr
    assert "readiness" not in "".join(ln for ln in r.stdout.splitlines() if '"hook ' in ln)


def test_role_lint_finds_no_play_on_a_host_name(tmp_path, tree, fleet):
    spec = importlib.util.spec_from_file_location(
        "role_lint_apply", ROOT / "tools" / "role_lint.py"
    )
    role_lint = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = role_lint  # its dataclasses look their module up
    spec.loader.exec_module(role_lint)
    site = ld.load_yaml(FLEET_SELECTION)
    books = _books(site, tree)
    inv = tmp_path / "hosts.yml"
    inv.write_text(render(fleet, "inventory", site)["hosts.yml"])
    for rel, text in books.items():
        pb = tmp_path / rel.replace("/", "_")
        pb.write_text(text)
        assert [f for f in role_lint.lint_playbook(pb, inv) if f.rule.startswith("PB")] == []
    # the lint does catch a play on a host name in the same inventory
    bad = tmp_path / "bad.yml"
    bad.write_text("- hosts: lake-core.example.internal\n  tasks: []\n")
    assert any(f.rule == "PB001" for f in role_lint.lint_playbook(bad, inv))


def test_a_cycle_in_the_selection_fails_the_render_cleanly(tree):
    site = copy.deepcopy(ld.load_yaml(SITE))
    sel = copy.deepcopy(selected(site, tree.mods))
    # make the platform require the object store, which requires secrets from the platform
    sel["example-platform"]["requires"].setdefault("capabilities", []).append(
        {"cap": "cap:object-store", "version": "1.0"}
    )
    with pytest.raises(apply.ApplyError, match="example-object-store, example-platform"):
        apply.render(site, sel, _dirs(sel))


# ----------------------------------------------------------------------------- review fixes


@pytest.mark.requires_tool("ansible-playbook")
def test_a_missing_module_group_fails_the_run_instead_of_matching_nothing(tmp_path, tree, fleet):
    """Without the guard, a play on a group the inventory lacks is "no hosts matched", exit 0."""
    site = ld.load_yaml(FLEET_SELECTION)
    sel = selected(site, tree.mods)
    books = apply.render(site, sel, _stub_roles(tmp_path / "modules", sel))
    for rel, text in books.items():
        (tmp_path / "out" / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / "out" / rel).write_text(text)
    # the inventory rendered WITHOUT --selection: no mod_* group
    (tmp_path / "hosts.yml").write_text(render(fleet, "inventory")["hosts.yml"])
    for pb, tags in (
        (apply.PLAYBOOK, ()),
        (apply.PLAYBOOK, ("--tags", "mod_example_inference")),
        (f"{apply.CHECKS_DIR}/example-object-store.yml", ("--tags", "health")),
    ):
        r = _ansible(tmp_path, "-i", "hosts.yml", str(tmp_path / "out" / pb), *tags)
        assert r.returncode != 0, pb
        assert "holds no host" in r.stdout, r.stdout


def test_plays_carry_only_the_module_tag():
    """Module a-b's tag is mod_a_b, and so would be module a's host role b's group tag."""
    sel = {"a-b": _mod("a-b"), "a": _mod("a")}
    sel["a"]["requires"]["hosts"][0]["role"] = "b"
    site = _sel_site(x=[("a-b", "x")])
    site["slots"]["y"] = [{"provider": "a", "instance": "y", "placement": {"b": "h"}}]
    plays = yaml.safe_load(
        apply.render(site, sel, {"a": "../m/a", "a-b": "../m/a-b"})["modules.yml"]
    )
    by_hosts = {p["hosts"]: p["tags"] for p in plays}
    assert by_hosts["mod_a_b"] == ["mod_a"]
    assert by_hosts["mod_a_b_server"] == ["mod_a_b"]
    assert by_hosts["localhost"] == ["always"]


def test_a_cycle_error_names_the_cycle_not_what_waits_on_it():
    sel = {"a": _mod("a", "y"), "b": _mod("b", "x"), "d": _mod("d", "x")}
    site = _sel_site(x=[("a", "a")], y=[("b", "b")], z=[("d", "d")])
    with pytest.raises(apply.ApplyError) as ei:
        apply.install_order(site, sel)
    assert str(ei.value).endswith(": a, b")  # d only waits for a


@pytest.mark.parametrize(
    "edit, why",
    [
        (lambda s: s["a"].update(kind="feature\n- hosts: all"), "kind"),
        (lambda s: s["a"].update(version="1.0 {{ lookup('pipe', 'id') }}"), "version"),
        (lambda s: s["a"]["contributes"]["roles"][0].update(file="roles/{{x}}"), "role path"),
        (lambda s: s["a"]["contributes"].update(preflight=[{"role": "role:a", "hook": "main"}]),
         "preflight hook"),
    ],
)  # fmt: skip
def test_render_refuses_a_value_that_would_add_yaml_or_jinja(edit, why):
    """The schema blocks these; render() holds them to their shape even without it."""
    sel = {"a": _mod("a")}
    sel["a"]["requires"]["hosts"][0]["roles"] = ["role:a"]
    sel["a"]["contributes"]["roles"] = [{"file": "roles/a"}]
    edit(sel)
    if why == "role path":
        sel["a"]["requires"]["hosts"][0]["roles"] = ["role:{{x}}"]
    with pytest.raises(apply.ApplyError, match=why):
        apply.render(_sel_site(x=[("a", "a")]), sel, {"a": "../m/a"})
    bad = _sel_site(x=[("a", "a")])
    bad["slots"]["x"][0]["placement"] = {"s\n- hosts: all": "h"}
    with pytest.raises(apply.ApplyError, match="host role"):
        apply.render(bad, {"a": _mod("a")}, {"a": "../m/a"})


def test_a_refused_render_writes_no_playbook(tmp_path, capsys, monkeypatch):
    def boom(*_a, **_k):
        raise apply.ApplyError("planted: no install order exists")

    monkeypatch.setattr(apply, "render", boom)
    out = tmp_path / "render"
    code = mcli.main(
        ["render", "--root", str(ROOT), "--examples", "--site", str(SITE), "--guests",
         str(GUESTS), "--out", str(out)]
    )  # fmt: skip
    assert code == 1
    assert "planted: no install order exists" in capsys.readouterr().err
    assert not (out / apply.PLAYBOOK).exists()


def test_the_writer_never_follows_a_link_planted_in_the_render(tmp_path):
    out = tmp_path / "render"
    out.mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (out / apply.CHECKS_DIR).symlink_to(elsewhere)
    with pytest.raises(ld.LoaderError, match="symbolic link"):
        mcli._write_new(out, {f"{apply.CHECKS_DIR}/a.yml": "x\n"})
    assert list(elsewhere.iterdir()) == []
    (out / "modules.yml").write_text("planted\n")
    with pytest.raises(FileExistsError):
        mcli._write_new(out, {"modules.yml": "x\n"})


# ----------------------------------------------------------------------------- module limits


def _write_books(base: Path, books: dict[str, str], lim: dict[str, str]) -> None:
    for rel, text in [*books.items(), *((f"limits/{r}", t) for r, t in lim.items())]:
        (base / rel).parent.mkdir(parents=True, exist_ok=True)
        (base / rel).write_text(text)


#: a quota script stand-in: --check exits 3 until the apply ran once on this host, then 0; every
#: call is logged, so a run shows what ran in what order
QUOTA_STUB = """#!/bin/sh
echo "quota $HOST ${1:-apply}" >> "$QLOG"
if [ "${1:-}" = --check ]; then [ -e "$QDIR/$HOST.capped" ] && exit 0; exit 3; fi
: > "$QDIR/$HOST.capped"
"""


@pytest.mark.requires_tool("ansible-playbook")
def test_the_limits_are_installed_before_the_modules_and_a_rerun_changes_nothing(
    tmp_path, tree, fleet
):
    site = ld.load_yaml(FLEET_SELECTION)
    sel = selected(site, tree.mods)
    lim = _limits(site, tree)
    books = apply.render(site, sel, _stub_roles(tmp_path / "modules", sel), lim)
    hosts = sorted({rel.split("/")[0] for rel in lim if "/" in rel})
    assert hosts == ["bus", "infer", "lake"]
    for h in hosts:  # the stand-in runs instead of the real script (which needs root)
        if f"{h}/{apply.QUOTA_SCRIPT}" in lim:
            lim[f"{h}/{apply.QUOTA_SCRIPT}"] = QUOTA_STUB.replace("$HOST", h)
    _write_books(tmp_path / "out", books, lim)
    inv = yaml.safe_load(render(fleet, "inventory", site)["hosts.yml"])
    for name in inv["all"]["children"]["guests"]["hosts"]:
        inv["all"]["children"]["guests"]["hosts"][name] = {
            "ansible_connection": "local", "ansible_python_interpreter": sys.executable,
        }  # fmt: skip
    (tmp_path / "hosts.yml").write_text(yaml.safe_dump(inv))
    bin_, units, sbin, qdir = (tmp_path / d for d in ("bin", "units", "sbin", "q"))
    for d in (bin_, units, sbin, qdir):
        d.mkdir()
    (bin_ / "systemctl").write_text('#!/bin/sh\necho "systemctl $*" >> "$QLOG"\n')
    (bin_ / "systemctl").chmod(0o755)
    log = tmp_path / "calls.log"
    env = dict(
        os.environ, ANSIBLE_HOME=str(tmp_path / ".ansible"), ANSIBLE_NOCOLOR="1",
        # no fact gathering: the stub roles need none, and it is most of the run time
        ANSIBLE_GATHERING="explicit",
        PATH=f"{bin_}:{os.environ['PATH']}", QLOG=str(log), QDIR=str(qdir),
    )  # fmt: skip
    pb = str(tmp_path / "out" / apply.PLAYBOOK)
    for name in inv["all"]["children"]["guests"]["hosts"]:  # every guest is local: one each
        (sbin / name).mkdir()
        (units / name).mkdir()
    args = ["ansible-playbook", "-i", "hosts.yml", pb, "-e", "ansible_become=false",
            "-e", f"hnx_limits_unit_dir={units}/{{{{ inventory_hostname }}}}",
            "-e", f"hnx_limits_sbin_dir={sbin}/{{{{ inventory_hostname }}}}"]  # fmt: skip

    def run(*extra: str) -> subprocess.CompletedProcess:
        log.write_text("")
        return subprocess.run(
            [*args, *extra], capture_output=True, text=True, env=env, cwd=tmp_path, timeout=300
        )

    # one module: its host's limits play runs first, then the module's hooks
    r = run("--tags", "mod_example_inference")
    assert r.returncode == 0, r.stdout + r.stderr
    out = r.stdout
    assert out.index("module limits on site host infer") < out.index("module example-inference")
    # only its own host's units: the other hosts' limits plays match no task under the tag
    infer = next(iter(inv["all"]["children"][apply.host_group("infer")]["hosts"]))
    assert [p.name for p in units.iterdir() if any(p.iterdir())] == [infer]
    assert sorted(p.name for p in (units / infer).iterdir()) == sorted(
        rel.split("/", 1)[1] for rel in lim if rel.startswith("infer/") and ".slice" in rel
    )
    first = log.read_text().splitlines()
    assert "quota infer --check" in first and "quota infer apply" in first
    # the whole playbook: every host's units, its quota script, a daemon-reload, a cap
    r = run()
    assert r.returncode == 0, r.stdout + r.stderr
    for rel, text in lim.items():
        if "/" not in rel:
            continue
        host, name = rel.split("/", 1)
        guest = next(iter(inv["all"]["children"][apply.host_group(host)]["hosts"]))
        dest = (sbin if name.endswith(".sh") else units) / guest / name
        assert dest.read_text() == text, rel
        assert oct(dest.stat().st_mode & 0o777) == ("0o755" if rel.endswith(".sh") else "0o644")
    calls = first + log.read_text().splitlines()
    assert "systemctl daemon-reload" in calls
    quota_hosts = [h for h in hosts if f"{h}/{apply.QUOTA_SCRIPT}" in lim]
    assert quota_hosts
    for h in quota_hosts:
        assert calls.index(f"quota {h} --check") < calls.index(f"quota {h} apply")
    # idempotent: nothing to copy, no reload, the caps already in place
    r = run()
    assert r.returncode == 0, r.stdout + r.stderr
    recap = [ln for ln in r.stdout.splitlines() if "changed=" in ln]
    assert recap and all("changed=0" in ln for ln in recap), r.stdout
    calls = log.read_text().splitlines()
    assert "systemctl daemon-reload" not in calls
    assert not any(c.endswith(" apply") for c in calls)
    quota = sorted(c for c in calls if c.startswith("quota "))
    assert quota == sorted(f"quota {h} --check" for h in quota_hosts)
    # a dry run reports an owed cap (the --check is read-only) and applies nothing
    (qdir / f"{quota_hosts[0]}.capped").unlink()
    r = run("--check")
    assert r.returncode == 0, r.stdout + r.stderr
    calls = [c for c in log.read_text().splitlines() if c.startswith("quota ")]
    assert sorted(calls) == sorted(f"quota {h} --check" for h in quota_hosts)
    owed = next(iter(inv["all"]["children"][apply.host_group(quota_hosts[0])]["hosts"]))
    recap = next(ln for ln in r.stdout.splitlines() if ln.startswith(owed) and "changed=" in ln)
    assert "changed=1" in recap, r.stdout


@pytest.mark.requires_tool("ansible-playbook")
def test_an_owed_cap_that_cannot_be_applied_fails_the_play(tmp_path, tree, fleet):
    site = ld.load_yaml(FLEET_SELECTION)
    sel = selected(site, tree.mods)
    lim = _limits(site, tree)
    books = apply.render(site, sel, _stub_roles(tmp_path / "modules", sel), lim)
    for rel in lim:
        if rel.endswith(apply.QUOTA_SCRIPT):
            lim[rel] = '#!/bin/sh\necho "owed: cannot cap" >&2\nexit 3\n'
    _write_books(tmp_path / "out", books, lim)
    inv = yaml.safe_load(render(fleet, "inventory", site)["hosts.yml"])
    for name in inv["all"]["children"]["guests"]["hosts"]:
        inv["all"]["children"]["guests"]["hosts"][name] = {
            "ansible_connection": "local", "ansible_python_interpreter": sys.executable,
        }  # fmt: skip
    (tmp_path / "hosts.yml").write_text(yaml.safe_dump(inv))
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    (bin_ / "systemctl").write_text("#!/bin/sh\n")
    (bin_ / "systemctl").chmod(0o755)
    env = dict(os.environ, ANSIBLE_HOME=str(tmp_path / ".ansible"), ANSIBLE_NOCOLOR="1",
               PATH=f"{bin_}:{os.environ['PATH']}")  # fmt: skip
    r = subprocess.run(
        ["ansible-playbook", "-i", "hosts.yml", str(tmp_path / "out" / apply.PLAYBOOK),
         "-e", "ansible_become=false", "-e", f"hnx_limits_unit_dir={tmp_path}",
         "-e", f"hnx_limits_sbin_dir={tmp_path}"],
        capture_output=True, text=True, env=env, cwd=tmp_path, timeout=300,
    )  # fmt: skip
    assert r.returncode != 0
    assert "cap and reserve every owed data root" in r.stdout
    # the module plays never ran on a host whose cap is owed
    assert "hook " not in r.stdout


def test_a_file_the_limits_render_does_not_write_is_refused(tree):
    site = ld.load_yaml(SITE)
    sel = selected(site, tree.mods)
    lim = {**_limits(site, tree), "core/evil.service": "[Service]\n"}
    with pytest.raises(apply.ApplyError, match="no file the limits render writes"):
        apply.render(site, sel, _dirs(sel), lim)
    lim = {**_limits(site, tree), "../x/hnx-a-b.slice": "x"}
    with pytest.raises(apply.ApplyError, match="not a site host name"):
        apply.render(site, sel, _dirs(sel), lim)


def test_without_limits_the_playbook_has_no_limits_play(tree):
    site = ld.load_yaml(SITE)
    plays = yaml.safe_load(_books(site, tree, with_limits=False)[apply.PLAYBOOK])
    assert not any(p["hosts"].startswith(apply.HOST_GROUP_PREFIX) for p in plays)


def test_the_limits_play_tag_is_never_a_module_tag():
    # a module named "limits" is tagged mod_limits; the limits plays are tagged hnx_limits
    assert not apply.LIMITS_TAG.startswith(apply.GROUP_PREFIX)
    assert apply.host_group("app-host") == "modhost_app_host"
    assert not apply.host_group("x").startswith(apply.GROUP_PREFIX)


def test_one_guest_behind_two_site_hosts_is_refused():
    site = {
        "hosts": {"h1": {"guest": "g"}, "h2": {"guest": "g"}},
        "slots": {},
        "features": {"a": {"placement": {"server": "h1"}}, "b": {"placement": {"server": "h2"}}},
    }
    with pytest.raises(apply.ApplyError, match="one guest is one host"):
        apply.inventory_groups(site, lambda g: "g.example.internal")


# ----------------------------------------------------------------------------- --group-vars


def _gv(tmp_path: Path, files: dict[str, str]) -> Path:
    d = tmp_path / "group_vars"
    d.mkdir()
    for name, text in files.items():
        (d / name).write_text(text)
    return d


def test_group_vars_are_carried_beside_the_inventory_and_plan_agrees(tmp_path, capsys):
    gv = _gv(tmp_path, {"mod_example_siem_suite_suite.yml": "suite_logical_id: siem-a\n",
                        "all.yaml": "x: 1"})  # fmt: skip
    out = tmp_path / "inv"
    args = ("--selection", str(FLEET_SELECTION), "--group-vars", str(gv))
    assert _guests_render(*args, "--out", str(out)) == 0
    text = (out / "group_vars" / "mod_example_siem_suite_suite.yml").read_text()
    assert yaml.safe_load(text) == {"suite_logical_id": "siem-a"}
    assert yaml.safe_load((out / "group_vars" / "all.yml").read_text()) == {"x": 1}
    capsys.readouterr()
    code = hnx.main(
        ["guests", "plan", str(FLEET), "--site", str(COMPUTE / "site.yml"), "--target",
         "inventory", *args, "--against", str(out), "--exit-code"]
    )  # fmt: skip
    assert code == 0, capsys.readouterr().out
    # a file dropped from the overlay is pruned like any other generated file
    (gv / "all.yaml").unlink()
    assert _guests_render(*args, "--out", str(out), "--prune") == 0
    assert not (out / "group_vars" / "all.yml").exists()


@pytest.mark.parametrize(
    "files, needle",
    [
        ({"mod_example_siem_suite_sutie.yml": "a: 1\n"}, "no group of this inventory"),
        ({"mod_x.yml": "$" + "ANSIBLE_VAULT;1.1;AES256\n6162\n"}, "ansible-vault"),
        ({"mod_example_siem_suite_suite.yml": "- a\n"}, "not a mapping"),
        ({"notes.txt": "x"}, "not <group>.yml"),
        ({"all.yml": "a: 1\n", "all.yaml": "a: 2\n"}, "a second file for group all"),
    ],
)
def test_a_group_vars_file_the_inventory_cannot_use_is_refused(tmp_path, capsys, files, needle):
    gv = _gv(tmp_path, files)
    out = tmp_path / "inv"
    code = _guests_render("--selection", str(FLEET_SELECTION), "--group-vars", str(gv),
                          "--out", str(out))  # fmt: skip
    assert code == 1
    assert needle in capsys.readouterr().err
    assert not out.exists()


def test_a_linked_or_unreadable_group_vars_file_is_2(tmp_path, capsys):
    gv = _gv(tmp_path, {})
    (tmp_path / "elsewhere.yml").write_text("a: 1\n")
    (gv / "all.yml").symlink_to(tmp_path / "elsewhere.yml")
    assert _guests_render("--group-vars", str(gv)) == 2
    (gv / "all.yml").unlink()
    (gv / "all.yml").write_text("a: [\n")
    assert _guests_render("--group-vars", str(gv)) == 2
    (gv / "all.yml").write_text("a: 1\na: 2\n")  # one of the two would be set silently
    assert _guests_render("--group-vars", str(gv)) == 2
    assert _guests_render("--group-vars", str(tmp_path / "missing")) == 2
    (gv / "all.yml").unlink()
    os.mkfifo(gv / "all.yml")  # refused, never waited on
    assert _guests_render("--group-vars", str(gv)) == 2


def test_group_vars_is_for_the_inventory_target_only(tmp_path, capsys):
    assert _guests_render("--group-vars", str(tmp_path), target="cloudinit") == 2
    assert "--group-vars is for the inventory target" in capsys.readouterr().err


@pytest.mark.requires_tool("ansible-playbook")
def test_ansible_reads_the_carried_group_vars(tmp_path, capsys):
    gv = _gv(tmp_path, {"mod_example_siem_suite_suite.yml": "probe_value: carried\n"})
    out = tmp_path / "inv"
    assert _guests_render("--selection", str(FLEET_SELECTION), "--group-vars", str(gv),
                          "--out", str(out)) == 0  # fmt: skip
    host = next(iter(yaml.safe_load((out / "hosts.yml").read_text())["all"]["children"][
        "mod_example_siem_suite_suite"]["hosts"]))  # fmt: skip
    env = dict(os.environ, ANSIBLE_HOME=str(tmp_path / ".ansible"), ANSIBLE_NOCOLOR="1")
    r = subprocess.run(
        ["ansible-inventory", "-i", str(out / "hosts.yml"), "--host", host],
        capture_output=True, text=True, env=env, timeout=120,
    )  # fmt: skip
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout)["probe_value"] == "carried"
