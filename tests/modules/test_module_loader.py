# SPDX-License-Identifier: Apache-2.0
"""The module loader (ADR-0027 follow-up 9; docs/modules.md, "What the loader checks"): it
discovers the manifests, refuses what cannot load, runs every rule with every input, and checks
what runs against what is declared, saying what it did not check."""

from __future__ import annotations

import copy
import json
import shutil
from pathlib import Path

import pytest
import yaml

from homelabnext.modules import cli as mcli
from homelabnext.modules import loader as ld

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "examples" / "modules"
SITES = {p.stem: ld.load_yaml(p) for p in sorted((EXAMPLES / "sites").glob("*.yml"))}
SLOTS = ld.load_yaml(EXAMPLES / "slots.yml")["slots"]
ROLES = json.loads((ROOT / "examples" / "model_roles.json").read_text())["roles"]
CORE = ld.core_names(ld.load_yaml(ROOT / "examples" / "services.yml"))
INVENTORY = ld.load_yaml(ROOT / "schemas/platform/examples/module_inventory.small-lab.yml")


def check(tree, roots=(EXAMPLES,), **kw):
    return ld.check(tree, slots=SLOTS, roles=ROLES, in_tree_roots=roots, core=CORE, **kw)


def examples(tmp_path=None, without=()):
    """The example modules, or a copy of them (to plant a defect) without some ids."""
    if tmp_path is None:
        return ld.discover(fixtures=EXAMPLES)
    root = tmp_path / "fixtures"
    shutil.copytree(EXAMPLES, root, ignore=shutil.ignore_patterns(*without))
    return ld.discover(fixtures=root)


def messages(report_or_list):
    items = report_or_list.problems if hasattr(report_or_list, "problems") else report_or_list
    return [str(p) for p in items]


@pytest.mark.parametrize("profile", sorted(SITES))
def test_the_example_lab_loads_clean_for_every_profile(profile):
    tree, found = examples()
    assert found == []
    report = check(tree, site=SITES[profile])
    assert report.problems == []
    assert report.notes == [
        "no inventory of what runs: the runtime half of the two-way check did not run"
    ]


def test_what_runs_on_the_small_lab_matches_what_it_declares():
    tree, _ = examples()
    report = check(tree, site=SITES["small-lab"], inventory=INVENTORY)
    assert report.problems == [] and report.notes == []


def test_without_a_site_the_site_half_is_named_as_not_checked():
    tree, _ = examples()
    report = check(tree)
    assert report.problems == []
    assert report.notes == [
        "no site selection: the site rules, the supply chain and the runtime check did not run"
    ]


def test_a_running_name_must_be_declared_selected_and_every_declared_one_must_run():
    tree, _ = examples()
    inv = copy.deepcopy(INVENTORY)
    inv["agents"].remove("core-staff-scorecard")  # declared but not running
    inv["units"].append("external-collector-extra")  # runs, undeclared
    inv["rows"].append("publishing-site")  # runs for a module the site does not select
    inv["units"].append("lake-compact")  # bound to no module id: the core's, not judged here
    inv["tables"].append("table:external_collector.extra")
    got = messages(check(tree, site=SITES["small-lab"], inventory=inv))
    assert got == [
        "running: agents core-staff-scorecard (core-staff) is declared but not running",
        "running: rows publishing-site runs for publishing, which the site does not select",
        "running: tables table:external_collector.extra runs but external-collector declares no such entry",
        "running: units external-collector-extra runs but external-collector declares no such entry",
    ]


def test_an_inventory_that_breaks_its_schema_is_refused_not_judged():
    tree, _ = examples()
    inv = {k: v for k, v in INVENTORY.items() if k != "tables"}
    got = messages(check(tree, site=SITES["small-lab"], inventory=inv))
    assert got and all(m.startswith("running: schema: ") for m in got)


def test_an_overlay_module_that_shadows_a_shipped_id_is_refused(tmp_path):
    overlay = tmp_path / "overlay"
    shutil.copytree(EXAMPLES / "publishing", overlay / "lab" / "modules" / "publishing")
    tree, found = ld.discover(fixtures=EXAMPLES, overlay=overlay)
    assert messages(found) == [
        "publishing: an overlay module shadows the fixture module of that id"
    ]
    assert tree.dirs["publishing"] == EXAMPLES / "publishing"


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ("id: other\n", "the manifest's id 'other' is not its directory"),
        ("id: [\n", "module.yml cannot be read (ParserError)"),
        ("- a list\n", "module.yml is not a mapping"),
        ("id: x\nid: x\n", "module.yml cannot be read (ConstructorError)"),
    ],
)
def test_a_manifest_that_cannot_be_read_as_its_own_id_is_refused(tmp_path, body, message):
    d = tmp_path / "lab" / "modules" / "x"
    d.mkdir(parents=True)
    (d / "module.yml").write_text(body)
    tree, found = ld.discover(overlay=tmp_path)
    assert messages(found) == [f"x: {message}"] and tree.mods == {}


def test_a_reserved_id_is_refused(tmp_path):
    d = tmp_path / "lab" / "modules" / "core"
    d.mkdir(parents=True)
    (d / "module.yml").write_text("id: core\n")
    assert messages(ld.discover(overlay=tmp_path)[1]) == ["core: a reserved id"]


def test_a_manifest_is_held_to_its_schema_before_any_rule_reads_it(tmp_path):
    tree, _ = examples(tmp_path)
    tree.mods["publishing"] = {**tree.mods["publishing"], "requires": "nothing"}
    got = messages(check(tree, (tmp_path / "fixtures",)))
    # the invalid manifest reaches no rule (it would crash one); the others are judged without it
    assert "publishing: schema: requires: is not of type 'object'" in got
    assert not [m for m in got if m.startswith("publishing: ") and ": schema: " not in m]


def test_a_contributed_file_must_be_a_regular_file_inside_the_module(tmp_path):
    tree, _ = examples(tmp_path)
    d = tree.dirs["external-collector"]
    doc = tree.mods["external-collector"]
    target = doc["contributes"]["services"][0]["file"]
    outside = tmp_path / "outside.yml"
    outside.write_text((d / target).read_text())
    (d / target).unlink()
    (d / target).symlink_to(outside)
    got = messages(check(tree, (tmp_path / "fixtures",)))
    assert f"external-collector: {target}: reached through a symbolic link" in got
    (d / target).unlink()
    got = messages(check(tree, (tmp_path / "fixtures",)))
    assert f"external-collector: {target}: not a regular file in the module" in got


def test_a_contributed_record_is_validated_against_its_record_type(tmp_path):
    tree, _ = examples(tmp_path)
    d = tree.dirs["external-collector"]
    rec = tree.mods["external-collector"]["contributes"]["mcp_servers"][0]["file"]
    doc = ld.load_yaml(d / rec)
    (d / rec).write_text(yaml.safe_dump({**doc, "id": "external-collector-other"}))
    got = messages(check(tree, (tmp_path / "fixtures",)))
    assert f"external-collector: {rec}: an MCP record's id is its file name" in got


def test_a_module_id_or_feature_row_that_is_a_core_name_is_refused():
    tree, _ = examples()
    core = ld.CoreNames(rows=frozenset({"publishing", "external-collector-receiver"}))
    got = messages(ld.check(tree, slots=SLOTS, roles=ROLES, in_tree_roots=(EXAMPLES,), core=core))
    assert got == [
        "external-collector: service row external-collector-receiver is a core service name",
        "publishing: the module id is a core service name",
    ]


def test_a_selection_that_breaks_its_schema_is_refused_before_the_site_rules():
    tree, _ = examples()
    site = {**SITES["small-lab"], "grants": {"publsh": []}}
    got = messages(check(tree, site=site))
    assert got and all(m.startswith("site: schema: ") for m in got), got


def test_a_fetched_module_without_a_lock_is_not_loadable(tmp_path):
    tree, _ = examples(tmp_path, without=("external-collector",))
    overlay = tmp_path / "overlay"
    d = overlay / "lab" / "modules" / "external-collector"
    shutil.copytree(EXAMPLES / "external-collector", d)
    doc = ld.load_yaml(d / "module.yml")
    doc["origin"] = {
        "kind": "git",
        "url": "https://git.example.invalid/modules/external-collector",
        "commit": "0123456789abcdef0123456789abcdef01234567",
    }
    (d / "module.yml").write_text(yaml.safe_dump(doc))
    tree, found = ld.discover(fixtures=tmp_path / "fixtures", overlay=overlay)
    assert found == []
    report = check(tree, (tmp_path / "fixtures",), site=SITES["small-lab"])
    assert "no lock file: every fetched module is refused" in report.notes
    assert "lock: external-collector: fetched (git) but not pinned in the lock: not loadable" in (
        messages(report)
    )


# ----------------------------------------------------------------------------- the CLI


def run(capsys, *argv):
    code = mcli.main(["check", "--root", str(ROOT), "--examples", *argv])
    return code, capsys.readouterr()


def test_the_cli_exits_0_clean_and_names_what_it_did_not_check(capsys):
    code, out = run(capsys, "--site", str(EXAMPLES / "sites" / "small-lab.yml"))
    assert code == 0
    assert "note: no inventory of what runs" in out.out
    assert out.out.rstrip().endswith("16 module(s), 0 problem(s)")


def test_the_cli_exits_1_on_a_problem_and_prints_json(capsys):
    code, out = run(
        capsys,
        "--site",
        str(EXAMPLES / "sites" / "small-lab.yml"),
        "--running",
        str(ROOT / "schemas/platform/negative/module_inventory.kind-missing.yml"),
        "--json",
    )
    assert code == 1
    doc = json.loads(out.out)
    assert doc["problems"] and all(p.startswith("running: schema:") for p in doc["problems"])


def test_the_cli_exits_2_on_an_unreadable_input(capsys, tmp_path):
    bad = tmp_path / "site.yml"
    bad.write_text("slots: [\n")
    code, out = run(capsys, "--site", str(bad))
    assert code == 2 and "cannot be read" in out.err


def test_the_cli_exits_100_on_an_internal_failure(capsys, monkeypatch):
    def boom(*_a, **_k):
        raise RuntimeError("x")

    monkeypatch.setattr(ld, "check", boom)
    code, out = run(capsys)
    assert code == 100 and "internal error" in out.err


def test_render_writes_limits_and_egress_only_for_a_clean_site(capsys, tmp_path):
    site = str(EXAMPLES / "sites" / "full.yml")
    argv = ["render", "--root", str(ROOT), "--examples", "--site", site, "--out", str(tmp_path)]
    assert mcli.main(argv) == 0
    assert any((tmp_path / "limits").iterdir()) and any((tmp_path / "egress").iterdir())
    bad = tmp_path / "bad.yml"
    bad.write_text(yaml.safe_dump({**SITES["full"], "features": {}}))
    out = tmp_path / "refused"
    argv[argv.index(site)] = str(bad)
    argv[argv.index(str(tmp_path))] = str(out)
    capsys.readouterr()
    assert mcli.main(argv) == 1 and not out.exists()
