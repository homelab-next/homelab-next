# SPDX-License-Identifier: Apache-2.0
"""The per-field review tier of an in-tree manifest (ADR-0027 follow-up 4; docs/modules.md, "Trust
tiers"): which change needs a human approve, which only the owner, fail closed, and the CLI that
checks every human-approve manifest has a code owner whose review approves it."""

from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from homelabnext.modules import cli as mcli
from homelabnext.modules import loader as ld
from homelabnext.modules import review_tier as rt

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "examples" / "modules"
KEYS = rt.schema_keys(json.loads((ROOT / "schemas/platform/module.schema.json").read_text()))
PRIV = rt.privileged_slots(ld.load_yaml(EXAMPLES / "slots.yml"))
MODS = {p.parent.name: ld.load_yaml(p) for p in sorted(EXAMPLES.glob("*/module.yml"))}


def tiers(old, new, priv=PRIV):
    return {c.field: c.tier for c in rt.classify(old, new, KEYS, priv)}


def test_the_privileged_slots_come_from_the_registry():
    assert {"cap:secrets", "cap:idp", "cap:edge", "cap:broker"} <= PRIV
    assert "cap:notify" not in PRIV
    assert rt.privileged_slots(None) is None
    assert rt.privileged_slots({"slots": []}) is None


@pytest.mark.parametrize("mid", sorted(MODS))
def test_an_unchanged_example_manifest_has_no_tier(mid):
    assert rt.classify(MODS[mid], copy.deepcopy(MODS[mid]), KEYS, PRIV) == []
    assert rt.tier_of([]) is None


def _edit(mid, fn):
    old = MODS[mid]
    new = copy.deepcopy(old)
    fn(new)
    return old, new


@pytest.mark.parametrize(
    ("mid", "edit", "field"),
    [
        (
            "example-object-store",
            lambda d: d["credentials"][0].update(purpose="changed"),
            "credentials",
        ),
        (
            "example-static-host",
            lambda d: d["control_plane"][0].update(description="changed"),
            "control_plane",
        ),
        ("publishing", lambda d: d["egress"].append({"from": "x", "to": "internet"}), "egress"),
        (
            "external-collector",
            lambda d: d["contributes"]["agents"][0]["needs"].append(
                {"cap": "cap:records", "access": "read", "scope": ["findings/"]}
            ),
            "contributes.agents.external-collector-analyst.needs",
        ),
        (
            "external-collector",
            lambda d: d["requires"]["capabilities"].append(
                {"cap": "cap:secrets", "version": "1.0", "purpose": "x"}
            ),
            "requires.capabilities.cap:secrets",
        ),
        ("example-orchestrator", lambda d: d.update(kind="feature"), "kind"),
        ("example-orchestrator", lambda d: d.update(origin={"kind": "git"}), "origin"),
        ("example-orchestrator", lambda d: d.update(id="renamed"), "id"),
        ("example-orchestrator", lambda d: d.update(surprise=1), "surprise"),
        ("example-orchestrator", lambda d: d["requires"].update(surprise=1), "requires.surprise"),
    ],
    ids=[
        "credentials",
        "control-plane",
        "egress",
        "agent-needs",
        "privileged-slot-required",
        "kind",
        "origin",
        "id",
        "unknown-top-level-key",
        "unknown-block-key",
    ],
)
def test_each_human_approve_field(mid, edit, field):
    got = tiers(*_edit(mid, edit))
    assert got.get(field) == rt.HUMAN, got
    assert rt.tier_of(rt.classify(*_edit(mid, edit), KEYS, PRIV)) == rt.HUMAN


def test_a_privileged_slot_provided_is_human_approve_and_another_is_owner():
    mid = next(m for m, d in MODS.items() if d.get("provides", {}).get("slots"))
    old = MODS[mid]
    new = copy.deepcopy(old)
    new["provides"]["slots"]["secrets"] = {"adapter": "x:y"}
    assert tiers(old, new)["provides.slots.secrets"] == rt.HUMAN
    new = copy.deepcopy(old)
    slot = next(iter(new["provides"]["slots"]))
    new["provides"]["slots"][slot] = {**new["provides"]["slots"][slot], "reason": "changed"}
    expect = rt.HUMAN if f"cap:{slot}" in PRIV else rt.OWNER
    assert tiers(old, new)[f"provides.slots.{slot}"] == expect


@pytest.mark.parametrize(
    ("edit", "field"),
    [
        (lambda d: d.update(title="changed"), "title"),
        (lambda d: d.update(version="9.9.9"), "version"),
        (
            lambda d: d["requires"]["capabilities"][1].update(purpose="changed"),
            "requires.capabilities.cap:notify",
        ),
        (
            lambda d: d["contributes"]["agents"][0].update(tools=["records.write_note"]),
            "contributes.agents.external-collector-analyst",
        ),
        (
            lambda d: d["contributes"]["agents"][0]["needs"].pop(),
            "contributes.agents.external-collector-analyst.needs",
        ),
    ],
    ids=["title", "version", "ordinary-capability", "agent-other-than-needs", "needs-narrowed"],
)
def test_owner_tier_changes(edit, field):
    old, new = _edit("external-collector", edit)
    got = tiers(old, new)
    assert got == {field: rt.OWNER}, got
    assert rt.tier_of(rt.classify(old, new, KEYS, PRIV)) == rt.OWNER


def test_removing_every_grant_of_an_agent_is_owner_and_adding_one_is_human():
    old, new = _edit("external-collector", lambda d: d["contributes"]["agents"][0].pop("needs"))
    assert tiers(old, new) == {"contributes.agents.external-collector-analyst.needs": rt.OWNER}
    assert tiers(new, old) == {"contributes.agents.external-collector-analyst.needs": rt.HUMAN}


@pytest.mark.parametrize(
    ("old", "new"),
    [
        (None, {"id": "x"}),  # a new module
        ({"id": "x"}, None),  # a removed one
        ({"id": "x"}, ["not", "a", "mapping"]),
    ],
    ids=["new", "removed", "not-a-mapping"],
)
def test_fail_closed_shapes(old, new):
    assert rt.tier_of(rt.classify(old, new, KEYS, PRIV)) == rt.HUMAN


def test_without_a_slot_registry_every_slot_change_is_human_approve():
    old, new = _edit(
        "external-collector",
        lambda d: d["requires"]["capabilities"][1].update(purpose="changed"),
    )
    assert tiers(old, new, priv=None) == {"requires.capabilities.cap:notify": rt.HUMAN}


def test_a_capability_list_that_names_no_capability_is_human_approve():
    old, new = _edit("external-collector", lambda d: d["requires"]["capabilities"].append({}))
    assert tiers(old, new) == {"requires.capabilities": rt.HUMAN}


def test_an_unreadable_manifest_is_an_error_string():
    assert rt.load_manifest(None) is None
    assert isinstance(rt.load_manifest("a: 1\na: 2\n"), str)  # duplicate keys
    assert isinstance(rt.load_manifest("[1]"), str)
    assert rt.load_manifest("id: x\n") == {"id": "x"}


@pytest.mark.parametrize(
    ("pattern", "path", "hit"),
    [
        ("*", "examples/modules/x/module.yml", True),
        ("/examples/modules/", "examples/modules/x/module.yml", True),
        ("/examples/modules/", "other/examples/modules/x/module.yml", False),
        ("/modules/", "examples/modules/x/module.yml", False),
        ("module.yml", "modules/x/module.yml", True),
        ("/tools/", "tools/x.py", True),
    ],
)
def test_codeowners_patterns(pattern, path, hit):
    assert bool(rt.codeowners_for([(pattern, ["@owner"])], path)) is hit


def test_the_last_matching_codeowners_rule_wins():
    rules = [("*", ["@a"]), ("/examples/modules/", ["@b"]), ("/examples/", [])]
    assert rt.codeowners_for(rules, "examples/modules/x/module.yml") == []
    assert rt.codeowners_for(rules[:2], "examples/modules/x/module.yml") == ["@b"]


def test_this_repository_codeowns_every_manifest_root():
    _, rules = rt.load_codeowners(ROOT)
    for glob in rt.MANIFEST_GLOBS:
        assert rt.codeowners_for(rules, glob.replace("*", "x")), glob


# ---------------------------------------------------------------- the CLI over a git checkout


def _git(root: Path, *args: str) -> None:
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.invalid",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.invalid",
    }
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, env=env)


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    shutil.copytree(EXAMPLES / "external-collector", root / "modules" / "external-collector")
    (root / "examples" / "modules").mkdir(parents=True)
    shutil.copy(EXAMPLES / "slots.yml", root / "examples" / "modules" / "slots.yml")
    (root / ".github").mkdir()
    (root / ".github" / "CODEOWNERS").write_text("/modules/ @owner\n")
    _git(root, "init", "-q")
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "base")
    return root


def _manifest(root: Path) -> Path:
    return root / "modules" / "external-collector" / "module.yml"


def _run(root: Path, capsys, *extra) -> tuple[int, dict]:
    rc = mcli.main(["review-tier", "--root", str(root), "--base", "HEAD", "--json", *extra])
    return rc, json.loads(capsys.readouterr().out)


def test_the_cli_reports_the_tier_and_passes_with_a_code_owner(repo, capsys):
    doc = yaml.safe_load(_manifest(repo).read_text())
    doc["egress"] = [*doc.get("egress", []), {"from": "receiver", "to": "internet"}]
    doc["title"] = "changed"
    _manifest(repo).write_text(yaml.safe_dump(doc, sort_keys=False))
    rc, out = _run(repo, capsys)
    assert rc == 0, out
    (m,) = out["manifests"]
    assert m["tier"] == rt.HUMAN and m["owners"] == ["@owner"]
    assert {c["field"]: c["tier"] for c in m["changes"]} == {"egress": rt.HUMAN, "title": rt.OWNER}


def test_the_cli_fails_a_human_approve_change_with_no_code_owner(repo, capsys):
    (repo / ".github" / "CODEOWNERS").write_text("/docs/ @owner\n")
    doc = yaml.safe_load(_manifest(repo).read_text())
    doc["credentials"] = [{"secret": "secret:external-collector/x", "purpose": "x"}]
    _manifest(repo).write_text(yaml.safe_dump(doc, sort_keys=False))
    rc, out = _run(repo, capsys)
    assert rc == 1
    assert "no CODEOWNERS owner" in out["problems"][0]


def test_an_owner_change_needs_no_code_owner(repo, capsys):
    (repo / ".github" / "CODEOWNERS").unlink()
    doc = yaml.safe_load(_manifest(repo).read_text())
    doc["title"] = "changed"
    _manifest(repo).write_text(yaml.safe_dump(doc, sort_keys=False))
    rc, out = _run(repo, capsys)
    assert rc == 0 and out["manifests"][0]["tier"] == rt.OWNER


def test_a_new_an_unreadable_and_a_linked_manifest_are_human_approve(repo, capsys):
    new = repo / "modules" / "brand-new" / "module.yml"
    new.parent.mkdir()
    new.write_text("id: brand-new\n")
    _manifest(repo).write_text("id: [unclosed\n")
    linked = repo / "modules" / "linked" / "module.yml"
    linked.parent.mkdir()
    linked.symlink_to(_manifest(repo))
    (repo / ".github" / "CODEOWNERS").write_text("")
    rc, out = _run(repo, capsys)
    assert rc == 1
    got = {m["path"]: m["tier"] for m in out["manifests"]}
    assert got == {
        "modules/brand-new/module.yml": rt.HUMAN,
        "modules/external-collector/module.yml": rt.HUMAN,
        "modules/linked/module.yml": rt.HUMAN,
    }
    assert len(out["problems"]) == 3


def test_a_removed_manifest_is_human_approve(repo, capsys):
    _manifest(repo).unlink()
    rc, out = _run(repo, capsys)
    assert rc == 0  # owned by /modules/
    assert out["manifests"][0]["changes"][0]["why"] == "a removed module"


def test_a_bad_base_is_a_usage_error(repo, capsys):
    assert mcli.main(["review-tier", "--root", str(repo), "--base", "no-such-rev"]) == 2
    assert mcli.main(["review-tier", "--root", str(repo), "--base", " "]) == 2


def test_an_unreadable_slot_registry_fails_closed(repo, capsys):
    (repo / "examples" / "modules" / "slots.yml").write_text("[unclosed\n")
    doc = yaml.safe_load(_manifest(repo).read_text())
    doc["requires"]["capabilities"][1]["purpose"] = "changed"
    _manifest(repo).write_text(yaml.safe_dump(doc, sort_keys=False))
    _, out = _run(repo, capsys)
    assert out["manifests"][0]["tier"] == rt.HUMAN


def test_the_step_summary_lists_each_manifest(repo, capsys, monkeypatch, tmp_path):
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    doc = yaml.safe_load(_manifest(repo).read_text())
    doc["title"] = "changed"
    _manifest(repo).write_text(yaml.safe_dump(doc, sort_keys=False))
    _run(repo, capsys)
    assert "| `modules/external-collector/module.yml` | owner | `title` |" in summary.read_text()
