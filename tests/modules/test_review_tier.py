# SPDX-License-Identifier: Apache-2.0
"""The per-field review tier of an in-tree module (ADR-0027 follow-up 4; docs/modules.md, "Trust
tiers"): which change needs a human approve, which only the owner, fail closed; the inputs read
as of the base commit; CODEOWNERS matched as GitHub matches it; and the CLI that checks every
human-approve change has a valid code owner."""

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
KEYS = rt.schema_keys(json.loads((ROOT / rt.SCHEMA).read_text()))
PRIV = rt.privileged_slots(ld.load_yaml(EXAMPLES / "slots.yml"))
MODS = {p.parent.name: ld.load_yaml(p) for p in sorted(EXAMPLES.glob("*/module.yml"))}
EC = "contributes.agents.external-collector-analyst"


def tiers(old, new, priv=PRIV, keys=KEYS):
    return {c.field: c.tier for c in rt.classify(old, new, keys, priv)}


def _edit(mid, fn):
    old = MODS[mid]
    new = copy.deepcopy(old)
    fn(new)
    return old, new


def test_the_privileged_slots_come_from_the_registry():
    assert {"cap:secrets", "cap:idp", "cap:edge", "cap:broker"} <= PRIV
    assert "cap:notify" not in PRIV
    for unreadable in (None, {"slots": []}, {"slots": {}}, {}):
        assert rt.privileged_slots(unreadable) is None, unreadable


@pytest.mark.parametrize("mid", sorted(MODS))
def test_an_unchanged_example_manifest_has_no_tier(mid):
    assert rt.classify(MODS[mid], copy.deepcopy(MODS[mid]), KEYS, PRIV) == []
    assert rt.tier_of([]) is None


@pytest.mark.parametrize(
    ("mid", "edit", "field"),
    [
        ("example-object-store", lambda d: d["credentials"][0].update(purpose="x"), "credentials"),
        (
            "example-static-host",
            lambda d: d["control_plane"][0].update(description="x"),
            "control_plane",
        ),
        ("publishing", lambda d: d["egress"].append({"from": "x", "to": "internet"}), "egress"),
        ("publishing", lambda d: d["data"][0].update(note="x"), "data"),
        ("publishing", lambda d: d["interfaces"][0].update(gate=False), "interfaces"),
        ("example-orchestrator", lambda d: d["lifecycle"].update(note="x"), "lifecycle"),
        (
            "external-collector",
            lambda d: d["contributes"]["agents"][0]["needs"].append(
                {"cap": "cap:records", "access": "read", "scope": ["findings/"]}
            ),
            f"{EC}.needs",
        ),
        (
            "external-collector",
            lambda d: d["contributes"]["agents"][0].update(tools=["records.write_note"]),
            EC,
        ),
        (
            "external-collector",
            lambda d: d["requires"]["capabilities"].append(
                {"cap": "cap:secrets", "version": "1.0", "purpose": "x"}
            ),
            "requires.capabilities.cap:secrets",
        ),
        (
            "external-collector",
            lambda d: d["prefers"]["capabilities"].append(
                {"cap": "cap:idp", "version": "1.0", "purpose": "x", "fallback": {"behaviour": "x"}}
            ),
            "prefers.capabilities.cap:idp",
        ),
        (
            "external-collector",  # B1: a fallback to a privileged slot
            lambda d: d["prefers"]["capabilities"][0]["fallback"].update(to="cap:secrets"),
            "prefers.capabilities.cap:lake-catalog",
        ),
        (
            "external-collector",
            lambda d: d["contributes"]["services"].append({"file": "x.yml"}),
            "contributes.services",
        ),
        ("external-collector", lambda d: d["contributes"]["roles"].pop(), "contributes.roles"),
        (
            "external-collector",
            lambda d: d["contributes"]["entry_points"][0].update(name="y"),
            "contributes.entry_points",
        ),
        (
            "external-collector",
            lambda d: d["contributes"]["scheduler_jobs"].pop(),
            "contributes.scheduler_jobs",
        ),
        (
            "external-collector",
            lambda d: d["contributes"]["mcp_servers"].pop(),
            "contributes.mcp_servers",
        ),
        (
            "external-collector",
            lambda d: d["contributes"]["preflight"].pop(),
            "contributes.preflight",
        ),
        ("example-orchestrator", lambda d: d.update(kind="feature"), "kind"),
        ("example-orchestrator", lambda d: d.update(origin={"kind": "git"}), "origin"),
        ("example-orchestrator", lambda d: d.update(id="renamed"), "id"),
        ("example-orchestrator", lambda d: d.update(surprise=1), "surprise"),
        ("example-orchestrator", lambda d: d["requires"].update(surprise=1), "requires.surprise"),
        (
            "external-collector",
            lambda d: d["contributes"].update(surprise=[]),
            "contributes.surprise",
        ),
    ],
    ids=[
        "credentials",
        "control-plane",
        "egress",
        "data",
        "interfaces",
        "lifecycle",
        "agent-needs-widened",
        "agent-definition",
        "privileged-slot-required",
        "privileged-slot-preferred",
        "privileged-fallback",
        "service-rows",
        "roles",
        "entry-points",
        "fleet-units",
        "mcp-records",
        "preflight",
        "kind",
        "origin",
        "id",
        "unknown-top-level-key",
        "unknown-block-key",
        "unknown-contribution",
    ],
)
def test_each_human_approve_field(mid, edit, field):
    got = tiers(*_edit(mid, edit))
    assert got.get(field) == rt.HUMAN, got
    assert rt.tier_of(rt.classify(*_edit(mid, edit), KEYS, PRIV)) == rt.HUMAN


def test_a_privileged_slot_provided_is_human_approve_and_another_is_owner():
    old = MODS["example-object-store"]
    new = copy.deepcopy(old)
    new["provides"]["slots"]["secrets"] = {"adapter": "x:y"}
    assert tiers(old, new)["provides.slots.secrets"] == rt.HUMAN
    new = copy.deepcopy(old)
    new["provides"]["slots"]["object-store"]["features"] = []
    assert tiers(old, new) == {"provides.slots.object-store": rt.OWNER}
    new = copy.deepcopy(old)
    new["provides"]["slots"] = ["object-store"]
    assert tiers(old, new) == {"provides.slots": rt.HUMAN}


@pytest.mark.parametrize(
    ("edit", "field"),
    [
        (lambda d: d.update(title="changed"), "title"),
        (lambda d: d.update(version="9.9.9"), "version"),
        (
            lambda d: d["requires"]["capabilities"][1].update(purpose="changed"),
            "requires.capabilities.cap:notify",
        ),
        (lambda d: d["contributes"]["agents"][0]["needs"].pop(), f"{EC}.needs"),
        (lambda d: d["contributes"]["detections"].pop(), "contributes.detections"),
        (lambda d: d["contributes"]["docs"].pop(), "contributes.docs"),
    ],
    ids=["title", "version", "ordinary-capability", "needs-narrowed", "detections", "docs"],
)
def test_owner_tier_changes(edit, field):
    old, new = _edit("external-collector", edit)
    got = tiers(old, new)
    assert got == {field: rt.OWNER}, got
    assert rt.tier_of(rt.classify(old, new, KEYS, PRIV)) == rt.OWNER


def test_removing_every_grant_of_an_agent_is_owner_and_adding_one_is_human():
    old, new = _edit("external-collector", lambda d: d["contributes"]["agents"][0].pop("needs"))
    assert tiers(old, new) == {f"{EC}.needs": rt.OWNER}
    assert tiers(new, old) == {f"{EC}.needs": rt.HUMAN}


def test_capability_entries_are_keyed_by_capability_and_instance():
    old, new = _edit(
        "external-collector",
        lambda d: d["requires"]["capabilities"][0].update(purpose="changed"),
    )
    assert tiers(old, new) == {"requires.capabilities.cap:object-store[samples]": rt.OWNER}


@pytest.mark.parametrize(
    "edit",
    [
        lambda d: d["requires"]["capabilities"].append(d["requires"]["capabilities"][1]),
        lambda d: d["requires"]["capabilities"].append({}),
        lambda d: d["contributes"]["agents"].append(d["contributes"]["agents"][0]),
        lambda d: d["requires"].update(capabilities={"not": "a list"}),
    ],
    ids=["duplicate-capability", "no-cap", "duplicate-agent", "not-a-list"],
)
def test_lists_that_cannot_be_keyed_are_human_approve(edit):
    old, new = _edit("external-collector", edit)
    assert set(tiers(old, new).values()) == {rt.HUMAN}


@pytest.mark.parametrize(
    ("old", "new"),
    [
        (None, {"id": "x"}),  # a new module
        ({"id": "x"}, None),  # a removed one
        ({"id": "x"}, ["not", "a", "mapping"]),
        ({"id": "x", 1: "a"}, {"id": "y", "b": 1}),  # keys of mixed types cannot be ordered
    ],
    ids=["new", "removed", "not-a-mapping", "mixed-type-keys"],
)
def test_fail_closed_shapes(old, new):
    assert rt.tier_of(rt.classify(old, new, KEYS, PRIV)) == rt.HUMAN


def test_without_a_slot_registry_every_slot_change_is_human_approve():
    old, new = _edit(
        "external-collector",
        lambda d: d["requires"]["capabilities"][1].update(purpose="changed"),
    )
    assert tiers(old, new, priv=None) == {"requires.capabilities.cap:notify": rt.HUMAN}


def test_without_a_schema_every_change_is_an_undefined_key():
    assert rt.schema_keys(None) == {}
    old, new = _edit("external-collector", lambda d: d.update(title="changed"))
    assert tiers(old, new, keys=rt.schema_keys(None)) == {"title": rt.HUMAN}


@pytest.mark.parametrize(
    ("rel", "tier"),
    [
        ("roles/external_collector_edge/tasks/main.yml", rt.HUMAN),
        ("agents/external-collector-analyst.spec.yml", rt.HUMAN),
        ("agents/external-collector-analyst.md", rt.HUMAN),
        ("prompts/external-collector-analyst.real.yml", rt.HUMAN),
        ("mcp/external-collector-probe.yml", rt.HUMAN),
        ("registry/services.yml", rt.HUMAN),
        ("hnx_modules/external_collector/checks.py", rt.HUMAN),  # code nothing names
        ("docs/external-collector.md", rt.OWNER),
        ("detections/external-collector-credential-reuse.yml", rt.OWNER),
        ("lake/sessions.table.yml", rt.OWNER),
        ("invariants/criteria.yml", rt.OWNER),
    ],
)
def test_a_module_file_takes_the_tier_of_what_names_it(rel, tier):
    refs = rt._references(MODS["external-collector"])
    assert rt._file_change(rel, refs).tier == tier


# ---------------------------------------------------------------- CODEOWNERS


@pytest.mark.parametrize("token", ["@octocat", "@octo-org/octocats", "docs@example.com", "@a"])
def test_valid_owners(token):
    assert rt.valid_owner(token)


@pytest.mark.parametrize(
    "token", ["octocat", "@", "@-bad", "@org/team/extra", "not-an-email", "@user@x", "#x"]
)
def test_invalid_owners(token):
    assert not rt.valid_owner(token)


#: GitHub's documented CODEOWNERS examples (docs.github.com, "About code owners"), plus the
#: gitignore rules they rest on
GITHUB_CASES = [
    ("*", "README.md", True),
    ("*.js", "src/app/index.js", True),
    ("*.js", "index.ts", False),
    ("*.go", "main.go", True),
    ("/build/logs/", "build/logs/today.log", True),
    ("/build/logs/", "src/build/logs/today.log", False),
    ("docs/*", "docs/getting-started.md", True),
    ("docs/*", "docs/build-app/troubleshooting.md", False),
    ("apps/", "apps/x.py", True),
    ("apps/", "src/apps/x.py", True),
    ("/docs/", "docs/a/b.md", True),
    ("/docs/", "src/docs/a.md", False),
    ("/scripts/", "scripts/run.sh", True),
    ("**/logs", "build/logs/x.log", True),
    ("**/logs", "logs/x.log", True),
    ("**/logs", "deeply/nested/logs/x.log", True),
    ("/apps/github", "apps/github", True),
    ("/apps/github", "apps/github/x.py", True),  # a directory without a trailing slash
    ("/apps/github", "apps/githubx", False),
    ("docs/*.md", "docs/a/b.md", False),  # * does not cross /
    ("a/**/b", "a/b", True),
    ("a/**/b", "a/x/y/b", True),
    ("/x/**", "x/y/z", True),
    ("[ab].md", "a.md", False),  # no character classes: [ is literal
    ("[ab].md", "[ab].md", True),
    ("?.md", "a.md", True),
    ("?.md", "ab.md", False),
]


@pytest.mark.parametrize(("pattern", "path", "hit"), GITHUB_CASES)
def test_codeowners_patterns_match_like_github(pattern, path, hit):
    assert bool(rt.codeowners_for([(pattern, ["@owner"])], path)) is hit


def test_the_last_matching_codeowners_rule_wins_and_an_empty_owner_list_unowns():
    rules = rt.parse_codeowners(
        "* @a\n/apps/ @octocat\n/apps/github\n# comment\n/examples/modules/ @b # trailing\n"
    )
    assert rt.codeowners_for(rules, "apps/github/x.py") == []
    assert rt.codeowners_for(rules, "apps/other.py") == ["@octocat"]
    assert rt.codeowners_for(rules, "examples/modules/x/module.yml") == ["@b"]
    assert rt.codeowners_for(rules, "README.md") == ["@a"]


def test_codeowners_escapes_sections_and_invalid_owners():
    rules = rt.parse_codeowners("\\#notes @a\n[Section]\n/x/ owner-without-at\n/y/ @b junk\n")
    assert rt.codeowners_for(rules, "#notes") == ["@a"]
    assert rt.codeowners_for(rules, "x/z") == []
    assert rt.codeowners_for(rules, "y/z") == ["@b"]
    assert [p for p, _ in rules] == ["\\#notes", "/x/", "/y/"]


def test_this_repository_codeowns_every_module_root():
    rules = rt.parse_codeowners((ROOT / ".github" / "CODEOWNERS").read_text())
    for r in rt.MODULE_ROOTS:
        assert rt.codeowners_for(rules, f"{r}/x/module.yml"), r


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


def _commit(root: Path) -> None:
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "c")


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    shutil.copytree(EXAMPLES / "external-collector", root / "modules" / "external-collector")
    (root / "examples" / "modules").mkdir(parents=True)
    shutil.copy(EXAMPLES / "slots.yml", root / rt.SLOTS)
    (root / "schemas" / "platform").mkdir(parents=True)
    shutil.copy(ROOT / rt.SCHEMA, root / rt.SCHEMA)
    (root / ".github").mkdir()
    (root / ".github" / "CODEOWNERS").write_text("/modules/ @owner\n")
    _git(root, "init", "-q")
    _commit(root)
    return root


def _manifest(root: Path) -> Path:
    return root / "modules" / "external-collector" / "module.yml"


def _change(root: Path, fn) -> None:
    doc = yaml.safe_load(_manifest(root).read_text())
    fn(doc)
    _manifest(root).write_text(yaml.safe_dump(doc, sort_keys=False))


def _run(root: Path, capsys, *extra, base="HEAD") -> tuple[int, dict]:
    rc = mcli.main(["review-tier", "--root", str(root), "--base", base, "--json", *extra])
    return rc, json.loads(capsys.readouterr().out)


def _by_path(out: dict) -> dict[str, str]:
    return {m["path"]: m["tier"] for m in out["manifests"]}


def test_the_cli_reports_the_tier_and_passes_with_a_code_owner(repo, capsys):
    _change(repo, lambda d: d.update(egress=[{"from": "receiver", "to": "internet"}], title="x"))
    rc, out = _run(repo, capsys)
    assert rc == 0, out
    (m,) = out["manifests"]
    assert m["tier"] == rt.HUMAN and m["owners"] == ["@owner"]
    assert {c["field"]: c["tier"] for c in m["changes"]} == {"egress": rt.HUMAN, "title": rt.OWNER}


def test_the_cli_fails_a_human_approve_change_with_no_code_owner(repo, capsys):
    (repo / ".github" / "CODEOWNERS").write_text("/docs/ @owner\n")
    _commit(repo)
    _change(repo, lambda d: d.update(credentials=[{"secret": "secret:x/y", "purpose": "x"}]))
    rc, out = _run(repo, capsys)
    assert rc == 1
    assert "no valid CODEOWNERS owner" in out["problems"][0]


def test_codeowners_is_read_as_of_the_base(repo, capsys):
    """B3: GitHub applies the base's CODEOWNERS, so a pull request cannot own its own change."""
    (repo / ".github" / "CODEOWNERS").write_text("/docs/ @owner\n")
    _commit(repo)
    (repo / ".github" / "CODEOWNERS").write_text("/modules/ @mallory\n")
    _change(repo, lambda d: d.update(credentials=[{"secret": "secret:x/y", "purpose": "x"}]))
    rc, out = _run(repo, capsys)
    assert rc == 1
    assert _by_path(out)[".github/CODEOWNERS"] == rt.HUMAN  # a governance change
    assert any("modules/external-collector/module.yml" in p for p in out["problems"])


def test_invalid_owner_tokens_and_a_non_utf8_codeowners_own_nothing(repo, capsys):
    (repo / ".github" / "CODEOWNERS").write_text("/modules/ owner-without-at\n")
    _commit(repo)
    _change(repo, lambda d: d.update(credentials=[{"secret": "secret:x/y", "purpose": "x"}]))
    rc, out = _run(repo, capsys)
    assert rc == 1
    (repo / ".github" / "CODEOWNERS").write_bytes(b"/modules/ @owner \xff\n")
    _commit(repo)
    rc, out = _run(repo, capsys, base="HEAD")
    assert rc == 1 and any("not UTF-8" in p for p in out["problems"])


def test_docs_codeowners_is_read_when_it_is_the_only_one(repo, capsys):
    (repo / ".github" / "CODEOWNERS").unlink()
    (repo / "docs").mkdir()
    (repo / "docs" / "CODEOWNERS").write_text("/modules/ @docs-owner\n")
    _commit(repo)
    _change(repo, lambda d: d.update(credentials=[{"secret": "secret:x/y", "purpose": "x"}]))
    rc, out = _run(repo, capsys)
    assert rc == 0 and out["manifests"][0]["owners"] == ["@docs-owner"]


def test_an_owner_change_needs_no_code_owner(repo, capsys):
    (repo / ".github" / "CODEOWNERS").unlink()
    _commit(repo)
    _change(repo, lambda d: d.update(title="changed"))
    rc, out = _run(repo, capsys)
    assert rc == 0 and out["manifests"][0]["tier"] == rt.OWNER


def test_the_slot_registry_is_read_at_both_ends(repo, capsys):
    """B2: a pull request that drops a slot's privileged flag still has its use of the slot
    judged by the base's registry, and the registry change itself is human-approve."""
    slots = yaml.safe_load((repo / rt.SLOTS).read_text())
    slots["slots"]["secrets"]["privileged"] = False
    (repo / rt.SLOTS).write_text(yaml.safe_dump(slots))
    _change(
        repo,
        lambda d: d["requires"]["capabilities"].append(
            {"cap": "cap:secrets", "version": "1.0", "purpose": "x"}
        ),
    )
    _, out = _run(repo, capsys)
    got = _by_path(out)
    assert got[rt.SLOTS] == rt.HUMAN
    changes = {c["field"]: c["tier"] for c in out["manifests"][1]["changes"]}
    assert changes["requires.capabilities.cap:secrets"] == rt.HUMAN


def test_an_empty_slot_registry_fails_closed(repo, capsys):
    (repo / rt.SLOTS).write_text("slots: {}\n")
    _commit(repo)
    _change(repo, lambda d: d["requires"]["capabilities"][1].update(purpose="changed"))
    _, out = _run(repo, capsys)
    assert _by_path(out)["modules/external-collector/module.yml"] == rt.HUMAN


def test_the_schema_is_read_as_of_the_base(repo, capsys):
    """S2: a pull request that adds a key to the schema still has its use judged undefined."""
    schema = json.loads((repo / rt.SCHEMA).read_text())
    schema["properties"]["surprise"] = {"type": "string"}
    (repo / rt.SCHEMA).write_text(json.dumps(schema))
    _change(repo, lambda d: d.update(surprise="x"))
    _, out = _run(repo, capsys)
    got = _by_path(out)
    assert got[rt.SCHEMA] == rt.HUMAN
    assert got["modules/external-collector/module.yml"] == rt.HUMAN


def test_module_files_are_classified(repo, capsys):
    mod = repo / "modules" / "external-collector"
    (mod / "docs" / "external-collector.md").write_text("changed\n")
    _, out = _run(repo, capsys)
    assert _by_path(out) == {"modules/external-collector/module.yml": rt.OWNER}
    (mod / "agents" / "external-collector-analyst.spec.yml").write_text("id: x\n")
    _, out = _run(repo, capsys)
    assert _by_path(out) == {"modules/external-collector/module.yml": rt.HUMAN}


def test_a_symbolic_link_anywhere_on_the_path_is_human_approve(repo, capsys, tmp_path):
    """S3: a linked parent directory, not just a linked file."""
    elsewhere = tmp_path / "elsewhere"
    shutil.copytree(repo / "modules" / "external-collector" / "docs", elsewhere)
    shutil.rmtree(repo / "modules" / "external-collector" / "docs")
    (repo / "modules" / "external-collector" / "docs").symlink_to(elsewhere)
    _, out = _run(repo, capsys)
    (m,) = out["manifests"]
    assert m["tier"] == rt.HUMAN
    assert any("symbolic link" in c["why"] for c in m["changes"])


def test_a_new_an_unreadable_an_aliased_and_a_linked_manifest_are_human_approve(repo, capsys):
    new = repo / "modules" / "brand-new" / "module.yml"
    new.parent.mkdir()
    new.write_text("id: brand-new\n")
    _manifest(repo).write_text("id: &a x\ntitle: *a\n")  # S4: aliases refused like the loader
    linked = repo / "modules" / "linked" / "module.yml"
    linked.parent.mkdir()
    linked.symlink_to(_manifest(repo))
    rc, out = _run(repo, capsys)
    got = _by_path(out)
    for p in (
        "modules/brand-new/module.yml",
        "modules/external-collector/module.yml",
        "modules/linked/module.yml",
    ):
        assert got[p] == rt.HUMAN, p
    assert rc == 0  # the base's CODEOWNERS owns /modules/


def test_a_rename_is_a_removal_and_an_addition(repo, capsys):
    _git(repo, "mv", "modules/external-collector", "modules/renamed-collector")
    _, out = _run(repo, capsys)
    got = _by_path(out)
    assert got["modules/external-collector/module.yml"] == rt.HUMAN
    assert got["modules/renamed-collector/module.yml"] == rt.HUMAN


def test_a_removed_manifest_is_human_approve(repo, capsys):
    _manifest(repo).unlink()
    rc, out = _run(repo, capsys)
    assert rc == 0  # owned by /modules/
    (m,) = out["manifests"]
    assert m["changes"][0]["why"] == "a removed module"


def test_a_path_outside_a_module_directory_is_human_approve(repo, capsys):
    (repo / "modules" / "stray.yml").write_text("x: 1\n")
    _, out = _run(repo, capsys)
    assert _by_path(out) == {"modules/stray.yml": rt.HUMAN}


def test_a_bad_base_is_a_usage_error(repo, capsys):
    assert mcli.main(["review-tier", "--root", str(repo), "--base", "no-such-rev"]) == 2
    assert mcli.main(["review-tier", "--root", str(repo), "--base", " "]) == 2


def test_ci_base_takes_the_pull_requests_base(repo, capsys, monkeypatch):
    base = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()
    monkeypatch.setattr(mcli.paths, "checkout_root", lambda: ROOT)  # tools/schema_check.py
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    monkeypatch.setenv("HNX_PR_BASE", base)
    _change(repo, lambda d: d.update(title="changed"))
    shutil.copytree(ROOT / "tools", repo / "tools", ignore=shutil.ignore_patterns("tests"))
    rc = mcli.main(["review-tier", "--root", str(repo), "--ci-base", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 0 and _by_path(out)["modules/external-collector/module.yml"] == rt.OWNER
    monkeypatch.setenv("GITHUB_EVENT_NAME", "schedule")
    assert mcli.main(["review-tier", "--root", str(repo), "--ci-base"]) == 2


def test_the_step_summary_lists_each_path(repo, capsys, monkeypatch, tmp_path):
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    _change(repo, lambda d: d.update(title="changed"))
    _run(repo, capsys)
    assert "| `modules/external-collector/module.yml` | owner | `title` |" in summary.read_text()
