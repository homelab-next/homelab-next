# SPDX-License-Identifier: Apache-2.0
"""The MCP catalog (ADR-0024): every validation rule fails on a bad record and passes on the
repository's catalog; the class table derived from it keeps every level and reader verdict the
hand-written table had; grants name catalog ids; first-party records match their code."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
import yaml

from homelabnext.agent import grant_problems
from homelabnext.agent.access import level_of
from homelabnext.agent.readers import ToolClasses, default_classes, lint_paths, reader_problems
from homelabnext.mcp import servers
from homelabnext.registry.model import load
from homelabnext.reviews import load_policy

ROOT = Path(__file__).resolve().parents[2]
CATALOG = ROOT / "examples" / "mcp"
REGISTRY = load(ROOT / "examples" / "services.yml")
POLICY = load_policy(ROOT / "examples" / "review-policy.yml")

#: the hand-written mcp section tool_classes.yml had before the catalog (behaviour to keep)
OLD_TABLE = {
    "lake": ["read"], "records": ["record-write"], "cases": ["record-write"],
    "hnx-catalog": ["read"], "hnx-broker": ["record-write", "exec"], "shell": ["exec"],
    "bash": ["exec"], "terminal": ["exec"], "exec": ["exec"], "ssh": ["exec"],
    "docker": ["exec"], "kubernetes": ["exec"], "ansible": ["exec"],
    "filesystem": ["read", "file-write"], "git": ["read", "file-write"],
    "github": ["egress", "file-write"], "gitlab": ["egress", "file-write"], "fetch": ["egress"],
    "http": ["egress"], "web": ["egress"], "web-search": ["egress"], "browser": ["egress"],
    "playwright": ["egress"], "puppeteer": ["egress"], "email": ["egress"], "smtp": ["egress"],
    "slack": ["egress"], "ntfy": ["egress"], "vault": ["credential"],
}  # fmt: skip


def _check(cat: servers.Catalog) -> list[str]:
    return servers.check(cat, registry=REGISTRY, policy=POLICY, source_root=ROOT)


def test_the_repository_catalog_passes_every_rule():
    cat = servers.load(CATALOG)
    assert len(cat.servers) >= 30
    assert _check(cat) == []


def test_the_derived_table_keeps_every_level_and_reader_verdict():
    """Behaviour unchanged: for every name the hand-written table classified, the level and the
    classes a reader may not hold are what they were (hnx-broker gained ``read`` for its
    read-only tools, which changes neither)."""
    table = default_classes()
    assert table.catalog is not None
    for name, old in OLD_TABLE.items():
        new = table.classify("mcp", name)
        assert new is not None, name
        assert level_of(new) == level_of(old), name
        assert set(new) & table.reader_forbidden == set(old) & table.reader_forbidden, name
    assert set(table.table["mcp"]) >= set(OLD_TABLE)


def test_first_party_records_list_exactly_their_code_tools():
    from homelabnext.broker.mcp_tools import TOOLS as BROKER_TOOLS
    from homelabnext.mcp.catalog import TOOLS

    cat = servers.load(CATALOG)
    assert {t["name"] for t in cat.get("hnx-catalog")["tools"]} == set(TOOLS)
    assert {t["name"] for t in cat.get("hnx-broker")["tools"]} == set(BROKER_TOOLS)


@pytest.fixture
def tmp_catalog(tmp_path):
    d = tmp_path / "mcp"
    shutil.copytree(CATALOG, d, ignore=shutil.ignore_patterns("clients"))
    return d


def _edit(d: Path, sid: str, fn) -> servers.Catalog:
    f = d / f"{sid}.yml"
    rec = yaml.safe_load(f.read_text())
    fn(rec)
    f.write_text(yaml.safe_dump(rec, sort_keys=False))
    return servers.load(d)


def _without_reviews(rec):
    rec.pop("reviews", None)


# every rule: (record, edit, a phrase of the problem); each fails here and passes on the repo
RULES = [
    ("notes", lambda r: r["origin"].update(sha256=None), "has no sha256 and no lock"),
    ("notes", lambda r: r["origin"].update(version=None), "has no exact version"),
    ("lake", lambda r: r["origin"].update(digest=None), "has no digest"),
    ("notes", lambda r: r.update(origin={"kind": "unknown", "hint": "launcher x"}), "origin is unknown"),
    ("notes", lambda r: r.update(origin={"kind": "git", "repo": "code.example/x", "commit": None}), "has no commit"),
    ("hnx-catalog", lambda r: r["origin"].update(path="homelabnext/nothing-here/"), "not in the source tree"),
    ("notes", lambda r: r["origin"].update(version="^1.2.0"), "origin"),  # schema: a range
    ("notes", lambda r: r.update(tools=[]), "lists no tools"),
    ("notes", lambda r: r["tools"].append(dict(r["tools"][0])), "is listed twice"),
    ("notes", lambda r: r.update(id="other-id"), "is not the file name"),
    ("fetch", lambda r: r.update(egress="none"), "classed egress but the server's egress is none"),
    ("notes", lambda r: r.update(egress=["internet"]), "no tool is classed egress"),
    ("notes", lambda r: r["env"].update(OTHER="secret:mcp_notes-token"), "are both delivered as"),
    ("notes", lambda r: r["settings"].update(NOTES_SESSION="x"), "names a credential"),
    ("notes", lambda r: r["parameters"]["mode"].update(env="LD_PRELOAD"), "may never be set by a grant"),
    ("notes", lambda r: r["parameters"]["mode"].update(env="NOTES_ROOT"), "also a fixed setting"),
    ("notes", lambda r: r["parameters"]["mode"].update(env="NOTES_WRITABLE_PREFIX"), "both set env"),
    ("notes", lambda r: r["parameters"]["mode"].update(default="admin"), "is not one of"),
    ("notes", lambda r: r["parameters"]["writable"].update(pattern="(["), "does not compile"),
    ("notes", lambda r: r["parameters"]["mode"].update(required=True), "is required and has a default"),
    ("notes", lambda r: r.update(instance="notes-{agent}"), "is not a parameter or builtin"),
    ("notes", lambda r: r["parameters"]["writable"].update(default="{mode}/"), "default may use only"),
    ("hnx-catalog", lambda r: r.update(implements=["cap:telepathy"]), "not a homelab-next capability contract"),
    ("bash", lambda r: r.update(replaced_by="puppeteer"), "is not an active catalog server"),
    ("lake", lambda r: r["transport"].update(endpoint="svc:nothing"), "is not a registry service"),
    ("lake", lambda r: r["transport"].update(endpoint="svc:records-db"), "speaks postgres"),
    ("lake", lambda r: r["transport"].update(path="/other"), "but the registry says"),
    ("lake", lambda r: r["transport"].update(type="sse"), "but the registry says"),
    ("lake", lambda r: r["runtime"].update(host="nowhere"), "is not a registry host"),
    ("ssh", lambda r: r.update(egress=["host:nowhere"]), "is not a registry host"),
    ("lake", lambda r: r.update(egress=["svc:nothing"]), "is not a registry service"),
    ("lake", lambda r: r["reviews"].pop(), "needs human approve review(s)"),
    ("lake", lambda r: r.update(description="changed"), "review(s) of the current content"),
    ("lake", lambda r: r.update(author="agent:example-checker"), "nobody reviews their own work"),
]  # fmt: skip


@pytest.mark.parametrize(("sid", "edit", "phrase"), RULES, ids=[r[2][:40] for r in RULES])
def test_each_rule_fails_on_a_bad_record(tmp_catalog, sid, edit, phrase):
    assert _check(servers.load(tmp_catalog)) == []  # passes before the edit
    problems = _check(_edit(tmp_catalog, sid, edit))
    assert any(phrase in p for p in problems), problems


def test_a_registry_mcp_entry_must_resolve_to_the_catalog(tmp_catalog):
    (tmp_catalog / "lake.yml").unlink()
    problems = _check(servers.load(tmp_catalog))
    assert any("MCP server 'lake' is not in the MCP catalog" in p for p in problems)


def test_a_registry_mcp_entry_must_be_the_records_endpoint(tmp_catalog):
    cat = _edit(tmp_catalog, "lake", lambda r: r["transport"].update(endpoint="svc:status-hub"))
    problems = servers.check(cat, registry=REGISTRY)
    assert any("does not name it as its endpoint" in p for p in problems)


def test_duplicate_ids_are_refused(tmp_catalog):
    (tmp_catalog / "zz-copy.yml").write_text((tmp_catalog / "lake.yml").read_text())
    problems = _check(servers.load(tmp_catalog))
    assert any("is already defined by lake.yml" in p for p in problems)


# ---------------------------------------------------------------------------------- grants
def test_grants_must_name_active_catalog_servers():
    table = default_classes()
    assert grant_problems({"mcp": ["lake", "shell"]}, table) == []
    assert "not in the MCP catalog" in grant_problems({"mcp": ["nothing"]}, table)[0]
    assert "is retired" in grant_problems({"mcp": ["puppeteer"]}, table)[0]
    assert "is a draft" in grant_problems({"mcp": ["web-search"]}, table)[0]
    assert grant_problems({"mcp": ["bash"]}, table) == []  # deprecated: still grantable


def test_local_only_data_never_reaches_a_cloud_profile():
    table = default_classes()
    assert grant_problems({"mcp": ["lake"]}, table, "p", "local-only") == []
    bad = grant_problems({"mcp": ["lake"]}, table, "p", "cloud-allowed")
    assert bad and "whose data is local-only" in bad[0]
    assert grant_problems({"mcp": ["hnx-catalog"]}, table, "p", "cloud-allowed") == []


def test_a_reader_cannot_hold_an_acting_catalog_server():
    assert reader_problems({"mcp": ["hnx-catalog", "lake"]}) == []
    assert "(exec)" in reader_problems({"mcp": ["hnx-broker"]})[0]
    assert "(egress, file-write)" in reader_problems({"mcp": ["github"]})[0]
    assert "(credential)" in reader_problems({"mcp": ["vault"]})[0]


def test_lint_reports_unknown_and_retired_grants(tmp_path):
    (tmp_path / "p.yml").write_text(
        yaml.safe_dump(
            {
                "id": "profile:x",
                "persona": "persona:a",
                "mcp": ["puppeteer", "nope"],
                "capabilities": [],
                "reads_untrusted": False,
            }
        )
    )
    problems, counts = lint_paths([tmp_path])
    assert counts["profile"] == 1
    assert any("retired" in p for _, p in problems) and any("'nope'" in p for _, p in problems)
    assert lint_paths([ROOT])[0] == []  # the repository's profiles all pass


def test_the_table_comes_from_the_catalog_directory_given(tmp_catalog):
    (tmp_catalog / "shell.yml").unlink()
    table = ToolClasses.load(catalog=tmp_catalog)
    assert table.classify("mcp", "shell") is None and table.classify("mcp", "lake") == ("read",)
    with pytest.raises(Exception, match="no MCP catalog directory"):
        ToolClasses.load(catalog=tmp_catalog / "missing")


def test_the_review_digest_is_the_record_without_its_reviews():
    from homelabnext.reviews import file_digest

    rec = yaml.safe_load((CATALOG / "lake.yml").read_text())
    assert file_digest(CATALOG / "lake.yml") == servers.record_digest(rec)
    assert rec["reviews"][0]["digest"] == servers.record_digest(rec)[:19]


def test_cli_check(capsys, tmp_catalog):
    from homelabnext import cli

    assert cli.main(["mcp", "catalog", "check"]) == 0
    _edit(tmp_catalog, "notes", lambda r: r.update(tools=[]))
    shutil.copy(ROOT / "examples" / "services.yml", tmp_catalog.parent / "services.yml")
    args = ["mcp", "catalog", "check", "--catalog", str(tmp_catalog), "--policy", "none"]
    assert cli.main([*args, "--grants", str(ROOT / "schemas" / "agent" / "examples")]) == 1
    assert "lists no tools" in capsys.readouterr().out
    assert cli.main(["mcp", "catalog", "list", "--catalog", str(CATALOG)]) == 0
    assert "hnx-broker\tactive" in capsys.readouterr().out
    assert cli.main(["mcp", "catalog", "classes"]) == 0
    assert yaml.safe_load(capsys.readouterr().out)["mcp"]["vault"] == ["credential"]
