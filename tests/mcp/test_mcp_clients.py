# SPDX-License-Identifier: Apache-2.0
"""Client configurations rendered from the MCP catalog: only granted servers, secrets as
placeholders, endpoints from the registry, instances per profile and lane with typed parameters,
every home from one source, drift detection, and llm-orchestrator's format (its loader's rules
encoded in :func:`homelabnext.mcp.clients.orch_accepts`)."""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

import pytest
import yaml

from homelabnext import cli
from homelabnext.mcp import clients, servers
from homelabnext.registry.model import load

ROOT = Path(__file__).resolve().parents[2]
CATALOG = servers.load(ROOT / "examples" / "mcp")
REGISTRY = load(ROOT / "examples" / "services.yml")
SPECS = ROOT / "examples" / "mcp" / "clients"
READER = ROOT / "schemas" / "agent" / "examples" / "profile.reader.json"
BROKER_AGENT = SPECS / "profile.broker-agent.json"
COLLECTOR = SPECS / "profile.collector.json"


def test_only_granted_servers_with_secret_placeholders_and_registry_urls():
    text, notes = clients.render_profile(CATALOG, READER, "claude-code", registry=REGISTRY)
    doc = json.loads(text)
    assert list(doc["mcpServers"]) == ["lake"] and notes == []
    lake = doc["mcpServers"]["lake"]
    assert lake["type"] == "http"
    assert lake["url"] == f"https://{REGISTRY.alias('lake-query')}:8443/mcp"
    assert lake["headers"] == {"Authorization": "Bearer ${HNX_SECRET_MCP_LAKE_TOKEN}"}
    assert "secret:" not in text and "do not edit" in doc["_generated"]


@pytest.mark.parametrize("client", ["claude-code", "claude-desktop", "generic", "hermes"])
def test_every_client_renders_the_broker_agent(client):
    text, _ = clients.render_profile(CATALOG, BROKER_AGENT, client, registry=REGISTRY)
    doc = yaml.safe_load(text)
    block = doc["mcp_servers"] if client == "hermes" else doc["mcpServers"]
    assert set(block) == {"hnx-broker", "hnx-catalog", "notes-broker-agent-real"}
    notes = block["notes-broker-agent-real"]
    assert notes["env"]["NOTES_TOKEN"] == "${HNX_SECRET_MCP_NOTES_TOKEN}"
    assert notes["env"]["NOTES_WRITABLE_PREFIX"] == "agents/broker-agent/"  # default, templated
    assert str(BROKER_AGENT) in block["hnx-catalog"]["args"]  # {profile_file}


def test_claude_desktop_leaves_remote_servers_out_and_says_so():
    text, notes = clients.render_profile(CATALOG, READER, "claude-desktop", registry=REGISTRY)
    assert json.loads(text)["mcpServers"] == {} and "cannot hold lake" in notes[0]


def test_parameters_are_typed_and_checked():
    ok = clients.instances(CATALOG, {"id": "profile:a", "mcp": ["notes"]},
                           lanes=["real", "shadow"], params={"notes@shadow": {"mode": "read"}})  # fmt: skip
    assert [(i.name, i.param_env["NOTES_MODE"]) for i in ok] == [
        ("notes-a-real", "write"), ("notes-a-shadow", "read")]  # fmt: skip
    many = clients.instances(CATALOG, {"id": "profile:a", "mcp": ["notes"]},
                             params={"notes": {"mode": ["read", "write"]}})  # fmt: skip
    assert len(many) == 2  # a list value: one instance per element
    for params, phrase in (
        ({"notes": {"mode": "admin"}}, "is not one of"),
        ({"notes": {"writable": "../escape"}}, "does not match"),
        ({"notes": {"colour": "red"}}, "has no parameter(s) ['colour']"),
        ({"lake": {"x": "y"}}, "which the profile is not granted"),
    ):
        with pytest.raises(clients.RenderError, match=re.escape(phrase)):
            clients.instances(CATALOG, {"id": "profile:a", "mcp": ["notes"]}, params=params)


def test_ungrantable_and_unknown_servers_are_refused():
    for name, phrase in (("puppeteer", "retired"), ("web-search", "draft"), ("nope", "not in")):
        with pytest.raises(clients.RenderError, match=phrase):
            clients.instances(CATALOG, {"id": "profile:a", "mcp": [name]})


def test_two_definitions_under_one_name_are_refused(tmp_path):
    d = tmp_path / "mcp"
    shutil.copytree(ROOT / "examples" / "mcp", d, ignore=shutil.ignore_patterns("clients"))
    rec = yaml.safe_load((d / "notes.yml").read_text())
    rec["instance"] = "notes"
    (d / "notes.yml").write_text(yaml.safe_dump(rec))
    cat = servers.load(d)
    insts = clients.instances(cat, {"id": "profile:a", "mcp": ["notes"]}, lanes=["real", "shadow"],
                              params={"notes@shadow": {"mode": "read"}})  # fmt: skip
    with pytest.raises(clients.RenderError, match="renders two different servers"):
        clients.home_servers(insts, "hermes")
    same = clients.instances(cat, {"id": "profile:a", "mcp": ["notes"]}, lanes=["real", "shadow"])
    assert list(clients.home_servers(same, "hermes")[0]) == ["notes"]  # identical: rendered once


def test_every_home_of_a_spec_holds_every_instance():
    r = clients.render_spec(SPECS / "hermes.yml")
    primary, fallback = (yaml.safe_load(o.text)["mcp_servers"] for o in r.outputs)
    assert primary == fallback
    assert {"notes-collector-real", "notes-collector-shadow", "records", "hnx-broker"} <= set(
        primary
    )
    assert primary["notes-collector-shadow"]["env"]["NOTES_MODE"] == "read"
    assert (
        primary["notes-collector-real"]["env"]["NOTES_WRITABLE_PREFIX"] == "agents/collector/inbox/"
    )


@pytest.mark.parametrize("spec", sorted(p.name for p in SPECS.glob("*.yml")))
def test_the_committed_renders_have_no_drift(spec):
    assert clients.drift(clients.render_spec(SPECS / spec)) == []


def test_check_finds_a_hand_edit_and_a_lost_entry_in_any_home(tmp_path, capsys):
    dst = tmp_path / "mcp"
    shutil.copytree(ROOT / "examples" / "mcp", dst)
    shutil.copy(ROOT / "examples" / "services.yml", tmp_path / "services.yml")
    spec = dst / "clients" / "hermes.yml"
    assert cli.main(["mcp", "catalog", "render", "--spec", str(spec), "--check"]) == 0
    fallback = dst / "clients" / "hermes" / "fallback.yaml"
    doc = yaml.safe_load(fallback.read_text().split("\n", 1)[1])
    doc["mcp_servers"].pop("records")  # the fallback home lost an entry
    fallback.write_text("# hand edit\n" + yaml.safe_dump(doc))
    assert cli.main(["mcp", "catalog", "render", "--spec", str(spec), "--check"]) == 1
    assert "fallback.yaml: differs from the render" in capsys.readouterr().out
    assert cli.main(["mcp", "catalog", "render", "--spec", str(spec)]) == 0
    assert "records" in yaml.safe_load(fallback.read_text())["mcp_servers"]


def test_render_one_profile_from_the_command_line(tmp_path, capsys):
    out = tmp_path / ".mcp.json"
    base = ["mcp", "catalog", "render", "--profile", str(COLLECTOR), "--client", "claude-code"]
    assert cli.main([*base, "--param", "notes.mode=read", "--out", str(out)]) == 0
    assert (
        json.loads(out.read_text())["mcpServers"]["notes-collector-real"]["env"]["NOTES_MODE"]
        == "read"
    )
    assert cli.main([*base, "--param", "notes.mode=read", "--out", str(out), "--check"]) == 0
    assert cli.main([*base, "--out", str(out), "--check"]) == 1  # mode differs: drift
    assert cli.main([*base, "--param", "notes.mode=root"]) == 1
    assert "is not one of" in capsys.readouterr().out
    assert cli.main([*base, "--param", "bad"]) == 2


def test_the_broker_docs_show_the_rendered_entry():
    rendered = json.loads((SPECS / "claude-code" / "broker-agent.mcp.json").read_text())
    want = json.dumps(
        {"hnx-broker": rendered["mcpServers"]["hnx-broker"]}, indent=2, sort_keys=True
    )
    doc = (ROOT / "docs" / "broker.md").read_text()
    assert f"```json\n{want}\n```" in doc
    assert '{"mcpServers": {"hnx-broker": {"command": "hnx",' not in doc  # the old hand-written one


# ----------------------------------------------------------------------- llm-orchestrator
def test_llm_orchestrator_catalog_and_grants_are_its_format():
    r = clients.render_spec(SPECS / "llm-orchestrator.yml")
    catalog, grants = r.outputs
    kinds = yaml.safe_load(catalog.text)["kinds"]
    assert kinds["notes"] == {
        "allowed_env": ["NOTES_MODE", "NOTES_WRITABLE_PREFIX"],
        "args": ["--from", "example-notes-mcp==1.2.0", "notes-mcp"],
        "command": "uvx",
        "env": {"NOTES_ROOT": "/srv/notes", "NOTES_TOKEN": "${HNX_SECRET_MCP_NOTES_TOKEN}"},
        "timeout": 120,
    }
    assert "lake" not in kinds and "hnx-catalog" not in kinds  # remote / per-instance args
    block = yaml.safe_load(grants.text)["grants"]
    assert list(block) == ["real", "shadow"]
    assert block["shadow"][0] == {"name": "notes-collector-shadow", "kind": "notes",
                                  "env": {"NOTES_MODE": "read", "NOTES_WRITABLE_PREFIX": "agents/collector/inbox/"}}  # fmt: skip
    assert clients.orch_accepts(catalog.text, {"collector": grants.text}) == []
    # byte-stable: rendering twice gives the same bytes, and the profile's own fields survive
    again = clients.render_spec(SPECS / "llm-orchestrator.yml")
    assert [o.expected() for o in again.outputs] == [o.expected() for o in r.outputs]
    assert (
        grants.expected().startswith("# SPDX-License-Identifier")
        and "name: collector" in grants.expected()
    )


@pytest.mark.parametrize(
    ("catalog", "grants", "phrase"),
    [
        ("kinds: {Bad: {command: x}}", "grants: {real: []}", "bad name"),  # grants.go:90
        ("kinds: {a: {args: []}}", "grants: {real: []}", "command is required"),  # :94
        ("kinds: {a: {command: x, allowed_env: [PATH]}}", "grants: {}", "never be grant-settable"),  # :98
        ("kinds: {a: {command: x, extra: 1}}", "grants: {}", "unknown field"),  # :85
        ("kinds: {a: {command: x}}", "grants: {real: [{name: s, kind: a}, {name: s, kind: a}]}", "granted twice"),  # :115
        ("kinds: {a: {command: x}}", "grants: {real: [{name: s, kind: b}]}", "unknown kind"),  # :119
        ("kinds: {a: {command: x, allowed_env: [M]}}", "grants: {real: [{name: s, kind: a, env: {N: v}}]}", "may not set env N"),  # :127
        ("kinds: {a: {command: x}}", "grants: {real: [{name: S!, kind: a}]}", "server name"),  # :111
    ],
)  # fmt: skip
def test_orch_accepts_encodes_the_orchestrators_rules(catalog, grants, phrase):
    assert any(phrase in p for p in clients.orch_accepts(catalog, {"p": grants}))


def test_a_per_instance_argument_cannot_be_an_orchestrator_kind():
    with pytest.raises(clients.RenderError, match="per instance"):
        clients.orch_catalog(CATALOG, {"hnx-catalog"})
    text, notes = clients.orch_catalog(CATALOG)
    assert any(n.startswith("hnx-catalog:") for n in notes) and "hnx-catalog" not in text


def test_the_grants_block_is_spliced_in_place():
    head = "name: x\n"
    once = clients.splice_grants(head, clients.ORCH_GRANTS_HEAD + "grants: {}\n")
    assert clients.splice_grants(once, clients.ORCH_GRANTS_HEAD + "grants: {}\n") == once
    assert once.startswith(head) and once.count(clients.GRANTS_MARKER) == 1


def test_a_deprecated_grant_renders_with_a_note(tmp_path):
    prof = tmp_path / "p.json"
    doc = json.loads(COLLECTOR.read_text())
    doc["mcp"] = doc["mcp_ceiling"] = ["bash"]
    prof.write_text(json.dumps(doc))
    text, notes = clients.render_profile(CATALOG, prof, "claude-code")
    assert "bash" in json.loads(text)["mcpServers"]
    assert any("deprecated" in n and "grant 'shell' instead" in n for n in notes)
