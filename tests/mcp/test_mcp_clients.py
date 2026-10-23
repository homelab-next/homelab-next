# SPDX-License-Identifier: Apache-2.0
"""Client configurations rendered from the MCP catalog: only granted servers, secrets as
placeholders, endpoints from the registry, instances per profile and lane with typed parameters,
every home from one source, drift detection, and llm-orchestrator's format (its loader's rules
encoded in :func:`homelabnext.mcp.clients.orch_accepts`)."""

from __future__ import annotations

import copy
import json
import re
import shutil
from pathlib import Path

import pytest
import yaml

from homelabnext import cli
from homelabnext.agent.compiler import CeilingPolicy, profile_digest
from homelabnext.mcp import clients, servers
from homelabnext.registry.model import load

ROOT = Path(__file__).resolve().parents[2]
CATALOG = servers.load(ROOT / "examples" / "mcp")
REGISTRY = load(ROOT / "examples" / "services.yml")
SPECS = ROOT / "examples" / "mcp" / "clients"
READER = ROOT / "schemas" / "agent" / "examples" / "profile.reader.json"
BROKER_AGENT = SPECS / "profile.broker-agent.json"
COLLECTOR = SPECS / "profile.collector.json"
NPM_PREFIX = "/var/lib/hnx/npm-prefix"
CTX = servers.LaunchContext(npm_prefix=NPM_PREFIX)


def _lax_review_policy(beside: Path) -> None:
    """The example review policy beside a copied catalog, asking no MCP server review: these
    tests edit records (render refuses a catalog with no review policy at all)."""
    doc = yaml.safe_load((ROOT / "examples" / "review-policy.yml").read_text())
    doc["requirements"]["mcp-server"] = {s: [] for s in doc["requirements"]["mcp-server"]}
    (beside / "review-policy.yml").write_text(yaml.safe_dump(doc))


def _policy() -> CeilingPolicy:
    """The example specs' ceiling policy, plus the schema example reader's ceiling."""
    doc = yaml.safe_load((SPECS / "policy" / "ceilings.yml").read_text())
    reader = json.loads(READER.read_text())
    doc["ceilings"]["profile:reader"] = {**reader["ceiling"], "data_tier": reader["data_tier"]}
    return CeilingPolicy.from_mapping(doc, source="the test policy")


POLICY = _policy()
#: a ceiling as wide as the catalog, for tests about something other than the ceiling
WIDE = CeilingPolicy.from_mapping(
    {"ceilings": {pid: {"mcp": sorted(CATALOG.servers), "capabilities": ["cap:records-propose"],
                        "tier": "write", "budgets": json.loads(COLLECTOR.read_text())["budgets"],
                        "data_tier": "local-only", "internet_mcp": sorted(CATALOG.servers)}
                  for pid in ("profile:collector",)}},
    source="the wide test policy",
)  # fmt: skip


def test_only_granted_servers_with_secret_placeholders_and_registry_urls():
    text, notes = clients.render_profile(
        CATALOG, READER, "claude-code", registry=REGISTRY, policy=POLICY
    )
    doc = json.loads(text)
    assert list(doc["mcpServers"]) == ["lake"] and notes == []
    lake = doc["mcpServers"]["lake"]
    assert lake["type"] == "http"
    assert lake["url"] == f"https://{REGISTRY.alias('lake-query')}:8443/mcp"
    assert lake["headers"] == {"Authorization": "Bearer ${HNX_SECRET_MCP_LAKE_TOKEN}"}
    assert "secret:" not in text and "do not edit" in doc["_generated"]


@pytest.mark.parametrize("client", ["claude-code", "generic", "hermes"])
def test_every_client_renders_the_broker_agent(client):
    text, _ = clients.render_profile(
        CATALOG, BROKER_AGENT, client, registry=REGISTRY, policy=POLICY
    )
    doc = yaml.safe_load(text)
    block = doc["mcp_servers"] if client == "hermes" else doc["mcpServers"]
    assert set(block) == {"hnx-broker", "hnx-catalog", "notes-broker-agent-real"}
    notes = block["notes-broker-agent-real"]
    assert notes["env"]["NOTES_TOKEN"] == "${HNX_SECRET_MCP_NOTES_TOKEN}"
    assert notes["env"]["NOTES_WRITABLE_PREFIX"] == "agents/broker-agent/"  # default, templated
    assert str(BROKER_AGENT) in block["hnx-catalog"]["args"]  # {profile_file}


def test_claude_desktop_leaves_remote_servers_out_and_says_so():
    text, notes = clients.render_profile(
        CATALOG, READER, "claude-desktop", registry=REGISTRY, policy=POLICY
    )
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
    _lax_review_policy(d.parent)
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
    _lax_review_policy(dst.parent)
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
    base = ["mcp", "catalog", "render", "--profile", str(COLLECTOR), "--client", "claude-code",
            "--policy", str(SPECS / "policy" / "ceilings.yml")]  # fmt: skip
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
        "args": ["--no-config", "--from", "example-notes-mcp==1.2.0", "notes-mcp"],
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
        clients.orch_catalog(CATALOG, {"hnx-catalog"}, CTX)
    text, notes = clients.orch_catalog(CATALOG, ctx=CTX)
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
    doc["reads_untrusted"] = False
    prof.write_text(json.dumps(doc))
    text, notes = clients.render_profile(
        CATALOG, prof, "claude-code", policy=WIDE, npm_prefix=NPM_PREFIX
    )
    assert "bash" in json.loads(text)["mcpServers"]
    assert any("deprecated" in n and "grant 'shell' instead" in n for n in notes)


def test_render_anchors_npx_at_an_absolute_npm_prefix(tmp_path):
    """Round 4, F1: an npm server renders only with an absolute ``npm_prefix`` (spec key or
    ``--npm-prefix``): missing or relative, the render is refused, never anchored in the
    client's working directory."""
    prof = tmp_path / "p.json"
    doc = json.loads(COLLECTOR.read_text())
    doc["mcp"] = doc["mcp_ceiling"] = ["bash"]
    doc["reads_untrusted"] = False
    prof.write_text(json.dumps(doc))
    with pytest.raises(clients.RenderError, match="npm_prefix is not given"):
        clients.render_profile(CATALOG, prof, "claude-code", policy=WIDE)
    with pytest.raises(clients.RenderError, match="npm_prefix is not an absolute path"):
        clients.render_profile(CATALOG, prof, "claude-code", policy=WIDE, npm_prefix="prefix")
    text, _ = clients.render_profile(
        CATALOG, prof, "claude-code", policy=WIDE, npm_prefix=NPM_PREFIX
    )
    assert json.loads(text)["mcpServers"]["bash"]["args"][:2] == ["-y", f"--prefix={NPM_PREFIX}"]
    spec = tmp_path / "spec.yml"
    spec.write_text(yaml.safe_dump({
        "client": "claude-code", "catalog": str(ROOT / "examples" / "mcp"), "policy": "pol.yml",
        "npm_prefix": "relative/prefix", "profiles": [{"file": str(prof)}],
        "outputs": [{"path": "out.json"}]}))  # fmt: skip
    (tmp_path / "pol.yml").write_text(yaml.safe_dump({"ceilings": {}}))
    with pytest.raises(clients.RenderError, match="npm_prefix is not an absolute path"):
        clients.render_spec(spec)


# ------------------------------------------------------------------ what render will trust
def _lean(tmp_path: Path, **changes) -> Path:
    doc = {**json.loads(COLLECTOR.read_text()), **changes}
    p = tmp_path / "lean.json"
    p.write_text(json.dumps(doc))
    return p


def test_render_refuses_a_profile_verify_would_refuse(tmp_path):
    reader = _lean(tmp_path, mcp=["shell", "vault"], mcp_ceiling=[], data_tier="cloud-allowed")
    with pytest.raises(clients.RenderError) as exc:
        clients.render_profile(CATALOG, reader, "claude-code", policy=WIDE)
    text = "\n".join(exc.value.problems)
    assert "readers cannot act" in text and "outside mcp_ceiling" in text
    with pytest.raises(clients.RenderError, match="not a compiled or lean agent profile"):
        clients.render_profile(
            CATALOG, _lean(tmp_path, digest="sha256:00"), "claude-code", policy=WIDE
        )
    compiled = json.loads(BROKER_AGENT.read_text())
    for edit, phrase in (
        (lambda d: d.pop("digest"), "carries its digest"),
        (lambda d: d["grants"]["mcp"].append("vault"), "outside ceiling"),
        (lambda d: d.update(budget_mode="warn"), "digest does not match"),
    ):
        doc = json.loads(json.dumps(compiled))
        edit(doc)
        f = tmp_path / "compiled.json"
        f.write_text(json.dumps(doc))
        with pytest.raises(clients.RenderError, match=phrase):
            clients.render_profile(CATALOG, f, "claude-code", policy=POLICY)


def test_a_lean_profile_cannot_switch_off_the_reader_rule_its_policy_forces(tmp_path):
    """The policy owner marks a profile a reader; ``reads_untrusted: false`` in the lean file
    (whoever last edited it) does not turn the reader rule off, as it does not for a compiled
    profile (verify_profile)."""
    wide = WIDE.ceiling("profile:collector")
    ceiling = {**wide, "reads_untrusted": True, "data_tier": "local-only"}
    ceiling["internet_mcp"] = sorted(CATALOG.servers)
    policy = CeilingPolicy.from_mapping(
        {"ceilings": {"profile:collector": ceiling}}, source="the reader policy"
    )
    assert policy.requires_reader("profile:collector")
    for flag in ({}, {"reads_untrusted": False}):
        lean = _lean(tmp_path, mcp=["shell"], mcp_ceiling=["shell"], **flag)
        with pytest.raises(clients.RenderError, match="readers cannot act"):
            clients.render_profile(CATALOG, lean, "claude-code", policy=policy)
    with pytest.raises(clients.RenderError, match="marks profile:collector as reading untrusted"):
        clients.render_profile(CATALOG, lean, "claude-code", policy=policy)
    # a policy that does not mark it a reader leaves the profile's own word standing
    assert not WIDE.requires_reader("profile:collector")
    ok = _lean(tmp_path, mcp=["notes"], mcp_ceiling=["notes"], reads_untrusted=False)
    assert clients.render_profile(CATALOG, ok, "claude-code", policy=WIDE)


def test_a_compiled_profile_is_judged_against_the_policy_and_the_lock(tmp_path):
    """A hand-edited compiled profile with a recomputed digest passes every check that reads only
    the file (its stored ceiling was edited with it): render needs the policy, and the lock."""
    forged = json.loads(BROKER_AGENT.read_text())
    forged["grants"]["mcp"].append("vault")
    forged["ceiling"]["mcp"].append("vault")
    forged["digest"] = profile_digest(forged)
    f = tmp_path / "forged.json"
    f.write_text(json.dumps(forged))
    with pytest.raises(clients.RenderError, match="rendered against the ceiling policy"):
        clients.render_profile(CATALOG, f, "claude-code", registry=REGISTRY)
    with pytest.raises(clients.RenderError, match="wider than the policy"):
        clients.render_profile(CATALOG, f, "claude-code", registry=REGISTRY, policy=POLICY)
    honest = json.loads(BROKER_AGENT.read_text())
    honest["budget_mode"] = "warn"  # within the policy, but not what was reviewed
    honest["digest"] = profile_digest(honest)
    f.write_text(json.dumps(honest))
    reviewed = {"profile:broker-agent": json.loads(BROKER_AGENT.read_text())["digest"]}
    kw = {"registry": REGISTRY, "policy": POLICY}
    assert clients.render_profile(CATALOG, f, "claude-code", **kw)
    with pytest.raises(clients.RenderError, match="is not the reviewed"):
        clients.render_profile(CATALOG, f, "claude-code", lock=reviewed, **kw)
    # a lean profile is held to the policy's ceiling when there is one
    lean = _lean(
        tmp_path, mcp=["notes", "records", "lake"], mcp_ceiling=["notes", "records", "lake"]
    )
    with pytest.raises(clients.RenderError, match="outside the policy's ceiling"):
        clients.render_profile(CATALOG, lean, "claude-code", registry=REGISTRY, policy=POLICY)
    # and refused without one: its own mcp_ceiling is whatever edited the file
    for f in (lean, COLLECTOR):
        with pytest.raises(clients.RenderError, match="lean profile is rendered against the"):
            clients.render_profile(CATALOG, f, "claude-code", registry=REGISTRY)
    # the CLI and a spec carry the policy too
    pol = SPECS / "policy" / "ceilings.yml"
    base = ["mcp", "catalog", "render", "--profile", str(BROKER_AGENT), "--client", "claude-code"]
    assert cli.main(base) == 1
    assert cli.main([*base, "--policy", str(pol)]) == 0
    spec = _hermes_copy(tmp_path)
    doc = yaml.safe_load(spec.read_text())
    doc.pop("policy")
    spec.write_text(yaml.safe_dump(doc))
    with pytest.raises(clients.RenderError, match="rendered against the ceiling policy"):
        clients.render_spec(spec)


def _open_param_catalog(tmp_path: Path) -> servers.Catalog:
    d = tmp_path / "mcp"
    shutil.copytree(ROOT / "examples" / "mcp", d, ignore=shutil.ignore_patterns("clients"))
    _lax_review_policy(d.parent)
    rec = yaml.safe_load((d / "notes.yml").read_text())
    rec["parameters"]["writable"].pop("pattern")  # a parameter with no type of its own
    rec["transport"]["args"] = ["--prefix={writable}", "--token=secret:mcp/notes-token"]
    (d / "notes.yml").write_text(yaml.safe_dump(rec))
    return servers.load(d)


def test_a_parameter_value_never_routes_a_secret_or_a_variable(tmp_path):
    cat = _open_param_catalog(tmp_path)
    prof = {"id": "profile:a", "mcp": ["notes"]}
    for value, phrase in (
        ("secret:mcp/vault-token", "carries $, secret:"),
        ("${VAULT_ROOT_TOKEN}", "carries $, secret:"),
        ("$(id)", "carries $, secret:"),
        ("a\nb", "control character"),
        (True, "is not a string"),
        (493, "is not a string"),
    ):
        with pytest.raises(clients.RenderError, match=re.escape(phrase)):
            clients.instances(cat, prof, params={"notes": {"writable": value}})
    with pytest.raises(clients.RenderError, match="profile_file"):
        clients.instances(cat, prof, profile_file="${HOME}/p.json")
    # a lane and a home are templated ({lane}, {home}) like a value: plain names only
    for kw in (
        {"lanes": ["${HNX_SECRET_MCP_VAULT_TOKEN}"]},
        {"lanes": ["$(id)"]},
        {"lanes": ["secret:mcp/vault-token"]},
        {"home": "secret:mcp/vault-token"},
        {"home": "${HOME}"},
        {"lanes": ["real\n"]},  # a pattern's $ matches before a final newline: fullmatch
        {"home": "primary\n"},
    ):
        with pytest.raises(clients.RenderError, match="is not a plain name"):
            clients.instances(cat, prof, params={"notes": {"writable": "x/"}}, **kw)
    (inst,) = clients.instances(cat, prof, params={"notes": {"writable": "x/"}})
    args = clients.definition(inst, "claude-code")["args"]
    # the record's own secret reference becomes a placeholder; a filled value stays verbatim
    assert args[-2:] == ["--prefix=x/", "--token=${HNX_SECRET_MCP_NOTES_TOKEN}"]


def test_render_writes_only_under_its_root_never_through_a_link(tmp_path):
    dst = tmp_path / "mcp"
    shutil.copytree(ROOT / "examples" / "mcp", dst)
    _lax_review_policy(dst.parent)
    shutil.copy(ROOT / "examples" / "services.yml", tmp_path / "services.yml")
    spec = dst / "clients" / "hermes.yml"
    doc = yaml.safe_load(spec.read_text())
    for path, phrase in (
        ("../../escape.yaml", "outside"),
        (str(tmp_path / "abs.yaml"), "absolute"),
    ):
        doc["outputs"] = [{"home": "primary", "path": path}]
        spec.write_text(yaml.safe_dump(doc))
        with pytest.raises(clients.RenderError, match=phrase):
            clients.render_spec(spec)
    target = tmp_path / "elsewhere.yaml"
    target.write_text("keep\n")
    (dst / "clients" / "link.yaml").symlink_to(target)
    doc["outputs"] = [{"home": "primary", "path": "link.yaml"}]
    spec.write_text(yaml.safe_dump(doc))
    with pytest.raises(clients.RenderError, match="symlink"):
        clients.render_spec(spec)
    assert target.read_text() == "keep\n"
    doc["outputs"] = [{"home": "primary", "path": "out/primary.yaml"}]
    spec.write_text(yaml.safe_dump(doc))
    assert cli.main(["mcp", "catalog", "render", "--spec", str(spec), "--root", str(tmp_path)]) == 0
    assert (tmp_path / "out" / "primary.yaml").is_file()
    assert not list((tmp_path / "out").glob(".*"))  # the temporary file was renamed into place


# ---------------------------------------------- llm-orchestrator: what its loaders accept
def _orch_copy(tmp_path: Path) -> Path:
    dst = tmp_path / "mcp"
    shutil.copytree(ROOT / "examples" / "mcp", dst)
    _lax_review_policy(dst.parent)
    shutil.copy(ROOT / "examples" / "services.yml", dst.parent)  # the registry beside it
    return dst / "clients" / "llm-orchestrator.yml"


def test_llm_orchestrator_refuses_a_granted_remote_server_and_one_empty_lane(tmp_path):
    lake = _lean(tmp_path, mcp=["notes", "records", "lake"],
                 mcp_ceiling=["notes", "records", "lake"])  # fmt: skip
    with pytest.raises(clients.RenderError, match="a streamable-http server; llm-orchestrator"):
        clients.render_profile(
            CATALOG, lake, "llm-orchestrator", lanes=["real", "shadow"], policy=WIDE
        )
    # a real lane without a shadow lane: llm-orchestrator fails every shadow job
    with pytest.raises(clients.RenderError, match="fails every shadow job"):
        clients.render_profile(CATALOG, COLLECTOR, "llm-orchestrator", lanes=["real"], policy=WIDE,
                               npm_prefix=NPM_PREFIX)  # fmt: skip
    block, _ = clients.render_profile(CATALOG, COLLECTOR, "llm-orchestrator",
                                      lanes=["real", "shadow"], policy=WIDE,
                                      npm_prefix=NPM_PREFIX)  # fmt: skip
    assert block.startswith("\n" + clients.GRANTS_MARKER)


def test_the_splice_never_makes_a_second_grants_key_or_drops_keys():
    block = clients.ORCH_GRANTS_HEAD + "grants: {real: [], shadow: []}\n"
    with pytest.raises(clients.RenderError, match="grants: key outside the generated block"):
        clients.splice_grants("name: x\ngrants: {real: []}\n", block)
    after = clients.splice_grants("name: x\n", block) + "toolsets: {real: a}\n"
    with pytest.raises(clients.RenderError, match=r"\['toolsets'\] follow the generated"):
        clients.splice_grants(after, block)
    # a new file: no leading blank lines; yaml.v3 refuses a duplicate key, and so does the check
    assert clients.splice_grants("", block).startswith(clients.GRANTS_MARKER)
    bad = clients.orch_accepts("kinds: {}", {"p": "name: x\nname: y\n"})
    assert bad and "duplicate key 'name'" in bad[0]


def test_a_spec_refuses_a_missing_grants_file_and_checks_every_orchestrator_profile(tmp_path):
    spec = _orch_copy(tmp_path)
    profiles = spec.parent / "llm-orchestrator" / "profiles"
    other = profiles / "monitor.yaml"  # not in the spec, but loaded by the same controller
    other.write_text("name: monitor\ngrants:\n  real: [{name: c, kind: collectormcp}]\n"
                     "  shadow: [{name: c, kind: collectormcp}]\n")  # fmt: skip
    with pytest.raises(clients.RenderError, match="unknown kind 'collectormcp'"):
        clients.render_spec(spec)
    other.unlink()
    (profiles / "collector.yaml").unlink()
    with pytest.raises(clients.RenderError, match="no such profile file"):
        clients.render_spec(spec)


def test_check_reports_a_file_the_spec_owns_but_does_not_render(tmp_path, capsys):
    spec = _orch_copy(tmp_path).with_name("hermes.yml")
    shutil.copy(ROOT / "examples" / "services.yml", tmp_path / "services.yml")
    (spec.parent / "hermes" / "old-home.yaml").write_text("mcp_servers: {}\n")
    assert cli.main(["mcp", "catalog", "render", "--spec", str(spec), "--check"]) == 1
    assert "old-home.yaml: owned by the spec (owns:) but not rendered" in capsys.readouterr().out


# ------------------------------------------------- homes, Claude Desktop, Hermes, digests
def test_claude_desktop_refuses_a_server_that_needs_a_secret():
    with pytest.raises(clients.RenderError, match=r"does not expand \$\{VAR\}.*notes-token"):
        clients.render_profile(
            CATALOG, BROKER_AGENT, "claude-desktop", registry=REGISTRY, policy=POLICY
        )


def test_hermes_refuses_an_sse_server(tmp_path):
    d = tmp_path / "mcp"
    shutil.copytree(ROOT / "examples" / "mcp", d, ignore=shutil.ignore_patterns("clients"))
    _lax_review_policy(d.parent)
    rec = yaml.safe_load((d / "lake.yml").read_text())
    rec["transport"]["type"] = "sse"
    (d / "lake.yml").write_text(yaml.safe_dump(rec))
    reg = copy.deepcopy(REGISTRY)  # the registry agrees (render runs the full record check)
    reg.services["lake-query"].mcp["transport"] = "sse"
    with pytest.raises(clients.RenderError, match="legacy sse transport"):
        clients.render_profile(servers.load(d), READER, "hermes", registry=reg, policy=POLICY)


def _hermes_copy(tmp_path: Path) -> Path:
    dst = tmp_path / "mcp"
    shutil.copytree(ROOT / "examples" / "mcp", dst)
    _lax_review_policy(dst.parent)
    shutil.copy(ROOT / "examples" / "services.yml", tmp_path / "services.yml")
    return dst / "clients" / "hermes.yml"


def test_each_home_can_differ_by_its_params_and_name(tmp_path):
    spec = _hermes_copy(tmp_path)
    notes = spec.parent.parent / "notes.yml"
    rec = yaml.safe_load(notes.read_text())
    rec["parameters"]["tier"] = {"env": "NOTES_TIER", "enum": ["primary", "fallback", "cloud"],
                                 "default": "{home}"}  # fmt: skip
    notes.write_text(yaml.safe_dump(rec))
    doc = yaml.safe_load(spec.read_text())
    doc["outputs"] = [
        {"home": "primary", "path": "a.yaml"},
        {"home": "fallback", "path": "b.yaml", "params": {"notes": {"tier": "cloud"}}},
    ]
    spec.write_text(yaml.safe_dump(doc))
    a, b = (yaml.safe_load(o.text)["mcp_servers"] for o in clients.render_spec(spec).outputs)
    assert a["notes-collector-real"]["env"]["NOTES_TIER"] == "primary"  # {home}
    assert b["notes-collector-real"]["env"]["NOTES_TIER"] == "cloud"  # the home's own value
    assert set(a) == set(b)


def test_a_file_drifts_only_when_a_record_it_holds_changes(tmp_path):
    spec = _hermes_copy(tmp_path)
    assert clients.drift(clients.render_spec(spec)) == []
    for o in clients.render_spec(spec).outputs:  # an editor's trailing newline is not drift
        o.path.write_text(o.path.read_text() + "\n")
    email = spec.parent.parent / "email.yml"  # no hermes home holds email
    email.write_text(email.read_text().replace("description: ", "description: Changed. ", 1))
    assert clients.drift(clients.render_spec(spec)) == []
    notes = spec.parent.parent / "notes.yml"
    notes.write_text(notes.read_text().replace("timeout: 120", "timeout: 90"))
    assert len(clients.drift(clients.render_spec(spec))) == 2


def test_a_spec_lane_or_home_is_a_plain_name_and_params_name_a_real_lane(tmp_path):
    dst = tmp_path / "mcp"
    shutil.copytree(ROOT / "examples" / "mcp", dst)
    _lax_review_policy(dst.parent)
    shutil.copy(ROOT / "examples" / "services.yml", tmp_path / "services.yml")
    spec = dst / "clients" / "hermes.yml"
    base = yaml.safe_load(spec.read_text())
    for edit, phrase in (
        (lambda d: d.update(lanes=["${HNX_SECRET_MCP_VAULT_TOKEN}"]), "lanes must list plain names"),
        (lambda d: d.update(lanes="real"), "lanes must list plain names"),
        (lambda d: d["outputs"][0].update(home="$(id)"), "home must be a plain name"),
        (lambda d: d["outputs"][0].update(home="primary\n"), "home must be a plain name"),
        (lambda d: d.update(lanes=["real\n", "shadow"]), "lanes must list plain names"),
        # a typo in a server or lane name is refused, never silently ignored
        (lambda d: d["profiles"][1]["params"].update({"notes@shadwo": {"mode": "read"}}),
         "'notes@shadwo': not a rendered lane"),
        (lambda d: d["outputs"][0].update(params={"nots": {"mode": "read"}}),
         "no profile of the spec is granted nots"),
        (lambda d: d["outputs"][0].update(params={"notes@rael": {"mode": "read"}}),
         "'notes@rael': not a rendered lane"),
    ):  # fmt: skip
        doc = yaml.safe_load(yaml.safe_dump(base))
        edit(doc)
        spec.write_text(yaml.safe_dump(doc))
        with pytest.raises(clients.RenderError, match=re.escape(phrase)):
            clients.render_spec(spec)
    with pytest.raises(clients.RenderError, match="is not a plain name"):
        clients.render_profile(CATALOG, COLLECTOR, "claude-code", lanes=["$(id)"], policy=WIDE)


def test_render_refuses_a_record_check_would_refuse(tmp_path):
    """Render used to judge profiles but never the records it writes: a literal credential, an
    unpinned launch or a record edited after its review rendered."""
    d = tmp_path / "mcp"
    shutil.copytree(ROOT / "examples" / "mcp", d, ignore=shutil.ignore_patterns("clients"))
    _lax_review_policy(d.parent)
    shutil.copy(ROOT / "examples" / "review-policy.yml", tmp_path / "review-policy.yml")
    pristine = (d / "notes.yml").read_text()
    for edit, phrase in (
        (lambda r: r["transport"].update(args=["--token", "fakeLiteralT0kenValue9Zq7"]),
         "follows --token"),
        (lambda r: r["transport"].update(bin="python", args=["-c", "x"]), "interpreter, shell"),
        (lambda r: r["origin"].update(sha256=None), "has no sha256"),
        (lambda r: r.update(description="changed after its review"), "of the current content"),
    ):  # fmt: skip
        rec = yaml.safe_load(pristine)
        edit(rec)
        (d / "notes.yml").write_text(yaml.safe_dump(rec))
        with pytest.raises(clients.RenderError, match=re.escape(phrase)):
            clients.render_profile(servers.load(d), COLLECTOR, "claude-code", policy=WIDE)
    # llm-orchestrator's catalog holds every grantable stdio server, granted or not
    (d / "notes.yml").write_text(pristine)
    rec = yaml.safe_load((d / "shell.yml").read_text())
    rec["transport"]["args"] = ["--api-key=fakeshort"]
    (d / "shell.yml").write_text(yaml.safe_dump(rec))
    kw = {"lanes": ["real", "shadow"], "policy": WIDE}
    assert clients.render_profile(servers.load(d), COLLECTOR, "claude-code", policy=WIDE)
    with pytest.raises(clients.RenderError, match="--api-key takes a credential"):
        clients.render_profile(servers.load(d), COLLECTOR, "llm-orchestrator", **kw)


def test_yaml_merge_keys_are_read_and_duplicates_still_refused():
    """yaml.v3 (llm-orchestrator) reads merge keys; the strict loader used to fail on them."""
    head = "defaults: &d {model: m, budget: 5}\nname: x\nlimits:\n  <<: *d\n  budget: 9\n"
    assert clients.load_strict(head, "p")["limits"] == {"model": "m", "budget": 9}
    text = clients.splice_grants(head, clients.ORCH_GRANTS_HEAD + "grants: {}\n")
    assert text.startswith(head)
    two_merges = "a: &a {x: 1}\nb: &b {x: 2}\nc:\n  <<: *a\n  <<: *b\n"  # PyYAML: last wins
    for dup in ("a: 1\na: 2\n", "d: &d {x: 1}\nc:\n  <<: *d\n  y: 1\n  y: 2\n", two_merges):
        with pytest.raises(clients.RenderError, match="duplicate key"):
            clients.load_strict(dup, "p")
    merged = "a: &a {x: 1}\nb: &b {y: 2}\nc:\n  <<: [*a, *b]\n"
    assert clients.load_strict(merged, "p")["c"] == {"x": 1, "y": 2}


def test_a_lean_profile_cannot_declare_itself_local_only_to_render_a_local_only_server():
    """The policy, not the profile, attests ``data_tier: local-only`` (round 4 design note)."""
    doc = yaml.safe_load((SPECS / "policy" / "ceilings.yml").read_text())
    del doc["ceilings"]["profile:collector"]["data_tier"]
    unattested = CeilingPolicy.from_mapping(doc, source="an unattested policy")
    with pytest.raises(clients.RenderError, match="does not attest data_tier: local-only"):
        clients.render_profile(CATALOG, COLLECTOR, "claude-code", policy=unattested)
    doc["ceilings"]["profile:collector"]["model_role"] = "mdl:main-reasoner"
    with pytest.raises(clients.RenderError, match="attests model_role mdl:main-reasoner"):
        clients.render_profile(
            CATALOG, COLLECTOR, "claude-code", policy=CeilingPolicy.from_mapping(doc)
        )
    assert clients.render_profile(CATALOG, COLLECTOR, "claude-code", policy=POLICY)


def test_render_needs_the_review_policy_and_runs_the_full_record_check(tmp_path, capsys):
    """Round 4 design notes: without ``review-policy.yml`` beside the catalog a render would
    write unreviewed records, so it is refused unless ``--no-review-policy`` says this is a local
    experiment; and render runs check's whole record rules (tools, egress included), not a
    subset."""
    d = tmp_path / "mcp"
    shutil.copytree(ROOT / "examples" / "mcp", d, ignore=shutil.ignore_patterns("clients"))
    with pytest.raises(clients.RenderError, match=r"no review-policy\.yml beside the catalog"):
        clients.render_profile(servers.load(d), COLLECTOR, "claude-code", policy=WIDE)
    assert clients.render_profile(
        servers.load(d), COLLECTOR, "claude-code", policy=WIDE, review_policy=False
    )
    pol = tmp_path / "pol.yml"
    pol.write_text((SPECS / "policy" / "ceilings.yml").read_text())
    base = ["mcp", "catalog", "render", "--catalog", str(d), "--profile", str(COLLECTOR),
            "--client", "claude-code", "--policy", str(pol)]  # fmt: skip
    assert cli.main(base) == 1
    assert "no review-policy.yml" in capsys.readouterr().out
    assert cli.main([*base, "--no-review-policy"]) == 0
    _lax_review_policy(tmp_path)
    notes = yaml.safe_load((d / "notes.yml").read_text())
    notes["egress"] = ["internet"]  # yet no tool is classed egress
    (d / "notes.yml").write_text(yaml.safe_dump(notes))
    with pytest.raises(clients.RenderError, match="egress names internet but no tool"):
        clients.render_profile(servers.load(d), COLLECTOR, "claude-code", policy=WIDE)
