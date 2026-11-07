# SPDX-License-Identifier: Apache-2.0
"""Client configurations rendered from the MCP catalog: only granted servers, secrets as
placeholders, endpoints from the registry, instances per profile and lane with typed parameters,
every home from one source, drift detection, and the orchestrator's format (its loader,
``orchestrator/internal/grants``, loads the committed render in place: its Go tests)."""

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


def test_the_scope_profile_path_is_absolute(monkeypatch):
    """hnx-catalog reads its scope from {profile_file}: a relative path would resolve in the
    client's working directory, where the agent may drop a wider locked profile."""
    with pytest.raises(clients.RenderError, match="profile_file is not an absolute path"):
        clients.render_profile(
            CATALOG, BROKER_AGENT, "claude-code", registry=REGISTRY, policy=POLICY,
            profile_file="build/profile.json",
        )  # fmt: skip
    # the documented one-off render with a relative --profile writes the resolved path
    monkeypatch.chdir(BROKER_AGENT.parent)
    text, _ = clients.render_profile(
        CATALOG, BROKER_AGENT.name, "claude-code", registry=REGISTRY, policy=POLICY
    )
    args = json.loads(text)["mcpServers"]["hnx-catalog"]["args"]
    assert args[args.index("--scope-from-profile") + 1] == str(BROKER_AGENT.resolve())
    # a server that does not read the profile does not need one
    assert clients.instances(CATALOG, {"id": "profile:a", "mcp": ["notes"]}, profile_file="")


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


# ----------------------------------------------------------------------- orchestrator
def test_orchestrator_catalog_and_grants_are_its_format():
    r = clients.render_spec(SPECS / "orchestrator.yml")
    catalog, grants = r.outputs
    kinds = yaml.safe_load(catalog.text)["kinds"]
    assert kinds["notes"] == {
        "allowed_env": ["NOTES_MODE", "NOTES_WRITABLE_PREFIX"],
        # an enum pinned to its values; the prefix bound to each granting profile's own scope
        # (binds: writable), never pinned to every profile's values at once
        "allowed_values": {"NOTES_MODE": ["read", "write"]},
        "profile_scope": {"root_key": "NOTES_ROOT", "scope_roots": ["notes/"],
                          "writable": ["NOTES_WRITABLE_PREFIX"]},
        "args": ["--no-config", "--from", "example-notes-mcp==1.2.0", "notes-mcp"],
        "command": "uvx",
        "env": {"NOTES_ROOT": "notes/", "NOTES_TOKEN": "${HNX_SECRET_MCP_NOTES_TOKEN}"},
        "timeout": 120,
    }
    assert "lake" not in kinds and "hnx-catalog" not in kinds  # remote / per-instance args
    block = yaml.safe_load(grants.text)["grants"]
    assert list(block) == ["real", "shadow"]
    assert block["shadow"][0] == {"name": "notes-collector-shadow", "kind": "notes",
                                  "env": {"NOTES_MODE": "read", "NOTES_WRITABLE_PREFIX": "agents/collector/inbox-shadow/"}}  # fmt: skip
    # byte-stable: rendering twice gives the same bytes, and the profile's own fields survive
    again = clients.render_spec(SPECS / "orchestrator.yml")
    assert [o.expected() for o in again.outputs] == [o.expected() for o in r.outputs]
    assert (
        grants.expected().startswith("# SPDX-License-Identifier")
        and "agent_key: collector" in grants.expected()
    )
    # the committed render is current: orchestrator/internal/grants loads it in place
    assert clients.drift(r) == []


def test_the_orchestrator_denies_the_catalogs_keys_character_for_character():
    """One deny list: the Go grants loader's DeniedEnvPattern is :data:`servers.DENIED_ENV`."""
    go = (ROOT / "orchestrator" / "internal" / "grants" / "grants.go").read_text()
    m = re.search(r"^const DeniedEnvPattern = `([^`]*)`$", go, re.M)
    assert m, "DeniedEnvPattern is no longer one raw string constant"
    assert m.group(1) == servers.DENIED_ENV.pattern
    assert servers.DENIED_ENV.flags & re.I  # Go compiles it (?i)


def test_the_old_client_name_still_renders():
    spec = yaml.safe_load((SPECS / "orchestrator.yml").read_text())
    assert clients.client_name("llm-orchestrator") == clients.ORCHESTRATOR
    assert clients._spec_problems({**spec, "client": "llm-orchestrator"}) == []
    assert clients._spec_problems({**spec, "client": "llm-orchestrators"})


def _rec(**param):
    rec = copy.deepcopy(CATALOG.servers["notes"])
    rec["parameters"]["writable"] = {**rec["parameters"]["writable"], **param}
    return rec


def test_a_scope_key_binds_to_the_profile_and_an_unbound_free_one_is_not_settable():
    kind, said = clients.orch_kind("notes", CATALOG.servers["notes"], CTX,
                                   {"NOTES_WRITABLE_PREFIX": {"agents/a/", "agents/b/"}})  # fmt: skip
    # another profile's value never becomes this kind's pin: the controller checks each grant
    # against its own profile's path scope and lane
    assert "NOTES_WRITABLE_PREFIX" not in kind["allowed_values"]
    assert kind["profile_scope"]["writable"] == ["NOTES_WRITABLE_PREFIX"]
    # a scope key that does not bind is refused, by the record check and by the render
    rec = _rec(binds=None, root=None)
    rec["parameters"]["writable"] = {k: v for k, v in rec["parameters"]["writable"].items() if v is not None}
    assert any("has no binds" in w for w in clients.orch_kind("notes", rec, CTX)[1])
    assert any("say how it binds" in p for p in servers._template_problems(rec, "notes"))
    # a free parameter that is not a scope key: pinned to the rendered values, else unsettable
    free = copy.deepcopy(CATALOG.servers["notes"])
    free["parameters"]["label"] = {"env": "NOTES_LABEL", "pattern": "[a-z]+"}
    kind, said = clients.orch_kind("notes", free, CTX)
    assert "NOTES_LABEL" not in kind["allowed_env"]
    assert any(w.startswith("note:notes: NOTES_LABEL has no enum") for w in said)
    kind, _ = clients.orch_kind("notes", free, CTX, {"NOTES_LABEL": {"b", "a"}})
    assert kind["allowed_values"]["NOTES_LABEL"] == ["a", "b"]


@pytest.mark.parametrize(
    ("param", "phrase"),
    [
        ({"binds": "writable", "root": "NOTES_NOPE"}, "needs root"),
        ({"binds": "agent_key", "root": "NOTES_ROOT"}, "root belongs to"),
        ({"binds": "lane", "root": None}, "binds lane needs enum"),
    ],
)
def test_a_binding_is_well_formed(param, phrase):
    rec = _rec(**param)
    rec["parameters"]["writable"] = {k: v for k, v in rec["parameters"]["writable"].items() if v is not None}
    assert any(phrase in p for p in servers._template_problems(rec, "notes"))


def test_the_render_checks_its_own_output():
    """A Python-only CI is not blind: the render reads its own catalog and blocks back."""
    cat = {"kinds": {"notes": {"allowed_env": ["M", "P"], "allowed_values": {"M": ["read"]},
                               "profile_scope": {"writable": ["P"]}}}}  # fmt: skip
    ok = {"real": [{"name": "n", "kind": "notes", "env": {"M": "read", "P": "x/"}}],
          "shadow": [{"name": "n", "kind": "notes"}]}  # fmt: skip
    assert clients.orch_render_problems(cat, {"p": ok}) == []
    for bad, phrase in (
        ({"real": ok["real"]}, "one lane"),
        ({**ok, "spare": []}, "unknown lane"),
        ({**ok, "real": ok["real"] * 2}, "granted twice"),
        ({**ok, "real": [{"name": "n", "kind": "other"}]}, "unknown kind"),
        ({**ok, "real": [{"name": "n", "kind": "notes", "env": {"Q": "1"}}]}, "not an allowed_env"),
        ({**ok, "real": [{"name": "n", "kind": "notes", "env": {"M": "write"}}]}, "allowed_values"),
    ):
        assert any(phrase in p for p in clients.orch_render_problems(cat, {"p": bad})), phrase


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
    # the shipped catalog deprecates nothing since ADR-0030 retired bash, exec and terminal
    d = tmp_path / "mcp"
    shutil.copytree(ROOT / "examples" / "mcp", d, ignore=shutil.ignore_patterns("clients"))
    _lax_review_policy(tmp_path)
    rec = yaml.safe_load((d / "fetch.yml").read_text())
    rec.update(status="deprecated", reason="moved to web", replaced_by="web")
    (d / "fetch.yml").write_text(yaml.safe_dump(rec))
    prof = tmp_path / "p.json"
    doc = json.loads(COLLECTOR.read_text())
    doc["mcp"] = doc["mcp_ceiling"] = ["fetch"]
    doc["reads_untrusted"] = False
    prof.write_text(json.dumps(doc))
    text, notes = clients.render_profile(
        servers.load(d), prof, "claude-code", policy=WIDE, npm_prefix=NPM_PREFIX
    )
    assert "fetch" in json.loads(text)["mcpServers"]
    assert any("deprecated" in n and "grant 'web' instead" in n for n in notes)


def test_render_anchors_npx_at_an_absolute_npm_prefix(tmp_path):
    """Round 4, F1: an npm server renders only with an absolute ``npm_prefix`` (spec key or
    ``--npm-prefix``): missing or relative, the render is refused, never anchored in the
    client's working directory."""
    prof = tmp_path / "p.json"
    doc = json.loads(COLLECTOR.read_text())
    doc["mcp"] = doc["mcp_ceiling"] = ["fetch"]
    doc["reads_untrusted"] = False
    prof.write_text(json.dumps(doc))
    with pytest.raises(clients.RenderError, match="npm_prefix is not given"):
        clients.render_profile(CATALOG, prof, "claude-code", policy=WIDE)
    with pytest.raises(clients.RenderError, match="npm_prefix is not an absolute path"):
        clients.render_profile(CATALOG, prof, "claude-code", policy=WIDE, npm_prefix="prefix")
    text, _ = clients.render_profile(
        CATALOG, prof, "claude-code", policy=WIDE, npm_prefix=NPM_PREFIX
    )
    assert json.loads(text)["mcpServers"]["fetch"]["args"][:2] == ["-y", f"--prefix={NPM_PREFIX}"]
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


def _open_param_catalog(tmp_path: Path) -> servers.ServerCatalog:
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


# ---------------------------------------------- orchestrator: what the render refuses itself
def _orch_copy(tmp_path: Path) -> Path:
    dst = tmp_path / "mcp"
    shutil.copytree(ROOT / "examples" / "mcp", dst)
    _lax_review_policy(dst.parent)
    shutil.copy(ROOT / "examples" / "services.yml", dst.parent)  # the registry beside it
    return dst / "clients" / "orchestrator.yml"


def test_the_orchestrator_refuses_a_granted_remote_server(tmp_path):
    lake = _lean(tmp_path, mcp=["notes", "records", "lake"],
                 mcp_ceiling=["notes", "records", "lake"])  # fmt: skip
    with pytest.raises(clients.RenderError, match="a streamable-http server; orchestrator"):
        clients.render_profile(CATALOG, lake, "orchestrator", lanes=["real", "shadow"], policy=WIDE)
    # one lane only: the render's own check refuses it, as the controller's loader would
    with pytest.raises(clients.RenderError, match="one lane and not the other"):
        clients.render_profile(CATALOG, COLLECTOR, "llm-orchestrator", lanes=["real"],
                               policy=WIDE, npm_prefix=NPM_PREFIX)  # fmt: skip
    block, _ = clients.render_profile(CATALOG, COLLECTOR, "orchestrator",
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
    with pytest.raises(clients.RenderError, match="duplicate key 'name'"):
        clients.load_strict("name: x\nname: y\n", "p")


def test_a_spec_refuses_a_missing_grants_file_and_reads_every_orchestrator_profile(tmp_path):
    spec = _orch_copy(tmp_path)
    profiles = spec.parent / "orchestrator" / "profiles"
    other = profiles / "monitor.yaml"  # not in the spec, but loaded by the same controller
    other.write_text("agent_key: monitor\nagent_key: other\n")
    with pytest.raises(clients.RenderError, match="duplicate key 'agent_key'"):
        clients.render_spec(spec)
    # the render's own check reads every profile the controller loads
    other.write_text("agent_key: monitor\ngrants:\n  real: [{name: c, kind: collectormcp}]\n")
    with pytest.raises(clients.RenderError, match="unknown kind 'collectormcp'"):
        clients.render_spec(spec)
    # its values for a pinned parameter join the pins; one off the parameter's type is refused
    other.write_text("agent_key: monitor\ngrants:\n  real: [{name: n, kind: notes, env: {NOTES_MODE: read}}]\n"
                     "  shadow: [{name: n, kind: notes, env: {NOTES_MODE: read}}]\n")  # fmt: skip
    assert clients.render_spec(spec).outputs
    other.write_text("agent_key: monitor\ngrants:\n  real: [{name: n, kind: notes, env: {NOTES_MODE: append}}]\n"
                     "  shadow: [{name: n, kind: notes, env: {NOTES_MODE: read}}]\n")  # fmt: skip
    with pytest.raises(clients.RenderError, match="allowed_values"):
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
    # the orchestrator's catalog holds every grantable stdio server, granted or not
    (d / "notes.yml").write_text(pristine)
    rec = yaml.safe_load((d / "cases.yml").read_text())
    rec["transport"]["args"] = ["--api-key=fakeshort"]
    (d / "cases.yml").write_text(yaml.safe_dump(rec))
    kw = {"lanes": ["real", "shadow"], "policy": WIDE}
    assert clients.render_profile(servers.load(d), COLLECTOR, "claude-code", policy=WIDE)
    with pytest.raises(clients.RenderError, match="--api-key takes a credential"):
        clients.render_profile(servers.load(d), COLLECTOR, "orchestrator", **kw)


def test_yaml_merge_keys_are_read_and_duplicates_still_refused():
    """The orchestrator's YAML library reads merge keys; the strict loader used to fail on them."""
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
    del doc["ceilings"]["profile:collector"]["tlp_ceiling"]  # it attests the tier it derives
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


def test_the_orchestrator_catalog_has_no_kind_for_a_server_that_acts_directly():
    """ADR-0030: a server that acts other than through the broker is a kind of the orchestrator's
    catalog only when a rendered profile is granted it (a policy's direct_mcp exception); else its
    controller refuses any profile's grant of it, a barrier behind the profile checks."""
    text, notes = clients.orch_catalog(CATALOG, (), CTX)
    kinds = yaml.safe_load(text)["kinds"]
    assert "hnx-broker" in kinds  # acts through the broker
    for sid in ("shell", "ssh", "ansible", "kubernetes", "vault", "filesystem", "git", "github"):
        assert sid not in kinds, sid
    # a lab that reviewed shell (active): no kind unless a rendered profile is granted it
    cat = copy.deepcopy(CATALOG)
    cat.servers["shell"]["status"] = "active"
    text, notes = clients.orch_catalog(cat, (), CTX)
    assert "shell" not in yaml.safe_load(text)["kinds"]
    assert any(n.startswith("shell: acts other than through the broker") for n in notes)
    text, _ = clients.orch_catalog(cat, {"shell"}, CTX)
    assert "shell" in yaml.safe_load(text)["kinds"]
    shipped = yaml.safe_load((SPECS / "orchestrator" / "mcp_catalog.yaml").read_text())
    assert not {"shell", "ssh", "ansible", "kubernetes", "vault"} & set(shipped["kinds"])
