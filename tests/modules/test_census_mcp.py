# SPDX-License-Identifier: Apache-2.0
"""The census of MCP servers (docs/modules.md, "MCP servers, from the installed clients"): the
server names each installed client configuration registers (the host parses the file and sends
only the names), and the loader matching each registered name back to its catalog record by the
record's instance template."""

from __future__ import annotations

import copy
import json
import re
import shutil
from pathlib import Path

import pytest
import yaml

from homelabnext.modules import census
from homelabnext.modules import loader as ld
from homelabnext.notify import record as nr

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "examples" / "modules"
SITE = ld.load_yaml(EXAMPLES / "sites" / "small-lab.yml")
SLOTS = ld.load_yaml(EXAMPLES / "slots.yml")["slots"]
ROLES = json.loads((ROOT / "examples" / "model_roles.json").read_text())["roles"]
INVENTORY = ld.load_yaml(ROOT / "schemas/platform/examples/module_inventory.small-lab.yml")
NOPAIRS = {"boot_id": None, "now": 0, "records": dict.fromkeys(nr.OWNERS)}
PROBE = "external-collector-probe"


def write(d: Path, mcp: dict[str, list[dict] | None]) -> Path:
    """A census as the role writes it: per host, its MCP client configurations (None: the host
    lists none, and its answer carries no ``mcp``)."""
    d.mkdir(parents=True, exist_ok=True)
    (d / "_hosts.json").write_text(json.dumps(sorted(mcp)))
    for host, configs in mcp.items():
        doc = {"host": host, "enabled": [], "active": [], "pairs": NOPAIRS}
        if configs is not None:
            doc["mcp"] = configs
        (d / f"{host}.json").write_text(json.dumps(doc))
    return d


def cfg(path: str, client: str, servers: list[str] | None) -> dict:
    """One configuration as the host reports it: None, absent."""
    return {
        "path": path,
        "client": client,
        "present": servers is not None,
        "servers": servers or [],
    }


# ----------------------------------------------------------------------------- gather


def test_mcp_servers_are_what_every_installed_client_configuration_registers(tmp_path):
    d = write(
        tmp_path / "c",
        {
            "agent-1": [
                cfg("/var/lib/agent/.mcp.json", "claude-code", ["hnx-broker", PROBE]),
                cfg("/var/lib/agent/absent.mcp.json", "generic", None),
            ],
            "agent-2": [cfg("/var/lib/hermes/config.yaml", "hermes", ["notes-a-real"])],
            "quiet": None,
        },
    )
    inventory, notes = census.gather(d)
    assert inventory["mcp_servers"] == ["external-collector-probe", "hnx-broker", "notes-a-real"]
    assert "mcp_servers" not in inventory["not_gathered"]
    assert "read the MCP client configurations of 2 host(s): 3 server name(s) registered" in notes
    assert (
        "agent-1: /var/lib/agent/absent.mcp.json is absent: generic registers nothing from it"
        in notes
    )
    schema = ld._schema("platform", "module_inventory.schema.json")
    assert ld._errors(schema, inventory) == []


def test_with_no_configuration_listed_mcp_servers_are_not_gathered(tmp_path):
    inventory, notes = census.gather(write(tmp_path / "c", {"a": None}))
    assert "mcp_servers" in inventory["not_gathered"] and "mcp_servers" not in inventory
    assert (
        "no host lists an installed MCP client configuration (module_census_mcp_configs): "
        "MCP servers not gathered" in notes
    )


def test_an_absent_configuration_still_gathers_the_kind_as_registering_nothing(tmp_path):
    d = write(tmp_path / "c", {"a": [cfg("/srv/agent/.mcp.json", "claude-code", None)]})
    inventory, _ = census.gather(d)
    assert inventory["mcp_servers"] == [] and "mcp_servers" not in inventory["not_gathered"]


@pytest.mark.parametrize(
    ("configs", "why"),
    [
        ([], "the MCP client configurations are not a non-empty list"),
        ("x", "the MCP client configurations are not a non-empty list"),
        ([{"path": "/a", "client": "claude-code"}], "is not {path, client, present, servers}"),
        # the text never comes back: an answer that carries it is not the module's
        ([{"path": "/a", "client": "claude-code", "text": "{}"}], "is not {path, client, present"),
        ([cfg("/a", "llm-orchestrator", [])], "names no known client"),
        ([{**cfg("/a", "claude-code", []), "present": "yes"}], "present or servers is malformed"),
        (
            [{**cfg("/a", "claude-code", []), "servers": {"a": 1}}],
            "present or servers is malformed",
        ),
        ([{**cfg("/a", "claude-code", None), "servers": ["a"]}], "is absent yet registers"),
        ([cfg("/a", "claude-code", ["a", "a"])], "the server names are not a set"),
        ([cfg("/a", "claude-code", ["Upper"])], "is not an inventory name"),
        ([cfg("/a", "claude-code", ["snake_case"])], "is not an inventory name"),
        ([cfg("/a", "claude-code", ["x" * 65])], "is not an inventory name"),
        ([cfg("/a", "claude-code", [5])], "is not an inventory name"),
    ],
)
def test_a_configuration_the_host_reports_malformed_fails_the_census(tmp_path, configs, why):
    with pytest.raises(census.CensusError, match=re.escape(why)):
        census.gather(write(tmp_path / "c", {"a": configs}))


def test_an_answer_with_an_unknown_key_still_fails(tmp_path):
    d = write(tmp_path / "c", {"a": None})
    doc = json.loads((d / "a.json").read_text())
    (d / "a.json").write_text(json.dumps({**doc, "mcp_servers": []}))
    with pytest.raises(census.CensusError, match=re.escape("not {host, enabled, active, pairs}")):
        census.gather(d)


# ----------------------------------------------------------------------------- the loader


@pytest.mark.parametrize(
    ("template", "name", "matches"),
    [
        ("{id}", PROBE, True),
        ("{id}", f"{PROBE}-x", False),
        ("{id}-{profile}-{lane}", f"{PROBE}-broker-agent-real", True),
        ("{id}-{profile}-{lane}", PROBE, False),
        ("notes-{profile}-{lane}", "notes-a-shadow", True),
        ("notes-{profile}-{lane}", "notes--real", False),
        ("{id}.{x}", f"{PROBE}.a", True),
        ("{id}.{x}", f"{PROBE}xa", False),  # a literal dot stays a dot
    ],
)
def test_an_instance_template_matches_the_names_a_client_registers(template, name, matches):
    assert bool(ld.instance_pattern(PROBE, template).fullmatch(name)) is matches


def tree_with(tmp_path, instance: str | None):
    root = tmp_path / "fixtures"
    shutil.copytree(EXAMPLES, root)
    rec = root / "external-collector" / "mcp" / f"{PROBE}.yml"
    doc = ld.load_yaml(rec)
    if instance is not None:
        doc["instance"] = instance
    rec.write_text(yaml.safe_dump(doc))
    tree, found = ld.discover(fixtures=root)
    assert found == []
    return tree, root


def check(tree, root, inventory, core=None):
    core = core or ld.core_names(ld.load_yaml(ROOT / "examples" / "services.yml"))[0]
    report = ld.check(
        tree,
        slots=SLOTS,
        roles=ROLES,
        in_tree_roots=(root,),
        core=core,
        site=SITE,
        inventory=inventory,
    )
    return [str(p) for p in report.problems]


def test_a_registered_instance_name_is_matched_back_to_its_record(tmp_path):
    tree, root = tree_with(tmp_path, "{id}-{profile}-{lane}")
    inv = copy.deepcopy(INVENTORY)
    inv["mcp_servers"] = [f"{PROBE}-collector-real", f"{PROBE}-collector-shadow"]
    assert check(tree, root, inv) == []


def test_a_declared_server_no_client_registers_is_not_running(tmp_path):
    tree, root = tree_with(tmp_path, None)
    inv = copy.deepcopy(INVENTORY)
    inv["mcp_servers"] = []
    assert check(tree, root, inv) == [
        f"running: mcp_servers {PROBE} (external-collector) is declared but not running"
    ]


def test_a_registered_name_no_record_matches_is_judged_by_its_module(tmp_path):
    tree, root = tree_with(tmp_path, None)
    inv = copy.deepcopy(INVENTORY)
    inv["mcp_servers"] = [PROBE, f"{PROBE}-extra", "publishing-feed"]
    assert check(tree, root, inv) == [
        f"running: mcp_servers {PROBE}-extra runs but external-collector declares no such entry",
        "running: mcp_servers publishing-feed runs for publishing, which the site does not select",
    ]


def test_a_name_bound_to_no_module_must_be_one_of_the_cores_records(tmp_path):
    tree, root = tree_with(tmp_path, None)
    core, problems = ld.core_names(
        ld.load_yaml(ROOT / "examples" / "services.yml"),
        mcp=[
            ("hnx-broker.yml", {"id": "hnx-broker"}),
            ("notes.yml", {"id": "notes", "instance": "notes-{profile}-{lane}"}),
        ],
    )
    assert problems == [] and core.mcp_known
    inv = copy.deepcopy(INVENTORY)
    inv["mcp_servers"] = [PROBE, "hnx-broker", "notes-a-real", "rogue"]
    assert check(tree, root, inv, core) == [
        "running: mcp_servers rogue runs but is no module's or the core's"
    ]
    # without the core's catalog read, a name bound to no module is not judged
    assert check(tree, root, inv) == []


def tree_with_records(tmp_path, extra: dict[str, list[tuple[str, str]]], probe: str | None = None):
    """The example tree with the probe's template set (``probe``) and more MCP records added per
    module, each ``(id, instance template)``: a copy of the probe's record under its own id."""
    root = tmp_path / "fixtures"
    shutil.copytree(EXAMPLES, root)
    base = ld.load_yaml(root / "external-collector" / "mcp" / f"{PROBE}.yml")
    if probe is not None:
        doc = dict(base, instance=probe)
        (root / "external-collector" / "mcp" / f"{PROBE}.yml").write_text(yaml.safe_dump(doc))
    for mod, records in extra.items():
        mdir = root / mod
        (mdir / "mcp").mkdir(exist_ok=True)
        manifest = ld.load_yaml(mdir / "module.yml")
        entries = manifest.setdefault("contributes", {}).setdefault("mcp_servers", [])
        for sid, template in records:
            doc = {k: v for k, v in base.items() if k != "headers"}
            doc.update(id=sid, instance=template)
            doc["runtime"] = dict(base["runtime"], user=sid)
            (mdir / "mcp" / f"{sid}.yml").write_text(yaml.safe_dump(doc))
            entries.append({"file": f"mcp/{sid}.yml"})
        (mdir / "module.yml").write_text(yaml.safe_dump(manifest))
    tree, found = ld.discover(fixtures=root)
    assert found == []
    return tree, root


def test_an_exact_id_wins_over_another_records_instance(tmp_path):
    # the probe's {id}-{profile} would claim external-collector-probe-b; the record with that id
    # takes it, so the probe registers nothing
    tree, root = tree_with_records(
        tmp_path, {"external-collector": [(f"{PROBE}-b", "{id}")]}, probe="{id}-{profile}"
    )
    inv = copy.deepcopy(INVENTORY)
    inv["mcp_servers"] = [f"{PROBE}-b"]
    assert check(tree, root, inv) == [
        f"running: mcp_servers {PROBE} (external-collector) is declared but not running"
    ]


def test_the_template_fixing_more_of_the_name_wins_and_a_tie_is_ambiguous(tmp_path):
    a, ax = "external-collector-a", "external-collector-a-x"
    tree, root = tree_with_records(
        tmp_path, {"external-collector": [(a, "{id}-{p}"), (ax, "{id}-{p}")]}
    )
    inv = copy.deepcopy(INVENTORY)
    # a-x-q: a's template fixes "external-collector-a-", a-x's "external-collector-a-x-": a-x's
    inv["mcp_servers"] = [PROBE, f"{a}-q", f"{ax}-q"]
    assert check(tree, root, inv) == []
    tree, root = tree_with_records(
        tmp_path / "tie", {"external-collector": [(a, "{id}-x-{p}"), (ax, "{id}-{p}")]}
    )
    inv["mcp_servers"] = [PROBE, f"{ax}-q"]
    assert sorted(check(tree, root, inv)) == [
        f"running: mcp_servers {a} (external-collector) is declared but not running",
        f"running: mcp_servers {ax} (external-collector) is declared but not running",
        f"running: mcp_servers {ax}-q is ambiguous: {a}, {ax} all match it",
    ]


def test_another_modules_template_never_claims_a_name_bound_to_a_module(tmp_path):
    # core-staff's record template begins "external-": it would claim external-collector-zz,
    # which is external-collector's to declare
    tree, root = tree_with_records(tmp_path, {"core-staff": [("core-staff-x", "external-{p}")]})
    inv = copy.deepcopy(INVENTORY)
    inv["mcp_servers"] = [PROBE, "external-collector-zz", "external-q"]
    problems = check(tree, root, inv)
    assert (
        "running: mcp_servers external-collector-zz runs but external-collector declares no such "
        "entry" in problems
    )
    # a name bound to no module may still be another module's instance
    assert not any("external-q" in p for p in problems), problems


def test_a_template_that_begins_with_another_placeholder_is_refused(tmp_path):
    assert ld.template_problem("{profile}-x") and ld.template_problem("{p}")
    assert ld.template_problem("{id}-{p}") is None and ld.template_problem("notes-{p}") is None
    assert not ld.instance_pattern("x", "{profile}-x").fullmatch("anything-x")
    tree, root = tree_with(tmp_path, "{profile}-{id}")
    inv = copy.deepcopy(INVENTORY)
    inv["mcp_servers"] = [f"a-{PROBE}"]
    problems = check(tree, root, inv)
    assert any("begins with a placeholder other than {id}" in p for p in problems), problems
    # the core's catalog too
    _, found = ld.core_names(
        ld.load_yaml(ROOT / "examples" / "services.yml"),
        mcp=[("lead.yml", {"id": "lead", "instance": "{profile}-lead"})],
    )
    assert any("begins with a placeholder other than {id}" in str(p) for p in found), found
