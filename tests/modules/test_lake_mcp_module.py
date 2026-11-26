# SPDX-License-Identifier: Apache-2.0
"""``modules/lake-mcp``: the read-only lake MCP server as a module (ADR-0030).

* The public tree loads clean with it; it requires slots and provides none, and has no egress.
* The forced command the role installs is the catalog record's launch (the same settings path),
  and the role's defaults name the module's declared secret.
"""

from __future__ import annotations

import shlex
from pathlib import Path

import pytest
import yaml

from homelabnext.lake import cli as lake_cli
from homelabnext.modules import cli as mcli
from homelabnext.modules import loader as ld

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "modules" / "lake-mcp"
DOC = ld.load_yaml(MODULE / "module.yml")
ROLE = MODULE / "roles" / "lake_mcp"


def _vars() -> dict:
    v = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text())
    v.update(yaml.safe_load((ROLE / "vars" / "main.yml").read_text()))
    return v


def _expand(text: str, v: dict) -> str:
    for _ in range(4):
        for k, val in v.items():
            if isinstance(val, str):
                text = text.replace("{{ " + k + " }}", val)
    return text


def test_the_module_is_a_feature_that_requires_slots_and_provides_none():
    assert DOC["kind"] == "feature" and DOC["id"] == "lake-mcp"
    assert "provides" not in DOC
    caps = {r["cap"] for r in DOC["requires"]["capabilities"]}
    assert caps == {"cap:lake-query", "cap:secrets"}
    assert DOC["egress"] == "none"


@pytest.mark.static
def test_the_public_tree_loads_clean_with_it(capsys):
    assert mcli.main(["check", "--root", str(ROOT)]) == 0
    assert " 0 problem(s)" in capsys.readouterr().out


@pytest.mark.static
def test_the_forced_command_is_the_catalog_records_launch():
    v = _vars()
    command = shlex.split(_expand(v["lake_mcp_command"], v))
    rec = yaml.safe_load((ROOT / "examples" / "mcp" / "hnx-lake.yml").read_text())
    assert command[0] == v["lake_mcp_hnx_bin"] and command[1:3] == ["lake", "mcp"]
    assert command[3:] == rec["transport"]["args"], "the record and the module start one server"
    ns = lake_cli._parser().parse_args(command[1:][1:])
    assert ns.cmd == "mcp" and ns.config == rec["transport"]["args"][1] and not ns.check


def test_the_key_options_restrict_everything_but_the_command():
    opts = _vars()["lake_mcp_key_options"]
    assert opts.lstrip().startswith('restrict,command="{{ lake_mcp_command }}"')


def test_the_role_reads_the_modules_declared_secret():
    refs = {k: c["default"] for k, c in DOC["config"].items() if c["type"] == "secret"}
    assert refs == {"reader_password": _vars()["lake_mcp_reader_cred"]}
    assert refs["reader_password"].startswith("secret:" + DOC["id"] + "/")


@pytest.mark.static
def test_the_readme_names_the_layers_and_the_placement():
    text = (MODULE / "README.md").read_text()
    for needle in ("restrict,command=", "select_only", "read-only", "--check", "mcp` extra"):
        assert needle in text, needle
