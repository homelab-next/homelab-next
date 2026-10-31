# SPDX-License-Identifier: Apache-2.0
"""An MCP catalog record's ``tlp`` (ADR-0033 decisions 11 and 12): the label of what the server
returns, agreeing with its ``data_tier``; a record without one is read from that tier."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
import yaml

from homelabnext.agent.readers import ToolClasses
from homelabnext.mcp import catalog_cli, servers
from homelabnext.tlp import Label

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "examples" / "mcp"


@pytest.mark.parametrize(
    "rec, want",
    [
        ({"data_tier": "local-only", "tlp": "amber"}, Label.AMBER),
        ({"data_tier": "cloud-allowed", "tlp": "clear"}, Label.CLEAR),
        ({"data_tier": "cloud-allowed"}, Label.CLEAR),  # the only label that tier allows
        ({"data_tier": "local-only"}, Label.RED),  # the most restrictive reading
        ({}, Label.RED),
        ({"data_tier": "cloud-allowed", "tlp": "nonsense"}, Label.RED),  # read as data
    ],
)
def test_record_label(rec, want):
    assert servers.record_label(rec) is want


@pytest.mark.parametrize(
    "rec, words",
    [
        (
            {"data_tier": "cloud-allowed", "tlp": "green"},
            "data_tier cloud-allowed disagrees with tlp green",
        ),
        (
            {"data_tier": "local-only", "tlp": "clear"},
            "data_tier local-only disagrees with tlp clear",
        ),
        ({"data_tier": "local-only", "tlp": "amber-strict"}, "not a TLP label"),
        ({"data_tier": "local-only", "tlp": "Amber"}, "is not written as 'amber'"),
    ],
)
def test_a_tlp_that_is_not_a_label_or_disagrees_with_the_tier_is_refused(rec, words):
    (p,) = servers.tlp_problems(rec, "x.yml")
    assert p.startswith("x.yml: ") and words in p


@pytest.mark.parametrize(
    "rec",
    [
        {"data_tier": "local-only", "tlp": "green"},
        {"data_tier": "local-only", "tlp": "amber+strict"},
        {"data_tier": "local-only", "tlp": "red"},
        {"data_tier": "cloud-allowed", "tlp": "clear"},
        {"data_tier": "local-only"},
    ],
)
def test_an_agreeing_or_absent_tlp_passes(rec):
    assert servers.tlp_problems(rec, "x.yml") == []


def _copy(tmp_path: Path) -> Path:
    d = tmp_path / "mcp"
    shutil.copytree(EXAMPLES, d, ignore=shutil.ignore_patterns("clients"))
    return d


def test_the_catalog_check_refuses_a_disagreeing_record_and_the_grant_reads_the_label(tmp_path):
    d = _copy(tmp_path)
    rec = yaml.safe_load((d / "lake.yml").read_text())
    rec["tlp"] = "clear"  # lake is local-only
    (d / "lake.yml").write_text(yaml.safe_dump(rec))
    problems = servers.check(servers.load(d), only=["lake"])
    assert any("mcp/lake.yml: data_tier local-only disagrees with tlp clear" in p for p in problems)
    rec["tlp"] = "amber"
    (d / "lake.yml").write_text(yaml.safe_dump(rec))
    cat = servers.load(d)
    assert not [p for p in servers.check(cat, only=["lake"]) if "tlp" in p]
    meta = ToolClasses.from_catalog(cat).catalog
    assert meta["lake"]["tlp"] == "amber"
    assert meta["web"]["tlp"] == "clear"  # cloud-allowed, no tlp
    assert meta["notes"]["tlp"] == "red"  # local-only, no tlp


def test_one_note_names_every_record_without_a_tlp(tmp_path, capsys):
    cat = servers.load(EXAMPLES)
    (note,) = servers.tlp_notes(cat)
    assert f"{len(cat.servers)} record(s) declare no tlp" in note
    assert "lake (red)" in note and "web (clear)" in note
    d = _copy(tmp_path)
    for f in d.glob("*.yml"):
        rec = yaml.safe_load(f.read_text())
        rec["tlp"] = str(servers.record_label(rec))
        f.write_text(yaml.safe_dump(rec))
    assert servers.tlp_notes(servers.load(d)) == []
    catalog_cli.main(["check", "--catalog", str(EXAMPLES), "--policy", "none", "--grants"])
    assert "note: tlp: " in capsys.readouterr().err
