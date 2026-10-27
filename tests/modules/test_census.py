# SPDX-License-Identifier: Apache-2.0
"""The inventory gathered from the hosts (homelabnext.modules.census, ``hnx modules gather``) and
the deploy's check (``hnx modules check --deploy``): docs/modules.md, "What the loader checks"."""

from __future__ import annotations

import json
import os
import re
import shutil
from pathlib import Path

import pytest

from homelabnext.modules import census
from homelabnext.modules import cli as mcli
from homelabnext.modules import loader as ld

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "examples" / "modules"
SMALL_LAB = EXAMPLES / "sites" / "small-lab.yml"


def write_census(d: Path, answers: dict[str, list[str]], hosts: list[str] | None = None) -> Path:
    d.mkdir(parents=True, exist_ok=True)
    (d / "_hosts.json").write_text(json.dumps(sorted(answers) if hosts is None else hosts))
    for host, lines in answers.items():
        (d / f"{host}.json").write_text(json.dumps({"host": host, "systemctl": lines}))
    return d


# ----------------------------------------------------------------------------- gather


def test_units_are_the_union_of_what_every_host_reports_enabled(tmp_path):
    d = write_census(
        tmp_path / "c",
        {
            "gpu-1": [
                "hnx-lake-compact.service enabled enabled",
                "hnx-lake-compact.timer enabled -",
            ],
            "infer-core.example": ["hnx-external-collector-pull.timer enabled"],
            "quiet": [],
        },
    )
    inventory, notes = census.gather(d)
    assert inventory == {
        "schema_version": "1.0",
        "units": ["external-collector-pull", "lake-compact"],
        "not_gathered": ["rows", "mcp_servers", "agents", "tables"],
    }
    assert notes == ["gathered from 3 host(s): 2 enabled fleet unit(s)"]
    # what it writes is a valid inventory
    schema = ld._schema("platform", "module_inventory.schema.json")
    assert ld._errors(schema, inventory) == []


def test_a_template_unit_is_left_out_and_noted(tmp_path):
    d = write_census(tmp_path / "c", {"h": ["hnx-page@.service enabled disabled"]})
    inventory, notes = census.gather(d)
    assert inventory["units"] == [] and "1 template unit(s)" in notes[-1]


@pytest.mark.parametrize(
    "line",
    [
        "hnx-x.service disabled",  # not enabled: systemctl was asked for enabled ones only
        "hnx-x.service enabled-runtime",
        "other.service enabled",  # not a fleet unit
        "hnx-X.service enabled",  # not the fleet's name shape
        "hnx-x.socket enabled",
        "hnx-x.service enabled enabled extra",
        "hnx-x.service enabled\nhnx-y.service enabled",  # one line is one line
        "hnx-1x.service enabled",  # a fleet name, but not an inventory name
        "hnx-x--y.service enabled",
        "",
    ],
)
def test_a_host_that_prints_anything_else_makes_the_census_unreadable(tmp_path, line):
    d = write_census(tmp_path / "c", {"h": ["hnx-ok.timer enabled", line]})
    with pytest.raises(census.CensusError, match=r"h: line 2"):
        census.gather(d)


def test_every_host_the_play_targeted_must_have_answered(tmp_path):
    d = write_census(tmp_path / "c", {"a": []}, hosts=["a", "b"])
    with pytest.raises(census.CensusError, match="no answer from b"):
        census.gather(d)


@pytest.mark.parametrize(
    "hosts",
    [[], ["a", "a"], ["../a"], [".a"], ["_hosts"], "a", [1], None],
)
def test_the_host_list_is_a_list_of_distinct_plain_names(tmp_path, hosts):
    d = tmp_path / "c"
    d.mkdir()
    (d / "_hosts.json").write_text(json.dumps(hosts))
    with pytest.raises(census.CensusError, match=re.escape("_hosts.json")):
        census.gather(d)


def test_without_a_host_list_the_census_is_unreadable(tmp_path):
    d = write_census(tmp_path / "c", {"a": []})
    (d / "_hosts.json").unlink()
    with pytest.raises(census.CensusError, match=re.escape("_hosts.json: cannot be read")):
        census.gather(d)


# What a host can do is print lines; the files are the controller's.  A file nobody asked for, an
# answer under another host's name, or a link are refused, never read as an answer.


def test_an_entry_that_is_no_listed_hosts_answer_is_refused(tmp_path):
    d = write_census(tmp_path / "c", {"a": []})
    (d / "forged.json").write_text(json.dumps({"host": "forged", "systemctl": []}))
    with pytest.raises(
        census.CensusError, match=re.escape("not a listed host's answer: forged.json")
    ):
        census.gather(d)


def test_an_answer_written_for_another_host_is_refused(tmp_path):
    d = write_census(tmp_path / "c", {"a": [], "b": []})
    (d / "a.json").write_text(json.dumps({"host": "b", "systemctl": []}))
    with pytest.raises(census.CensusError, match=re.escape("a.json: written for b")):
        census.gather(d)


@pytest.mark.parametrize(
    "doc",
    [
        {"host": "a"},
        {"host": "a", "systemctl": "hnx-x.service enabled"},
        {"host": "a", "systemctl": [1]},
        {"host": "a", "systemctl": [], "units": ["x"]},  # no way to hand in a finished list
        ["a"],
    ],
)
def test_an_answer_of_another_shape_is_refused(tmp_path, doc):
    d = write_census(tmp_path / "c", {"a": []})
    (d / "a.json").write_text(json.dumps(doc))
    with pytest.raises(census.CensusError):
        census.gather(d)


def test_a_linked_answer_or_directory_is_refused(tmp_path):
    d = write_census(tmp_path / "c", {"a": []})
    real = tmp_path / "elsewhere.json"
    real.write_text(json.dumps({"host": "a", "systemctl": ["hnx-x.service enabled"]}))
    (d / "a.json").unlink()
    (d / "a.json").symlink_to(real)
    with pytest.raises(census.CensusError, match=re.escape("a.json: not a regular file")):
        census.gather(d)
    link = tmp_path / "link"
    link.symlink_to(write_census(tmp_path / "c2", {"a": []}))
    with pytest.raises(census.CensusError, match="not a directory"):
        census.gather(link)


def test_a_fifo_answer_is_refused_never_waited_on(tmp_path):
    d = write_census(tmp_path / "c", {"a": []})
    (d / "a.json").unlink()
    os.mkfifo(d / "a.json")
    with pytest.raises(census.CensusError, match=re.escape("a.json: not a regular file")):
        census.gather(d)


def test_an_oversized_answer_is_refused(tmp_path):
    d = write_census(tmp_path / "c", {"a": []})
    (d / "a.json").write_bytes(b" " * (ld.MAX_BYTES + 1))
    with pytest.raises(census.CensusError, match=re.escape("a.json: over")):
        census.gather(d)


def test_too_many_lines_are_refused(tmp_path):
    lines = [f"hnx-u{i}.service enabled" for i in range(census.MAX_LINES + 1)]
    d = write_census(tmp_path / "c", {"a": lines})
    with pytest.raises(census.CensusError, match="over"):
        census.gather(d)


# ----------------------------------------------------------------------------- the loader


def test_a_gathered_inventory_compares_units_and_notes_the_kinds_it_does_not_report():
    tree, _ = ld.discover(ROOT / "modules", EXAMPLES, None)
    site = ld.load_yaml(SMALL_LAB)
    inventory = {"schema_version": "1.0", "units": ["external-collector-extra", "lake-compact"],
                 "not_gathered": ["rows", "mcp_servers", "agents", "tables"]}  # fmt: skip
    slots = ld.load_yaml(EXAMPLES / "slots.yml")["slots"]
    roles = json.loads((ROOT / "examples" / "model_roles.json").read_text())["roles"]
    report = ld.check(
        tree, slots=slots, roles=roles, in_tree_roots=(ROOT / "modules", EXAMPLES), site=site,
        inventory=inventory,
    )  # fmt: skip
    assert [str(p) for p in report.problems] == [
        "running: units external-collector-extra runs but external-collector declares no such entry"
    ]
    assert (
        "the inventory does not report rows, mcp_servers, agents, tables: not compared "
        "(not_gathered)" in report.notes
    )


# ----------------------------------------------------------------------------- the CLI


def test_hnx_modules_gather_writes_a_new_inventory(tmp_path, capsys):
    d = write_census(tmp_path / "c", {"a": ["hnx-lake-compact.timer enabled"]})
    out = tmp_path / "inventory.json"
    assert mcli.main(["gather", str(d), "--out", str(out)]) == 0
    assert json.loads(out.read_text())["units"] == ["lake-compact"]
    assert "1 unit(s) written" in capsys.readouterr().out
    # never over an existing file, and an unreadable census is a usage error (2), not an inventory
    assert mcli.main(["gather", str(d), "--out", str(out)]) == 2
    (d / "a.json").unlink()
    assert mcli.main(["gather", str(d), "--out", str(tmp_path / "other.json")]) == 2
    assert "no answer from a" in capsys.readouterr().err
    assert not (tmp_path / "other.json").exists()


def overlay(tmp_path: Path, *, site=True, roles=True, services=True) -> Path:
    """An overlay whose lab is the repository's small-lab example."""
    lab = tmp_path / "overlay" / "lab"
    lab.mkdir(parents=True)
    if site:
        shutil.copy(SMALL_LAB, lab / "modules.yml")
    if roles:
        shutil.copy(ROOT / "examples" / "model_roles.json", lab / "model_roles.json")
    if services:
        shutil.copy(ROOT / "examples" / "services.yml", lab / "services.yml")
    return lab.parent


def deploy_check(capsys, ov: Path, *extra: str) -> tuple[int, dict]:
    code = mcli.main(["check", "--root", str(ROOT), "--overlay", str(ov), "--deploy", "--json",
                      *extra])  # fmt: skip
    out = capsys.readouterr().out
    return code, json.loads(out) if out else {}


def test_the_deploy_check_refuses_a_lab_that_falls_back_to_the_examples(tmp_path, capsys):
    code, doc = deploy_check(capsys, overlay(tmp_path, site=False, roles=False, services=False))
    assert code == 1
    assert [p for p in doc["problems"] if p.startswith("deploy:")] == [
        "deploy: the core registry: the overlay has no lab/services.yml",
        "deploy: the role table: the overlay has no lab/model_roles.json",
        "deploy: the site selection: the overlay has no lab/modules.yml",
    ]


def test_the_deploy_check_refuses_problems_in_the_lab(tmp_path, capsys):
    """The small lab's modules live under examples/, which a deploy never loads: its selection
    then names modules that do not exist, and the deploy is refused."""
    code, doc = deploy_check(capsys, overlay(tmp_path))
    assert code == 1
    assert doc["problems"] and not any(p.startswith("deploy:") for p in doc["problems"])


def test_the_deploy_check_needs_an_overlay_and_never_loads_the_fixtures(tmp_path, capsys):
    assert mcli.main(["check", "--root", str(ROOT), "--deploy"]) == 2
    assert "--deploy needs --overlay" in capsys.readouterr().err
    ov = overlay(tmp_path)
    assert mcli.main(["check", "--root", str(ROOT), "--overlay", str(ov), "--deploy",
                      "--examples"]) == 2  # fmt: skip
    assert "--deploy refuses --examples" in capsys.readouterr().err


def test_with_every_input_the_overlays_own_the_deploy_check_is_the_plain_check(tmp_path, capsys):
    """--deploy adds no rule of its own once nothing falls back: the same problems as the check
    make gates runs, here over a lab whose selection names modules it does not ship (no public
    module tree exists yet, so a lab brings its own); the gathered inventory passes its schema."""
    ov = overlay(tmp_path)
    d = write_census(tmp_path / "c", {"a": ["hnx-lake-compact.timer enabled"]})
    inv = tmp_path / "inventory.json"
    assert mcli.main(["gather", str(d), "--out", str(inv)]) == 0
    capsys.readouterr()
    code, deploy = deploy_check(capsys, ov, "--running", str(inv))
    plain = mcli.main(["check", "--root", str(ROOT), "--overlay", str(ov), "--running", str(inv),
                       "--json"])  # fmt: skip
    doc = json.loads(capsys.readouterr().out)
    assert code == plain == 1
    assert deploy["problems"] == doc["problems"] and deploy["problems"]
    assert not any(p.startswith(("deploy:", "running: schema")) for p in deploy["problems"])
