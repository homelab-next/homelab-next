# SPDX-License-Identifier: Apache-2.0
"""``modules/source-census``: the daily census as a module (ADR-0049 decisions 8 and 9).

* The public tree loads clean with it, and it names slots and no product.
* Its two criteria are well-formed contributed criteria whose observables are the very command the
  unit runs, with arguments the command accepts; its unit is least-privilege and pages only through
  the notify slot's pair.
* The settings path, the state path and the credential names agree across the manifest, the unit,
  the criteria and the role.
"""

from __future__ import annotations

import shlex
from pathlib import Path

import yaml

from homelabnext.generators import fleet_units
from homelabnext.lake import cli as census_cli
from homelabnext.modules import cli as mcli
from homelabnext.modules import loader as ld
from homelabnext.modules.rules import criterion_problems

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "modules" / "source-census"
DOC = ld.load_yaml(MODULE / "module.yml")
CRITERIA = ld.load_yaml(MODULE / "criteria" / "criteria.yml")["criteria"]
UNITS = ld.load_yaml(MODULE / "units" / "fleet_units.yml")
SETTINGS = "/etc/hnx-modules/source-census/census.yml"


def test_the_module_is_a_feature_that_requires_slots_and_provides_none():
    assert DOC["kind"] == "feature" and DOC["id"] == "source-census"
    assert "provides" not in DOC
    caps = {r["cap"] for r in DOC["requires"]["capabilities"]}
    assert caps == {"cap:lake-query", "cap:lake-catalog", "cap:notify", "cap:secrets"}
    assert DOC["egress"] == "none"


def test_the_public_tree_loads_clean_with_it(capsys):
    assert mcli.main(["check", "--root", str(ROOT)]) == 0
    out = capsys.readouterr().out
    assert (
        "source-census" not in out.split("hnx modules:")[0].replace("note:", "")
        or "problem" not in out
    )
    assert " 0 problem(s)" in out


def test_its_files_are_what_the_manifest_contributes():
    c = DOC["contributes"]
    assert [e["file"] for e in c["roles"]] == ["roles/source_census"]
    for key in ("scheduler_jobs", "invariants", "docs"):
        for e in c[key]:
            assert (MODULE / e["file"]).is_file(), e
    assert (MODULE / "data" / "manager-benign.yml").is_file()


def test_the_criteria_are_the_modules_own_and_well_formed():
    ids = [c["id"] for c in CRITERIA]
    assert ids == ["source-census/sources-flowing", "source-census/all-classes-dark"]
    for cr in CRITERIA:
        assert criterion_problems(cr, "source-census", set()) == [], cr["id"]
        assert cr["evidence"] == "auto" and cr["timeout"] >= 60


def test_the_criteria_run_the_command_the_unit_runs_and_never_page():
    (unit,) = fleet_units.validate(UNITS)
    unit_argv = shlex.split(unit["exec"])
    assert unit_argv[1:3] == ["lake", "source-census"] and unit_argv[3:5] == ["--config", SETTINGS]
    for cr in CRITERIA:
        argv = shlex.split(cr["observable"])
        assert argv[:5] == unit_argv[:5], "the criterion and the unit run one command"
        assert "--no-notify" in argv, "an ad-hoc run never pages or touches the paging state"
        want = cr["id"].split("/")[1]
        ns = census_cli._parser().parse_args(argv[2:])  # the command accepts its own arguments
        assert ns.criterion == want and ns.no_notify and ns.config == SETTINGS


def test_the_unit_is_least_privilege_and_pages_only_through_notify():
    (unit,) = fleet_units.validate(UNITS)
    assert unit["name"] == "source-census-run" and unit["name"].startswith(DOC["id"])
    assert unit["user"] == "hnx-source-census" and not unit.get("run_as_root")
    assert unit["pages_directly"] is False
    assert not unit.get("hardening_opt_out")
    assert unit["read_write_paths"] == ["/var/lib/hnx-modules/source-census/state"]
    assert unit["on_calendar"][0].endswith("UTC")
    rendered = fleet_units.render(UNITS)
    assert any("NoNewPrivileges=yes" in text for text in rendered.values())


def test_the_paging_titles_are_the_modules_notify_pair_and_carry_no_counts():
    (pair,) = DOC["contributes"]["notify_pairs"]
    assert pair == {"problem": census_cli.TITLE_FLAGGED, "recovery": census_cli.TITLE_CLEAN}


def test_the_role_writes_what_the_unit_and_criteria_read():
    defaults = yaml.safe_load((MODULE / "roles/source_census/defaults/main.yml").read_text())
    vars_ = yaml.safe_load((MODULE / "roles/source_census/vars/main.yml").read_text())
    assert (
        vars_["source_census_config_file"].replace(
            "{{ source_census_config_dir }}", "/etc/hnx-modules/source-census"
        )
        == SETTINGS
    )
    assert vars_["source_census_state_dir"].endswith("/state")
    assert defaults["source_census_user"] == UNITS[0]["user"]
    assert defaults["source_census_hnx_bin"] == shlex.split(UNITS[0]["exec"])[0]
    refs = {k: v["default"] for k, v in DOC["config"].items() if v["type"] == "secret"}
    assert set(refs) == {"reader_password", "notify_token"}
    assert refs["reader_password"] == defaults["source_census_reader_cred"]
    assert refs["notify_token"] == defaults["source_census_notify_cred"]
    assert all(ref.partition("/")[0].endswith(":" + DOC["id"]) for ref in refs.values())


def test_the_readme_names_the_interface_it_assumes():
    text = (MODULE / "README.md").read_text()
    for needle in (
        "soc.raw_archive",
        "ONGOING",
        "RECOVERED",
        "manager-errors",
        "analyzer:source-census",
    ):
        assert needle in text, needle
