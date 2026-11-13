# SPDX-License-Identifier: Apache-2.0
"""Planned core slots (ADR-0027 decision 9; docs/modules/planned.md): a selection may declare a
required core slot it does not serve yet, with what will serve it and a date to review the plan.
``hnx modules check`` then warns, instead of refusing "a required core slot has no provider"; a
planned slot is not served, so it satisfies no requirement and is never a provider, an instance,
an egress target or an upstream; ``--deploy`` refuses one whose ``review_by`` has passed.  Each
rule is shown refusing a planted defect."""

from __future__ import annotations

import copy
import datetime as dt
import json
import shutil
from pathlib import Path

import pytest
import yaml

from homelabnext.modules import cli as mcli
from homelabnext.modules import loader as ld
from homelabnext.modules import rules as mr
from homelabnext.modules.providers import ProviderLookupError, provider_for

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "examples" / "modules"
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "selection.planned.yml"
SLOTS = ld.load_yaml(EXAMPLES / "slots.yml")["slots"]
ROLES = json.loads((ROOT / "examples" / "model_roles.json").read_text())["roles"]
REGISTRY = ld.load_yaml(ROOT / "examples" / "services.yml")
CORE, _ = ld.core_names(REGISTRY)
REQUIRED = sorted(s for s, d in SLOTS.items() if d.get("required_in_core"))
PLANNED = ("edge", "idp", "inference")


@pytest.fixture(scope="module")
def tree():
    tree, found = ld.discover(fixtures=EXAMPLES)
    assert found == []
    return tree


@pytest.fixture(scope="module")
def ins(tree):
    return ld.inputs(tree)


def fixture() -> dict:
    return ld.load_yaml(FIXTURE)


def problems(site, tree, ins, *, mods=None, rows=None, today=None):
    return mr.site_problems(
        site, tree.mods if mods is None else mods, SLOTS,
        rows=ins.rows if rows is None else rows, units=ins.units,
        privileged_units=ins.privileged_units, roles=ROLES, registry=CORE.rows, today=today,
    )  # fmt: skip


def check(tree, site, **kw):
    return ld.check(
        tree, slots=SLOTS, roles=ROLES, in_tree_roots=(EXAMPLES,), core=CORE, site=site, **kw
    )


# ----------------------------------------------------------------------------- the fixture passes


def test_the_fixture_is_a_staged_lab(tree, ins):
    site = fixture()
    assert sorted(site["planned"]) == list(PLANNED)
    assert set(site["planned"]) <= set(REQUIRED)
    assert not set(site["planned"]) & (set(site["slots"]) | set(site["incumbents"]))
    assert problems(site, tree, ins) == []


def test_each_planned_slot_is_a_warning_with_its_why_and_review_by(tree):
    report = check(tree, fixture())
    assert report.problems == []
    assert report.warnings == [
        "edge: a required core slot has no provider yet (planned: the front door, after idp; "
        "review by 2027-01-15)",
        "idp: a required core slot has no provider yet (planned: an identity provider module, "
        "the next stage; review by 2027-01-15)",
        "inference: a required core slot has no provider yet (planned: a model server module, "
        "once the GPU host is up; review by 2027-03-01)",
    ]


def test_the_cli_prints_the_warnings_and_exits_zero(capsys):
    argv = ["check", "--root", str(ROOT), "--examples", "--site", str(FIXTURE)]
    assert mcli.main(argv) == 0
    out = capsys.readouterr().out
    assert [ln for ln in out.splitlines() if ln.startswith("warning: ")] == [
        f"warning: {w}" for w in mr.planned_warnings(fixture())
    ]
    assert out.rstrip().endswith("0 problem(s), 3 warning(s)")
    assert mcli.main([*argv, "--json"]) == 0
    got = capsys.readouterr()
    doc = json.loads(got.out)
    assert (doc["problems"], doc["warnings"]) == ([], mr.planned_warnings(fixture()))
    assert "warning: idp: a required core slot has no provider yet" in got.err


def test_without_the_plan_it_is_the_same_error_as_before(tree, ins):
    site = fixture()
    del site["planned"]
    got = problems(site, tree, ins)
    assert sorted(p for p in got if "required core slot" in p) == [
        f"{s}: a required core slot has no provider" for s in PLANNED
    ]


def test_the_check_reads_no_date_so_an_expired_plan_is_only_a_warning(tree, monkeypatch):
    """The plain check is a pure function of its files: no date is read, whatever HNX_TODAY
    says; only a deploy judges review_by against the date."""
    monkeypatch.setenv("HNX_TODAY", "2099-01-01")
    report = check(tree, fixture())
    assert (report.problems, len(report.warnings)) == ([], 3)


# ----------------------------------------------------------------------------- planted defects


DEFECTS = {
    "an unknown slot": (
        lambda s: s["planned"].__setitem__("no-such-slot", {"why": "x", "review_by": "2027-01-15"}),
        "planned.no-such-slot: no such slot in the slot registry",
    ),
    "an optional slot": (
        lambda s: (
            s["slots"].pop("hot-index"),
            s["planned"].__setitem__("hot-index", {"why": "x", "review_by": "2027-01-15"}),
        ),
        "planned.hot-index: not a required core slot (only one may be planned; an optional slot "
        "the site does not select is left out)",
    ),
    "a module provider and a plan": (
        lambda s: s["slots"].__setitem__(
            "idp", [{"provider": "example-platform", "instance": "platform"}]
        ),
        "planned.idp: the slot is also selected under slots (a module provider): one answer per "
        "slot",
    ),
    "none and a plan": (
        lambda s: s["slots"].__setitem__("edge", "none"),
        "planned.edge: the slot is also selected under slots (none): one answer per slot",
    ),
    "an incumbent and a plan": (
        lambda s: s["incumbents"].__setitem__("idp", {"service": "idp", "why": "x"}),
        "planned.idp: the slot is also an incumbent: one answer per slot",
    ),
    "a review_by that is no calendar date": (
        lambda s: s["planned"]["idp"].__setitem__("review_by", "2027-02-30"),
        "planned.idp: review_by '2027-02-30' is not a date",
    ),
}


@pytest.mark.parametrize("name", sorted(DEFECTS))
def test_each_planted_planned_defect_is_refused(tree, ins, name):
    mutate, want = DEFECTS[name]
    site = fixture()
    mutate(site)
    assert want in problems(site, tree, ins)


@pytest.mark.parametrize(
    ("plan", "where"),
    [
        ({"why": "x"}, "site: schema: planned/idp: 'review_by' is a required property"),
        ({"why": "x", "review_by": "soon"}, "site: schema: planned/idp/review_by: does not match"),
        ({"why": "x", "review_by": dt.date(2027, 1, 15)}, "site: schema: planned/idp/review_by: "),
        ({"review_by": "2027-01-15"}, "site: schema: planned/idp: 'why' is a required property"),
    ],
)
def test_review_by_is_required_and_must_be_a_date(tree, plan, where):
    """An unquoted YAML date is a date object, not the string the schema holds it to: the
    refusal names the field (quote it)."""
    site = fixture()
    site["planned"]["idp"] = plan
    got = [str(p) for p in check(tree, site).problems]
    assert any(p.startswith(where) for p in got), got


def test_a_review_by_that_has_passed_is_refused_given_the_date(tree, ins):
    site = fixture()
    on = dt.date(2027, 1, 16)
    got = problems(site, tree, ins, today=on)
    assert got == [
        f"planned.{s}: review_by 2027-01-15 has passed (2027-01-16): serve the slot (a provider "
        "or an incumbent) or review the plan and set a new date"
        for s in ("edge", "idp")
    ]
    # the day itself has not passed
    assert problems(site, tree, ins, today=dt.date(2027, 1, 15)) == []


# ----------------------------------------------------------------------------- not served


def test_a_module_whose_hard_requirement_is_planned_is_refused_by_name(tree, ins):
    """example-object-store and example-siem-suite require cap:secrets."""
    site = fixture()
    del site["incumbents"]["secrets"]
    site["planned"]["secrets"] = {"why": "a secret store module", "review_by": "2027-01-15"}
    got = problems(site, tree, ins)
    for mid in ("example-object-store", "example-siem-suite"):
        assert (
            f"{mid}: requires cap:secrets, which the site plans but does not serve yet (a "
            "planned slot satisfies no requirement)"
        ) in got
    assert "secrets: a required core slot has no provider" not in got


def test_a_planned_slot_is_never_an_egress_target(tree, ins):
    mods = copy.deepcopy(tree.mods)
    mods["publishing"]["egress"] = [{"host": "publisher", "to": ["svc:idp"], "purpose": "x"}]
    site = fixture()
    site["features"]["publishing"] = {"placement": {"publisher": "core"}}
    site["grants"]["egress"]["publishing"] = {"publisher": ["svc:idp"]}
    got = problems(site, tree, ins, mods=mods)
    assert "publishing: host publisher egresses to svc:idp, which is no service" in got


def test_a_planned_slot_is_never_an_upstream(tree, ins):
    rows = copy.deepcopy(ins.rows)
    rows["external-collector"] = {
        **rows.get("external-collector", {}),
        "collector-console": {"capability": "collector-console", "upstreams": ["idp"]},
    }
    site = fixture()
    site["grants"]["upstreams"] = {"external-collector": ["cap:idp"]}
    got = problems(site, tree, ins, rows=rows)
    assert (
        "external-collector: service collector-console upstream idp is not selected, nor a "
        "fallback for it"
    ) in got


def test_a_planned_orchestration_binds_no_agent_lane(tree, ins):
    """An agent lane binds to a module orchestration instance; a planned one has none."""
    site = fixture()
    del site["slots"]["orchestration"]
    site["planned"]["orchestration"] = {"why": "an orchestrator module", "review_by": "2027-01-15"}
    got = problems(site, tree, ins)
    assert "core-staff-scorecard: lane real bound to unselected instance platform" in got


def test_provider_for_says_a_planned_slot_is_not_served(tree):
    with pytest.raises(ProviderLookupError, match="idp: planned, not served yet"):
        provider_for(fixture(), tree.mods, "cap:idp")


def test_hnx_modules_providers_lists_the_planned_slots(capsys):
    argv = ["providers", "--root", str(ROOT), "--examples", "--site", str(FIXTURE)]
    assert mcli.main([*argv, "--json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["planned"] == {
        s: {"why": v["why"], "review_by": v["review_by"]} for s, v in fixture()["planned"].items()
    }
    assert not {p["slot"] for p in doc["providers"]} & set(PLANNED)
    assert mcli.main(argv) == 0
    assert (
        "idp: planned, not served yet (an identity provider module, the next stage; review by "
        "2027-01-15)"
    ) in capsys.readouterr().out


# ----------------------------------------------------------------------------- at deploy time


#: the operator's staged lab: five incumbents, one module provider, six planned slots
INCUMBENT = ("backup", "broker", "dns", "events", "secrets")
STAGED = ("agent-runtime", "edge", "idp", "inference", "orchestration", "records")
PROVIDER = "example-siem-suite"  # serves notify; requires cap:secrets (an incumbent)


@pytest.fixture(scope="module")
def checkout(tmp_path_factory) -> Path:
    """A checkout root whose public modules/ tree holds one module (the deploy check loads no
    fixture), with the core's roles and the slot registry."""
    root = tmp_path_factory.mktemp("checkout")
    (root / "examples" / "modules").mkdir(parents=True)
    shutil.copy(EXAMPLES / "slots.yml", root / "examples" / "modules" / "slots.yml")
    shutil.copytree(ROOT / "ansible" / "roles", root / "ansible" / "roles")
    d = root / "modules" / PROVIDER
    shutil.copytree(EXAMPLES / PROVIDER, d)
    doc = ld.load_yaml(d / "module.yml")
    for kind, rel in [
        *ld.contributed_files(doc),
        *(("lifecycle", p) for p in ld.lifecycle_playbooks(doc)),
    ]:  # a public module ships its roles and playbooks
        if not rel.startswith(ld.FIXTURE_UNSHIPPED) or (d / rel).exists():
            continue
        if kind == "roles":
            (d / rel / "tasks").mkdir(parents=True)
            (d / rel / "tasks" / "main.yml").write_text("- {}\n")
        else:
            (d / rel).parent.mkdir(parents=True, exist_ok=True)
            (d / rel).write_text("- {}\n")
    return root


def _staged_overlay(tmp_path: Path, review_by: str = "2027-01-15") -> Path:
    lab = tmp_path / "overlay" / "lab"
    (lab / "mcp").mkdir(parents=True)
    (lab / "keyring").mkdir()
    (lab / "keyring" / "keyring.json").write_text('{"principals": []}')
    shutil.copy(ROOT / "examples" / "model_roles.json", lab / "model_roles.json")
    reg = copy.deepcopy(REGISTRY)
    for i, cap in enumerate(("backup", "broker")):  # the example registry has no row for these
        reg["services"][cap] = {
            **copy.deepcopy(reg["services"]["secrets"]),
            "capability": cap,
            "impl": f"incumbent-{cap}",
            "port": 9100 + i,
            "health": {"kind": "tcp"},
            "tags": ["core"],
        }
    reg["services"]["notify"]["impl"] = "litware-siem"  # the provider's product: provider_for
    (lab / "services.yml").write_text(yaml.safe_dump(reg, sort_keys=False))
    site = {
        "profile": "staged",
        "hosts": {
            "core": {
                "kind": "host",
                "addresses": ["192.0.2.10"],
                "capacity": {"cpu": 16, "memory_mb": 32768, "disk_gb": 2000},
            }
        },
        "slots": {
            "notify": [{"provider": PROVIDER, "instance": "siem", "placement": {"suite": "core"}}]
        },
        "incumbents": {s: {"service": s, "why": f"the lab's own {s}"} for s in INCUMBENT},
        "planned": {
            s: {"why": f"a {s} module, a later stage", "review_by": review_by} for s in STAGED
        },
    }
    (lab / "modules.yml").write_text(yaml.safe_dump(site, sort_keys=False))
    return lab.parent


def _deploy(capsys, root: Path, ov: Path) -> tuple[int, dict]:
    code = mcli.main(["check", "--root", str(root), "--overlay", str(ov), "--deploy", "--json"])
    return code, json.loads(capsys.readouterr().out)


def test_a_staged_lab_passes_the_deploy_check(checkout, tmp_path, capsys, monkeypatch):
    assert set(INCUMBENT) | set(STAGED) | {"notify"} == set(REQUIRED)
    monkeypatch.setenv("HNX_TODAY", "2026-11-13")
    code, doc = _deploy(capsys, checkout, _staged_overlay(tmp_path))
    assert (code, doc["problems"]) == (0, [])
    assert doc["modules"] == 1
    assert [w.split(":")[0] for w in doc["warnings"]] == list(STAGED)


def test_the_deploy_check_refuses_an_expired_plan(checkout, tmp_path, capsys, monkeypatch):
    ov = _staged_overlay(tmp_path)
    monkeypatch.setenv("HNX_TODAY", "2027-01-15")
    assert _deploy(capsys, checkout, ov)[0] == 0  # the day itself has not passed
    monkeypatch.setenv("HNX_TODAY", "2027-01-16")
    code, doc = _deploy(capsys, checkout, ov)
    assert code == 1
    assert doc["problems"] == [
        f"site: planned.{s}: review_by 2027-01-15 has passed (2027-01-16): serve the slot (a "
        "provider or an incumbent) or review the plan and set a new date"
        for s in STAGED
    ]
    # the same files without --deploy read no date: warnings only
    plain = mcli.main(["check", "--root", str(checkout), "--overlay", str(ov), "--json"])
    assert (plain, json.loads(capsys.readouterr().out)["problems"]) == (0, [])


def test_the_deploy_check_reads_the_date_from_hnx_today_only(checkout, tmp_path, capsys,
                                                             monkeypatch):  # fmt: skip
    monkeypatch.setenv("HNX_TODAY", "not-a-date")
    argv = ["check", "--root", str(checkout), "--overlay", str(_staged_overlay(tmp_path))]
    assert mcli.main([*argv, "--deploy"]) == 2
    assert "HNX_TODAY='not-a-date' is not a YYYY-MM-DD date" in capsys.readouterr().err


def test_a_staged_lab_whose_provider_requires_a_planned_slot_is_refused(checkout, tmp_path,
                                                                        capsys, monkeypatch):  # fmt: skip
    monkeypatch.setenv("HNX_TODAY", "2026-11-13")
    ov = _staged_overlay(tmp_path)
    path = ov / "lab" / "modules.yml"
    site = yaml.safe_load(path.read_text())
    del site["incumbents"]["secrets"]
    site["planned"]["secrets"] = {"why": "a secret store module", "review_by": "2027-01-15"}
    path.write_text(yaml.safe_dump(site, sort_keys=False))
    code, doc = _deploy(capsys, checkout, ov)
    assert (code, doc["problems"]) == (
        1,
        [
            f"site: {PROVIDER}: requires cap:secrets, which the site plans but does not serve "
            "yet (a planned slot satisfies no requirement)"
        ],
    )
