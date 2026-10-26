# SPDX-License-Identifier: Apache-2.0
"""Swap record 1.2's module-keyed part (draft ``platform/module_swap`` 1.0,
``homelabnext.modules.swap``): the documented swap of the ``samples`` object store driven from
plan to decommission over the fictional examples, and each semantic rule refusing a planted
defect."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
import yaml

from homelabnext.modules import swap as ms

ROOT = Path(__file__).resolve().parents[2]
MODULES_DIR = ROOT / "examples" / "modules"
EXAMPLE = ROOT / "schemas/platform/examples/module_swap.object-store-samples.json"


def load(p: Path) -> dict:
    return yaml.safe_load(p.read_text(encoding="utf-8"))


MODULES = {p.parent.name: load(p) for p in sorted(MODULES_DIR.glob("*/module.yml"))}
#: sites/full.yml is the selection after the swap (samples on other-object-store); the swap starts
#: from the same site with samples on example-object-store
AFTER = load(MODULES_DIR / "sites" / "full.yml")


def before() -> dict:
    site = copy.deepcopy(AFTER)
    for line in site["slots"]["object-store"]:
        if line["instance"] == "samples":
            line["provider"] = "example-object-store"
    return site


@pytest.fixture
def swap() -> dict:
    return json.loads(EXAMPLE.read_text(encoding="utf-8"))


@pytest.fixture
def mods() -> dict:
    return copy.deepcopy(MODULES)


def test_the_documented_swap_runs_from_plan_to_decommission(swap, mods):
    """docs/modules.md, "How a swap works": plan (the dependants, core included), the
    re-check holds, migration in the slot's neutral format, cutover by the selection diff (which
    lands exactly on sites/full.yml), then decommission waits on the outgoing credentials."""
    site = before()
    report = ms.dependants_report(swap, mods, site)
    assert {e["module"] for e in report} == {
        "external-collector",
        "example-sandbox",
        "publishing",
        "example-lake",
    }
    assert ms.blocked(report) == []
    assert ms.module_swap_problems(swap, mods, site) == []
    assert ms.cutover_problems(swap, mods, site) == []
    after = ms.apply_selection_diff(site, swap, mods)
    assert after == AFTER
    # example-object-store still serves `objects`: its credentials stay, none is owed
    assert ms.decommission_problems(swap, mods, after) == []
    # once it serves nothing, every credential it issued is revoked before decommission
    gone = copy.deepcopy(after)
    gone["slots"]["object-store"] = [
        c for c in gone["slots"]["object-store"] if c["provider"] != "example-object-store"
    ]
    assert ms.decommission_problems(swap, mods, gone) == [
        "secret:example-object-store/access-key is not revoked"
    ]
    swap["credentials_revoked"].append("secret:example-object-store/access-key")
    assert ms.decommission_problems(swap, mods, gone) == []


def test_a_dependant_that_no_longer_holds_blocks_the_cutover(swap, mods):
    """The incoming store loses the metadata feature the collector requires: the re-check
    blocks, and a record still carrying the old, clean report is refused."""
    offer = mods["other-object-store"]["provides"]["slots"]["object-store"]
    offer["features"] = []
    report = ms.dependants_report(swap, mods, before())
    collector = next(e for e in report if e["module"] == "external-collector")
    assert collector["verdict"] == "blocks" and collector["checks"]["features"] == "fails"
    assert collector["reasons"] == ["other-object-store does not offer metadata"]
    assert ms.blocked(report) == ["external-collector"]
    problems = ms.module_swap_problems(swap, mods, before())
    assert any("dependants.report differs" in p for p in problems)
    assert any("the re-check blocks ['external-collector']" in p for p in problems)
    # an honest record (its report recomputed) holds, but its cutover is refused
    swap["dependants"] = {"report": report, "blocked": ms.blocked(report)}
    assert ms.module_swap_problems(swap, mods, before()) == []
    assert ms.cutover_problems(swap, mods, before()) == [
        "the cutover is blocked by external-collector"
    ]
    with pytest.raises(ValueError, match="cutover refused: the cutover is blocked"):
        ms.apply_selection_diff(before(), swap, mods)


def test_a_failed_preference_falls_back_rather_than_blocks(swap, mods):
    mods["core-staff"].setdefault("prefers", {}).setdefault("capabilities", []).append(
        {
            "cap": "cap:object-store",
            "instance": "samples",
            "features": ["immutability"],
            "purpose": "keeps scorecard snapshots write-once when it can",
            "fallback": {"behaviour": "keeps them in the lake"},
        }
    )
    report = ms.dependants_report(swap, mods, before())
    core = next(e for e in report if e["module"] == "core-staff")
    assert (core["kind"], core["relation"], core["verdict"]) == ("core", "prefers", "falls-back")
    assert ms.blocked(report) == []


def test_a_requirement_on_another_instance_is_not_a_dependant(swap, mods):
    site = before()
    asks = mods["publishing"]["requires"]["capabilities"]
    for ask in asks:
        if ask["cap"] == "cap:object-store":
            ask["instance"] = "objects"
    assert "publishing" not in {e["module"] for e in ms.dependants_report(swap, mods, site)}


def _same(d):
    d["to_module"] = d["from_module"]


def _feature_module(d):
    d["to_module"] = "publishing"


def _unknown(d):
    d["to_module"] = "no-such-store"


def _wrong_start(d):
    d["from_module"], d["to_module"] = d["to_module"], d["from_module"]


def _diff_wrong_instance(d):
    d["route"]["selection_diff"][0]["instance"] = "objects"


def _legs_miss_an_instance(d):
    d["legs"] = [{"instance": "objects", "order": 1}, {"instance": "samples", "order": 2}]


def _legs_orders(d):
    d["slots"].append({"slot": "object-store", "instance": "objects"})
    d["legs"] = [{"instance": "samples", "order": 1}, {"instance": "objects", "order": 3}]


def _report_edited(d):
    d["dependants"]["report"][0]["verdict"] = "blocks"


def _report_drops_one(d):
    d["dependants"]["report"].pop()


def _migration_format(d):
    d["migration"]["format"] = "native-dump"


def _migration_count(d):
    d["migration"]["import_result"]["imported"] = 1841


def _migration_rejected(d):
    d["migration"]["import_result"]["rejected"] = 3


def _migration_and_start_empty(d):
    d["start_empty"] = {"reason": "no reason that holds here", "decided_by": "platform-team"}


def _site_has_no_line(d):
    d["slots"].append({"slot": "static-hosting", "instance": "samples"})


def _revokes_a_stranger(d):
    d["credentials_revoked"] = ["secret:other-object-store/admin-token"]


CASES = [
    (_same, "a swap moves between two modules"),
    (_feature_module, "is a feature module, not a provider"),
    (_unknown, "has no manifest"),
    (_wrong_start, "the site is the selection the swap starts from"),
    (_diff_wrong_instance, "route.selection_diff is"),
    (_legs_miss_an_instance, "legs must name every instance"),
    (_legs_orders, "orders must be 1..n"),
    (_report_edited, "dependants.report differs"),
    (_report_drops_one, "dependants.report differs"),
    (_migration_format, "is not one example-object-store migrates object-store in"),
    (_migration_count, "imported 1841 but the boundary counts 1842"),
    (_migration_rejected, "migration rejected 3 record(s)"),
    (_migration_and_start_empty, "migration and start_empty are exclusive"),
    (_site_has_no_line, "static-hosting/samples is served by nothing"),
    (_revokes_a_stranger, "which example-object-store does not issue"),
]


@pytest.mark.parametrize(("mutate", "needle"), CASES, ids=[c[0].__name__.strip("_") for c in CASES])
def test_a_bad_swap_is_refused(swap, mods, mutate, needle):
    mutate(swap)
    problems = ms.module_swap_problems(swap, mods, before())
    assert any(needle in p for p in problems), (needle, problems)


def test_a_selection_diff_applies_once_and_only_to_its_own_start(swap, mods):
    after = ms.apply_selection_diff(before(), swap, mods)
    with pytest.raises(
        ValueError, match=r"served by .*other-object-store.* not example-object-store"
    ):
        ms.apply_selection_diff(after, swap, mods)


def test_a_diff_that_strays_from_the_record_is_never_applied(swap, mods):
    """The diff is the record's checked one: a line flipping to another module, or one more line
    than the swap moves, is refused before anything changes."""
    swap["route"]["selection_diff"][0]["to"] = "example-object-store"
    with pytest.raises(ValueError, match=r"route\.selection_diff is"):
        ms.apply_selection_diff(before(), swap, mods)


def test_the_cutover_waits_on_the_data_decision(swap, mods):
    del swap["migration"]
    assert ms.cutover_problems(swap, mods, before()) == [
        "the cutover waits on a migration or a recorded start_empty decision"
    ]
    swap["start_empty"] = {
        "reason": "the samples are re-collected within a day",
        "decided_by": "platform-team",
    }
    assert ms.cutover_problems(swap, mods, before()) == []


def test_a_slot_the_site_turns_off_is_reported_not_a_crash(swap, mods):
    site = before()
    site["slots"]["object-store"] = "none"
    problems = ms.module_swap_problems(swap, mods, site)
    assert any("object-store/samples is served by nothing" in p for p in problems)


def test_the_incoming_module_s_own_requirements_must_be_selected(swap, mods):
    mods["other-object-store"]["requires"]["capabilities"].append(
        {"cap": "cap:notify", "version": "1.0", "purpose": "pages on a failed replication"}
    )
    site = before()
    site["slots"].pop("notify", None)
    problems = ms.module_swap_problems(swap, mods, site)
    assert "other-object-store requires cap:notify, which the site does not select" in problems


def test_a_module_asking_twice_has_one_stable_order(swap, mods):
    asks = mods["publishing"]["requires"]["capabilities"]
    first = next(a for a in asks if a["cap"] == "cap:object-store")
    asks.append({**first, "features": ["immutability"]})
    report = ms.dependants_report(swap, mods, before())
    swap["dependants"] = {"report": list(reversed(report)), "blocked": ms.blocked(report)}
    assert ms.module_swap_problems(swap, mods, before()) == []
    assert ms.blocked(report) == ["publishing"]


def test_a_site_naming_an_unknown_module_is_a_problem_not_a_crash(swap, mods):
    site = before()
    site["slots"]["object-store"].append({"provider": "ghost-store", "instance": "spare"})
    assert any("no manifest" in p for p in ms.module_swap_problems(swap, mods, site))
