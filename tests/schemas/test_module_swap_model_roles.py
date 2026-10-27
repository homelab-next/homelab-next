# SPDX-License-Identifier: Apache-2.0
"""Swap record 1.2's model-role leg (``model_roles`` in the draft ``platform/module_swap`` 1.0,
``homelabnext.modules.swap.model_role_problems``): an inference swap that rebinds
``mdl:fast-classifier`` from the shipped example's binding to another quant of its model in the
example model store, checked against
both role tables, the store and the pinned evaluation report for the table after the rebind."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
import yaml

from homelabnext import paths
from homelabnext.golden import pins as gp
from homelabnext.golden.canary import benign_model
from homelabnext.models import store as st
from homelabnext.modules import swap as ms
from homelabnext.registry.models import RoleTable

ROOT = Path(__file__).resolve().parents[2]
MODULES_DIR = ROOT / "examples" / "modules"
EXAMPLE = ROOT / "schemas/platform/examples/module_swap.inference-rebind.json"
ROLES = paths.example_file("model_roles.json")
STORE = st.load(paths.example_file("model-serving", "model_store.json"))
BEFORE = RoleTable.load(ROLES)
#: the incoming binding: the store entry serving the role's own model id under other weights,
#: pinned by its revision and digest (found, not named: model ids stay out of the source)
(ENTRY,) = (
    e
    for e in STORE.entries.values()
    if e.served_model_name == BEFORE.get("fast-classifier").bindings[0].model_id
)
#: a store entry for another model id, which is no binding of the role
(STRANGER, *_) = (
    e for e in STORE.entries.values() if e.served_model_name != ENTRY.served_model_name
)


def load(p: Path) -> dict:
    return yaml.safe_load(p.read_text(encoding="utf-8"))


def _modules() -> dict:
    mods = {p.parent.name: load(p) for p in sorted(MODULES_DIR.glob("*/module.yml"))}
    other = copy.deepcopy(mods["example-inference"])
    other["id"] = "other-inference"
    mods["other-inference"] = other
    return mods


SITE = load(MODULES_DIR / "sites" / "full.yml")  # inference on example-inference: the start


def _rebound(model_id: str = ENTRY.served_model_name, digest: str = ENTRY.digest) -> RoleTable:
    doc = json.loads(ROLES.read_text(encoding="utf-8"))
    doc["roles"]["fast-classifier"]["bindings"] = [
        {
            "backend": "svc:inference",
            "model_id": model_id,
            "version": ENTRY.revision,
            "digest": digest,
        }
    ]
    return RoleTable.from_dict(doc)


def _live(role, binding):
    """A stand-in for a live canary run: the benign scripted model, recorded as live.  The check
    validates a report's shape, not its provenance, which is all these tests need."""
    return benign_model, "live"


AFTER = _rebound()


@pytest.fixture(scope="module")
def reports() -> dict:
    run = gp.run_eval
    return {
        "live": run(AFTER, gp.DEFAULT_SUITES, gp.fake_factory, model_name="fake-golden",
                    canary_factory=_live),
        "fake": run(AFTER, gp.DEFAULT_SUITES, gp.fake_factory, model_name="fake-golden"),
        "old": run(BEFORE, gp.DEFAULT_SUITES, gp.fake_factory, model_name="fake-golden",
                   canary_factory=_live),
    }  # fmt: skip


def _swap(report: dict) -> dict:
    swap = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    swap["model_roles"][0]["evaluation"]["report"] = gp.report_digest(report)
    return swap


def _evidence(
    *reports: dict, after: RoleTable = AFTER, store=STORE, live: bool = True
) -> ms.ModelEvidence:
    return ms.ModelEvidence(
        before=BEFORE, after=after, reports=reports, store=store, require_live=live
    )


def test_the_example_rebinds_the_shipped_binding_to_the_store_entry():
    leg = json.loads(EXAMPLE.read_text(encoding="utf-8"))["model_roles"][0]
    assert leg["from"] == {"pin": ms._pin_of(BEFORE.get(leg["role"]).bindings[0])}
    assert leg["to"] == {"pin": ms._pin_of(AFTER.get(leg["role"]).bindings[0])}
    assert leg["evaluation"]["require_live"] is True


def test_a_valid_rebind_holds_through_the_cutover(reports):
    swap, mods = _swap(reports["live"]), _modules()
    models = _evidence(reports["live"])
    assert ms.model_role_problems(swap, models) == []
    assert ms.module_swap_problems(swap, mods, SITE, models=models) == []
    assert ms.cutover_problems(swap, mods, SITE, models=models) == []
    after = ms.apply_selection_diff(SITE, swap, mods, models=models)
    assert after["slots"]["inference"][0]["provider"] == "other-inference"


def test_a_rebind_may_name_the_new_binding_by_its_store_entry(reports):
    swap = _swap(reports["live"])
    swap["model_roles"][0]["to"] = {"store_entry": ENTRY.id}
    assert ms.model_role_problems(swap, _evidence(reports["live"])) == []


def test_without_a_store_a_pinned_rebind_resolves_in_the_tables_alone(reports):
    """Only where the policy does not require live: live evidence comes with the store."""
    swap = _swap(reports["live"])
    swap["model_roles"][0]["evaluation"]["require_live"] = False
    assert ms.model_role_problems(swap, _evidence(reports["live"], store=None, live=False)) == []


def test_live_evidence_needs_the_store(reports):
    swap = _swap(reports["live"])
    (p,) = ms.model_role_problems(swap, _evidence(reports["live"], store=None))
    assert p.endswith("live evidence is required, and no model store is given")


def test_the_record_with_legs_needs_their_evidence(reports):
    swap = _swap(reports["live"])
    assert ms.module_swap_problems(swap, _modules(), SITE) == [
        "the record rebinds model roles, and no model evidence is given to check it"
    ]
    with pytest.raises(ValueError, match="no model evidence"):
        ms.apply_selection_diff(SITE, swap, _modules())


def test_a_missing_report_is_refused(reports):
    swap = _swap(reports["live"])
    (p,) = ms.model_role_problems(swap, _evidence(reports["fake"]))
    assert "the evaluation report sha256:" in p and "is not supplied" in p


def test_a_report_for_the_old_binding_is_refused(reports):
    swap = _swap(reports["old"])
    p = ms.model_role_problems(swap, _evidence(reports["old"]))
    assert any("evaluation report is stale" in x and "pin mdl:fast-classifier" in x for x in p)
    assert any(
        f"mdl:fast-classifier -> svc:inference {ENTRY.served_model_name}: the canary ran against "
        "a different pin" in x
        for x in p
    )


def test_a_fake_canary_entry_is_refused_where_live_is_required(reports):
    swap = _swap(reports["fake"])
    p = ms.model_role_problems(swap, _evidence(reports["fake"]))
    assert p and all("a live run is required" in x for x in p)
    assert any(f"svc:inference {ENTRY.served_model_name}: the canary ran against" in x for x in p)


def test_without_require_live_a_fake_report_still_meets_the_pins_check_guard(reports):
    """``pins check`` without ``--require-live`` refuses an all-fake report on a table that is
    not the shipped example; the leg applies the same guard, so dropping the flag is no way out."""
    swap = _swap(reports["fake"])
    swap["model_roles"][0]["evaluation"]["require_live"] = False
    (p,) = ms.model_role_problems(swap, _evidence(reports["fake"], live=False))
    assert "every egress canary in the report ran against the fake" in p


def test_the_record_cannot_waive_the_policy_live_requirement(reports):
    swap = _swap(reports["fake"])
    swap["model_roles"][0]["evaluation"]["require_live"] = False
    p = ms.model_role_problems(swap, _evidence(reports["fake"]))
    assert p and all("a live run is required" in x for x in p)


def test_the_record_may_ask_for_live_where_the_policy_does_not(reports):
    swap = _swap(reports["fake"])
    p = ms.model_role_problems(swap, _evidence(reports["fake"], live=False))
    assert p and all("a live run is required" in x for x in p)


@pytest.fixture(scope="module")
def mixed() -> tuple[dict, RoleTable]:
    """A table with a second role rebound too, so its canary entries can be live while the
    rebound role's new binding ran against the fake: the all-fake guard does not trip."""
    doc = json.loads(ROLES.read_text(encoding="utf-8"))
    doc["roles"]["fast-classifier"]["bindings"] = [
        {"backend": "svc:inference", "model_id": ENTRY.served_model_name,
         "version": ENTRY.revision, "digest": ENTRY.digest}
    ]  # fmt: skip
    after = RoleTable.from_dict(doc)

    def canary(role, binding):
        return benign_model, ("fake" if role == "fast-classifier" else "live")

    report = gp.run_eval(
        after, gp.DEFAULT_SUITES, gp.fake_factory, model_name="fake-golden", canary_factory=canary
    )
    return report, after


def test_a_fake_new_binding_in_an_otherwise_live_report_is_refused(mixed):
    report, after = mixed
    assert gp.fake_canary_on_a_real_table(report, after) is None
    swap = _swap(report)
    swap["model_roles"][0]["evaluation"]["require_live"] = False
    (p,) = ms.model_role_problems(swap, _evidence(report, after=after, live=False))
    assert "the new binding's egress canary ran against the 'fake' model" in p


def test_an_unknown_role_is_refused(reports):
    swap = _swap(reports["live"])
    swap["model_roles"][0]["role"] = "mdl:no-such-role"
    p = ms.model_role_problems(swap, _evidence(reports["live"]))
    assert p == [
        p[0],
        "mdl:fast-classifier: its bindings differ between the role tables, and no model_roles "
        "leg rebinds it",
    ]
    assert p[0].startswith("model_roles mdl:no-such-role: no model role 'no-such-role'")


@pytest.mark.parametrize(
    ("to", "store", "needle"),
    [
        ({"store_entry": STRANGER.id}, STORE, f"store entry {STRANGER.id!r} is 0 bindings"),
        ({"store_entry": "no-such-entry"}, STORE, "'no-such-entry' is not in the model store"),
        ({"store_entry": ENTRY.id}, None, "no model store is given"),
        ({"pin": "sha256:" + "0" * 64}, STORE, "is no binding of it"),
    ],
)
def test_an_unresolvable_new_binding_is_refused(reports, to, store, needle):
    swap = _swap(reports["live"])
    swap["model_roles"][0]["to"] = to
    (p,) = ms.model_role_problems(swap, _evidence(reports["live"], store=store))
    assert "the new binding does not resolve in the role table after" in p and needle in p


def test_a_new_binding_the_store_cannot_serve_is_refused():
    """Named by pin, the binding is in the table, but no store entry has its weights."""
    after = _rebound(digest="sha256:" + "1" * 64)
    report = gp.run_eval(
        after, gp.DEFAULT_SUITES, gp.fake_factory, model_name="fake-golden", canary_factory=_live
    )
    swap = _swap(report)
    swap["model_roles"][0]["to"] = {"pin": ms._pin_of(after.get("fast-classifier").bindings[0])}
    (p,) = ms.model_role_problems(swap, _evidence(report, after=after))
    assert "the new binding does not resolve in the model store" in p
    assert "matches no store entry" in p


def test_an_old_binding_not_in_the_starting_table_is_refused(reports):
    swap = _swap(reports["live"])
    swap["model_roles"][0]["from"] = {"store_entry": ENTRY.id}
    (p,) = ms.model_role_problems(swap, _evidence(reports["live"]))
    assert "the old binding does not resolve in the role table before" in p


def test_a_leg_on_an_instance_the_swap_does_not_move_is_refused(reports):
    swap = _swap(reports["live"])
    swap["model_roles"][0]["instance"] = "other"
    (p,) = ms.model_role_problems(swap, _evidence(reports["live"]))
    assert "inference/other is not a slot instance the swap moves" in p


def test_a_leg_that_rebinds_nothing_is_refused(reports):
    swap = _swap(reports["old"])
    swap["model_roles"][0]["to"] = swap["model_roles"][0]["from"]
    models = ms.ModelEvidence(before=BEFORE, after=BEFORE, reports=[reports["old"]], store=None)
    assert ms.model_role_problems(swap, models) == [
        "model_roles mdl:fast-classifier: the role's bindings are the same in both tables; "
        "nothing is rebound"
    ]


def test_a_changed_role_without_a_leg_is_refused(reports):
    swap = _swap(reports["live"])
    del swap["model_roles"]
    assert ms.model_role_problems(swap, _evidence(reports["live"])) == [
        "mdl:fast-classifier: its bindings differ between the role tables, and no model_roles "
        "leg rebinds it"
    ]
    assert ms.module_swap_problems(swap, _modules(), SITE, models=_evidence(reports["live"]))


@pytest.mark.parametrize("legs", [[], None, {}, "mdl:fast-classifier"])
def test_model_roles_present_but_not_legs_is_refused(reports, legs):
    swap = _swap(reports["live"])
    swap["model_roles"] = legs
    assert ms.model_role_problems(swap, _evidence(reports["live"])) == [
        "model_roles must be a non-empty list of legs, or absent"
    ]


def test_an_inference_swap_without_evidence_is_refused(reports):
    swap = _swap(reports["live"])
    del swap["model_roles"]
    assert ms.module_swap_problems(swap, _modules(), SITE) == [
        "the swap moves the inference slot, and no model evidence is given: the role tables "
        "before and after it are what show which model roles it rebinds"
    ]


def test_an_inference_swap_that_rebinds_nothing_holds_with_its_evidence(reports):
    swap = _swap(reports["old"])
    del swap["model_roles"]
    models = ms.ModelEvidence(before=BEFORE, after=BEFORE, store=STORE)
    assert ms.module_swap_problems(swap, _modules(), SITE, models=models) == []


@pytest.mark.parametrize("role", ["mdl:fast-classifier", "fast-classifier"])
def test_a_second_leg_for_the_role_is_refused(reports, role):
    swap = _swap(reports["live"])
    second = copy.deepcopy(swap["model_roles"][0])
    second["role"] = role
    swap["model_roles"].append(second)
    p = ms.model_role_problems(swap, _evidence(reports["live"]))
    assert p == [f"model_roles {role}: the role is rebound by more than one leg"]


def test_a_role_only_one_table_has_is_refused(reports):
    doc = json.loads(ROLES.read_text(encoding="utf-8"))
    doc["roles"]["fast-classifier"]["bindings"] = AFTER.pins()["fast-classifier"]
    doc["roles"]["extra-role"] = copy.deepcopy(doc["roles"]["fast-classifier"])
    doc["roles"]["extra-role"].pop("fallback", None)
    after = RoleTable.from_dict(doc)
    p = ms.model_role_problems(_swap(reports["live"]), _evidence(reports["live"], after=after))
    assert p[0].startswith("mdl:extra-role is only in the role table after")


@pytest.mark.parametrize(
    ("mutate", "needle"),
    [
        (lambda leg: leg.update(to={"pin": leg["to"]["pin"], "store_entry": ENTRY.id}),
         "to must be exactly one of {pin} or {store_entry}"),
        (lambda leg: leg.update({"from": {"pin": "not-a-digest"}}),
         "from names no pin digest or store entry id"),
        (lambda leg: leg.pop("role"), "a leg's role must be a string"),
        (lambda leg: leg.update(evaluation={"report": 1}), "evaluation must name its report"),
        (lambda leg: leg["evaluation"].update(require_live="yes"),
         "evaluation.require_live must be a boolean"),
    ],
)  # fmt: skip
def test_a_malformed_leg_is_refused_by_name(reports, mutate, needle):
    swap = _swap(reports["live"])
    mutate(swap["model_roles"][0])
    p = ms.model_role_problems(swap, _evidence(reports["live"]))
    assert p[0] == f"model_roles[0]: {needle}" or p[0].startswith(f"model_roles[0]: {needle}")


def test_a_leg_that_is_not_a_mapping_is_refused(reports):
    swap = _swap(reports["live"])
    swap["model_roles"] = ["mdl:fast-classifier"]
    p = ms.model_role_problems(swap, _evidence(reports["live"]))
    assert p[0] == "model_roles[0]: a leg must be a mapping"


def test_a_report_that_is_not_a_mapping_is_refused(reports):
    junk = ["not", "a", "report"]
    swap = _swap(reports["live"])
    swap["model_roles"][0]["evaluation"]["report"] = gp.report_digest(junk)
    p = ms.model_role_problems(swap, _evidence(junk))
    assert any("not a " in x and "report" in x for x in p)
