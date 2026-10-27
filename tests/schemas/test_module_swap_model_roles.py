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


def _evidence(*reports: dict, after: RoleTable = AFTER, store=STORE) -> ms.ModelEvidence:
    return ms.ModelEvidence(before=BEFORE, after=after, reports=reports, store=store)


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
    swap = _swap(reports["live"])
    assert ms.model_role_problems(swap, _evidence(reports["live"], store=None)) == []


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
    (p,) = ms.model_role_problems(swap, _evidence(reports["fake"]))
    assert "every egress canary in the report ran against the fake" in p


def test_an_unknown_role_is_refused(reports):
    swap = _swap(reports["live"])
    swap["model_roles"][0]["role"] = "mdl:no-such-role"
    (p,) = ms.model_role_problems(swap, _evidence(reports["live"]))
    assert p.startswith("model_roles mdl:no-such-role: no model role 'no-such-role'")


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
        "model_roles mdl:fast-classifier: the old and new binding are the same pin; "
        "nothing is rebound"
    ]
