# SPDX-License-Identifier: Apache-2.0
"""Swap record 1.2's model-role legs that ADD and REMOVE a role (``change: add|remove`` in the
draft ``platform/module_swap`` 1.0, ``homelabnext.modules.swap.model_role_problems``).

A role that only the table after has (the first role of an empty table included) is covered by an
add leg carrying the evidence a rebind does: the new binding (by pin or store entry, in the store,
on the instance the leg moves) and the pinned live report for the table after.  A role only the
table before has is covered by a remove leg (the old binding, and the report for the table
after).  The rebind gate is unchanged: a rebind leg still cannot cover a role one table lacks."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
import yaml

from homelabnext import paths
from homelabnext.golden import pins as gp
from homelabnext.golden.canary import benign_decider, benign_model
from homelabnext.models import store as st
from homelabnext.modules import swap as ms
from homelabnext.registry.models import RoleTable

ROOT = Path(__file__).resolve().parents[2]
MODULES_DIR = ROOT / "examples" / "modules"
EXAMPLE = ROOT / "schemas/platform/examples/module_swap.inference-add.json"
STORE = st.load(paths.example_file("model-serving", "model_store.json"))
SHIPPED = RoleTable.load(paths.example_file("model_roles.json"))
(ENTRY,) = (
    e
    for e in STORE.entries.values()
    if e.served_model_name == SHIPPED.get("fast-classifier").bindings[0].model_id
)
SITE = yaml.safe_load((MODULES_DIR / "sites" / "full.yml").read_text(encoding="utf-8"))
EMPTY = RoleTable.from_dict({"version": 1, "roles": {}})


def _binding(backend: str = "inference", digest: str = ENTRY.digest) -> dict:
    return {
        "backend": f"svc:{backend}",
        "model_id": ENTRY.served_model_name,
        "version": ENTRY.revision,
        "digest": digest,
    }


def _decision_doc(*bindings: dict) -> dict:
    return {
        "version": 1,
        "roles": {
            "fast-classifier": {
                "kind": "decision",
                "tier": "fast",
                "bindings": list(bindings) or [_binding()],
            }
        },
    }


#: the table after the add: the first role, a decision role, of a table that had none
ADDED = RoleTable.from_dict(_decision_doc())


def _modules() -> dict:
    mods = {
        p.parent.name: yaml.safe_load(p.read_text(encoding="utf-8"))
        for p in sorted(MODULES_DIR.glob("*/module.yml"))
    }
    other = copy.deepcopy(mods["example-inference"])
    other["id"] = "other-inference"
    mods["other-inference"] = other
    return mods


def _run(table: RoleTable, mode: str = "live") -> dict:
    return gp.run_eval(
        table,
        gp.DEFAULT_SUITES,
        gp.fake_factory,
        model_name="fake-golden",
        canary_factory=lambda r, b: (benign_model, mode),
        decision_canary_factory=lambda r, b: (benign_decider, mode),
    )


@pytest.fixture(scope="module")
def reports() -> dict:
    return {"live": _run(ADDED), "fake": _run(ADDED, "fake"), "empty": _run(EMPTY)}


def _swap(report: dict, **leg) -> dict:
    swap = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    swap["model_roles"][0]["evaluation"]["report"] = gp.report_digest(report)
    swap["model_roles"][0].update(leg)
    return swap


def _ev(*reports: dict, before=EMPTY, after=ADDED, store=STORE, live=True) -> ms.ModelEvidence:
    return ms.ModelEvidence(
        before=before, after=after, reports=reports, store=store, require_live=live
    )


def _removal(report: dict) -> dict:
    """The reverse swap: the table after the add is the start, the empty table the end."""
    swap = _swap(
        report,
        change="remove",
        **{"from": {"pin": ms._pin_of(ADDED.get("fast-classifier").bindings[0])}},
    )
    del swap["model_roles"][0]["to"]
    return swap


# ---------------------------------------------------------------- add


def test_the_example_adds_the_role_with_its_one_binding(reports):
    leg = json.loads(EXAMPLE.read_text(encoding="utf-8"))["model_roles"][0]
    assert leg["change"] == "add" and "from" not in leg
    assert leg["to"] == {"pin": ms._pin_of(ADDED.get("fast-classifier").bindings[0])}
    assert (
        leg["evaluation"]["require_live"] is True
    )  # the digest is set per run (the code is an input)


def test_an_add_leg_holds_through_the_cutover(reports):
    swap, mods, models = _swap(reports["live"]), _modules(), _ev(reports["live"])
    assert ms.model_role_problems(swap, models) == []
    assert ms.module_swap_problems(swap, mods, SITE, models=models) == []
    assert ms.cutover_problems(swap, mods, SITE, models=models) == []


def test_an_add_leg_may_name_the_new_binding_by_its_store_entry(reports):
    swap = _swap(reports["live"], to={"store_entry": ENTRY.id})
    assert ms.model_role_problems(swap, _ev(reports["live"])) == []


def test_an_added_role_with_no_leg_is_refused(reports):
    swap = _swap(reports["live"])
    del swap["model_roles"]
    assert ms.model_role_problems(swap, _ev(reports["live"])) == [
        "mdl:fast-classifier is only in the role table after, and no model_roles leg adds it "
        "(change: add, with the new binding and the live report for the table after)"
    ]


def test_a_rebind_leg_still_cannot_cover_an_added_role(reports):
    """The rebind gate is unchanged: a rebind names a role both tables have."""
    swap = _swap(reports["live"], change="rebind", **{"from": {"pin": "sha256:" + "0" * 64}})
    (p,) = ms.model_role_problems(swap, _ev(reports["live"]))
    assert p == (
        "model_roles mdl:fast-classifier: the role is only in the role table after: a role the "
        "swap brings needs an add leg (change: add), not a rebind"
    )
    swap = _swap(reports["live"])
    del swap["model_roles"][0]["change"]  # rebind is the default, and names its old binding
    p = ms.model_role_problems(swap, _ev(reports["live"]))
    assert p[0] == "model_roles[0]: from must be exactly one of {pin} or {store_entry}"
    assert p[1].startswith("mdl:fast-classifier is only in the role table after, and no")


def test_an_add_leg_for_a_role_the_table_before_has_is_refused(reports):
    swap = _swap(reports["live"])
    before = RoleTable.from_dict(_decision_doc(_binding(digest="sha256:" + "1" * 64)))
    (p,) = ms.model_role_problems(swap, _ev(reports["live"], before=before))
    assert p.endswith("an add leg brings a role only the table after has; this one is in the "
                      "table before")  # fmt: skip


def test_an_add_leg_names_no_old_binding(reports):
    swap = _swap(reports["live"], **{"from": {"pin": "sha256:" + "0" * 64}})
    p = ms.model_role_problems(swap, _ev(reports["live"]))
    assert p[0] == "model_roles[0]: an add leg names no from binding" and len(p) == 2


def test_an_add_leg_needs_its_new_binding(reports):
    swap = _swap(reports["live"])
    del swap["model_roles"][0]["to"]
    assert ms.model_role_problems(swap, _ev(reports["live"]))[0] == (
        "model_roles[0]: to must be exactly one of {pin} or {store_entry}"
    )


def test_an_add_needs_the_live_report_for_the_table_after(reports):
    swap = _swap(reports["live"])
    (p,) = ms.model_role_problems(swap, _ev(reports["empty"]))
    assert "is not supplied; the leg's evidence is the pinned report for the role table after" in p
    p = ms.model_role_problems(_swap(reports["fake"]), _ev(reports["fake"]))
    assert p and all("a live run is required" in x for x in p)


def test_an_add_without_the_store_is_refused_where_live_is_required(reports):
    (p,) = ms.model_role_problems(_swap(reports["live"]), _ev(reports["live"], store=None))
    assert p.endswith("live evidence is required, and no model store is given")


def test_an_added_binding_the_store_cannot_serve_is_refused():
    after = RoleTable.from_dict(_decision_doc(_binding(digest="sha256:" + "1" * 64)))
    report = _run(after)
    swap = _swap(report, to={"pin": ms._pin_of(after.get("fast-classifier").bindings[0])})
    (p,) = ms.model_role_problems(swap, _ev(report, after=after))
    assert "the new binding does not resolve in the model store" in p


def test_an_add_onto_a_backend_the_swap_does_not_install_is_refused():
    after = RoleTable.from_dict(_decision_doc(_binding(backend="elsewhere")))
    report = _run(after)
    swap = _swap(report, to={"pin": ms._pin_of(after.get("fast-classifier").bindings[0])})
    (p,) = ms.model_role_problems(swap, _ev(report, after=after))
    assert "the new binding's backend svc:elsewhere is not the instance the leg moves" in p


def test_an_add_brings_one_binding():
    after = RoleTable.from_dict(_decision_doc(_binding(), _binding(backend="elsewhere")))
    report = _run(after)
    swap = _swap(report)
    p = ms.model_role_problems(swap, _ev(report, after=after))
    assert any("the role is added with 2 bindings; an add leg brings a role with its one" in x
               for x in p), p  # fmt: skip


def test_an_add_on_an_instance_the_swap_does_not_move_is_refused(reports):
    swap = _swap(reports["live"], instance="other")
    p = ms.model_role_problems(swap, _ev(reports["live"]))
    assert "inference/other is not a slot instance the swap moves" in p[0]


def test_the_added_role_is_evaluated_by_its_kind(reports):
    """The decision role's report holds its decision suite and a decision canary entry."""
    rep = reports["live"]
    assert list(rep["golden"]) == ["decision-smoke"]
    assert rep["canary"]["fast-classifier"]["bindings"][0]["kind"] == "decision"


def test_an_add_next_to_an_unchanged_role_holds():
    """A table that already has a role gains a second one: only the new one needs a leg."""
    before_doc = json.loads(paths.example_file("model_roles.json").read_text(encoding="utf-8"))
    after_doc = copy.deepcopy(before_doc)
    after_doc["roles"]["triage-decider"] = _decision_doc()["roles"]["fast-classifier"]
    before, after = RoleTable.from_dict(before_doc), RoleTable.from_dict(after_doc)
    suite = {
        "suite": "triage-decision",
        "kind": "decision",
        "role": "triage-decider",
        "tasks": [{"id": "t", "prompt": "Rollback: revert.", "question": "Rollback named?",
                   "expect": {"scorer": "probability", "min": 0.8}}],
    }  # fmt: skip
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "triage_decision.yml"
        path.write_text(yaml.safe_dump(suite), encoding="utf-8")
        suites = (*gp.DEFAULT_SUITES, path)
        report = gp.run_eval(
            after, suites, gp.fake_factory, model_name="fake-golden",
            canary_factory=lambda r, b: (benign_model, "live"),
            decision_canary_factory=lambda r, b: (benign_decider, "live"),
        )  # fmt: skip
        swap = _swap(report, role="mdl:triage-decider")
        models = ms.ModelEvidence(
            before=before, after=after, reports=[report], store=STORE, suites=suites
        )
        assert ms.model_role_problems(swap, models) == []


# ---------------------------------------------------------------- remove


def test_a_remove_leg_holds(reports):
    swap = _removal(reports["empty"])
    assert ms.model_role_problems(swap, _ev(reports["empty"], before=ADDED, after=EMPTY)) == []


def test_a_removed_role_with_no_leg_is_refused(reports):
    swap = _removal(reports["empty"])
    del swap["model_roles"]
    assert ms.model_role_problems(swap, _ev(reports["empty"], before=ADDED, after=EMPTY)) == [
        "mdl:fast-classifier is only in the role table before, and no model_roles leg removes "
        "it (change: remove, with the old binding and the report for the table after)"
    ]


@pytest.mark.parametrize("change", ["rebind", "add"])
def test_another_change_cannot_cover_a_removed_role(reports, change):
    swap = _removal(reports["empty"])
    leg = swap["model_roles"][0]
    leg["change"] = change
    leg["to"] = {"pin": "sha256:" + "0" * 64}
    if change == "add":
        del leg["from"]
    (p,) = ms.model_role_problems(swap, _ev(reports["empty"], before=ADDED, after=EMPTY))
    assert (
        "the role is only in the role table before: a role the swap drops needs a remove "
        f"leg (change: remove), not a{'n' if change == 'add' else ''} {change}" in p
    )


def test_a_remove_leg_names_no_new_binding(reports):
    swap = _removal(reports["empty"])
    swap["model_roles"][0]["to"] = {"pin": "sha256:" + "0" * 64}
    p = ms.model_role_problems(swap, _ev(reports["empty"], before=ADDED, after=EMPTY))
    assert p[0] == "model_roles[0]: a remove leg names no to binding" and len(p) == 2


def test_a_remove_leg_names_a_binding_of_the_role(reports):
    swap = _removal(reports["empty"])
    swap["model_roles"][0]["from"] = {"pin": "sha256:" + "0" * 64}
    (p,) = ms.model_role_problems(swap, _ev(reports["empty"], before=ADDED, after=EMPTY))
    assert "the old binding does not resolve in the role table before" in p


def test_a_remove_needs_the_report_for_the_table_after(reports):
    swap = _removal(reports["live"])  # the report for the table before
    p = ms.model_role_problems(swap, _ev(reports["live"], before=ADDED, after=EMPTY))
    assert any("evaluation report is stale" in x for x in p)


def test_a_remove_leg_for_a_role_the_table_after_keeps_is_refused(reports):
    swap = _removal(reports["live"])
    after = RoleTable.from_dict(_decision_doc(_binding(digest="sha256:" + "1" * 64)))
    (p,) = ms.model_role_problems(swap, _ev(reports["live"], before=ADDED, after=after))
    assert p.endswith("a remove leg drops a role only the table before has; this one is in the "
                      "table after")  # fmt: skip


def test_an_unknown_change_is_refused(reports):
    swap = _swap(reports["live"], change="replace")
    p = ms.model_role_problems(swap, _ev(reports["live"]))
    assert p[0] == "model_roles[0]: change must be one of ['add', 'rebind', 'remove']"
    assert len(p) == 2  # and the added role is uncovered


def test_the_schema_takes_each_change_and_no_other():
    import jsonschema
    from schema_check import build_registry

    schema = json.loads((ROOT / "schemas/platform/module_swap.schema.json").read_text())
    v = jsonschema.Draft202012Validator(schema, registry=build_registry(ROOT))
    doc = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    assert not list(v.iter_errors(doc))
    doc["model_roles"][0]["change"] = "replace"
    assert list(v.iter_errors(doc))
