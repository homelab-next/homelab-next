# SPDX-License-Identifier: Apache-2.0
"""G-11: every model is pinned by version and digest; a changed pin needs a new evaluation."""

import copy
import json
import shutil
from pathlib import Path

import jsonschema
import pytest

from homelabnext.golden import pins
from homelabnext.golden.cli import main as golden_main
from homelabnext.registry.models import RoleTable, RoleTableError

ROOT = Path(__file__).resolve().parents[2]
ROLES = ROOT / "examples" / "model_roles.json"
REPORT = ROOT / "examples" / "model_roles.eval.json"
SUITES = list(pins.DEFAULT_SUITES)


def table_doc():
    return json.loads(ROLES.read_text())


def fresh(doc=None):
    t = RoleTable.from_dict(doc or table_doc())
    return t, pins.run_eval(t, SUITES, pins.fake_factory, model_name="fake-golden")


def test_the_committed_table_is_schema_valid_and_fully_pinned():
    from schema_check import build_registry

    schema = json.loads((ROOT / "schemas/platform/model_roles.json").read_text())
    v = jsonschema.Draft202012Validator(schema, registry=build_registry(ROOT))
    assert not list(v.iter_errors(table_doc()))
    assert RoleTable.load(ROLES).unpinned() == []


def test_the_committed_report_is_current_passing_and_reproducible():
    stored = pins.load_report(REPORT)
    assert pins.check_report(stored, RoleTable.load(ROLES), SUITES) == []
    assert fresh()[1] == stored
    assert stored["summary"]["ok"] and stored["replay"]["gate"]["passed"]


def test_an_unpinned_binding_fails():
    doc = table_doc()
    del doc["roles"]["fast-classifier"]["bindings"][0]["digest"]
    t, rep = fresh(doc)
    (p,) = pins.check_report(rep, t, SUITES)
    assert "mdl:fast-classifier" in p and "not pinned" in p


@pytest.mark.parametrize(
    ("field", "value"),
    [("version", "2026.10.1"), ("digest", "sha256:" + "a" * 64), ("model_id", "example-4b-q8")],
)
def test_a_changed_pin_makes_the_stored_report_stale_until_regenerated(field, value):
    stored = pins.load_report(REPORT)
    doc = table_doc()
    doc["roles"]["fast-classifier"]["bindings"][0][field] = value
    t = RoleTable.from_dict(doc)
    (p,) = pins.check_report(stored, t, SUITES)
    assert "stale" in p and "pin mdl:fast-classifier" in p and "main-reasoner" not in p
    _, regenerated = fresh(doc)
    assert pins.check_report(regenerated, t, SUITES) == []


def test_a_changed_suite_makes_the_report_stale(tmp_path):
    suite = tmp_path / "classifier_smoke.yml"
    shutil.copy(SUITES[0], suite)
    suite.write_text(suite.read_text() + "\n# reviewed\n")
    p = pins.check_report(pins.load_report(REPORT), RoleTable.load(ROLES), [suite])
    assert any("stale" in x and "suites" in x for x in p)


def test_a_failing_evaluation_fails():
    t = RoleTable.load(ROLES)

    def bad(role):
        return (lambda messages, params: "I refuse to answer in JSON, sorry"), "bad"

    rep = pins.run_eval(t, SUITES, bad, model_name="bad")
    assert not rep["summary"]["ok"]
    (p,) = pins.check_report(rep, t, SUITES)
    assert "did not pass" in p


def test_every_role_must_be_evaluated():
    doc = table_doc()
    doc["roles"]["embedder"] = copy.deepcopy(doc["roles"]["fast-classifier"])
    t, rep = fresh(doc)
    assert "mdl:embedder is pinned but nothing evaluates it" in pins.check_report(rep, t, SUITES)


def test_garbage_report_and_bad_digest():
    t = RoleTable.load(ROLES)
    assert pins.check_report([], t, SUITES) == ["not a hnx-model-eval/1 report"]
    doc = table_doc()
    doc["roles"]["main-reasoner"]["bindings"][0]["digest"] = "md5:abc"
    with pytest.raises(RoleTableError, match="sha256"):
        RoleTable.from_dict(doc)


def test_cli_report_then_check_and_a_tampered_fake_report(tmp_path, capsys):
    roles, report = tmp_path / "roles.json", tmp_path / "eval.json"
    shutil.copy(ROLES, roles)
    args = ["--roles", str(roles), "--report", str(report)]
    assert golden_main(["pins", "report", *args]) == 0
    assert golden_main(["pins", "check", *args]) == 0
    doc = json.loads(report.read_text())
    doc["golden"]["classifier-smoke"]["tasks"][0]["score"] = 0.5  # summary still says ok
    report.write_text(json.dumps(doc))
    assert golden_main(["pins", "check", *args]) == 1
    assert "does not reproduce" in capsys.readouterr().out
    t = json.loads(roles.read_text())
    t["roles"]["main-reasoner"]["bindings"][0]["version"] = "2026.11.0"
    roles.write_text(json.dumps(t))
    assert golden_main(["pins", "check", *args]) == 1
    assert golden_main(["pins", "check", "--roles", str(roles), "--report", "/nonexistent"]) == 1
