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
    p, *canary = pins.check_report(stored, t, SUITES)
    assert "stale" in p and "pin mdl:fast-classifier" in p and "main-reasoner" not in p
    # and the canary entry names the binding whose pin it no longer matches
    assert all(c.startswith("mdl:fast-classifier -> svc:inference") for c in canary)
    assert any("a different pin" in c for c in canary)
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


# ---- the canary's output budget is the role's own (params.max_tokens), not a fixed suite value
def _budget_recorder():
    from homelabnext.golden import canary

    seen: dict[str, set] = {}

    def factory(role, binding):
        def completer(messages, params):
            seen.setdefault(role, set()).add(params["max_tokens"])
            return canary.benign_model(messages, params)

        return completer, "fake"

    return seen, factory


def _run_with(doc, factory):
    t = RoleTable.from_dict(doc)
    return t, pins.run_eval(
        t, SUITES, pins.fake_factory, model_name="fake-golden", canary_factory=factory
    )


def test_the_canary_runs_a_chat_role_at_its_declared_output_budget():
    from homelabnext.golden import canary

    doc = table_doc()
    doc["roles"]["main-reasoner"]["params"] = {"max_tokens": 8192}
    seen, factory = _budget_recorder()
    _, rep = _run_with(doc, factory)
    assert seen["main-reasoner"] == {8192}
    # a role that declares a budget gets it; the suite's default is only for one that does not
    assert seen["fast-classifier"] == {256}
    entry = rep["canary"]["main-reasoner"]["bindings"][0]
    assert entry["max_tokens"] == 8192
    del doc["roles"]["main-reasoner"]["params"]
    seen, factory = _budget_recorder()
    _, rep = _run_with(doc, factory)
    default = canary.load_suite(canary.DEFAULT_SUITE).max_tokens
    assert seen["main-reasoner"] == {default}
    assert rep["canary"]["main-reasoner"]["bindings"][0]["max_tokens"] == default


def test_a_canary_entry_run_at_another_budget_is_stale():
    doc = table_doc()
    doc["roles"]["main-reasoner"]["params"] = {"max_tokens": 8192}
    t, rep = fresh(doc)
    assert pins.check_report(rep, t, SUITES) == []
    entry = rep["canary"]["main-reasoner"]["bindings"][0]
    entry["max_tokens"] = 512
    assert any(
        "mdl:main-reasoner" in p and "output budget" in p for p in pins.check_report(rep, t, SUITES)
    )
    # an entry from before the budget was recorded counts as the suite's default budget
    del entry["max_tokens"]
    assert any("output budget" in p for p in pins.check_report(rep, t, SUITES))


@pytest.mark.parametrize("budget", [8, 131072])
def test_a_budget_the_canary_cannot_run_is_refused(budget):
    doc = table_doc()
    doc["roles"]["main-reasoner"]["params"] = {"max_tokens": budget}
    doc["roles"]["main-reasoner"]["max_context_tokens"] = 131072
    with pytest.raises(ValueError, match="max_tokens"):
        fresh(doc)


# ---- a live run waits as long as the budget needs: the client timeout is a run option
def test_live_runs_take_a_client_timeout_and_refuse_a_nonpositive_one(capsys, monkeypatch):
    from homelabnext.golden import cli as gcli

    seen = {}

    def fake_live(registry, table, client_kwargs=None):
        seen.update(client_kwargs or {})
        raise ValueError("stop here")

    monkeypatch.setattr(gcli, "_live", fake_live)
    base = ["pins", "report", "--roles", str(ROLES), "--report", "/nonexistent/r.json"]
    with pytest.raises(ValueError, match="stop here"):
        golden_main([*base, "--registry", "services.yml", "--timeout", "900"])
    assert seen["timeout"] == 900.0
    seen.clear()
    with pytest.raises(ValueError, match="stop here"):
        golden_main([*base, "--registry", "services.yml"])
    assert seen["timeout"] == 30.0  # the client's own default when none is given
    for bad in ("0", "-5", "nan"):
        with pytest.raises(SystemExit):
            golden_main([*base, "--registry", "services.yml", "--timeout", bad])
    capsys.readouterr()
