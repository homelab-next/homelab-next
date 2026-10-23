# SPDX-License-Identifier: Apache-2.0
"""A suite that cannot fail proves nothing: every deliberately broken fake must be caught,
and caught by the check that names the defect."""

import pytest

from homelabnext.conform import CAPABILITIES, EXTENDED, run_capability
from homelabnext.conform.cli import main
from homelabnext.conform.registry import load_module
from homelabnext.conform.runner import mutation_runs

ALL = [*CAPABILITIES, *EXTENDED]
CASES = [(c, name) for c in ALL for name in load_module(c).MUTANTS]


def test_every_capability_has_at_least_one_mutant():
    for cap in ALL:
        assert load_module(cap).MUTANTS, f"{cap} has no deliberately broken fake"


@pytest.mark.parametrize(("cap", "name"), CASES)
def test_mutant_is_caught_by_the_named_check(cap, name):
    m = load_module(cap).MUTANTS[name]
    run = run_capability(cap, f"broken:{name}")
    failed = [r.check for r in run.failed_must]
    assert m.fails in failed, f"{cap}/{name}: expected {m.fails!r} to fail, failed {failed}"
    assert not run.ok
    # the check it names exists and is a MUST (a SHOULD miss would not fail the capability)
    spec = next(s for s in load_module(cap).SUITE.specs if s.id == m.fails)
    assert spec.severity == "must"


@pytest.mark.parametrize(("cap", "name"), CASES)
def test_mutant_run_names_the_exact_check_on_the_command_line(cap, name, capsys):
    # the whole-suite run is test_mutant_is_caught_by_the_named_check: here only the CLI's
    # verdict and wording are under test, so only the named check runs
    m = load_module(cap).MUTANTS[name]
    code = main(["run", cap, "--target", f"broken:{name}", "--check", m.fails])
    out = capsys.readouterr().out
    assert code == 1
    assert f"[FAIL] {m.fails}" in out, out


def test_broken_without_a_name_runs_the_first_mutant(capsys):
    assert main(["run", "secrets", "--target", "broken"]) == 1
    assert "errors-never-contain-values" in capsys.readouterr().out


def test_unknown_mutant_is_a_misconfiguration(capsys):
    assert main(["run", "secrets", "--target", "broken:nope"]) == 2
    assert "no mutant" in capsys.readouterr().err


def test_a_mutant_that_slips_through_is_reported(monkeypatch):
    from homelabnext.conform.core import Mutant

    mod = load_module("secrets")
    # a "broken" fake that is actually fine: the suite cannot tell, so it must be flagged.  Only
    # the two mutants under test run: every registered one is proved by the tests above.
    leaky = mod.MUTANTS["error-leaks-value"]
    harmless = Mutant(mod.FakeSecretStore, "errors-never-contain-values", "no-op")
    monkeypatch.setattr(mod, "MUTANTS", {"harmless": harmless, "error-leaks-value": leaky})
    runs = {m.name: m for m in mutation_runs("secrets")}
    assert runs["harmless"].detected is False and runs["harmless"].failed == []
    assert runs["error-leaks-value"].detected is True


def test_mutation_runs_report_what_failed(monkeypatch):
    mod = load_module("object-store")
    monkeypatch.setattr(mod, "MUTANTS", {"weak-etag": mod.MUTANTS["weak-etag"]})
    (m,) = mutation_runs("object-store")
    assert m.name == "weak-etag" and m.detected and m.failed == ["etag-tracks-content"]


def test_a_mutant_caught_only_by_a_skippable_check_does_not_count(monkeypatch):
    from homelabnext.conform.core import Mutant

    mod = load_module("object-store")
    only = Mutant(mod.FakeObjectStore, "user-metadata-preserved", "names a SHOULD with requires")
    monkeypatch.setattr(mod, "MUTANTS", {"metadata-only": only})
    (m,) = mutation_runs("object-store")
    assert m.detected is False and m.reason
