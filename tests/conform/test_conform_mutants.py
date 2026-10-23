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
    m = load_module(cap).MUTANTS[name]
    code = main(["run", cap, "--target", f"broken:{name}"])
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
    # a "broken" fake that is actually fine: the suite cannot tell, so it must be flagged
    monkeypatch.setitem(
        mod.MUTANTS, "harmless", Mutant(mod.FakeSecretStore, "errors-never-contain-values", "no-op")
    )
    runs = {m.name: m for m in mutation_runs("secrets")}
    assert runs["harmless"].detected is False and runs["harmless"].failed == []
    assert runs["error-leaks-value"].detected is True


def test_mutation_runs_report_what_failed():
    (m,) = [r for r in mutation_runs("object-store") if r.name == "weak-etag"]
    assert m.detected and m.failed == ["etag-tracks-content"]


def test_a_mutant_caught_only_by_a_skippable_check_does_not_count(monkeypatch):
    from homelabnext.conform.core import Mutant

    mod = load_module("object-store")
    monkeypatch.setitem(
        mod.MUTANTS,
        "metadata-only",
        Mutant(mod.FakeObjectStore, "user-metadata-preserved", "names a SHOULD with requires"),
    )
    (m,) = [r for r in mutation_runs("object-store") if r.name == "metadata-only"]
    assert m.detected is False and m.reason


def test_the_fakes_satisfy_the_new_security_checks_and_their_mutants_are_caught():
    """One mutant per conformance gap found in review; each must be caught by its named check."""
    expected = {
        "broker": {
            "allowlist-per-caller-only",
            "redacts-by-key-name",
            "redacts-ok-calls-only",
            "handler-error-passed-through",
        },
        "records": {
            "completes-inbox-notes",
            "completes-denied-notes",
            "partial-completion",
            "decide-follows-traversal",
            "read-follows-traversal",
        },
        "idp": {"alg-none-accepted", "empty-signature-accepted", "exp-not-enforced"},
        "lake-query": {"interpolated-params"},
        "secrets": {
            "error-cause-leaks-value",
            "lease-never-expires",
            "unknown-lease-valid",
            "negative-ttl-accepted",
        },
        "events": {"loses-unsettled-on-restart", "restart-at-tail", "double-settle"},
        "object-store": {"keys-resolved-as-paths"},
    }
    for cap, names in expected.items():
        runs = {m.name: m for m in mutation_runs(cap)}
        for name in names:
            assert runs[name].detected, (cap, name, runs[name].reason, runs[name].failed)


def test_a_mutant_declaring_the_features_its_check_needs_counts(monkeypatch):
    """``Mutant.features``: a mutant whose factory supports a check's ``requires`` is run with
    them declared and may name that check; the same mutant without them proves nothing."""
    from homelabnext.conform.core import Mutant

    mod = load_module("backup")

    class NeverNoticesCorruption(mod.FakeBackupStore):
        def verify(self, snapshot_id):
            super().verify(snapshot_id)
            return True

    declared = Mutant(
        NeverNoticesCorruption,
        "verify-detects-corruption",
        "verify ignores the bytes",
        features=frozenset({"fault-injection"}),
    )
    bare = Mutant(NeverNoticesCorruption, "verify-detects-corruption", "verify ignores the bytes")
    monkeypatch.setitem(mod.MUTANTS, "declared", declared)
    monkeypatch.setitem(mod.MUTANTS, "bare", bare)
    runs = {m.name: m for m in mutation_runs("backup")}
    assert runs["declared"].detected, runs["declared"].reason
    assert runs["bare"].detected is False and "can skip" in runs["bare"].reason
    # the CLI's broken:<mutant> runs with the mutant's features too
    run = run_capability("backup", "broken:declared")
    assert "verify-detects-corruption" in [r.check for r in run.failed_must]
