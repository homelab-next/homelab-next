# SPDX-License-Identifier: Apache-2.0
"""Every capability ships a suite of 6-24 checks and a fake that passes all of them."""

import re
from pathlib import Path

import pytest

from homelabnext.conform import CAPABILITIES, EXTENDED, run_capability
from homelabnext.conform.registry import load_module, load_suite

ROOT = Path(__file__).resolve().parents[2]
ALL = [*CAPABILITIES, *EXTENDED]
#: docs/conformance.md: at least six checks, so a suite says something; at most 24, one per
#: clause of a Protocol docstring with room to grow, so a suite stays one readable file and a run
#: against a real service stays short (a contract with more clauses than that is two capabilities)
MIN_CHECKS, MAX_CHECKS = 6, 24


def test_the_documented_bound_is_the_one_tested():
    text = (ROOT / "docs" / "conformance.md").read_text(encoding="utf-8")
    # whitespace, not a space: a reflow that wraps "6 to\n24 checks" must not hide one
    bounds = re.findall(r"(\d+)\s+to\s+(\d+)\s+checks", text)
    assert bounds == [(str(MIN_CHECKS), str(MAX_CHECKS))] * 2, bounds


def test_capability_list_is_the_one_in_interfaces_md():
    text = (ROOT / "docs" / "interfaces.md").read_text(encoding="utf-8")
    para = re.search(r"^- Capability names.*?(?=^- )", text, re.S | re.M).group(0)
    names = tuple(re.findall(r"`([a-z-]+)`", para.split(":", 1)[1]))
    assert names == CAPABILITIES and len(names) == 18


def test_capabilities_yml_matches_the_core_list():
    import yaml

    doc = yaml.safe_load((ROOT / "capabilities.yml").read_text(encoding="utf-8"))
    assert doc["capabilities"] == list(CAPABILITIES)


@pytest.mark.parametrize("cap", ALL)
def test_suite_shape(cap):
    suite = load_suite(cap)
    assert suite.name == cap
    assert suite.tier == ("core" if cap in CAPABILITIES else "extended")
    n = len(suite.specs)
    assert MIN_CHECKS <= n <= MAX_CHECKS, f"{cap} has {n} checks"
    assert sum(s.severity == "must" for s in suite.specs) >= 6, "too few MUST checks"
    assert all(s.summary.strip() for s in suite.specs)
    assert suite.protocol and ":" in suite.protocol
    mod, _, attr = suite.protocol.partition(":")
    import importlib

    assert hasattr(importlib.import_module(mod), attr), f"protocol {suite.protocol} missing"


@pytest.mark.parametrize("cap", ALL)
def test_the_fake_passes_every_check_with_no_skips(cap):
    run = run_capability(cap, "fake")
    assert run.error is None
    bad = [(r.check, r.evidence) for r in run.results if r.status != "pass"]
    assert not bad, f"{cap}: {bad}"
    assert run.passing


@pytest.mark.parametrize("cap", ALL)
def test_the_fake_satisfies_its_protocol(cap):
    mod = load_module(cap)
    suite = mod.SUITE
    import importlib

    pmod, _, attr = suite.protocol.partition(":")
    proto = getattr(importlib.import_module(pmod), attr)
    subject = mod.make_fake()
    try:
        assert isinstance(subject, proto), f"{type(subject).__name__} is not a {attr}"
    finally:
        getattr(subject, "close", lambda: None)()


@pytest.mark.parametrize("cap", ALL)
def test_each_capability_has_a_test_folder_for_x04(cap):
    assert list((ROOT / "conformance" / cap).glob("test_*.py")), cap


def test_checks_are_deterministic_across_two_runs():
    for cap in ("secrets", "events", "idp", "cases"):
        a = [r.to_dict() for r in run_capability(cap, "fake").results]
        b = [r.to_dict() for r in run_capability(cap, "fake").results]
        assert a == b


@pytest.mark.parametrize("cap", ALL)
def test_mutants_name_checks_that_cannot_skip(cap):
    """A mutant caught only by a check that can skip proves nothing where that check skips."""
    mod = load_module(cap)
    specs = {s.id: s for s in mod.SUITE.specs}
    for name, m in mod.MUTANTS.items():
        assert not specs[m.fails].can_skip_with(m.features), f"{cap}/{name}: {m.fails} can skip"
