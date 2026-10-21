# SPDX-License-Identifier: Apache-2.0
"""The conformance coverage gate: passes this tree, fails on a missing or failing capability."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import conform_coverage as gate

from homelabnext.conform import CAPABILITIES


def _ok_report():
    return {
        "capabilities": {
            c: {"suite": True, "passing": True, "failed_must": []} for c in CAPABILITIES
        },
        "capabilities_without_passing_test": [],
    }


def test_complete_report_has_no_problems():
    assert gate.missing_passes(_ok_report()) == []


def test_missing_capability_is_reported():
    rep = _ok_report()
    del rep["capabilities"]["secrets"]
    assert gate.missing_passes(rep) == ["secrets: not in the report"]


def test_failing_and_suiteless_capabilities_are_reported():
    rep = _ok_report()
    rep["capabilities"]["idp"]["passing"] = False
    rep["capabilities"]["idp"]["failed_must"] = ["x"]
    rep["capabilities"]["broker"]["suite"] = False
    rep["capabilities_without_passing_test"] = ["idp"]
    probs = gate.missing_passes(rep)
    assert any(p.startswith("idp: suite does not pass") for p in probs)
    assert "broker: no suite" in probs and "idp: listed without a passing test" in probs


def test_this_tree_passes(capsys):
    assert gate.main([]) == 0
    assert "all 16 capabilities" in capsys.readouterr().out
