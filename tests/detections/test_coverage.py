# SPDX-License-Identifier: Apache-2.0
"""D-04: the ATT&CK coverage report counts only rules whose fixtures pass (golden report)."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from homelabnext.detections.cli import main
from homelabnext.detections.coverage import check_golden, coverage_report
from homelabnext.detections.runner import run_all
from homelabnext.detections.sigma import load_rules

REPO = Path(__file__).resolve().parents[2]
DET = REPO / "detections"
GOLDEN = DET / "attack_coverage.json"
FX = "fixtures/web-shell-write"


@pytest.fixture
def det(tmp_path):
    root = tmp_path / "detections"
    shutil.copytree(DET, root)
    return root


def _report(root):
    return coverage_report(load_rules(root), run_all(root))


def _failing(rep):
    """The uncounted rules whose fixtures failed (an inert rule is uncounted by its status)."""
    return [u for u in rep["uncounted"] if not u["reason"].startswith("status ")]


def test_committed_golden_report_is_current(capsys):
    assert main(["coverage", "--check", str(GOLDEN)]) == 0
    rep = json.loads(GOLDEN.read_text())
    assert _failing(rep) == []
    inert = [u["rule"] for u in rep["uncounted"]]  # status unsupported: tested, never counted
    assert rep["summary"]["rules_counted"] == rep["summary"]["rules_total"] - len(inert) >= 6
    assert "T1505.003" in rep["techniques"]


def test_a_rule_whose_must_fire_misses_is_not_counted(det, capsys):
    benign = (det / FX / "must_not_fire" / "admin-edits-php.json").read_text()
    (det / FX / "must_fire" / "iis-drops-aspx.json").write_text(benign)
    rep = _report(det)
    assert "T1505.003" not in rep["techniques"]
    assert {
        "rule": "det:web-shell-write",
        "reason": "must_fire missed: iis-drops-aspx.json",
    } in rep["uncounted"]
    assert "T1505.003" not in rep["tactics"]["persistence"]
    # the committed golden report is now stale, and the check says which technique dropped
    rc = main(["--root", str(det), "coverage", "--check", str(GOLDEN)])
    out = capsys.readouterr().out
    assert rc == 1
    assert "technique T1505.003: in the golden report, no passing rule covers it now" in out


def test_a_rule_that_fires_on_benign_input_is_not_counted(det):
    hit = (det / FX / "must_fire" / "iis-drops-aspx.json").read_text()
    (det / FX / "must_not_fire" / "worker-writes-image.json").write_text(hit)
    rep = _report(det)
    assert "T1505.003" not in rep["techniques"]
    assert _failing(rep)[0]["reason"] == "must_not_fire fired: worker-writes-image.json"


def test_a_rule_without_fixtures_is_not_counted(det):
    shutil.rmtree(det / FX / "must_fire")
    rep = _report(det)
    assert _failing(rep) == [{"rule": "det:web-shell-write", "reason": "no must_fire fixture"}]
    shutil.rmtree(det / FX / "must_not_fire")
    rep = _report(det)
    assert _failing(rep)[0]["reason"] == "no must_fire fixture"


def test_evasion_misses_are_gaps_not_coverage_loss():
    rep = json.loads(GOLDEN.read_text())
    assert {"rule": "det:web-shell-write", "evasion": "double-extension.json"} in rep[
        "evasion_gaps"
    ]
    assert "det:web-shell-write" in rep["techniques"]["T1505.003"]["rules"]


def test_out_writes_the_report_and_check_handles_bad_input(det, tmp_path, capsys):
    out = tmp_path / "cov.json"
    assert main(["--root", str(det), "coverage", "--out", str(out)]) == 0
    assert json.loads(out.read_text()) == json.loads(GOLDEN.read_text())
    capsys.readouterr()
    assert main(["--root", str(det), "coverage"]) == 0
    assert json.loads(capsys.readouterr().out) == json.loads(GOLDEN.read_text())
    assert check_golden(_report(det), "not json")[0].startswith("golden report is not JSON")
    assert main(["--root", str(det), "coverage", "--check", str(tmp_path / "missing.json")]) == 1
    rep = _report(det)
    rep2 = dict(rep, uncounted=[{"rule": "det:x", "reason": "r"}])
    assert check_golden(rep2, json.dumps(rep))[0] == "golden report differs from the current one"
