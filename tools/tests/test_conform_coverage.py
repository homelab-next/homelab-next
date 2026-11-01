# SPDX-License-Identifier: Apache-2.0
"""The conformance coverage gate: passes this tree, fails on a missing or failing capability."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import conform_coverage as gate

from homelabnext.conform import CAPABILITIES, EXPERIMENTAL


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
    out = capsys.readouterr().out
    assert f"all {len(CAPABILITIES) - len(EXPERIMENTAL)} blocking capabilities" in out
    assert f"({len(EXPERIMENTAL)} frozen or experimental, in make experimental)" in out


def test_a_frozen_capability_is_not_required():
    rep = _ok_report()
    for c in EXPERIMENTAL:
        del rep["capabilities"][c]
    assert gate.missing_passes(rep) == []
    assert set(gate.BLOCKING) == set(CAPABILITIES) - set(EXPERIMENTAL)
    assert {"codemode-executor", "codemode-runner"} <= set(EXPERIMENTAL)
    # the projects suite also checks the OpenProject adapter, so it stays blocking
    assert "projects" in gate.BLOCKING


def _fake_hnx(monkeypatch, rc, report=None, stdout=""):
    """``gate._hnx`` that answers ``list`` and writes ``report`` to the ``--out`` path."""
    import subprocess

    def run(root, *args):
        if args[0] == "report" and report is not None:
            out = Path(args[args.index("--out") + 1])
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(report))
        code = 0 if args[0] == "list" else rc
        return subprocess.CompletedProcess(args, code, stdout if args[0] == "report" else "", "")

    monkeypatch.setattr(gate, "_hnx", run)


def _verdict_report(failing=()):
    from homelabnext.conform.report import SCHEMA

    rep = _ok_report()
    rep["schema"] = SCHEMA
    for c, e in rep["capabilities"].items():
        e["verdict"] = "fail" if c in failing else "pass"
        e["passing"] = c not in failing
    rep["capabilities_without_passing_test"] = list(failing)
    return rep


def test_the_report_comes_from_the_out_file_never_stdout(monkeypatch, tmp_path):
    # a clean-looking report printed by an adapter, and no report file: could not be produced
    _fake_hnx(monkeypatch, 0, None, stdout=json.dumps(_verdict_report()))
    assert gate.main(["--root", str(tmp_path)]) == 2


def test_verdicts_that_disagree_with_the_exit_code_are_not_judged(monkeypatch, tmp_path):
    _fake_hnx(monkeypatch, 0, _verdict_report(failing=["idp"]))
    assert gate.main(["--root", str(tmp_path)]) == 2
    _fake_hnx(monkeypatch, 1, _verdict_report(failing=["idp"]))
    assert gate.main(["--root", str(tmp_path)]) == 1
    _fake_hnx(monkeypatch, 0, _verdict_report())
    assert gate.main(["--root", str(tmp_path)]) == 0
    assert (tmp_path / "build" / "conform-report.json").is_file()


def test_a_report_left_over_from_an_earlier_run_is_not_judged(monkeypatch, tmp_path):
    stale = tmp_path / "build" / "conform-report.json"
    stale.parent.mkdir(parents=True)
    stale.write_text(json.dumps(_verdict_report()))
    _fake_hnx(monkeypatch, 100, None)
    assert gate.main(["--root", str(tmp_path)]) == 2
