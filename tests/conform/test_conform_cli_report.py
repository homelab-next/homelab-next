# SPDX-License-Identifier: Apache-2.0
"""``hnx conform``: list, run, mutants, report and the exporter's JSON."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from homelabnext import cli as hnx
from homelabnext.conform import CAPABILITIES, build_report
from homelabnext.conform.cli import main
from homelabnext.conform.registry import load_module

ROOT = Path(__file__).resolve().parents[2]


def test_list_shows_the_fifteen(capsys):
    assert main(["list"]) == 0
    out = capsys.readouterr().out.splitlines()
    assert [ln.split()[0] for ln in out] == list(CAPABILITIES)
    assert len(out) == 15


def test_dash_dash_list_spelling_from_the_docs(capsys):
    assert main(["--list"]) == 0
    assert len(capsys.readouterr().out.splitlines()) == 15


def test_list_json_and_all(capsys):
    main(["list", "--json", "--all"])
    rows = json.loads(capsys.readouterr().out)["capabilities"]
    assert {r["capability"] for r in rows} >= set(CAPABILITIES) | {"backup", "dns", "edge"}
    assert {r["tier"] for r in rows} == {"core", "extended"}
    assert all(r["checks"]["must"] >= 6 for r in rows)


def test_run_passes_on_the_fake_and_prints_json(capsys):
    assert main(["run", "notify", "--json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    (run,) = doc["runs"]
    assert run["ok"] and run["passing"] and run["counts"]["failed_must"] == 0
    assert all(r["status"] == "pass" for r in run["results"])


def test_run_all_and_out_file(tmp_path, capsys):
    out = tmp_path / "res.json"
    assert main(["run", "all", "--out", str(out)]) == 0
    doc = json.loads(out.read_text())
    assert [r["capability"] for r in doc["runs"]] == list(CAPABILITIES)
    assert "PASS" in capsys.readouterr().out


def test_run_single_check_and_verbose(capsys):
    assert main(["run", "secrets", "--check", "put-get-roundtrip", "-v"]) == 0
    out = capsys.readouterr().out
    assert "[ok] put-get-roundtrip" in out and "versions-increase" not in out


def test_unknown_capability_exits_2(capsys):
    assert main(["run", "teleporter"]) == 2
    assert "unknown capability" in capsys.readouterr().err


def test_missing_suites_exits_2(tmp_path, capsys):
    # a root with no conformance/ tree cannot produce a report
    assert main(["--root", str(tmp_path), "report"]) == 2
    assert "source checkout" in capsys.readouterr().err


def test_strict_turns_a_should_failure_into_a_failure(monkeypatch, capsys):
    mod = load_module("object-store")
    spec = next(s for s in mod.SUITE.specs if s.id == "user-metadata-preserved")
    monkeypatch.setitem(
        mod.SUITE._specs,
        spec.id,
        type(spec)(
            spec.id,
            spec.summary,
            "should",
            spec.requires,
            lambda s: (_ for _ in ()).throw(AssertionError("dropped")),
        ),
    )
    assert main(["run", "object-store"]) == 0
    assert "(should)" in capsys.readouterr().out
    assert main(["run", "object-store", "--strict"]) == 1


def test_could_not_measure_exits_100(tmp_path, capsys):
    t = tmp_path / "t.yml"
    t.write_text(
        "capabilities:\n  events:\n    adapter: conformance.fakes.object_store:FakeObjectStore\n"
        "    config: {nope: 1}\n"
    )
    assert main(["run", "events", "--target", str(t)]) == 100
    assert "could not build subject" in capsys.readouterr().out


def test_mutants_command(capsys):
    assert main(["mutants"]) == 0
    out = capsys.readouterr().out
    assert out.count("caught") >= 15 and "MISSED" not in out
    assert main(["mutants", "events", "--json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["mutants"][0]["detected"] is True


def test_report_all_green_on_the_fakes(capsys):
    assert main(["report", "--json"]) == 0
    rep = json.loads(capsys.readouterr().out)
    assert rep["schema"] == "homelabnext.conform.report/1"
    assert rep["ok"] is True and rep["capabilities_without_passing_test"] == []
    assert set(rep["capabilities"]) == set(CAPABILITIES)
    e = rep["capabilities"]["secrets"]
    assert e["passing"] and e["executed"] >= 6 and e["mutants"][0]["detected"] is True


def test_report_names_capabilities_without_a_passing_test(monkeypatch, tmp_path):
    # 1. a declared capability with no suite at all
    root = tmp_path / "tree"
    shutil_tree(root)
    (root / "capabilities.yml").write_text("capabilities: [secrets, teleporter]\n")
    rep = build_report(root)
    assert rep["capabilities_without_passing_test"] == ["teleporter"]
    assert rep["capabilities"]["teleporter"]["suite"] is False
    assert rep["capabilities"]["secrets"]["passing"] is True


def shutil_tree(dst):
    import shutil

    shutil.copytree(
        ROOT / "conformance",
        dst / "conformance",
        ignore=shutil.ignore_patterns("__pycache__", "test_*.py"),
    )


def test_report_flags_a_vacuous_suite(monkeypatch):
    """A suite whose broken fake is not caught does not count as a passing test."""
    from homelabnext.conform.core import Mutant

    mod = load_module("events")
    monkeypatch.setitem(mod.MUTANTS, "harmless", Mutant(mod.FakeEventBus, "ack-settles-once", "n"))
    rep = build_report(capabilities=["events", "secrets"])
    assert rep["capabilities_without_passing_test"] == ["events"]
    assert "harmless" in rep["capabilities"]["events"]["reason"]


def test_report_flags_a_failing_must_check_on_a_real_target(tmp_path):
    t = tmp_path / "t.yml"
    t.write_text(
        "capabilities:\n  secrets:\n    adapter: conformance.fakes.secret_store:LeakyErrorSecretStore\n"
    )
    rep = build_report(target=str(t), capabilities=["secrets"])
    assert rep["capabilities_without_passing_test"] == ["secrets"]
    assert rep["capabilities"]["secrets"]["failed_must"] == ["errors-never-contain-values"]
    assert "mutants" not in rep["capabilities"]["secrets"]  # mutation proof is for the fake target


def test_report_exit_codes(tmp_path, capsys):
    t = tmp_path / "t.yml"
    t.write_text(
        "capabilities:\n  secrets:\n    adapter: conformance.fakes.secret_store:LeakyErrorSecretStore\n"
    )
    assert main(["report", "--target", str(t), "--json"]) in (1, 100)
    capsys.readouterr()


def test_human_report_lists_missing(capsys):
    main(["report", "--no-mutants"])
    out = capsys.readouterr().out
    assert out.strip().endswith("capabilities without a passing test: none")


def test_hnx_dispatcher_and_module_entry_point():
    assert "conform" in hnx.COMMANDS
    assert hnx.main(["conform", "list"]) == 0
    p = subprocess.run(
        [sys.executable, "-m", "homelabnext.cli", "conform", "run", "idp", "--target", "broken"],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    assert p.returncode == 1 and "payload-splice-rejected" in p.stdout


@pytest.mark.parametrize("flag", ["-h", "--help"])
def test_help(flag, capsys):
    with pytest.raises(SystemExit) as e:
        main([flag])
    assert e.value.code == 0


def test_run_rejects_unknown_check_ids(capsys):
    assert main(["run", "idp", "--check", "no-such-id"]) == 2
    assert "no-such-id" in capsys.readouterr().err
    assert main(["run", "all", "--check", "put-get-roundtrip"]) == 0  # secrets and object-store


def test_run_fails_when_too_few_checks_execute(tmp_path, capsys):
    """Skips are not passes: a target on which nearly everything skips fails `run`."""
    mod = tmp_path / "bare_store.py"
    mod.write_text(
        "from conformance.fakes.object_store import FakeObjectStore\n"
        "class Bare(FakeObjectStore):\n"
        "    features = frozenset()\n"
    )
    t = tmp_path / "t.yml"
    t.write_text("capabilities:\n  object-store: {adapter: 'bare_store:Bare'}\n")
    sys.path.insert(0, str(tmp_path))
    try:
        assert main(["run", "object-store", "--target", str(t)]) == 0  # one skip of twelve
        assert (
            main(["run", "object-store", "--target", str(t), "--check", "user-metadata-preserved"])
            == 1
        )
        assert "0 check(s) executed" in capsys.readouterr().out
    finally:
        sys.path.remove(str(tmp_path))
        sys.modules.pop("bare_store", None)


def test_runs_and_reports_record_their_provenance(tmp_path, capsys):
    assert main(["run", "secrets", "--json"]) == 0
    prov = json.loads(capsys.readouterr().out)["runs"][0]["provenance"]
    assert len(prov["suite_sha256"]) == 64 and prov["adapter"] == "builtin:fake"
    t = tmp_path / "t.yml"
    t.write_text(
        "capabilities:\n  secrets: {adapter: 'conformance.fakes.secret_store:FakeSecretStore'}\n"
    )
    assert main(["run", "secrets", "--json", "--target", str(t)]) == 0
    prov = json.loads(capsys.readouterr().out)["runs"][0]["provenance"]
    assert prov["adapter_file"].endswith("conformance/fakes/secret_store.py")
    out = tmp_path / "rep.json"
    assert main(["report", "--out", str(out), "--no-mutants"]) == 0
    rep = json.loads(out.read_text())
    assert "git_sha" in rep and rep["capabilities"]["idp"]["provenance"]["suite_sha256"]
