# SPDX-License-Identifier: Apache-2.0
"""Verdicts and exit codes: a real failure is never filed as an outage, an outage is never a
pass, and the inputs that decide coverage (``capabilities.yml``, ``builtin:``) are validated."""

import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from homelabnext.conform import cli, report, runner
from homelabnext.conform.adapters._env import AdapterConfigError
from homelabnext.conform.core import CheckResult
from homelabnext.conform.registry import ConformError, declared_capabilities
from homelabnext.conform.report import build_report, exit_code
from homelabnext.conform.runner import CapabilityRun, run_capability
from homelabnext.conform.target import Binding, Target, binding_from_mapping, make_factory
from homelabnext.invariants import Context
from homelabnext.invariants.api import ERROR, FAIL
from homelabnext.invariants.plugins import pillar_x

ROOT = Path(__file__).resolve().parents[2]


def _passes(n):
    return [CheckResult(f"c{i}", True, "", "must", "pass") for i in range(n)]


def _canned_runs(monkeypatch, runs):
    def fake_run(cap, target, root=None, *, only=None):
        return runs[cap]

    monkeypatch.setattr(report, "run_capability", fake_run)


# ---- the exit code is a function of the verdicts --------------------------------------------


def test_one_outage_does_not_hide_a_capability_with_too_few_checks(monkeypatch, capsys):
    _canned_runs(
        monkeypatch,
        {
            "secrets": CapabilityRun("secrets", "t", error="down", error_kind="unmeasured"),
            "notify": CapabilityRun("notify", "t", results=_passes(3)),
        },
    )
    rep = build_report(target="t", mutants=False, capabilities=["secrets", "notify", "teleporter"])
    v = {c: e["verdict"] for c, e in rep["capabilities"].items()}
    assert v == {"secrets": "unmeasured", "notify": "fail", "teleporter": "fail"}
    assert rep["verdicts"] == {"pass": 0, "fail": 2, "unmeasured": 1, "misconfigured": 0}
    assert exit_code(rep) == 1
    monkeypatch.setattr(cli, "build_report", lambda *a, **k: rep)
    assert cli.main(["report", "--json"]) == 1, "a real failure was filed as could-not-measure"
    capsys.readouterr()


def test_a_missed_mutant_is_a_failure_even_beside_an_outage(monkeypatch):
    from homelabnext.conform.core import Mutant
    from homelabnext.conform.registry import load_module

    _canned_runs(
        monkeypatch,
        {
            "events": CapabilityRun("events", "fake", results=_passes(8)),
            "secrets": CapabilityRun("secrets", "fake", error="down", error_kind="unmeasured"),
        },
    )
    mod = load_module("events")
    monkeypatch.setitem(mod.MUTANTS, "harmless", Mutant(mod.FakeEventBus, "ack-settles-once", "n"))
    rep = build_report(target="fake", capabilities=["events", "secrets"])
    assert rep["capabilities"]["events"]["verdict"] == "fail"
    assert exit_code(rep) == 1


@pytest.mark.parametrize(
    ("kinds", "code"),
    [
        (["unmeasured"], 100),
        (["misconfigured"], 2),
        (["misconfigured", "unmeasured"], 2),
        ([], 0),
    ],
)
def test_outages_alone_decide_the_code_only_when_nothing_failed(monkeypatch, kinds, code):
    caps = ["secrets", "notify", "idp"][: len(kinds) + 1]
    runs = {
        c: CapabilityRun(c, "t", error="x", error_kind=k)
        for c, k in zip(caps[:-1], kinds, strict=True)
    }
    runs[caps[-1]] = CapabilityRun(caps[-1], "t", results=_passes(6))
    _canned_runs(monkeypatch, runs)
    assert exit_code(build_report(target="t", mutants=False, capabilities=caps)) == code


# ---- a factory's error is the run's, not the command's ---------------------------------------


def _bound(factory_exc):
    tgt = Target("t", {c: Binding(c, adapter="x:y") for c in ("secrets", "notify")})

    def make(binding, suite=None, root=None):
        if binding.capability == "secrets":

            def boom():
                raise factory_exc

            return boom
        return make_factory(Binding(binding.capability, builtin="fake"), suite, root)

    return tgt, make


def test_an_adapter_missing_a_setting_is_misconfigured_for_its_capability_alone(monkeypatch):
    tgt, make = _bound(AdapterConfigError("secrets: HNX_ENDPOINT_SECRETS is not set"))
    monkeypatch.setattr(runner, "make_factory", make)
    run = run_capability("secrets", tgt)
    assert run.verdict == "misconfigured" and "HNX_ENDPOINT_SECRETS" in run.error
    assert run_capability("notify", tgt).verdict == "pass", "the next capability still runs"


def test_a_value_error_from_a_probe_is_could_not_measure_not_misconfiguration(monkeypatch):
    tgt, make = _bound(json.JSONDecodeError("Expecting value", "", 0))
    monkeypatch.setattr(runner, "make_factory", make)
    run = run_capability("secrets", tgt)  # raised ConformError (exit 2) before the fix
    assert run.verdict == "unmeasured" and "JSONDecodeError" in run.error


def test_a_bad_waiver_is_still_misconfiguration_before_any_subject_is_built(monkeypatch):
    built = []
    tgt = Target("t", {"secrets": Binding("secrets", adapter="x:y", waive={"no-such": "r"})})
    monkeypatch.setattr(runner, "make_factory", lambda *a, **k: built.append(1))
    with pytest.raises(ConformError, match="no check 'no-such'"):
        run_capability("secrets", tgt)
    assert built == []


def test_run_all_reports_a_misconfigured_capability_and_runs_the_rest(monkeypatch, capsys):
    tgt, make = _bound(AdapterConfigError("secrets: HNX_ENDPOINT_SECRETS is not set"))
    monkeypatch.setattr(runner, "make_factory", make)
    monkeypatch.setattr(runner, "load_target", lambda spec, root=None: tgt)
    monkeypatch.setattr(cli, "CAPABILITIES", ("secrets", "notify"))
    assert cli.main(["run", "all", "--target", "t"]) == 2
    out = capsys.readouterr().out
    assert "MISCONFIGURED  secrets" in out and "PASS  notify" in out


def test_report_records_a_misconfigured_binding_as_a_suite_that_exists(tmp_path):
    target = tmp_path / "t.yml"
    target.write_text("capabilities:\n  notify:\n    builtin: fake\n")
    rep = build_report(ROOT, str(target), mutants=False, capabilities=["notify", "secrets"])
    e = rep["capabilities"]["secrets"]  # the target file has no binding for it
    assert e["suite"] is True and e["verdict"] == "misconfigured", e
    assert exit_code(rep) == 2


# ---- --out ------------------------------------------------------------------------------------


def test_out_creates_its_directory(tmp_path, capsys):
    out = tmp_path / "build" / "nested" / "res.json"
    assert cli.main(["run", "notify", "--out", str(out)]) == 0
    assert json.loads(out.read_text())["runs"][0]["verdict"] == "pass"
    capsys.readouterr()


def test_an_unwritable_out_is_misconfiguration_not_a_failed_check(tmp_path, capsys):
    blocker = tmp_path / "file"
    blocker.write_text("")
    assert cli.main(["run", "notify", "--out", str(blocker / "res.json")]) == 2
    assert "cannot write --out" in capsys.readouterr().err


# ---- builtin: ---------------------------------------------------------------------------------


@pytest.mark.parametrize("value", ["fakes", "incumbent", "broken:", "brokenx"])
def test_an_unknown_builtin_is_refused_not_run_as_the_first_mutant(value):
    with pytest.raises(ConformError, match="builtin must be"):
        binding_from_mapping("secrets", {"builtin": value})
    with pytest.raises(ConformError, match="builtin must be"):
        make_factory(Binding("secrets", builtin=value), root=ROOT)


@pytest.mark.parametrize("value", ["fake", "broken", "broken:leaky-error"])
def test_the_known_builtins_still_bind(value):
    assert binding_from_mapping("secrets", {"builtin": value}).builtin == value


# ---- capabilities.yml -------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "capabilites:\n  - secrets\n",  # the key misspelled
        "capabilities: []\n",
        "capabilities:\n",
        "",
        "capabilities: secrets\n",
        "capabilities: [secrets, 3]\n",
        "capabilities: [secrets, secrets]\n",
        "capabilities: [secrets]\ncapabilities: [notify]\n",
    ],
)
def test_a_capabilities_file_that_declares_nothing_usable_is_refused(tmp_path, text, capsys):
    (tmp_path / "capabilities.yml").write_text(text)
    with pytest.raises(ConformError, match=r"capabilities\.yml"):
        declared_capabilities(tmp_path)
    # X-04 reports an error, never a pass with 0 capabilities
    assert pillar_x.x04(Context(tmp_path)).status == ERROR
    # the exporter exits 2 (misconfiguration), which X-10 reads as could-not-measure
    shutil.copytree(
        ROOT / "conformance" / "suites",
        tmp_path / "conformance" / "suites",
        ignore=shutil.ignore_patterns("__pycache__"),
    )
    assert cli.main(["--root", str(tmp_path), "report", "--json"]) == 2
    capsys.readouterr()


def test_a_tree_without_the_file_falls_back(tmp_path):
    assert declared_capabilities(tmp_path) is None
    assert report.declared_capabilities(tmp_path)[0] == "lake-query"


def test_x04_ignores_the_harness_directories_without_a_file(tmp_path):
    for d in ("suites", "protocols", "fakes", "targets", "fixtures"):
        (tmp_path / "conformance" / d).mkdir(parents=True)
    (tmp_path / "conformance" / "notify").mkdir()
    (tmp_path / "conformance" / "notify" / "test_notify.py").write_text("")
    assert pillar_x._capabilities(tmp_path) == ["notify"]


def test_x10_refuses_a_report_that_names_no_capability(tmp_path):
    from homelabnext.conform.plugins import x10_conformance as x10

    (tmp_path / "conformance" / "suites").mkdir(parents=True)
    empty = {"schema": report.SCHEMA, "capabilities_without_passing_test": [], "capabilities": {}}

    def run(argv, timeout=120):
        Path(argv[argv.index("--out") + 1]).write_text(json.dumps(empty))
        return 0, ""

    r = x10.x10(Context(tmp_path, run))
    assert r.status == ERROR and "names no capability" in r.evidence
    assert r.status != FAIL


def test_an_explicitly_empty_capability_list_is_refused():
    with pytest.raises(ConformError, match="no capabilities"):
        build_report(capabilities=[])


# ---- provenance -------------------------------------------------------------------------------


def _tree(tmp_path):
    for rel in ("suites/s.py", "suites/_util.py", "protocols/p.py", "fakes/f.py"):
        f = tmp_path / "conformance" / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(f"# {rel}\n")
    return tmp_path


@pytest.mark.parametrize("rel", ["suites/_util.py", "protocols/p.py", "fakes/f.py"])
def test_the_tree_digest_covers_the_shared_check_code(tmp_path, rel):
    root = _tree(tmp_path)
    before = runner.tree_digest(root)
    (root / "conformance" / rel).write_text("# changed\n")
    assert runner.tree_digest(root) != before


def test_the_tree_digest_notices_a_renamed_file(tmp_path):
    root = _tree(tmp_path)
    before = runner.tree_digest(root)
    (root / "conformance/suites/_util.py").rename(root / "conformance/suites/_other.py")
    assert runner.tree_digest(root) != before
    assert len(before) == len(hashlib.sha256().hexdigest())


@pytest.mark.skipif(shutil.which("git") is None, reason="needs git")
def test_dirty_says_whether_the_checkout_matches_its_sha(tmp_path):
    git = ["git", "-C", str(tmp_path), "-c", "user.name=t", "-c", "user.email=t@example.invalid"]
    subprocess.run([*git, "init", "-q"], check=True)
    (tmp_path / "a.txt").write_text("1\n")
    subprocess.run([*git, "add", "a.txt"], check=True)
    subprocess.run([*git, "commit", "-qm", "a"], check=True)
    assert runner.git_dirty(tmp_path) is False
    (tmp_path / "a.txt").write_text("2\n")
    assert runner.git_dirty(tmp_path) is True


def test_a_run_records_the_tree_digest_and_dirty_flag():
    meta = run_capability("notify", "fake").meta
    assert meta["tree_sha256"] == runner.tree_digest(ROOT)
    assert "dirty" in meta and meta["adapter"] == "builtin:fake"


def test_an_adapter_binding_records_its_file_hash():
    b = Binding("notify", adapter="homelabnext.conform.adapters._env:resolve")
    meta = runner.provenance("notify", b, ROOT)
    src = ROOT / "homelabnext/conform/adapters/_env.py"
    assert meta["adapter_sha256"] == hashlib.sha256(src.read_bytes()).hexdigest()


def test_cli_entry_point_still_imports():
    p = subprocess.run(
        [sys.executable, "-m", "homelabnext.cli", "conform", "list"],
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=False,
    )
    assert p.returncode == 0 and "lake-query" in p.stdout


def test_x10_names_the_misconfigured_capabilities(tmp_path):
    from homelabnext.conform.plugins import x10_conformance as x10

    (tmp_path / "conformance" / "suites").mkdir(parents=True)
    doc = {
        "schema": report.SCHEMA,
        "capabilities_without_passing_test": ["secrets"],
        "capabilities": {"secrets": {"passing": False, "verdict": "misconfigured"}},
    }

    def run(argv, timeout=120):
        Path(argv[argv.index("--out") + 1]).write_text(json.dumps(doc))
        return 2, ""

    r = x10.x10(Context(tmp_path, run))
    assert r.status == ERROR and "misconfigured for: secrets" in r.evidence
