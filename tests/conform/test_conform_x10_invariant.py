# SPDX-License-Identifier: Apache-2.0
"""Invariant X-10 (every capability has a passing conformance test): pass/fail fixtures, the
real report, and registration through all three plugin routes."""

import json
import shutil
import sys
from pathlib import Path

import pytest
import yaml

from homelabnext.conform.plugins import x10_conformance as x10
from homelabnext.invariants import Context, Registry, default_registry, load_directory
from homelabnext.invariants.api import ERROR, FAIL, PASS, SKIP
from homelabnext.invariants.plugins import pillar_x

ROOT = Path(__file__).resolve().parents[2]


def tree(tmp_path):
    (tmp_path / "conformance" / "suites").mkdir(parents=True)
    return tmp_path


def canned(rc, payload):
    seen = []

    def run(argv, timeout=120):
        seen.append(list(argv))
        text = payload if isinstance(payload, str) else json.dumps(payload)
        return rc, text

    run.seen = seen
    return run


GOOD = {
    "capabilities_without_passing_test": [],
    "capabilities": {"secrets": {"passing": True}, "events": {"passing": True}},
}
BAD = {
    "capabilities_without_passing_test": ["events"],
    "capabilities": {
        "secrets": {"passing": True},
        "events": {"passing": False, "reason": "mutant 'dlq' not caught by check 'x'"},
    },
}


def test_pass_fixture(tmp_path):
    run = canned(0, GOOD)
    r = x10.x10(Context(tree(tmp_path), run))
    assert r.status == PASS and "2 capabilities" in r.evidence
    argv = run.seen[0]
    assert argv[1:4] == ["-m", "homelabnext.cli", "conform"] and "--json" in argv
    assert argv[argv.index("--root") + 1] == str(tmp_path)


def test_fail_fixture_names_the_capability_and_reason(tmp_path):
    r = x10.x10(Context(tree(tmp_path), canned(1, BAD)))
    assert r.status == FAIL
    assert "events" in r.evidence and "not caught" in r.evidence


def test_skip_when_the_tree_has_no_suites(tmp_path):
    r = x10.x10(Context(tmp_path, canned(0, GOOD)))
    assert r.status == SKIP and "no conformance/suites" in r.evidence


@pytest.mark.parametrize(
    ("rc", "payload"),
    [
        (100, "it broke"),
        (2, "hnx conform: needs a source checkout"),
        (0, "not json at all"),
        (0, {"x": 1}),
    ],
)
def test_could_not_measure_is_error_never_pass_or_fail(tmp_path, rc, payload):
    r = x10.x10(Context(tree(tmp_path), canned(rc, payload)))
    assert r.status == ERROR


def test_parser_tolerates_leading_noise():
    assert x10._parse("warning: x\n" + json.dumps(GOOD))["capabilities_without_passing_test"] == []


def test_target_comes_from_the_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("HNX_CONFORM_TARGET", "staging")
    run = canned(0, GOOD)
    x10.x10(Context(tree(tmp_path), run))
    argv = run.seen[0]
    assert argv[argv.index("--target") + 1] == "staging"


def test_real_report_on_this_repository_passes():
    r = x10.x10(Context(ROOT))
    assert r.status == PASS, r.evidence


def test_x04_now_passes_on_this_repository():
    r = pillar_x.x04(Context(ROOT))
    assert r.status == PASS, r.evidence


def _run_with_checkout_on_path(argv, timeout=120):
    """Like Context._run, but this checkout provides `homelabnext` (the copied tree has none)."""
    import os
    import subprocess

    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env=env)
    return p.returncode, ((p.stdout or "") + (p.stderr or "")).strip()


def test_real_report_fails_when_a_suite_is_removed(tmp_path):
    root = tmp_path / "t"
    shutil.copytree(
        ROOT / "conformance", root / "conformance", ignore=shutil.ignore_patterns("__pycache__")
    )
    (root / "capabilities.yml").write_text("capabilities: [secrets, teleporter]\n")
    r = x10.x10(Context(root, run=_run_with_checkout_on_path))
    assert r.status == FAIL and "teleporter" in r.evidence


def test_registers_through_register_and_plugins_dir():
    reg = Registry()
    x10.register(reg)
    assert reg.get("X-10").statement == "every capability has a passing conformance test"
    reg2 = Registry()
    loaded = load_directory(reg2, ROOT / "homelabnext" / "conform" / "plugins")
    assert "x10_conformance" in loaded and reg2.get("X-10") is not None
    assert default_registry().get("X-10") is None  # opt-in: loaded by entry point or --plugins-dir


def test_end_to_end_through_hnx_invariants_run(tmp_path):
    register = tmp_path / "invariants.yml"
    register.write_text(
        yaml.safe_dump(
            {
                "schema": "homelabnext.registers.invariants/1",
                "criteria": [
                    {
                        "id": "X-10",
                        "statement": "Every capability has a passing conformance test.",
                        "evidence": "plugin",
                        "plugin": "X-10",
                        "remediation": "Fix the failing suite or add the missing fake mutant.",
                    }
                ],
            }
        )
    )
    from homelabnext.invariants.__main__ import main

    out = tmp_path / "out.json"
    code = main(
        [
            "run",
            str(register),
            "--root",
            str(ROOT),
            "--out",
            str(out),
            "--plugins-dir",
            str(ROOT / "homelabnext" / "conform" / "plugins"),
            "--no-notify",
        ]
    )
    doc = json.loads(out.read_text())
    assert doc["results"]["X-10"]["status"] == "pass", doc["results"]["X-10"]
    assert code == 0 and sys.executable
