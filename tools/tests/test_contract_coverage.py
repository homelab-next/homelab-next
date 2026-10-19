# SPDX-License-Identifier: Apache-2.0
"""The contract coverage gate (T-07, Q-05): passes this tree; fails when a seam lacks a passing
publisher or consumer test, including a new event type whose schema lands without fixtures."""

import json
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import contract_coverage as gate

REPO = Path(__file__).resolve().parents[2]
EV, TB = gate.MODULES["event"], gate.MODULES["table"]


def _all_pass(seams):
    return {
        (gate.MODULES[k], f"test_{r}_contract[{n}]"): "passed" for k, n in seams for r in gate.ROLES
    }


def test_every_schema_is_a_seam():
    seams = gate.expected_seams()
    assert ("event", "task.queued") in seams
    assert ("event", "deploy.changed") in seams
    assert ("table", "authentication") in seams
    assert ("event", "envelope") not in seams


def test_complete_results_have_no_problems():
    seams = gate.expected_seams()
    assert gate.problems(seams, _all_pass(seams)) == []


def test_missing_failed_and_skipped_are_reported():
    seams = [("event", "a.b"), ("table", "t")]
    res = _all_pass(seams)
    del res[(EV, "test_consumer_contract[a.b]")]
    res[(TB, "test_publisher_contract[t]")] = "skipped"
    res[(TB, "test_consumer_contract[t]")] = "failed"
    assert gate.problems(seams, res) == [
        "event a.b: no consumer contract test ran",
        "table t: publisher contract test skipped",
        "table t: consumer contract test failed",
    ]


def test_parse_junit(tmp_path):
    xml = tmp_path / "j.xml"
    xml.write_text(
        '<testsuites><testsuite name="pytest">'
        f'<testcase classname="{EV}" name="test_publisher_contract[a.b]"/>'
        f'<testcase classname="{EV}" name="test_consumer_contract[a.b]"><failure message="x"/></testcase>'
        f'<testcase classname="{TB}" name="test_publisher_contract[t]"><skipped message="s"/></testcase>'
        f'<testcase classname="{TB}" name="test_consumer_contract[t]"><error message="e"/></testcase>'
        "</testsuite></testsuites>"
    )
    assert gate.parse_junit(xml) == {
        (EV, "test_publisher_contract[a.b]"): "passed",
        (EV, "test_consumer_contract[a.b]"): "failed",
        (TB, "test_publisher_contract[t]"): "skipped",
        (TB, "test_consumer_contract[t]"): "failed",
    }
    assert gate.main(["--junit", str(xml)]) == 1


def _run(env_schemas=None):
    import os

    env = os.environ.copy()
    if env_schemas:
        env["HNX_SCHEMAS_DIR"] = str(env_schemas)
    return subprocess.run(
        [sys.executable, str(REPO / "tools" / "contract_coverage.py")],
        capture_output=True, text=True, cwd=REPO, env=env, check=False,
    )  # fmt: skip


def test_gate_passes_this_tree_and_fails_a_new_type_without_fixtures(tmp_path):
    ok = _run()
    assert ok.returncode == 0, ok.stdout + ok.stderr
    assert "0 missing" in ok.stdout

    schemas = tmp_path / "schemas"
    shutil.copytree(REPO / "schemas", schemas)
    doc = json.loads((schemas / "events" / "task.queued.schema.json").read_text())
    doc["$id"] = doc["$id"].replace("task.queued", "vm.rebooted")
    doc["allOf"][1]["properties"]["type"]["const"] = "homelabnext.vm.rebooted"
    (schemas / "events" / "vm.rebooted.schema.json").write_text(json.dumps(doc))
    bad = _run(schemas)
    assert bad.returncode == 1, bad.stdout + bad.stderr
    assert "MISSING event vm.rebooted: publisher contract test failed" in bad.stdout
    assert "MISSING event vm.rebooted: consumer contract test failed" in bad.stdout
