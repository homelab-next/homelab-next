# SPDX-License-Identifier: Apache-2.0
"""The example invariants register speaks the checklist's language, and its gates really gate.

Its ids are docs/checklist.md row ids: an id that means something else than the checklist row of
the same name (as F-01..F-03 once did) is how two documents drift apart while both look right.
"""

import pathlib
import re
import shutil
import subprocess

import pytest
import yaml

from homelabnext.invariants import Context, run_criteria
from homelabnext.registers.schema import validate_invariants

REPO = pathlib.Path(__file__).resolve().parents[2]
REGISTER = REPO / "examples" / "registers" / "invariants.yml"
CHECKLIST = REPO / "docs" / "checklist.md"
ROW = re.compile(r"^\| ([A-Z]-\d{2}) \| (.+?) \| (.+) \| (PUBLIC-NOW|SERVER) \|$")


def checklist():
    return {m[1]: m[2] for line in CHECKLIST.read_text().splitlines() if (m := ROW.match(line))}


def register():
    return validate_invariants(yaml.safe_load(REGISTER.read_text()))


def by_id():
    return {c["id"]: c for c in register()["criteria"]}


def test_every_criterion_is_a_checklist_row_with_the_same_meaning():
    rows = checklist()
    for c in register()["criteria"]:
        assert c["id"] in rows, f"{c['id']} is not a checklist row"
        if c["evidence"] != "plugin":  # plugin rows word their statement for the plugin
            assert c["statement"].rstrip(".") == rows[c["id"]], c["id"]


def test_retired_ids_are_checklist_conflicts_with_a_live_replacement():
    reg = register()
    live = {c["id"] for c in reg["criteria"]}
    assert set(reg["retired"]) == {"F-01", "F-02", "F-03"}
    assert {t["replaced_by"] for t in reg["retired"].values()} <= live


# rows whose gate already runs in `make check`; each must be runnable from a checkout
GATED = ["F-05", "F-18", "D-02", "D-07", "Q-09", "Q-10", "M-17", "L-06", "L-07"]


def test_ci_gates_are_auto_criteria_with_a_remediation():
    crit = by_id()
    for i in GATED:
        c = crit[i]
        assert c["evidence"] == "auto" and c.get("expect_regex"), i
        assert len(c["remediation"]) > 40, i


def _run(root, only):
    return run_criteria(register()["criteria"], Context(root), only=set(only))["results"]


def test_fast_gates_pass_on_the_repository():
    # the slow ones (leak scans, schema check, goldens) run in `make check` and via hnx itself;
    # M-17 compares with HEAD, so it is exercised in a scratch repository below instead
    res = _run(REPO, ["D-02", "Q-09", "L-06", "L-07"])
    assert {i: r["status"] for i, r in res.items()} == dict.fromkeys(
        ["D-02", "Q-09", "L-06", "L-07"], "pass"
    )


def _git(cwd, *args):
    subprocess.run(
        ["git", "-c", "user.email=t@example.org", "-c", "user.name=t", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
    )


@pytest.fixture
def scratch(tmp_path):
    root = tmp_path / "checkout"
    (root / "tools").mkdir(parents=True)
    for f in ("tools/check_spdx.py", "tools/register_ids.py", "LICENSE"):
        shutil.copy(REPO / f, root / f)
    shutil.copytree(REPO / "homelabnext", root / "homelabnext")
    _git(root, "init", "-q")
    return root


def test_q09_fails_on_a_missing_header_or_licence(scratch):
    (scratch / "ok.py").write_text("# SPDX-License-Identifier: Apache-2.0\n")
    _git(scratch, "add", "-A")
    assert _run(scratch, ["Q-09"])["Q-09"]["status"] == "pass"
    (scratch / "bad.py").write_text("print('no header')\n")
    _git(scratch, "add", "bad.py")
    r = _run(scratch, ["Q-09"])["Q-09"]
    assert r["status"] == "fail" and "bad.py" in r["evidence"]
    (scratch / "bad.py").unlink()
    _git(scratch, "add", "-A")
    (scratch / "LICENSE").write_text("")
    assert _run(scratch, ["Q-09"])["Q-09"]["status"] == "fail"


def test_m17_fails_when_an_id_vanishes_and_passes_when_it_is_retired(scratch):
    reg = scratch / "invariants.yml"
    reg.write_text("criteria:\n- id: F-01\n  x: 1\n- id: X-02\n  x: 2\n")
    _git(scratch, "add", "-A")
    _git(scratch, "commit", "-qm", "seed")
    assert _run(scratch, ["M-17"])["M-17"]["status"] == "pass"
    reg.write_text("criteria:\n- id: X-02\n  x: 2\n")
    r = _run(scratch, ["M-17"])["M-17"]
    assert r["status"] == "fail" and "F-01" in r["evidence"]
    reg.write_text("retired:\n  F-01:\n    reason: wrong meaning\ncriteria:\n- id: X-02\n  x: 2\n")
    assert _run(scratch, ["M-17"])["M-17"]["status"] == "pass"


def test_m17_outside_a_git_checkout_could_not_measure(tmp_path):
    assert _run(tmp_path, ["M-17"])["M-17"]["status"] == "error"
