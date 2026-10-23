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
GATED = ["F-05", "F-18", "D-02", "D-07", "Q-04", "Q-07", "Q-09", "Q-10", "Q-11"]
GATED += ["M-01", "M-02", "M-03", "M-04", "M-17", "L-06", "L-07", "F-07", "F-17", "Q-05", "Q-08"]
GATED += ["F-21"]
# the CLI gates of `make check` and CI (fast: they run in `make invariants`)
FAST_GATES = ["D-04", "T-07", "R-01", "R-03", "R-04", "R-07", "M-12", "G-01", "G-02", "G-03"]
FAST_GATES += ["G-11", "G-13", "K-02", "K-03", "K-04", "K-12", "K-15", "L-05", "F-19"]
# the rows proven by named tests: the criterion runs that pytest selection (slow, like D-07)
PYTEST_ROWS = ["T-02", "T-04", "S-06", "S-07", "O-08", "P-02", "P-03", "P-07", "A-03", "A-04"]
PYTEST_ROWS += [
    "G-04",
    "A-05",
    "K-06",
    "K-07",
    "K-08",
    "K-13",
    "K-14",
    "G-10",
    "M-06",
    "M-07",
    "M-08",
]
PYTEST_ROWS += ["M-09", "M-14", "L-03", "L-08"]
GATED += FAST_GATES + PYTEST_ROWS + ["M-16"]


def test_ci_gates_are_auto_criteria_with_a_remediation():
    crit = by_id()
    for i in GATED:
        c = crit[i]
        assert c["evidence"] == "auto" and c.get("expect_regex"), i
        assert len(c["remediation"]) > 40, i


def _run(root, only):
    return run_criteria(register()["criteria"], Context(root), only=set(only))["results"]


def test_fast_cli_gates_pass_on_the_repository():
    res = _run(REPO, FAST_GATES)
    bad = {i: r["evidence"] for i, r in res.items() if r["status"] != "pass"}
    assert not bad and set(res) == set(FAST_GATES)


def test_fast_cli_gates_are_red_on_an_empty_checkout(tmp_path, monkeypatch):
    # nothing to validate must never read as "validated": each gate fails or cannot measure.
    # G-01 and K-15 audit data the package ships (prompt templates, the required safety specs),
    # so they still find it; their own tests prove they fail on a bad template or spec.
    monkeypatch.setenv("PYTHONPATH", str(REPO))
    res = _run(tmp_path, [i for i in FAST_GATES if i not in ("G-01", "K-15")])
    assert {i for i, r in res.items() if r["status"] not in ("fail", "error")} == set()


def test_pytest_rows_run_a_named_selection_and_refuse_a_partial_run():
    crit = by_id()
    for i in PYTEST_ROWS:
        c = crit[i]
        assert (
            c.get("slow") is True and "-m pytest -q -p no:cacheprovider tests/" in c["observable"]
        )
        assert "exit 100" in c["observable"], i  # a missing test dependency is could-not-measure
        rx = re.compile(c["expect_regex"])
        assert rx.search("12 passed, 30 deselected in 0.41s"), i
        assert rx.search("8 passed in 1.69s"), i
        for partial in (
            "11 passed, 1 skipped in 0.5s",
            "no tests ran in 0.1s",
            "1 failed, 3 passed",
        ):
            assert not rx.search(partial), (i, partial)


def test_a_pytest_row_fails_when_its_tests_fail(tmp_path, monkeypatch):
    # L-08's own observable, pointed at a checkout whose runner tests are broken
    monkeypatch.setenv("PYTHONPATH", str(REPO))
    (tmp_path / "tests/invariants").mkdir(parents=True)
    (tmp_path / "tests/invariants/test_inv_runner.py").write_text(
        "def test_exit_code_semantics():\n    assert False\n"
    )
    r = _run(tmp_path, ["L-08"])["L-08"]
    assert r["status"] == "fail"


def test_m16_fails_on_a_record_without_its_uid(scratch):
    d = scratch / "reg" / "lessons"
    d.mkdir(parents=True)
    uid = "01a15e4e-0000-7000-8000-000000000001"
    (d / f"{uid}.md").write_text(f"---\nuid: {uid}\ntype: lesson\n---\n")
    _git(scratch, "add", "-A")
    assert _run(scratch, ["M-16"])["M-16"]["status"] == "pass"
    (d / "LL-NEW-x.md").write_text("---\nid: LL-NEW\ntitle: x\n---\n")
    _git(scratch, "add", "-A")
    r = _run(scratch, ["M-16"])["M-16"]
    assert r["status"] == "fail" and "still numbered LL-NEW" in r["evidence"]


def test_m16_fails_on_a_misnamed_or_shared_uid_as_make_ids_check_does(scratch):
    """M-16 runs what its checklist row names (`make ids-check`: check-dupes and check-uids), so
    a record named for another uid, or two files holding one uid, fail it too."""
    d = scratch / "reg" / "lessons"
    d.mkdir(parents=True)
    u1, u2 = "01a15e4e-0000-7000-8000-000000000001", "01a15e4e-0000-7000-8000-000000000002"
    (d / f"{u1}.md").write_text(f"---\nuid: {u1}\ntype: lesson\n---\n")
    _git(scratch, "add", "-A")
    assert _run(scratch, ["M-16"])["M-16"]["status"] == "pass"
    (d / f"{u2}.md").write_text(f"---\nuid: {u1}\ntype: lesson\n---\n")  # u1 twice, misnamed
    _git(scratch, "add", "-A")
    r = _run(scratch, ["M-16"])["M-16"]
    assert r["status"] == "fail" and f"uid {u1} is also the uid of" in r["evidence"]


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


#: an actor that acts other than through the broker (ADR-0030): the shell server, directly
_DIRECT_ACTOR = {"id": "profile:actor", "persona": "persona:a", "mcp": ["shell"],
                 "capabilities": [], "reads_untrusted": False}  # fmt: skip
_BROKER_ACTOR = {**_DIRECT_ACTOR, "mcp": ["hnx-broker"], "capabilities": ["cap:broker"]}


def test_g13_fails_on_an_actor_that_acts_directly(tmp_path, monkeypatch):
    monkeypatch.setenv("PYTHONPATH", str(REPO))
    (tmp_path / "actor.yml").write_text(yaml.safe_dump(_BROKER_ACTOR))
    assert _run(tmp_path, ["G-13"])["G-13"]["status"] == "pass"
    (tmp_path / "actor.yml").write_text(yaml.safe_dump(_DIRECT_ACTOR))
    r = _run(tmp_path, ["G-13"])["G-13"]
    assert r["status"] == "fail" and "'shell' (exec)" in r["evidence"]
    # G-03 is about readers: an actor's direct tool is not its red
    assert _run(tmp_path, ["G-03"])["G-03"]["status"] == "pass"
