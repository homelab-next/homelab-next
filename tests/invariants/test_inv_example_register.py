# SPDX-License-Identifier: Apache-2.0
"""The example invariants register speaks the checklist's language, and its gates really gate.

Its ids are docs/checklist.md row ids: an id that means something else than the checklist row of
the same name (as F-01..F-03 once did) is how two documents drift apart while both look right.
"""

import os
import pathlib
import re
import shutil
import subprocess
import sys

import pytest
import yaml

from homelabnext.invariants import Context, run_criteria
from homelabnext.invariants.plugins.pillar_x import SERVER_ONLY
from homelabnext.registers.schema import validate_invariants

REPO = pathlib.Path(__file__).resolve().parents[2]
REGISTER = REPO / "examples" / "registers" / "invariants.yml"
CHECKLIST = REPO / "docs" / "checklist.md"
ROW = re.compile(r"^\| ([A-Z]-\d{2}) \| (.+?) \| (.+) \| (PUBLIC-NOW|SERVER) \|$")


def checklist():
    return {m[1]: m[2] for line in CHECKLIST.read_text().splitlines() if (m := ROW.match(line))}


def checklist_tags():
    return {m[1]: m[4] for line in CHECKLIST.read_text().splitlines() if (m := ROW.match(line))}


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


def test_no_criterion_is_a_plugin_that_can_only_skip():
    """A criterion whose check reports skip everywhere is a placeholder that reads as run (the
    runner exits 0 on it); a SERVER row with no check yet is a deferred criterion with a why."""
    for c in register()["criteria"]:
        if c["evidence"] == "plugin":
            assert c["plugin"] not in SERVER_ONLY, c["id"]
        if c.get("deferred"):
            assert c["evidence"] in ("server", "manual") and len(c["why"]) > 60, c["id"]
    for i in SERVER_ONLY:
        assert by_id()[i]["evidence"] == "server" and by_id()[i]["deferred"] is True, i


def test_every_public_now_row_has_a_criterion_the_runner_executes():
    """docs/checklist.md: a PUBLIC-NOW row is decidable from this repository, so a row with no
    criterion is a claim nobody runs (23 such rows were found and given one)."""
    crit = by_id()
    public = sorted(i for i, tag in checklist_tags().items() if tag == "PUBLIC-NOW")
    missing = [i for i in public if i not in crit]
    assert missing == []
    for i in public:  # no exception: a row only a forge or a host can decide is SERVER
        c = crit[i]
        assert c["evidence"] in ("auto", "plugin") and not c.get("deferred"), i


def test_a_server_row_is_never_run_as_if_it_were_public():
    tags = checklist_tags()
    for c in register()["criteria"]:
        if tags[c["id"]] == "SERVER":
            assert c["evidence"] in ("server", "manual"), c["id"]


def test_slow_criteria_have_room_to_finish():
    # the runner's default is 120 s; the coverage floor runs the security suites under coverage
    assert by_id()["Q-07"]["timeout"] >= 900


def test_retired_ids_are_checklist_conflicts_with_a_live_replacement():
    reg = register()
    live = {c["id"] for c in reg["criteria"]}
    assert set(reg["retired"]) == {"F-01", "F-02", "F-03"}
    assert {t["replaced_by"] for t in reg["retired"].values()} <= live


# rows whose gate already runs in `make check`; each must be runnable from a checkout
GATED = ["F-05", "F-18", "D-02", "D-07", "Q-04", "Q-07", "Q-09", "Q-10", "Q-11"]
GATED += ["M-01", "M-02", "M-03", "M-04", "M-17", "L-06", "L-07", "F-07", "F-17", "Q-05", "Q-08"]
GATED += ["F-21", "Q-01", "Q-06"]
# the CLI gates of `make check` and CI (fast: they run in `make invariants`)
FAST_GATES = ["D-04", "T-07", "R-01", "R-03", "R-04", "R-07", "M-12", "G-01", "G-02", "G-03"]
FAST_GATES += ["G-11", "K-02", "K-03", "K-04", "K-12", "K-15", "L-05", "F-19"]
FAST_GATES += ["P-14", "R-09", "A-08", "A-10"]
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
PYTEST_ROWS += ["F-15", "F-22", "O-05", "O-06", "O-07", "O-09", "O-10", "O-11"]
PYTEST_ROWS += ["P-10", "P-11", "P-12", "P-13", "Q-02", "Q-03", "A-09", "A-11", "A-13"]
GATED += FAST_GATES + PYTEST_ROWS + ["M-16"]


def test_ci_gates_are_auto_criteria_with_a_remediation():
    crit = by_id()
    for i in GATED:
        c = crit[i]
        assert c["evidence"] == "auto" and c.get("expect_regex"), i
        assert len(c["remediation"]) > 40, i


def _run(root, only):
    return run_criteria(register()["criteria"], Context(root), only=set(only))["results"]


def test_fast_cli_gates_pass_on_the_repository_in_ci_s_invariants_job():
    """Each fast gate passing on this repository is decided by CI's `invariants` job, which runs
    every fast criterion of this register through the runner (`make invariants`, exit 1 on a fail,
    exit 100 on could-not-measure); `make check` runs the same commands as its own gates.  Running
    them here again cost about 55 s of a 60 s suite budget, so this test holds the wiring instead:
    every fast gate is a criterion `--fast` selects, and the job and the target really run it."""
    crit = by_id()
    for i in FAST_GATES:
        assert not crit[i].get("slow") and not crit[i].get("deferred"), i
    make = (REPO / "Makefile").read_text()
    target = re.search(r"^invariants:\n\t(.+)$", make, re.M)
    assert target, "the Makefile has no invariants target"
    assert "invariants run examples/registers/invariants.yml --fast" in target[1]
    jobs = yaml.safe_load((REPO / ".github/workflows/ci.yml").read_text())["jobs"]
    runs = [s.get("run", "") for s in jobs["invariants"]["steps"]]
    assert any(r.strip().startswith("make invariants") for r in runs), runs
    assert "if" not in jobs["invariants"]


def test_fast_cli_gates_are_red_on_an_empty_checkout(tmp_path, monkeypatch):
    # nothing to validate must never read as "validated": each gate fails or cannot measure.
    # G-01 and K-15 audit data the package ships (prompt templates, the required safety specs),
    # so they still find it; their own tests prove they fail on a bad template or spec.
    monkeypatch.setenv("PYTHONPATH", str(REPO))
    res = _run(tmp_path, [i for i in FAST_GATES if i not in ("G-01", "K-15")])
    assert {i for i, r in res.items() if r["status"] not in ("fail", "error")} == set()


def test_p14_accepts_zero_problems_only():
    """`.*0 problem(s)` also matched "10 problem(s)": the count starts at a word boundary."""
    rx = re.compile(by_id()["P-14"]["expect_regex"])
    line = "hnx mcp catalog: 31 server(s), 10 profile(s), 2 manifest(s), {} problem(s)"
    assert rx.search(line.format(0))
    assert not rx.search(line.format(10))


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


def test_q06_cannot_measure_without_the_network(monkeypatch):
    """pip-audit with no route to PyPI exits 1 with a ConnectionError traceback, which read as a
    FAIL of the security checks; an unreachable index is could-not-measure (exit 100)."""
    pytest.importorskip("pip_audit")
    pytest.importorskip("ruff")
    monkeypatch.setenv("PYTHONPATH", str(REPO))
    # the observable's `python3` is this interpreter, which has ruff and pip-audit
    monkeypatch.setenv("PATH", f"{pathlib.Path(sys.executable).parent}:{os.environ['PATH']}")
    for var in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.setenv(var, "http://127.0.0.1:9")  # the discard port: refused at once
    for var in ("NO_PROXY", "no_proxy"):
        monkeypatch.delenv(var, raising=False)
    r = _run(REPO, ["Q-06"])["Q-06"]
    assert r["status"] == "error" and "pypi.org is unreachable" in r["evidence"], r


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
