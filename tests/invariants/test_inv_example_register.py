# SPDX-License-Identifier: Apache-2.0
"""The example invariants register speaks the checklist's language, and its gates really gate.

Its ids are docs/checklist.md row ids: an id that means something else than the checklist row of
the same name (as F-01..F-03 once did) is how two documents drift apart while both look right.
"""

import os
import pathlib
import re
import shlex
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
GATED += ["F-21", "F-23", "Q-01", "Q-06"]
# the CLI gates of `make check` and CI (fast: they run in `make invariants`)
FAST_GATES = ["D-04", "T-07", "R-01", "R-03", "R-04", "R-07", "M-12", "G-01", "G-02", "G-03"]
FAST_GATES += ["G-11", "G-13", "K-02", "K-03", "K-04", "K-12", "K-15", "L-05", "F-19"]
FAST_GATES += ["P-14", "R-09", "A-08", "A-10", "A-14"]
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


def test_a14_fails_on_a_home_that_names_an_address_or_an_engine_model_id(tmp_path, monkeypatch):
    """A-14 over the example controller's homes: they pass; a home naming an engine address or
    model id (tests/generators/fixtures/hermes-homes/fail) fails, and so does no home at all."""
    monkeypatch.setenv("PYTHONPATH", str(REPO))
    example = tmp_path / "examples" / "llm-orchestrator-gateway"
    example.mkdir(parents=True)
    shutil.copy(REPO / "examples/llm-orchestrator-gateway/model_roles.json", example)
    assert _run(tmp_path, ["A-14"])["A-14"]["status"] == "fail"  # no home: nothing checked
    shutil.copytree(REPO / "examples/llm-orchestrator-gateway/homes", example / "homes")
    assert _run(tmp_path, ["A-14"])["A-14"]["status"] == "pass"
    fixtures = REPO / "tests/generators/fixtures/hermes-homes/fail"
    for bad in sorted(fixtures.iterdir()):
        shutil.copytree(bad, example / "homes" / bad.name)
        r = _run(tmp_path, ["A-14"])["A-14"]
        assert r["status"] == "fail" and bad.name in r["evidence"], (bad.name, r)
        shutil.rmtree(example / "homes" / bad.name)


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


# tests a row's selection must reach: the claims its checklist row makes, each one test
ROW_CLAIMS = {
    # "missing, resized, changed or unlisted files fail" and "fetches by commit, refuses a mismatch"
    "A-09": [
        "test_store_check_passes_on_the_manifests_files_and_fails_on_a_changed_byte",
        "test_store_check_reports_missing_resized_and_unlisted_files",
        "test_model_store_fetches_at_the_pinned_revision_and_the_store_check_passes",
        "test_model_store_refuses_a_download_whose_sha256_is_not_the_manifests",
    ],
    # "a backend id, Ollama or a direct connection is refused"
    "A-11": [
        "test_open_webui_points_at_the_gateway_with_its_own_key",
        "test_open_webui_refuses_anything_but_the_gateway",
    ],
}


@pytest.mark.parametrize("row", sorted(ROW_CLAIMS))
def test_a_narrowed_pytest_row_still_selects_its_row_s_claims(row):
    """A-09's `-k` was narrowed to the role's revision and sha256 tests and silently dropped every
    store-check test, the row's first claim; `--collect-only` is how the runner would select."""
    pytest.importorskip("jsonschema")
    obs = by_id()[row]["observable"]
    args = shlex.split(obs.split("python3 -m pytest", 1)[1])
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", *args],
        cwd=REPO,
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": str(REPO)},
    )
    assert proc.returncode == 0, proc.stdout[-2000:]
    collected = {line.split("::")[-1].split("[")[0] for line in proc.stdout.splitlines()}
    assert [t for t in ROW_CLAIMS[row] if t not in collected] == []


def test_a_pytest_row_fails_when_its_tests_fail(tmp_path, monkeypatch):
    # L-08's own observable, pointed at a checkout whose runner tests are broken
    monkeypatch.setenv("PYTHONPATH", str(REPO))
    (tmp_path / "tests/invariants").mkdir(parents=True)
    (tmp_path / "tests/invariants/test_inv_runner.py").write_text(
        "def test_exit_code_semantics():\n    assert False\n"
    )
    r = _run(tmp_path, ["L-08"])["L-08"]
    assert r["status"] == "fail"


# loopback's discard port: a proxy that refuses every connection at once
DEAD_PROXY = "http://127.0.0.1:9"  # no-raw-endpoint: allow a test proxy that nothing serves


def test_q06_cannot_measure_without_the_network(monkeypatch):
    """pip-audit with no route to PyPI exits 1 with a ConnectionError traceback, which read as a
    FAIL of the security checks; an unreachable index is could-not-measure (exit 100)."""
    pytest.importorskip("pip_audit")
    pytest.importorskip("ruff")
    monkeypatch.setenv("PYTHONPATH", str(REPO))
    # the observable's `python3` is this interpreter, which has ruff and pip-audit
    monkeypatch.setenv("PATH", f"{pathlib.Path(sys.executable).parent}:{os.environ['PATH']}")
    for var in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.setenv(var, DEAD_PROXY)
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


#: an actor that acts other than through the broker (ADR-0030): the shell server, directly
_DIRECT_ACTOR = {"id": "profile:actor", "persona": "persona:a", "mcp": ["shell"],
                 "capabilities": [], "reads_untrusted": False}  # fmt: skip
_BROKER_ACTOR = {**_DIRECT_ACTOR, "mcp": ["hnx-broker"], "capabilities": ["cap:broker"]}


def _no_exception_policy(root) -> None:
    """The ceiling policy G-13 and G-04 lint with, listing no direct exception."""
    pol = root / "examples" / "mcp" / "clients" / "policy" / "ceilings.yml"
    pol.parent.mkdir(parents=True, exist_ok=True)
    entry = {"mcp": ["shell"], "capabilities": [], "tier": "read"}
    pol.write_text(yaml.safe_dump({"ceilings": {"profile:actor": entry}}))


def test_g13_fails_on_an_actor_that_acts_directly(tmp_path, monkeypatch):
    monkeypatch.setenv("PYTHONPATH", str(REPO))
    _no_exception_policy(tmp_path)
    (tmp_path / "actor.yml").write_text(yaml.safe_dump(_BROKER_ACTOR))
    assert _run(tmp_path, ["G-13"])["G-13"]["status"] == "pass"
    (tmp_path / "actor.yml").write_text(yaml.safe_dump(_DIRECT_ACTOR))
    r = _run(tmp_path, ["G-13"])["G-13"]
    assert r["status"] == "fail" and "'shell' (exec)" in r["evidence"]
    # G-03 is about readers: an actor's direct tool is not its red (the shipped shell is an
    # unreviewed draft, which G-03's catalog rule reports, but not the broker rule)
    assert "agents act only through the broker" not in _run(tmp_path, ["G-03"])["G-03"]["evidence"]


def test_g04_runs_the_broker_rule_before_its_tests(tmp_path, monkeypatch):
    """R3.4: G-04's observable once ran one test file, so an actor holding a direct tool (not
    limited to allowlisted actions at all) left it green; it now lints every profile first."""
    monkeypatch.setenv("PYTHONPATH", str(REPO))
    _no_exception_policy(tmp_path)
    (tmp_path / "tests" / "agent").mkdir(parents=True)
    for name in ("test_agent_handoff.py", "test_agent_broker_only.py"):
        (tmp_path / "tests" / "agent" / name).write_text("def test_ok():\n    assert True\n")
    (tmp_path / "actor.yml").write_text(yaml.safe_dump(_BROKER_ACTOR))
    assert _run(tmp_path, ["G-04"])["G-04"]["status"] == "pass"
    (tmp_path / "actor.yml").write_text(yaml.safe_dump(_DIRECT_ACTOR))
    r = _run(tmp_path, ["G-04"])["G-04"]
    assert r["status"] == "fail" and "'shell' (exec)" in r["evidence"]


def test_g13_honours_a_direct_exception_its_ceiling_policy_makes(tmp_path, monkeypatch):
    """S4: G-13 linted without the ceiling policy, so a lab that made a sanctioned direct exception
    (a reviewed acts_via: direct record and the policy's direct_mcp) had a standing red."""
    import json as _json

    from homelabnext.mcp import servers

    ex = tmp_path / "examples"
    shutil.copytree(REPO / "examples" / "mcp", ex / "mcp", ignore=shutil.ignore_patterns("clients"))
    shutil.copy(REPO / "examples" / "review-policy.yml", ex / "review-policy.yml")
    rec = yaml.safe_load((ex / "mcp" / "shell.yml").read_text())
    rec["status"] = "active"  # the lab reviewed its shell
    digest = servers.record_digest(rec)[:19]
    rec["reviews"] = [
        {"by": b, "kind": k, "role": r, "date": "2026-10-23", "verdict": "pass", "digest": digest}
        for b, k, r in (("agent:example-checker", "agent", "check"),
                        ("agent:example-auditor", "agent", "audit"),
                        ("human:example-operator", "human", "approve"))
    ]  # fmt: skip
    (ex / "mcp" / "shell.yml").write_text(yaml.safe_dump(rec))
    pol = ex / "mcp" / "clients" / "policy" / "ceilings.yml"
    pol.parent.mkdir(parents=True)
    entry = {"mcp": ["shell"], "capabilities": [], "tier": "read"}
    pol.write_text(yaml.safe_dump({"ceilings": {"profile:actor": entry}}))
    monkeypatch.setenv("PYTHONPATH", str(REPO))
    monkeypatch.setenv("HNX_EXAMPLES_DIR", str(ex))
    (tmp_path / "actor.json").write_text(_json.dumps(_DIRECT_ACTOR))
    r = _run(tmp_path, ["G-13"])["G-13"]
    assert r["status"] == "fail" and "direct_mcp entry" in r["evidence"]
    pol.write_text(
        yaml.safe_dump({"ceilings": {"profile:actor": {**entry, "direct_mcp": ["shell"]}}})
    )
    assert _run(tmp_path, ["G-13"])["G-13"]["status"] == "pass"


#: observables whose tests need something that is not always there, and the first statement that
#: makes its absence could-not-measure (exit 100) rather than a failure of the invariant
NEEDS = {
    "F-15": 'import importlib.metadata as m; m.version("homelabnext")',  # __version__ is 0.0.0+local
    "P-11": "import nats",  # the real-bus test skips without it, and a skip is not a pass
    "P-13": "import nats",
}


@pytest.mark.parametrize("cid", sorted(NEEDS))
def test_an_observable_that_needs_an_install_cannot_measure_without_it(cid, tmp_path, monkeypatch):
    """F-15's test reads the installed version (``0.0.0+local`` on a bare checkout, so the
    changelog section it looks for is missing) and P-11/P-13 skip their real-bus test without
    ``nats``: each reported FAIL where the check could not be made.  The guard is the first
    statement and its failure is exit 100 (``error``), never a pass or a fail."""
    c = by_id()[cid]
    obs = c["observable"]
    at = obs.find(NEEDS[cid])
    assert at >= 0, obs
    assert re.match(r"[^|]*'\s*(2>/dev/null\s*)?\|\| exit 100;", obs[at:]), obs
    work = min(i for i in (obs.find("check_changelog"), obs.find("-m pytest")) if i >= 0)
    assert at < work, obs  # the guard runs before the work it guards
    # a python3 on which that statement fails, as on a checkout that is not installed (any other
    # statement runs on the real interpreter, so the other guards pass and this one decides)
    shim = tmp_path / "bin"
    shim.mkdir()
    (shim / "python3").write_text(
        f'#!/bin/sh\ncase "$*" in *\'{NEEDS[cid]}\'*) exit 1;; esac\nexec {sys.executable} "$@"\n'
    )
    (shim / "python3").chmod(0o755)
    monkeypatch.setenv("PATH", f"{shim}:{os.environ['PATH']}")
    probe = {**c, "observable": c["observable"], "slow": False}
    r = run_criteria([probe], Context(REPO), only={cid})["results"][cid]
    assert r["status"] == "error", r
