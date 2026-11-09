# SPDX-License-Identifier: Apache-2.0
"""The orchestration suite's fault injection against this repository's controller (ADR-0026 stage
2, PR 2.8): the two MUST checks that need it run and pass on the real binary, and the pieces they
rest on (the runner body's pid file, the adapter's process faults) hold on their own."""

from __future__ import annotations

import json
import os
import signal
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from conformance.fakes import llm_orchestrator_hermes as body
from homelabnext.conform.adapters import llm_orchestrator as adapter
from homelabnext.conform.adapters._env import AdapterConfigError
from tests.suite_policy import require_tool

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import orchestration_conformance as harness

RUN = "0123456789abcdef0123456789abcdef"
FAULT_CHECKS = (
    "killed-worker-fails-run-and-frees-capacity",
    "restart-reconciles-runs-and-capacity",
)


# no network in the test run: the module cache only (CI's Go leg fetches it before the namespace)
OFFLINE = dict(os.environ, GOFLAGS="-mod=readonly", GOWORK="off", GOPROXY="off")


def _module_builds_offline() -> bool:
    """Whether this Go can build the orchestrator module from the module cache alone: the
    module's toolchain or newer, and every dependency cached."""
    proc = subprocess.run(
        ["go", "list", "-deps", "./cmd/controller"],
        cwd=ROOT / "orchestrator",
        env=OFFLINE,
        capture_output=True,
        check=False,
    )
    return proc.returncode == 0


@pytest.fixture
def offline_go() -> str:
    # skips ("not available", a registered reason) where Go or the cached module is missing, and
    # fails instead under HNX_REQUIRE_GO=1, CI's Go leg, which fetches the module first
    return require_tool(
        "go",
        available=_module_builds_offline,
        unusable="the orchestrator module is not available offline (its toolchain or its cached dependencies)",
    )


@pytest.mark.usefixtures("offline_go")
def test_the_fault_injection_checks_pass_strict_on_the_real_controller(tmp_path):
    binary = tmp_path / "controller"
    subprocess.run(
        ["go", "build", "-o", str(binary), "./cmd/controller"],
        cwd=ROOT / "orchestrator",
        check=True,
        env=OFFLINE,
    )
    out = tmp_path / "result.json"
    args = [
        "run",
        "--controller",
        str(binary),
        "--work",
        str(tmp_path / "work"),
        "--strict",
        "--out",
        str(out),
    ]
    for c in FAULT_CHECKS:
        args += ["--check", c]
    assert harness.main(args) == 0
    (run,) = json.loads(out.read_text())["runs"]
    results = {r["check"]: r["status"] for r in run["results"]}
    assert results == dict.fromkeys(FAULT_CHECKS, "pass"), results
    # a session that ended removed its pid file; one that was killed left it, and is not running
    for p in (tmp_path / "work" / "pids").glob("*.pid"):
        assert not harness.is_session(int(p.read_text()), p.name.removesuffix(".pid")), p
    # the restart check's executing run was reconciled by the restarted controller: failed with
    # the reconciliation's reason, and never retried (a session killed while the controller ran
    # would have been a recorded failure, with an automatic retry of the work)
    db = sqlite3.connect(tmp_path / "work" / "state" / "controller.db")
    try:
        reconciled = [
            r
            for (r,) in db.execute(
                "SELECT run_id FROM jobs WHERE local_failed_reason LIKE ?",
                ("%controller-restart-reconciliation%",),
            )
        ]
        assert len(reconciled) == 1, reconciled
        retries = db.execute(
            "SELECT COUNT(*) FROM jobs WHERE retry_of_run_id = ?", (reconciled[0],)
        ).fetchone()[0]
        assert retries == 0, f"the reconciled run {reconciled[0]} was retried"
    finally:
        db.close()


def test_the_runner_body_records_its_session_pid(tmp_path):
    path = body.write_pid_file({body.PID_DIR_ENV: str(tmp_path), "HNX_RUN_ID": RUN}, 4242)
    assert path == tmp_path / f"{RUN}.pid" and path.read_text() == "4242\n"
    assert not list(tmp_path.glob("*.tmp"))
    assert body.write_pid_file({"HNX_RUN_ID": RUN}, 1) is None
    assert body.write_pid_file({body.PID_DIR_ENV: str(tmp_path), "HNX_RUN_ID": "../x"}, 1) is None


def test_the_runner_body_reads_its_prompt_from_stdin():
    code, _, err = body.run(["--stdin"], stdin=lambda: "no job line here")
    assert code == 1 and "no hnx-conform-job: line" in err
    code, _, err = body.run([], stdin=lambda: "x")
    assert code == 2 and "--stdin" in err


def test_process_faults_kill_the_recorded_session(tmp_path):
    proc = subprocess.Popen(["sleep", "30"], env=dict(os.environ, HNX_RUN_ID=RUN))
    other = subprocess.Popen(["sleep", "30"])  # a reused pid: not the run's session
    try:
        faults = adapter.ProcessFaults(tmp_path, ["true"], lambda: True)
        other_run = "c" * 32
        (tmp_path / f"{other_run}.pid").write_text(f"{other.pid}\n")
        faults.kill(other_run)
        (tmp_path / f"{'b' * 32}.pid").write_text("1\n")
        faults.kill("b" * 32)  # never pid 1
        assert other.poll() is None, "a process that is not the run's session was killed"
        (tmp_path / f"{RUN}.pid").write_text(f"{proc.pid}\n")
        faults.kill(RUN)
        assert proc.wait(timeout=30) == -signal.SIGKILL
        with pytest.raises(ValueError):
            faults.kill("../../etc")
    finally:
        for p in (proc, other):
            p.kill()
            p.wait()


def test_process_faults_restart_runs_the_command_and_waits_for_health(tmp_path):
    marker = tmp_path / "restarted"
    calls = []

    def healthy():
        calls.append(1)
        return len(calls) > 2

    faults = adapter.ProcessFaults(tmp_path, ["touch", str(marker)], healthy, sleep=lambda s: None)
    faults.restart()
    assert marker.exists() and len(calls) == 3
    failing = adapter.ProcessFaults(tmp_path, ["false"], lambda: True)
    with pytest.raises(Exception, match="restart command failed"):
        failing.restart()
    clock = iter(range(0, 1000, 10))
    never = adapter.ProcessFaults(
        tmp_path, ["true"], lambda: False, wait_s=5, clock=lambda: next(clock), sleep=lambda s: None
    )
    with pytest.raises(Exception, match="did not answer"):
        never.restart()


def test_a_session_without_a_pid_file_is_not_measured(tmp_path):
    clock = iter(range(0, 1000, 10))
    faults = adapter.ProcessFaults(
        tmp_path, ["true"], lambda: True, wait_s=5, clock=lambda: next(clock), sleep=lambda s: None
    )
    with pytest.raises(Exception, match="no session pid"):
        faults.kill(RUN)


def test_fault_injection_needs_both_settings(monkeypatch, tmp_path):
    monkeypatch.setenv("HNX_ENDPOINT_ORCHESTRATION", f"http://{harness.LOOPBACK}:9")
    monkeypatch.setenv(adapter.PROFILES_ENV, str(tmp_path))
    monkeypatch.delenv(adapter.PID_DIR_ENV, raising=False)
    monkeypatch.delenv(adapter.RESTART_ENV, raising=False)
    with pytest.raises(AdapterConfigError, match=adapter.PID_DIR_ENV):
        adapter.make(fault_injection=True)
    monkeypatch.setenv(adapter.PID_DIR_ENV, str(tmp_path))
    monkeypatch.setenv(adapter.RESTART_ENV, "not json")
    with pytest.raises(AdapterConfigError, match="JSON"):
        adapter.make(fault_injection=True)
    monkeypatch.setenv(adapter.RESTART_ENV, json.dumps(["restart"]))
    subject = adapter.make(fault_injection=True)
    assert isinstance(subject._faults, adapter.ProcessFaults)
    assert adapter.make()._faults is None  # a target without fault_injection declares none


def test_the_harness_refuses_a_used_work_directory(tmp_path):
    (tmp_path / "x").write_text("")
    assert harness.main(["run", "--controller", "/bin/true", "--work", str(tmp_path)]) == 2
    assert harness.main(["run", "--controller", "/bin/true", "--work", "relative"]) == 2


def test_the_harness_config_gives_sessions_only_the_pid_directory(tmp_path):
    cfg = json.loads(harness.write_config(tmp_path, 18000).read_text())
    assert cfg["runner"]["env_allowlist"] == ["HNX_CONFORM_PID_DIR"]
    assert cfg["api_auth"] == {"enabled": False} and cfg["http_addr"].startswith(
        harness.LOOPBACK + ":"
    )
    assert "{prompt}" not in cfg["runner"]["exec"]["argv"]  # the prompt goes on stdin


def _spawn(argv, **env):
    return subprocess.Popen(argv, env=dict(os.environ, **env), start_new_session=True)


def test_a_restart_kills_the_controller_before_its_sessions(tmp_path, monkeypatch):
    """A session killed while its controller still runs is a failure that controller records
    (and retries), not a crash it reconciles: the controller goes first, and is waited for."""
    work = tmp_path
    (work / "pids").mkdir()
    cfg = str(work / "controller.yaml")
    controller = _spawn(["sh", "-c", "sleep 30", "serve", "--config", cfg])
    session = _spawn(["sleep", "30"], HNX_RUN_ID=RUN)
    stale = _spawn(["sleep", "30"], HNX_RUN_ID="f" * 32)  # a pid file naming another run's pid
    try:
        (work / "controller.pid").write_text(f"{controller.pid}\n")
        (work / "pids" / f"{RUN}.pid").write_text(f"{session.pid}\n")
        (work / "pids" / f"{'e' * 32}.pid").write_text(f"{stale.pid}\n")
        (work / "pids" / f"{'d' * 32}.pid").write_text("1\n")
        order = []
        real_kill = harness._kill

        def kill(pid):
            order.append(pid)
            real_kill(pid)

        monkeypatch.setattr(harness, "_kill", kill)
        harness.stop(work)
        assert order == [controller.pid, session.pid], order
        assert not Path(f"/proc/{controller.pid}").exists(), "the controller was not waited for"
        assert session.wait(timeout=30) == -signal.SIGKILL
        assert stale.poll() is None, "a pid that was no longer the run's session was killed"
        assert not list((work / "pids").glob("*.pid"))
    finally:
        for p in (controller, session, stale):
            p.kill()
            p.wait()
