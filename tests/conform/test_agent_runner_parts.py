# SPDX-License-Identifier: Apache-2.0
"""The agent-runner suite's development launcher, piece by piece (ADR-0051 step 2): what the
suite's checks cannot pin down on their own."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from conformance.fakes import agent_runner_body as body
from conformance.fakes.agent_runner_launcher import SUPERVISOR, _count_calls, classify
from homelabnext.orchestration.trace import RUN_TOKEN_HEADER


class _NoGateway:
    def records(self, tag):
        return []

    def dropped(self):
        return 0

    def watermark(self):
        return 2_000_000_000.0  # later than any run's end below


def test_the_body_sends_the_run_token_in_the_shared_header():
    # the body imports nothing of the repository, so its copy is held equal here
    assert body.RUN_TOKEN_HEADER == RUN_TOKEN_HEADER == "X-HNX-Run-Token"


def test_a_stop_keeps_the_bodys_status_when_the_sweep_reaps_it():
    """The SIGTERM handler's sweep reaps every child, the body included: the supervisor must
    record the body's own end (killed by the sweep's SIGKILL), never a clean exit."""
    rd, wr = os.pipe()
    sup = subprocess.Popen(
        [sys.executable, "-I", str(SUPERVISOR), str(wr), "--", "sleep", "30"], pass_fds=(wr,)
    )
    os.close(wr)
    try:
        deadline = time.monotonic() + 10
        while not _has_child(sup.pid) and time.monotonic() < deadline:
            time.sleep(0.02)
        sup.send_signal(signal.SIGTERM)
        assert sup.wait(30) == 0
    finally:
        sup.kill()
    with os.fdopen(rd, "rb") as f:
        ended = json.loads(f.read())
    assert ended == {"stopped": True, "signal": signal.SIGKILL}, ended


def _has_child(pid: int) -> bool:
    for name in os.listdir("/proc"):
        if name.isdigit():
            try:
                stat = Path(f"/proc/{name}/stat").read_text()
            except OSError:
                continue
            if int(stat.rsplit(")", 1)[1].split()[1]) == pid:
                return True
    return False


def _run(launcher, w, body=None, **kw):
    from conformance.suites.agent_runner import _session

    return _session(launcher, w, w.run(**kw), body=body)[1]


def test_a_record_the_body_plants_is_never_read():
    """The body shares the development launcher's uid and knows the run's root: a clean-exit
    record it writes there must not hide how it really ended (exit 3, which nothing maps)."""
    from conformance.fakes.agent_runner_launcher import DevLauncher
    from conformance.suites.agent_runner import PROBE, World

    w = World()
    try:
        out = _run(DevLauncher(gateway_wait_s=0.1), w, [sys.executable, "-I", str(PROBE), "plant"])
    finally:
        w.close()
    assert (out.exit_code, out.cls) == (3, "Internal"), (out.exit_code, out.cls, out.detail)


def test_the_launcher_refuses_a_spec_naming_another_gateway():
    """The trusted launcher holds the pin itself, so the property does not rest on the body."""
    from conformance.fakes.agent_runner_launcher import DevLauncher
    from conformance.fakes.runner_world import FakeGateway
    from conformance.suites.agent_runner import World

    w, elsewhere = World(), FakeGateway()
    try:
        trusting = DevLauncher(
            [sys.executable, "-I", str(body.__file__), "--mutant", "follows-spec-url"],
            gateway_wait_s=0.1,
        )
        out = _run(trusting, w, gateway_url=elsewhere.url, pinned_gateway=w.gateway.url)
    finally:
        elsewhere.close()
        w.close()
    assert out.cls == "Internal" and "pinned" in out.detail, (out.cls, out.detail)
    assert elsewhere.calls == []


def test_a_supervisor_that_does_not_exit_0_loses_the_record():
    """No record, or a supervisor that failed, is never read as a clean exit."""
    from conformance.fakes.agent_runner_launcher import DevLauncher, _Run

    rd, wr = os.pipe()
    os.write(wr, b'{"stopped": false, "code": 0}')
    os.close(wr)
    proc = subprocess.Popen([sys.executable, "-c", "raise SystemExit(1)"])
    proc.wait()
    h = _Run(run=None, gateway=None, root=Path("/nonexistent"), proc=proc)  # type: ignore[arg-type]
    h.record_fd = rd
    assert DevLauncher()._record(h) == {"lost": True}


@pytest.mark.parametrize(
    ("ended", "why"),
    [({"code": 0, "survivors": [4242]}, "survived"), ({"lost": True}, "lost")],
)
def test_a_run_whose_end_is_not_clean_is_internal(ended, why):
    cls, detail = classify(
        stopped=None, ended=ended, records=[{"type": "end", "turns": 1}], why_invalid="",
        exit_classes={}, gateway=_NoGateway(), tag="t", end_time=1_000_000_000.0,
    )  # fmt: skip
    assert cls == "Internal" and why in detail, (cls, detail)


def test_progress_counts_records_however_spaced_and_never_a_bad_line():
    raw = b"\n".join(
        [
            b'{"type":"call","role":"r","sized":false,"span_id":"00f067aa0ba902b7"}',
            b'{"type": "call", "role": "r", "sized": false, "span_id": "00f067aa0ba902b8"}',
            b'{"type": "tool_call"}',
            b'{"type": "call", "pad": "' + b"x" * 17000 + b'"}',
            b'{"type": "ca',
        ]
    )
    assert _count_calls(raw) == 2


@pytest.mark.parametrize(
    "check",
    [
        "gateway-url-is-pinned",
        "stall-counts-only-corroborated-progress",
        "progress-reads-any-json-spacing",
        "context-refusal-is-context-exceeded",
    ],
)
def test_the_checks_of_this_round_pass_on_the_fake(check):
    from homelabnext.conform import run_capability

    (res,) = run_capability("agent-runner", "fake", only=[check]).results
    assert res.status == "pass", res.evidence


def test_a_body_that_follows_the_specs_gateway_is_caught():
    from homelabnext.conform import run_capability

    run = run_capability("agent-runner", "broken:follows-spec-url", only=["gateway-url-is-pinned"])
    assert [r.check for r in run.failed_must] == ["gateway-url-is-pinned"]


def test_every_launcher_rule_check_runs_on_every_target():
    """No check is gated on a feature: a provider's target supplies its body and exit_classes and
    runs under the reference launcher, so the launcher's rules are never skipped."""
    from homelabnext.conform.registry import load_module

    assert [s.id for s in load_module("agent-runner").SUITE.specs if s.requires] == []


def test_a_stall_timeout_under_twice_the_gateway_wait_is_refused():
    """A stall shorter than the time records may take to arrive would stall runs whose records
    are merely late: the launcher refuses it before starting anything (ADR-0051 decision 10)."""
    from conformance.fakes.agent_runner_launcher import DevLauncher, min_stall_timeout
    from conformance.suites.agent_runner import World

    assert min_stall_timeout(2.0) == pytest.approx(4.05)
    w = World()
    try:
        out = _run(DevLauncher(gateway_wait_s=1.0), w, limits={"stall_timeout_s": 1.5})
    finally:
        w.close()
    assert out.cls == "Internal" and "stall_timeout_s" in out.detail, (out.cls, out.detail)
    assert w.gateway.calls == []


@pytest.mark.parametrize(
    "check", ["stale-records-freeze-the-stall-timer", "an-old-drop-does-not-stale-a-new-run"]
)
def test_the_stale_record_checks_pass_on_the_fake(check):
    from homelabnext.conform import run_capability

    (res,) = run_capability("agent-runner", "fake", only=[check]).results
    assert res.status == "pass", res.evidence
