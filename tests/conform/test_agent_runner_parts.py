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
        return time.time() + 60


def test_the_body_sends_the_run_token_in_the_shared_header():
    # the body imports nothing of the repository, so its copy is held equal here
    assert body.RUN_TOKEN_HEADER == RUN_TOKEN_HEADER == "X-HNX-Run-Token"


def test_a_stop_keeps_the_bodys_status_when_the_sweep_reaps_it(tmp_path):
    """The SIGTERM handler's sweep reaps every child, the body included: the supervisor must
    record the body's own end (killed by the sweep's SIGKILL), never a clean exit."""
    exit_file = tmp_path / "exit.json"
    sup = subprocess.Popen(
        [sys.executable, "-I", str(SUPERVISOR), str(exit_file), "--", "sleep", "30"]
    )
    try:
        deadline = time.monotonic() + 10
        while not _has_child(sup.pid) and time.monotonic() < deadline:
            time.sleep(0.02)
        sup.send_signal(signal.SIGTERM)
        assert sup.wait(30) == 0
    finally:
        sup.kill()
    ended = json.loads(exit_file.read_text())
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


def test_the_exit_file_is_never_written_through_a_link(tmp_path):
    target = tmp_path / "elsewhere"
    target.write_text("untouched")
    exit_file = tmp_path / "exit.json"
    exit_file.symlink_to(target)
    sup = subprocess.run(
        [sys.executable, "-I", str(SUPERVISOR), str(exit_file), "--", "true"],
        capture_output=True,
        check=False,
    )
    assert sup.returncode != 0 and target.read_text() == "untouched"


@pytest.mark.parametrize(
    ("ended", "why"),
    [({"code": 0, "survivors": [4242]}, "survived"), ({"lost": True}, "lost")],
)
def test_a_run_whose_end_is_not_clean_is_internal(ended, why):
    cls, detail = classify(
        stopped=None, ended=ended, records=[{"type": "end", "turns": 1}], why_invalid="",
        exit_classes={}, gateway=_NoGateway(), tag="t", end_time=time.time(),
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
