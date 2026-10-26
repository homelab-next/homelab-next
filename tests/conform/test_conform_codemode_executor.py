# SPDX-License-Identifier: Apache-2.0
"""The codemode-executor suite's harness rules and the reference fake's own fixes.

The suite (``conformance/suites/codemode_executor.py``) proves the contract; these pin what it
cannot see from one subject: that a declared language without programs is never a pass, that
the broker is served where the executor says, and the fake's output cut, program-size refusal
and kill of a run stopped before it started its session.
"""

import json
import os
import socket

import pytest

from conformance.fakes import code_executor as fake
from conformance.protocols.codemode_executor import (
    MAX_PROGRAM_CHARS,
    MESSAGE_MAX,
    BrokerEndpoint,
    Limits,
    PendingCall,
    ProgramTooLarge,
    UnencodableProgram,
)
from conformance.suites import codemode_executor as suite
from homelabnext.conform.core import run_checks

LOOPBACK = "127.0.0.1"  # no-raw-endpoint: allow the tests bind loopback only


def _run(ex, program, limits=None):
    with suite._Broker((LOOPBACK, 0)) as b:
        return ex.run(program, language="python", broker=b.endpoint, limits=limits or Limits())


class _TwoLanguages(fake.ForkingExecutor):
    languages = frozenset({"python", "typescript"})


def test_a_declared_language_without_programs_is_untested_never_a_pass():
    results = {r.check: r for r in run_checks(suite.SUITE, _TwoLanguages)}
    runs_programs = set(results) - {"unknown-language-refused"}
    for check in runs_programs:
        assert not results[check].ok, check
        assert "untested: this check has no program in typescript" in results[check].evidence
    assert results["unknown-language-refused"].ok


def test_the_broker_is_served_where_the_executor_declares():
    with socket.socket() as s:
        s.bind((LOOPBACK, 0))
        port = s.getsockname()[1]
    seen = []

    class Declared(fake.ForkingExecutor):
        broker_bind = (LOOPBACK, port)

        def run(self, program, *, language, broker, limits):
            seen.append((broker.host, broker.port))
            return super().run(program, language=language, broker=broker, limits=limits)

    (res,) = run_checks(suite.SUITE, Declared, only=["broker-call-roundtrip"])
    assert res.ok, res.evidence
    assert seen == [(LOOPBACK, port)]


@pytest.mark.parametrize(
    ("data", "limit"),
    [
        ("été".encode() * 2000, 4096),  # multi-byte characters across the cut
        (b"\xff" * 8000, 4096),  # each invalid byte becomes a three-byte U+FFFD
        (b"ok \xe2\x82", 4096),  # a character cut in half by the child
        (b"x" * 10, 4),
    ],
)
def test_output_is_cut_on_a_character_boundary_within_its_bytes(data, limit):
    text = fake.cut_text(data, limit)
    assert len(text.encode()) <= limit
    assert text  # something survives the cut


def test_printed_invalid_and_multibyte_output_stays_within_its_cap():
    ex = fake.ForkingExecutor()
    try:
        for program in (
            "import sys\nsys.stdout.buffer.write(b'\\xff' * 3000)\nresult = 1\n",
            "print('\\u00e9' * 2047)\nresult = 1\n",
        ):
            res = _run(ex, program, Limits(output_bytes=4096))
            assert res.status == "ok", res
            assert len(res.output.encode()) <= 4096, len(res.output.encode())
    finally:
        ex.close()


def test_a_megabyte_program_is_refused_not_a_crash():
    ex = fake.ForkingExecutor()
    endpoint = BrokerEndpoint(LOOPBACK, 9, "t")
    with pytest.raises(ProgramTooLarge):
        ex.run("#" * (1 << 20), language="python", broker=endpoint, limits=Limits())
    assert len("#" * MAX_PROGRAM_CHARS) == MAX_PROGRAM_CHARS


def test_error_messages_are_one_bounded_line():
    msg = fake.clean_message("a\nb\r\u2028c\u202ed\te" + "x" * 5000)
    assert len(msg) == MESSAGE_MAX and msg.startswith("a b  c d\te")


def test_a_run_stopped_before_its_session_exists_still_dies(monkeypatch):
    """The group exists only once the child has called setsid(); with the group kill failing as
    it would then, the direct kill still ends the process before run() returns."""
    pids = []
    real_watch = fake.ForkingExecutor._watch

    def watch(self, pid, *args, **kw):
        pids.append(pid)
        return real_watch(self, pid, *args, **kw)

    def no_group(pid, sig):
        raise ProcessLookupError(pid)

    monkeypatch.setattr(fake.ForkingExecutor, "_watch", watch)
    monkeypatch.setattr(fake.os, "killpg", no_group)
    ex = fake.ForkingExecutor()
    try:
        res = _run(ex, "import time\ntime.sleep(30)\n", Limits(wall_s=0.05))
    finally:
        ex.close()
    assert (res.status, res.limit) == ("limit", "wall")
    (pid,) = pids
    assert not os.path.exists(f"/proc/{pid}"), "the stopped run's process outlived run()"


def test_a_split_character_is_dropped_not_replaced():
    assert fake.cut_text("aé".encode() * 3, 4) == "aéa"  # "aéaé" cut at 4 bytes: é dropped
    assert "\ufffd" not in fake.cut_text("é".encode() * 3000, 4095)
    assert fake.cut_text(b"\xff\xe2\x82", 2) == ""  # a replacement that does not fit is dropped
    # three bytes of a four-byte character: a U+FFFD would fit, and must still not appear
    assert fake.cut_text("\U0001f600".encode() * 2, 7) == "\U0001f600"


def test_a_lone_surrogate_program_is_refused_not_a_crash():
    ex = fake.ForkingExecutor()
    endpoint = BrokerEndpoint(LOOPBACK, 9, "t")
    with pytest.raises(UnencodableProgram):
        ex.run("result = '\ud800'", language="python", broker=endpoint, limits=Limits())
    assert issubclass(UnencodableProgram, ValueError)


def test_messages_lose_zero_width_bidi_bom_and_surrogate_characters():
    msg = fake.clean_message("a\u200bb\u200fc\u061cd\ufeffe\ud800f\tg")
    assert msg == "a b c d e f\tg"


_PENDING = {
    "step": 1,
    "action": "hold",
    "request_id": "req-1",
    "request_digest": "sha256:" + "0" * 64,
}


@pytest.mark.parametrize(
    "header",
    [
        b"not json",
        b"[1, 2]",
        b'{"status": "running"}',
        b'{"status": "limit", "limit": "cpu"}',  # a limit is the parent's to decide
        b'{"status": "error", "error": "a string"}',
        b'{"status": "paused"}',
        b'{"status": "paused", "pending": []}',
        b'{"status": "paused", "pending": [{"step": 1}]}',
        b'{"status": "paused", "pending": ["x"]}',
        json.dumps({"status": "paused", "pending": [{**_PENDING, "step": "1"}]}).encode(),
        json.dumps({"status": "paused", "pending": [{**_PENDING, "step": -1}]}).encode(),
        json.dumps({"status": "paused", "pending": [{**_PENDING, "request_id": 7}]}).encode(),
    ],
)
def test_a_forged_or_malformed_result_header_is_a_sandbox_error(header):
    res = fake.outcome(header, b"", False, "")
    assert (res.status, res.error.kind) == ("error", "sandbox"), res


def test_an_unreadable_value_is_a_sandbox_error():
    res = fake.outcome(b'{"status": "ok"}', b"{not json", False, "")
    assert (res.status, res.error.kind) == ("error", "sandbox")


def test_a_valid_pending_header_is_cleaned_and_kept():
    entry = {**_PENDING, "action": "hold\u2028x"}
    res = fake.outcome(
        json.dumps({"status": "paused", "pending": [entry]}).encode(), b"", False, ""
    )
    assert res.status == "paused"
    assert res.pending == (PendingCall(1, "hold x", "req-1", _PENDING["request_digest"]),)


def test_an_error_header_with_an_unknown_kind_or_unsafe_message_is_cleaned():
    header = {"status": "error", "error": {"kind": "made-up", "message": "a\nb" + "x" * 3000}}
    res = fake.outcome(json.dumps(header).encode(), b"", False, "")
    assert res.error.kind == "sandbox" and len(res.error.message) == MESSAGE_MAX
    assert "\n" not in res.error.message
