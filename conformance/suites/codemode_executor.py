# SPDX-License-Identifier: Apache-2.0
"""``codemode-executor``: one program in a fresh sandbox that reaches only the broker (ADR-0031).

Every check runs real programs against a stand-in broker the suite serves where the executor
declares (``broker_bind``, loopback by default), and judges from outside the sandbox where it
can: a decoy listener that must see no connection, a canary in the harness's own environment and
files that must not appear in a result, a scratch marker a second run must not find, the calls
the broker saw.  Each check holds its programs per language: a language the executor declares
and the check has no program for fails the check as untested, never passes it.  The programs
are Python only for now; a TypeScript executor needs them written for it (docs/codemode.md).
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import secrets
import select
import shutil
import socket
import tempfile
import threading
from collections.abc import Mapping
from typing import Any

from conformance.fakes.code_executor import (
    CatchablePauseExecutor,
    ForkingExecutor,
    LeakyEnvExecutor,
    NoCallCapExecutor,
    NoTimeoutExecutor,
    OpenEgressExecutor,
    ReusedStateExecutor,
    UnboundedResultExecutor,
)
from conformance.protocols.codemode_executor import (
    DEFAULT_BROKER_BIND,
    ERROR_KINDS,
    MAX_PROGRAM_CHARS,
    MESSAGE_MAX,
    MESSAGE_UNSAFE,
    VALUE_JSON,
    BrokerEndpoint,
    ExecutionError,
    ExecutionResult,
    Limits,
    PendingCall,
    ProgramTooLarge,
    UnencodableProgram,
    UnsupportedLanguage,
)
from homelabnext.conform.core import Mutant, Suite

from ._util import raises

SUITE = Suite(
    "codemode-executor",
    "the sandbox for one Code Mode program: broker-only egress, no credentials, caps, disposable",
    "conformance.protocols.codemode_executor:CodeExecutor",
)

#: the caps of a check's run unless it sets its own: small, so a check that hits one is quick
LIMITS = Limits(cpu_s=2.0, memory_bytes=256 << 20, wall_s=5.0, output_bytes=4096, result_bytes=4096)
#: how long the harness waits for ``run`` past the run's own wall cap before calling it hung
_HUNG_S = 10.0


#: the stand-in broker's reasons and request ids (slugs, as schemas/codemode has them)
DENY_REASON, ERROR_REASON = "action-not-granted", "handler-failed"


class _Broker:
    """A stand-in broker: ``echo`` returns its args, ``hold`` is pending approval, ``fail``
    answers with an error, ``deny`` and anything else is denied, and a call with another token is
    denied.  Records every call it answers, and the pending replies it gave."""

    def __init__(self, bind: tuple[str, int]) -> None:
        self.token = secrets.token_hex(16)
        self.calls: list[tuple[str, str, Any]] = []
        self.pending: list[tuple[str, str]] = []  # (request_id, request_digest) given out
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(tuple(bind))
        self._sock.listen(16)
        self._sock.settimeout(0.05)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    @property
    def endpoint(self) -> BrokerEndpoint:
        host, port = self._sock.getsockname()[:2]
        return BrokerEndpoint(host, port, self.token)

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except OSError:
                continue
            with conn:
                conn.settimeout(2.0)
                buf = b""
                try:
                    while not buf.endswith(b"\n"):
                        chunk = conn.recv(65536)
                        if not chunk:
                            break
                        buf += chunk
                    req = json.loads(buf)
                    action, args = req.get("action"), req.get("args")
                    self.calls.append((req.get("token"), action, args))
                    conn.sendall(json.dumps(self._answer(req, buf)).encode() + b"\n")
                except (OSError, ValueError, AttributeError):
                    continue

    def _answer(self, req: dict, raw: bytes) -> dict:
        action = req.get("action")
        if req.get("token") != self.token:
            return {"ok": False, "denied": True, "reason": "token-invalid"}
        if action == "echo":
            return {"ok": True, "value": req.get("args")}
        if action == "hold":
            rid = f"req-{len(self.pending) + 1}"
            digest = "sha256:" + hashlib.sha256(raw).hexdigest()
            self.pending.append((rid, digest))
            return {"ok": False, "pending": True, "request_id": rid, "request_digest": digest}
        if action == "fail":
            return {"ok": False, "error": True, "reason": ERROR_REASON}
        return {"ok": False, "denied": True, "reason": DENY_REASON}

    def close(self) -> None:
        self._stop.set()
        with contextlib.suppress(OSError):  # wake the accept() now, not at its next timeout
            socket.create_connection(self._sock.getsockname()[:2], timeout=0.5).close()
        self._thread.join(timeout=1.0)
        self._sock.close()

    def __enter__(self) -> _Broker:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def _bind(ex: Any) -> tuple[str, int]:
    """Where the target's sandbox can reach the broker (``broker_bind``, else loopback)."""
    host, port = getattr(ex, "broker_bind", DEFAULT_BROKER_BIND)
    return str(host), int(port)


def _broker(ex: Any) -> _Broker:
    """The stand-in broker, served at the target's ``broker_bind``."""
    return _Broker(_bind(ex))


def _languages(ex: Any, *programs: Mapping[str, str]) -> list[str]:
    """The languages the target declares, each of which has a program in every table here.  A
    declared language a table lacks makes the check untested, which fails it: a check never
    passes on languages it did not run."""
    langs = sorted(ex.languages)
    assert langs, "the executor declares no language"
    missing = sorted({lang for lang in langs for table in programs if lang not in table})
    assert not missing, f"untested: this check has no program in {', '.join(missing)}"
    return langs


def _run(
    ex: Any, program: str, broker: _Broker, limits: Limits = LIMITS, language: str = "python"
) -> ExecutionResult:
    """``ex.run`` with a bound: a run that has not returned well past its own wall cap fails
    the check instead of hanging the harness."""
    box: dict[str, Any] = {}

    def go() -> None:
        try:
            box["result"] = ex.run(
                program, language=language, broker=broker.endpoint, limits=limits
            )
        except BaseException as exc:  # handed to the check below, as the subject raised it
            box["error"] = exc

    t = threading.Thread(target=go, daemon=True)
    t.start()
    t.join(limits.wall_s + _HUNG_S)
    assert not t.is_alive(), f"run did not return within {limits.wall_s + _HUNG_S}s"
    if "error" in box:
        raise box["error"]
    res = box["result"]
    assert isinstance(res, ExecutionResult), f"run returned {type(res).__name__}, not a result"
    return res


def _error(res: ExecutionResult, kind: str, what: str) -> ExecutionError:
    """The result is an error of ``kind`` whose message is one bounded, clean line."""
    err = res.error
    got = (res.status, err.kind if isinstance(err, ExecutionError) else err)
    assert got == ("error", kind), (
        f"{what}: status {got[0]!r} error {got[1]!r}, not ('error', {kind!r})"
    )
    assert kind in ERROR_KINDS
    assert isinstance(err.message, str) and len(err.message) <= MESSAGE_MAX, (
        f"{what}: an error message of {len(err.message)} characters (at most {MESSAGE_MAX})"
    )
    assert not re.search(MESSAGE_UNSAFE, err.message), f"{what}: the message is not one clean line"
    assert res.value is None, f"{what}: an error carries a value {res.value!r}"
    return err


def _ok(res: ExecutionResult, what: str) -> Any:
    assert res.status == "ok", f"{what}: status {res.status!r} ({res.error or res.limit}), not ok"
    return res.value


@SUITE.check(
    "broker-call-roundtrip",
    "a program's broker calls reach the broker with the run's token and their values come back",
)
def _(ex):
    programs = {
        "python": "a = broker.call('echo', {'n': 1})\n"
        "b = broker.call('echo', {'n': 2})\n"
        "result = {'sum': a['n'] + b['n'], 'nested': broker.call('echo', {'x': [1, 'y']})}\n",
    }
    for lang in _languages(ex, programs):
        with _broker(ex) as b:
            res = _run(ex, programs[lang], b, language=lang)
            assert _ok(res, "three echo calls") == {"sum": 3, "nested": {"x": [1, "y"]}}, res.value
            assert [(t, a) for t, a, _ in b.calls] == [(b.token, "echo")] * 3, b.calls


@SUITE.check(
    "no-network-but-broker",
    "a program cannot connect or send to anything but the broker, nor resolve a name",
)
def _(ex):
    host = _bind(ex)[0]  # the decoys listen on other ports of the broker's host
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        tcp.bind((host, 0))
        tcp.listen(8)
        udp.bind((host, 0))
        tport, uport = tcp.getsockname()[1], udp.getsockname()[1]
        program = f"""
import socket
tried = {{}}
def attempt(name, fn):
    try:
        fn()
        tried[name] = 'reached'
    except OSError:
        tried[name] = 'refused'
def tcp():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    try:
        s.connect(({host!r}, {tport}))
    finally:
        s.close()
def tcp_ex():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    try:
        if s.connect_ex(({host!r}, {tport})) != 0:
            raise OSError('connect_ex refused')
    finally:
        s.close()
def udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.sendto(b'x', ({host!r}, {uport}))
    finally:
        s.close()
def lookup():
    socket.getaddrinfo('localhost', {tport})
def by_name():
    socket.create_connection(('localhost', {tport}), timeout=1).close()
for name, fn in [('tcp', tcp), ('tcp-ex', tcp_ex), ('udp', udp), ('lookup', lookup),
                 ('by-name', by_name)]:
    attempt(name, fn)
result = {{'tried': tried, 'broker': broker.call('echo', {{'still': 'reachable'}})}}
"""
        programs = {"python": program}
        for lang in _languages(ex, programs):
            with _broker(ex) as b:
                got = _ok(_run(ex, programs[lang], b, language=lang), "egress probes")
            assert got["broker"] == {"still": "reachable"}, f"the broker was not reachable: {got}"
            reached = sorted(k for k, v in got["tried"].items() if v != "refused")
            assert not reached, f"the program reached past the broker: {reached}"
            ready, _, _ = select.select([tcp, udp], [], [], 0.02)
            assert not ready, "the decoy listener saw traffic from the sandbox"
    finally:
        tcp.close()
        udp.close()


@SUITE.check(
    "no-credentials",
    "the sandbox environment and readable files hold none of the caller's secrets, nor the token",
)
def _(ex):
    name, value = "HNX_CONFORM_CANARY_TOKEN", secrets.token_hex(16)
    home = tempfile.mkdtemp(prefix="hnx-canary-")
    path = os.path.join(home, "credentials")
    with open(path, "w", encoding="utf-8") as f:
        f.write(value)
    before = os.environ.get(name)
    os.environ[name] = value  # in the harness's own environment, as a runner's would be
    try:
        program = f"""
import os
seen = {{'env': dict(os.environ), 'files': {{}}}}
for p in [{path!r}]:
    try:
        with open(p) as f:
            seen['files'][p] = f.read()
    except OSError:
        pass
for d in sorted({{os.getcwd(), os.path.expanduser('~')}}):
    for n in os.listdir(d):
        try:
            with open(os.path.join(d, n)) as f:
                seen['files'][os.path.join(d, n)] = f.read(4096)
        except OSError:
            pass
result = seen
"""
        programs = {"python": program}
        for lang in _languages(ex, programs):
            with _broker(ex) as b:
                res = _run(ex, programs[lang], b, Limits(result_bytes=1 << 20), lang)
                got = _ok(res, "reading the environment and files")
                assert not res.truncated, "the probe's result was truncated; it cannot be judged"
                text = json.dumps(got)
                assert value not in text, "the caller's canary secret is visible in the sandbox"
                assert name not in got["env"], f"the caller's {name} is in the sandbox environment"
                env = json.dumps(got["env"])
                assert b.token not in env, "the broker token is in the environment"
                assert path not in got["files"], "the caller's credentials file is readable"
    finally:
        if before is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = before
        shutil.rmtree(home, ignore_errors=True)


@SUITE.check(
    "limits-enforced",
    "CPU, memory, wall-clock and output caps end the run with status limit naming the cap",
)
def _(ex):
    cases = [
        ("cpu", {"python": "while True:\n    pass\n"}, Limits(cpu_s=0.05, wall_s=5.0)),
        # resident memory: every chunk is written, so it is committed, not only reserved; a
        # refused allocation is retried, so only the cap can end the run
        (
            "memory",
            {
                "python": "x = []\nwhile True:\n    try:\n        x.append(b'x' * (1 << 20))\n"
                "    except MemoryError:\n        pass\n"
            },
            Limits(memory_bytes=64 << 20),
        ),
        (
            "wall",
            {"python": "import time\ntime.sleep(0.3)\nresult = 'slept'\n"},
            Limits(wall_s=0.05),
        ),
        (
            "output",
            {"python": "for _ in range(1024):\n    print('x' * 1023)\nresult = 'printed'\n"},
            Limits(output_bytes=4096),
        ),
        # four-byte characters: a line is 4093 bytes, so the cap falls three bytes into a
        # character, which is dropped, never returned half or as U+FFFD
        (
            "output",
            {
                "python": "for _ in range(1024):\n    print('\\U0001f600' * 1023)\n"
                "result = 'printed'\n"
            },
            Limits(output_bytes=4096),
        ),
    ]
    langs = _languages(ex, *(programs for _, programs, _ in cases))
    with _broker(ex) as b:
        for (cap, programs, limits), lang in ((c, lang) for c in cases for lang in langs):
            res = _run(ex, programs[lang], b, limits, lang)
            assert (res.status, res.limit) == ("limit", cap), (
                f"over the {cap} cap: status {res.status!r} limit {res.limit!r}, "
                f"not ('limit', {cap!r})"
            )
            assert len(res.output.encode()) <= limits.output_bytes, f"{cap}: output past its cap"
            assert "\ufffd" not in res.output, f"{cap}: the output cut left a broken character"


@SUITE.check(
    "disposable",
    "a second run sees no file, variable or interpreter state the first one left",
)
def _(ex):
    mark = "hnx-mark-" + secrets.token_hex(4)
    attr = mark.replace("-", "_")
    first = f"""
import builtins, os, sys, tempfile
wrote = []
for d in sorted({{os.getcwd(), tempfile.gettempdir(), os.path.expanduser('~')}}):
    try:
        with open(os.path.join(d, {mark!r}), 'w') as f:
            f.write('1')
        wrote.append(d)
    except OSError:
        pass
os.environ[{mark!r}] = '1'
setattr(builtins, {attr!r}, 1)
sys.modules[{mark!r}] = sys
result = wrote
"""
    for lang in _languages(ex, {"python": first}):
        _disposable(ex, lang, first, mark, attr)


def _disposable(ex: Any, lang: str, first: str, mark: str, attr: str) -> None:
    with _broker(ex) as b:
        wrote = _ok(_run(ex, first, b, language=lang), "the first run")
        assert wrote, "the first run found no writable scratch directory (cwd, TMPDIR or HOME)"
        second = f"""
import builtins, os, sys, tempfile
found = []
for d in sorted(set({wrote!r}) | {{os.getcwd(), tempfile.gettempdir(), os.path.expanduser('~')}}):
    if os.path.exists(os.path.join(d, {mark!r})):
        found.append('file in ' + d)
if {mark!r} in os.environ:
    found.append('environment variable')
if hasattr(builtins, {attr!r}) or {mark!r} in sys.modules:
    found.append('interpreter state')
result = found
"""
        found = _ok(_run(ex, second, b, language=lang), "the second run")
    assert found == [], f"the second run saw the first run's {found}"


@SUITE.check(
    "result-bounded",
    "a value longer than result_bytes comes back as a truncated prefix, never whole",
)
def _(ex):
    limits = Limits(result_bytes=4095)
    big_programs = {
        "python": "result = {'rows': ['\\u00e9t\\u00e9-' + str(i) for i in range(5000)]}\n"
    }
    small_programs = {"python": "result = {'a': [1, 2], 'b': None}\n"}
    for lang in _languages(ex, big_programs, small_programs):
        _bounded(ex, lang, limits, big_programs[lang], small_programs[lang])


def _bounded(ex: Any, lang: str, limits: Limits, big_program: str, small_program: str) -> None:
    with _broker(ex) as b:
        big = _run(ex, big_program, b, limits, lang)
        # the pinned serialization (VALUE_JSON), so the prefix is judged byte for byte
        full = json.dumps({"rows": [f"été-{i}" for i in range(5000)]}, **VALUE_JSON)
        assert big.status == "ok" and big.truncated is True, (
            f"a {len(full.encode())}-byte value over a {limits.result_bytes}-byte cap: "
            f"status {big.status!r}, truncated {big.truncated!r}"
        )
        assert isinstance(big.value, str), f"a truncated value is {type(big.value).__name__}"
        size = len(big.value.encode())
        assert 0 < size <= limits.result_bytes, f"the truncated value is {size} bytes"
        assert full.startswith(big.value), "the truncated value is not a prefix of the value"
        small = _run(ex, small_program, b, limits, lang)
        assert (small.status, small.truncated) == ("ok", False), small
        assert small.value == {"a": [1, 2], "b": None}, small.value


@SUITE.check(
    "program-error-is-a-status",
    "a program that fails to compile, raises, exits non-zero or leaves a non-JSON value ends error",
)
def _(ex):
    cases = [
        ("syntax", {"python": "def broken(:\n    pass\n"}),
        # a long, multi-line message: it comes back as one line of at most MESSAGE_MAX characters
        ("runtime", {"python": "raise ValueError('line one\\nline two\\u2028' + 'x' * 5000)\n"}),
        ("runtime", {"python": "result = object()\n"}),
        # raised by the program, not an exhausted cap: a runtime error, never limit memory
        ("runtime", {"python": "raise MemoryError('raised, not exhausted')\n"}),
        ("runtime", {"python": "import sys\nsys.exit(3)\n"}),
    ]
    clean_exit = {"python": "import sys\nresult = 'done'\nsys.exit(0)\n"}
    langs = _languages(ex, clean_exit, *(programs for _, programs in cases))
    with _broker(ex) as b:
        for lang in langs:
            for kind, programs in cases:
                _error(_run(ex, programs[lang], b, language=lang), kind, programs[lang].strip())
            assert _ok(_run(ex, clean_exit[lang], b, language=lang), "exit 0") == "done"


@SUITE.check(
    "denied-call-is-a-status",
    "a denied broker call raises broker.Denied in the program; escaping, it ends the run denied",
)
def _(ex):
    caught = {
        "python": "try:\n    broker.call('deny', {})\nexcept broker.Denied:\n    result = 'caught'\n"
    }
    escaped = {"python": "broker.call('deny', {})\nresult = 'went on'\n"}
    for lang in _languages(ex, caught, escaped):
        with _broker(ex) as b:
            res = _run(ex, caught[lang], b, language=lang)
            assert _ok(res, "a caught denial") == "caught", res.value
            res = _run(ex, escaped[lang], b, language=lang)
            assert res.status == "denied", f"an escaping denial ended {res.status!r}"
            assert res.value is None, f"a denied run carries a value {res.value!r}"


@SUITE.check(
    "denial-reason-reaches-the-program",
    "the reason the broker gives for a denial is the reason the program reads",
)
def _(ex):
    programs = {
        "python": "try:\n    broker.call('deny', {})\nexcept broker.Denied as e:\n"
        "    result = e.reason\n"
    }
    for lang in _languages(ex, programs):
        with _broker(ex) as b:
            got = _ok(_run(ex, programs[lang], b, language=lang), "a caught denial")
        assert got == DENY_REASON, (
            f"the program read reason {got!r}, the broker gave {DENY_REASON!r}"
        )


@SUITE.check(
    "pending-pauses-the-run",
    "a call that needs approval ends the run paused, with the call pending; the program cannot "
    "swallow it",
)
def _(ex):
    programs = {
        "python": "broker.call('echo', {'n': 0})\n"
        "try:\n    broker.call('hold', {'n': 1})\nexcept Exception:\n    result = 'swallowed'\n"
        "broker.call('echo', {'after': 'the pause'})\nresult = 'went on'\n"
    }
    for lang in _languages(ex, programs):
        with _broker(ex) as b:
            res = _run(ex, programs[lang], b, language=lang)
            assert res.status == "paused", (
                f"a pending call ended the run {res.status!r} (value {res.value!r}), not paused"
            )
            ((rid, digest),) = b.pending
            assert res.pending == (PendingCall(1, "hold", rid, digest),), res.pending
            assert [a for _, a, _ in b.calls] == ["echo", "hold"], (
                f"the program went on calling after the pause: {b.calls}"
            )
            assert res.value is None, f"a paused run carries a value {res.value!r}"


@SUITE.check(
    "broker-error-is-an-error",
    "an error reply is a catchable broker.Error; escaping, it or an unreachable broker ends the "
    "run with error kind broker",
)
def _(ex):
    caught = {
        "python": "try:\n    broker.call('fail', {})\nexcept broker.Error as e:\n    result = e.reason\n"
    }
    escaped = {"python": "broker.call('fail', {})\nresult = 'went on'\n"}
    unreachable = {"python": "broker.call('echo', {})\nresult = 'reached'\n"}
    for lang in _languages(ex, caught, escaped, unreachable):
        with _broker(ex) as b:
            got = _ok(_run(ex, caught[lang], b, language=lang), "a caught error reply")
            assert got == ERROR_REASON, f"the program read reason {got!r}, not {ERROR_REASON!r}"
            _error(_run(ex, escaped[lang], b, language=lang), "broker", "an escaping error reply")
        # an endpoint nothing answers on: a socket held bound but not listening for the run, so
        # the port cannot be taken by anything else meanwhile
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as held:
            held.bind(_bind(ex))
            host, port = held.getsockname()[:2]
            box = _Gone(BrokerEndpoint(host, port, secrets.token_hex(16)))
            res = _run(ex, unreachable[lang], box, language=lang)
        _error(res, "broker", "an unreachable broker")


class _Gone:
    """An endpoint with no broker behind it, in ``_run``'s broker slot."""

    def __init__(self, endpoint: BrokerEndpoint) -> None:
        self.endpoint = endpoint


@SUITE.check(
    "call-cap-enforced",
    "a call past max_calls is refused before the broker as call-cap-reached, and the run goes on",
)
def _(ex):
    programs = {
        "python": "got = []\nfor i in range(3):\n    try:\n"
        "        got.append(broker.call('echo', {'i': i}))\n"
        "    except broker.Denied as e:\n        got.append(e.reason)\nresult = got\n"
    }
    for lang in _languages(ex, programs):
        with _broker(ex) as b:
            res = _run(ex, programs[lang], b, Limits(max_calls=2), lang)
            got = _ok(res, "three calls under a cap of two")
            assert len(b.calls) == 2, f"the broker saw {len(b.calls)} calls under a cap of two"
            assert got == [{"i": 0}, {"i": 1}, "call-cap-reached"], got


@SUITE.check(
    "unencodable-program-refused",
    "a program that is not UTF-8 text (a lone surrogate) is refused before anything runs",
)
def _(ex):
    programs = {"python": "broker.call('echo', {})\nresult = '\ud800'\n"}
    for lang in _languages(ex, programs):
        with _broker(ex) as b:
            raises(
                lambda lang=lang: ex.run(
                    programs[lang], language=lang, broker=b.endpoint, limits=LIMITS
                ),
                "a program holding a lone surrogate",
                UnencodableProgram,
            )
            assert b.calls == [], f"the refused program ran: {b.calls}"


@SUITE.check(
    "oversized-program-refused",
    f"a program longer than {MAX_PROGRAM_CHARS} characters is refused before anything runs; one "
    "of exactly that length runs",
)
def _(ex):
    heads = {"python": "result = 'fits'\n#"}
    for lang in _languages(ex, heads):
        head = heads[lang]
        # four UTF-8 bytes a character: the cap is in characters, whatever the encoding
        fits = head + "\U0001f600" * (MAX_PROGRAM_CHARS - len(head))
        with _broker(ex) as b:
            assert _ok(_run(ex, fits, b, language=lang), "a program at the cap") == "fits"
            raises(
                lambda p=fits + "x", lang=lang: ex.run(
                    p, language=lang, broker=b.endpoint, limits=LIMITS
                ),
                f"a program of {MAX_PROGRAM_CHARS + 1} characters",
                ProgramTooLarge,
            )
            assert b.calls == [], f"the refused program ran: {b.calls}"


@SUITE.check(
    "unknown-language-refused",
    "a language the executor does not list is refused before anything runs",
)
def _(ex):
    assert ex.languages and "cobol" not in ex.languages, f"languages {sorted(ex.languages)}"
    with _broker(ex) as b:
        raises(
            lambda: ex.run(
                "broker.call('echo', {})", language="cobol", broker=b.endpoint, limits=LIMITS
            ),
            "language cobol",
            UnsupportedLanguage,
        )
        assert b.calls == [], f"the refused program ran: {b.calls}"


@SUITE.check(
    "output-returned",
    "what the program prints comes back as output",
    severity="should",
)
def _(ex):
    programs = {"python": "print('hello from the sandbox')\nresult = 1\n"}
    for lang in _languages(ex, programs):
        with _broker(ex) as b:
            res = _run(ex, programs[lang], b, language=lang)
        assert _ok(res, "printing") == 1
        assert "hello from the sandbox" in res.output, f"output {res.output!r}"


def make_fake():
    return ForkingExecutor()


MUTANTS = {
    "open-egress": Mutant(
        OpenEgressExecutor,
        "no-network-but-broker",
        "the sandbox's network is on: a program reaches any address, not only the broker",
    ),
    "env-leak": Mutant(
        LeakyEnvExecutor,
        "no-credentials",
        "the sandbox inherits the caller's environment variables",
    ),
    "no-timeout": Mutant(
        NoTimeoutExecutor,
        "limits-enforced",
        "no wall-clock cap: a program that sleeps runs as long as it likes",
    ),
    "reused-state": Mutant(
        ReusedStateExecutor,
        "disposable",
        "one scratch directory for every run, never cleaned",
    ),
    "no-call-cap": Mutant(
        NoCallCapExecutor,
        "call-cap-enforced",
        "the broker client never counts calls; a loop calls the broker without end",
    ),
    "pause-catchable": Mutant(
        CatchablePauseExecutor,
        "pending-pauses-the-run",
        "a pending reply is an ordinary exception: except Exception swallows the pause",
    ),
    "unbounded-result": Mutant(
        UnboundedResultExecutor,
        "result-bounded",
        "an oversized value is returned whole",
    ),
}
