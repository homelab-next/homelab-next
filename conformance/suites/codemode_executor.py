# SPDX-License-Identifier: Apache-2.0
"""``codemode-executor``: one program in a fresh sandbox that reaches only the broker (ADR-0031).

Every check runs real programs against a stand-in broker the suite serves on loopback, and
judges from outside the sandbox where it can: a decoy listener that must see no connection, a
canary in the harness's own environment and files that must not appear in a result, a scratch
marker a second run must not find.  The programs are Python (the only language the reference
fake runs; a TypeScript executor needs the same programs written for it, docs/codemode.md).
"""

from __future__ import annotations

import contextlib
import json
import os
import secrets
import select
import shutil
import socket
import tempfile
import threading
from typing import Any

from conformance.fakes.code_executor import (
    ForkingExecutor,
    LeakyEnvExecutor,
    NoTimeoutExecutor,
    OpenEgressExecutor,
    ReusedStateExecutor,
    UnboundedResultExecutor,
)
from conformance.protocols.codemode_executor import (
    BrokerEndpoint,
    ExecutionResult,
    Limits,
    UnsupportedLanguage,
)
from homelabnext.conform.core import Mutant, Suite

from ._util import raises

SUITE = Suite(
    "codemode-executor",
    "the sandbox for one Code Mode program: broker-only egress, no credentials, caps, disposable",
    "conformance.protocols.codemode_executor:CodeExecutor",
)

LOOPBACK = "127.0.0.1"  # no-raw-endpoint: allow the stand-in broker binds loopback only
#: the caps of a check's run unless it sets its own: small, so a check that hits one is quick
LIMITS = Limits(cpu_s=2.0, memory_bytes=256 << 20, wall_s=5.0, output_bytes=4096, result_bytes=4096)
#: how long the harness waits for ``run`` past the run's own wall cap before calling it hung
_HUNG_S = 10.0


class _Broker:
    """A stand-in broker on loopback: ``echo`` returns its args, ``deny`` and anything else is
    denied, and a call with another token is denied.  Records every call it answers."""

    def __init__(self, host: str) -> None:
        self.token = secrets.token_hex(16)
        self.calls: list[tuple[str, str, Any]] = []
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.bind((host, 0))
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
                    ok = req.get("token") == self.token and action == "echo"
                    reply = {"ok": True, "value": args} if ok else {"ok": False, "denied": True}
                    conn.sendall(json.dumps(reply).encode() + b"\n")
                except (OSError, ValueError, AttributeError):
                    continue

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


def _broker(ex: Any) -> _Broker:
    """The stand-in broker, bound where the target's sandbox can reach it (``broker_host``)."""
    return _Broker(getattr(ex, "broker_host", LOOPBACK))


def _run(ex: Any, program: str, broker: _Broker, limits: Limits = LIMITS) -> ExecutionResult:
    """``ex.run`` with a bound: a run that has not returned well past its own wall cap fails
    the check instead of hanging the harness."""
    box: dict[str, Any] = {}

    def go() -> None:
        try:
            box["result"] = ex.run(
                program, language="python", broker=broker.endpoint, limits=limits
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


def _ok(res: ExecutionResult, what: str) -> Any:
    assert res.status == "ok", f"{what}: status {res.status!r} ({res.error or res.limit}), not ok"
    return res.value


@SUITE.check(
    "broker-call-roundtrip",
    "a program's broker calls reach the broker with the run's token and their values come back",
)
def _(ex):
    with _broker(ex) as b:
        res = _run(
            ex,
            "a = broker.call('echo', {'n': 1})\n"
            "b = broker.call('echo', {'n': 2})\n"
            "result = {'sum': a['n'] + b['n'], 'nested': broker.call('echo', {'x': [1, 'y']})}\n",
            b,
        )
        assert _ok(res, "three echo calls") == {"sum": 3, "nested": {"x": [1, "y"]}}, res.value
        assert [(t, a) for t, a, _ in b.calls] == [(b.token, "echo")] * 3, b.calls


@SUITE.check(
    "no-network-but-broker",
    "a program cannot connect or send to anything but the broker, nor resolve a name",
)
def _(ex):
    host = getattr(ex, "broker_host", LOOPBACK)
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
        with _broker(ex) as b:
            got = _ok(_run(ex, program, b), "egress probes")
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
        with _broker(ex) as b:
            res = _run(ex, program, b, Limits(result_bytes=1 << 20))
            got = _ok(res, "reading the environment and files")
            assert not res.truncated, "the probe's result was truncated; it cannot be judged"
            text = json.dumps(got)
            assert value not in text, "the caller's canary secret is visible in the sandbox"
            assert name not in got["env"], f"the caller's {name} is in the sandbox environment"
            assert b.token not in json.dumps(got["env"]), "the broker token is in the environment"
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
        ("cpu", "while True:\n    pass\n", Limits(cpu_s=0.05, wall_s=5.0)),
        ("memory", "x = bytearray(1 << 30)\nresult = len(x)\n", Limits(memory_bytes=256 << 20)),
        ("wall", "import time\ntime.sleep(0.3)\nresult = 'slept'\n", Limits(wall_s=0.05)),
        (
            "output",
            "for _ in range(1024):\n    print('x' * 1023)\nresult = 'printed'\n",
            Limits(output_bytes=4096),
        ),
    ]
    with _broker(ex) as b:
        for cap, program, limits in cases:
            res = _run(ex, program, b, limits)
            assert (res.status, res.limit) == ("limit", cap), (
                f"over the {cap} cap: status {res.status!r} limit {res.limit!r}, "
                f"not ('limit', {cap!r})"
            )
            assert len(res.output.encode()) <= limits.output_bytes, f"{cap}: output past its cap"


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
    with _broker(ex) as b:
        wrote = _ok(_run(ex, first, b), "the first run")
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
        found = _ok(_run(ex, second, b), "the second run")
    assert found == [], f"the second run saw the first run's {found}"


@SUITE.check(
    "result-bounded",
    "a value longer than result_bytes comes back as a truncated prefix, never whole",
)
def _(ex):
    limits = Limits(result_bytes=4095)
    with _broker(ex) as b:
        big = _run(
            ex, "result = {'rows': ['\\u00e9t\\u00e9-' + str(i) for i in range(5000)]}\n", b, limits
        )
        full = json.dumps(
            {"rows": [f"été-{i}" for i in range(5000)]},
            ensure_ascii=False,
            separators=(",", ":"),
        )
        assert big.status == "ok" and big.truncated is True, (
            f"a {len(full.encode())}-byte value over a {limits.result_bytes}-byte cap: "
            f"status {big.status!r}, truncated {big.truncated!r}"
        )
        assert isinstance(big.value, str), f"a truncated value is {type(big.value).__name__}"
        size = len(big.value.encode())
        assert 0 < size <= limits.result_bytes, f"the truncated value is {size} bytes"
        assert full.startswith(big.value), "the truncated value is not a prefix of the value"
        small = _run(ex, "result = {'a': [1, 2], 'b': None}\n", b, limits)
        assert (small.status, small.truncated) == ("ok", False), small
        assert small.value == {"a": [1, 2], "b": None}, small.value


@SUITE.check(
    "program-error-is-a-status",
    "a program that raises, does not compile or leaves a non-JSON value ends with status error",
)
def _(ex):
    cases = [
        ("exception", "raise ValueError('boom')\n"),
        ("syntax", "def broken(:\n    pass\n"),
        ("unserializable", "result = object()\n"),
    ]
    with _broker(ex) as b:
        for kind, program in cases:
            res = _run(ex, program, b)
            assert (res.status, res.error) == ("error", kind), (
                f"{kind}: status {res.status!r} error {res.error!r}, not ('error', {kind!r})"
            )
            assert res.value is None, f"{kind}: an error carries a value {res.value!r}"


@SUITE.check(
    "denied-call-is-a-status",
    "a denied broker call raises broker.Denied in the program; escaping, it ends the run denied",
)
def _(ex):
    with _broker(ex) as b:
        caught = _run(
            ex,
            "try:\n    broker.call('deny', {})\nexcept broker.Denied:\n    result = 'caught'\n",
            b,
        )
        assert _ok(caught, "a caught denial") == "caught", caught.value
        escaped = _run(ex, "broker.call('deny', {})\nresult = 'went on'\n", b)
        assert escaped.status == "denied", f"an escaping denial ended {escaped.status!r}"
        assert escaped.value is None, f"a denied run carries a value {escaped.value!r}"


@SUITE.check(
    "unknown-language-refused",
    "a language the executor does not list is refused before anything runs",
)
def _(ex):
    assert "python" in ex.languages, f"languages {sorted(ex.languages)} lack python"
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
    with _broker(ex) as b:
        res = _run(ex, "print('hello from the sandbox')\nresult = 1\n", b)
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
    "unbounded-result": Mutant(
        UnboundedResultExecutor,
        "result-bounded",
        "an oversized value is returned whole",
    ),
}
