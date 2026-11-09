# SPDX-License-Identifier: Apache-2.0
"""``agent-runner``: the agent-runner contract, the ``agent-runtime`` slot (ADR-0051, contract
version 1.0; :mod:`conformance.protocols.agent_runner`).

Each check plays the controller, the deploy and the world. It:
- builds a session spec, the run's inputs and a grants file with its pin;
- serves a scripted fake gateway and fake MCP servers on loopback
  (:mod:`conformance.fakes.runner_world`);
- starts the session through the subject's launcher and judges the outcome, the gateway's and
  the MCP servers' records, and what is left behind.

The subject is always a launcher. A provider's target supplies only its body's argv and its
``exit_classes``, and runs under the reference launcher (later the controller's ``runner/agent``),
which its own target certifies. So the checks of the launcher's own rules always run: they put a
suite body (``conformance/fakes/agent_runner_probe.py``) under the launcher, whatever the
provider's runtime does.

These are the checks that need no systemd (ADR-0051 implementation step 2). The unit launcher's
checks (isolation from the controller, sibling runs, an OOM kill, the polkit rule) come with that
launcher, step 4.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from conformance.fakes.agent_runner_launcher import DevLauncher
from conformance.fakes.runner_world import FakeGateway, FakeMCP
from conformance.protocols.agent_runner import CLASSES, RunInputs
from homelabnext.conform.core import Mutant, Suite

SUITE = Suite(
    "agent-runner",
    "the agent-runner contract: a session spec in, a usage stream and an answer out, classes from "
    "typed signals, the run's key and trace on every call, servers from the grants file",
    "conformance.protocols.agent_runner:AgentRunner",
    tier="extended",
)

HERE = Path(__file__).resolve().parent.parent / "fakes"
PROBE = HERE / "agent_runner_probe.py"
STDIO = HERE / "runner_mcp_stdio.py"
WAIT_S = 60.0
ROLE = "main-reasoner"


def _probe(*args: str) -> list[str]:
    return [sys.executable, "-I", str(PROBE), *args]


class World:
    """One check's world: a gateway, MCP servers, a profile's key and its neighbours' keys."""

    def __init__(self) -> None:
        self.gateway = FakeGateway()
        self.local_mcp = FakeMCP()
        self.remote_mcp = FakeMCP()
        self.key = "key-run-" + secrets.token_hex(12)
        self.tmp = Path(tempfile.mkdtemp(prefix="hnx-runner-world-"))
        self.handles: list[tuple[Any, Any]] = []
        self.servers: dict[str, dict[str, Any]] = {
            "lake": {
                "kind": "lake-query",
                "transport": "http",
                "locality": "local",
                "url": self.local_mcp.url,
            },
            "web": {
                "kind": "fetch",
                "transport": "http",
                "locality": "non-local",
                "url": self.remote_mcp.url,
            },
        }

    def close(self) -> None:
        for r, h in self.handles:
            release = getattr(r, "release", None)
            if release is not None:
                release(h)
        self.gateway.close()
        self.local_mcp.close()
        self.remote_mcp.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def stdio(self, sid: str, *args: str) -> Path:
        """Grant a stdio server ``sid`` (``runner_mcp_stdio.py``); its marker file says it ran."""
        mark = self.tmp / f"{sid}.started"
        self.servers[sid] = {
            "kind": "notes",
            "transport": "stdio",
            "locality": "local",
            "command": sys.executable,
            "args": ["-I", str(STDIO), "--mark", str(mark), *args],
        }
        return mark

    def run(
        self,
        *,
        servers: list[Any] | None = None,
        script: list[dict] | None = None,
        limits: dict[str, Any] | None = None,
        gateway_url: str | None = None,
        pinned_gateway: str | None = None,
        grants_pin: str | None = None,
        run_token: bool = True,
        **spec_extra: Any,
    ) -> RunInputs:
        run_id = secrets.token_hex(16)
        tag = f"hnx:{run_id}"
        self.trace_id = secrets.token_hex(16)
        self.tag = tag
        self.gateway.script(tag, script or [{"content": "the answer"}])
        spec: dict[str, Any] = {
            "spec_version": "1.0",
            "run_id": run_id,
            "agent_key": "triage",
            "lane": "real",
            "prompt": {"credential": "prompt"},
            "toolsets": [],
            "servers": servers if servers is not None else [],
            "target": {
                "gateway_url": gateway_url or self.gateway.url,
                "model_role": ROLE,
                "cloud": False,
            },
            "limits": {
                "timeout_s": 60,
                "stall_timeout_s": 0,
                "max_turns": 10,
                "liveness": "progress",
                **(limits or {}),
            },
            "gateway_tag": tag,
            "trace": f"00-{self.trace_id}-{secrets.token_hex(8)}-01",
            "credentials": {"gateway_key": "gateway-key"},
            **spec_extra,
        }
        inputs = {"prompt": b"Answer the question.", "gateway-key": self.key.encode()}
        if run_token:
            spec["credentials"]["run_tokens"] = {"gateway": "run-token-gateway"}
            self.run_token = "hnxrun1." + secrets.token_hex(16)
            inputs["run-token-gateway"] = self.run_token.encode()
        grants = json.dumps(
            {
                "grants_version": "1.0",
                "profile": "triage",
                "profile_digest": "sha256:" + "ab" * 32,
                "servers": self.servers,
            }
        ).encode()
        pin = grants_pin or "sha256:" + hashlib.sha256(grants).hexdigest()
        url = gateway_url or self.gateway.url
        return RunInputs(spec, inputs, grants, pin, pinned_gateway or url)


def _session(
    r: Any, w: World, run: RunInputs, body: list[str] | None = None, timeout: float = WAIT_S
):
    h = r.start(run, w.gateway, body=body)
    w.handles.append((r, h))
    return h, r.wait(h, timeout)


def _calls(w: World) -> list[dict[str, Any]]:
    return [c for c in w.gateway.calls if c["tag"] == w.tag]


def _with_world(fn):
    def check(r):
        w = World()
        try:
            return fn(r, w)
        finally:
            w.close()

    check.__name__ = fn.__name__
    return check


# --------------------------------------------------------------------------------- a. answers
@SUITE.check("session-answers", "a spec in, the answer and a valid stream ending in end out")
@_with_world
def _answers(r, w):
    _, out = _session(r, w, w.run(script=[{"content": "forty-two"}]))
    assert out.cls is None, f"a clean session ended {out.cls} ({out.detail})"
    assert out.answer == "forty-two", f"the answer came back as {out.answer!r}"
    assert out.records and out.records[-1]["type"] == "end", f"no end record: {out.records}"
    assert out.cls in (None, *CLASSES)


# ------------------------------------------------------------------------------ b. sized calls
@SUITE.check(
    "usage-sizes-each-call",
    "every model call is a call record, sized when the gateway "
    "sized it, unsized (never left out) when it did not (ADR-0026 decision 13)",
)
@_with_world
def _sizes(r, w):
    _, out = _session(
        r,
        w,
        w.run(
            servers=["lake"],
            script=[
                {"tool": ["lake", "query"]},
                {"tool": ["lake", "query"], "usage": False},
                {"content": "done"},
            ],
        ),
    )
    assert out.cls is None, f"the session ended {out.cls} ({out.detail})"
    calls = [x for x in out.records if x["type"] == "call"]
    assert len(calls) == len(_calls(w)) == 3, (
        f"{len(_calls(w))} model calls, {len(calls)} call records: {calls}"
    )
    assert [c["sized"] for c in calls] == [True, False, True], calls
    sized = [c for c in calls if c["sized"]]
    assert all(c["input_tokens"] > 0 and c["output_tokens"] > 0 for c in sized), sized


# ------------------------------------------------------------------------------- c. cancel
@SUITE.check(
    "cancel-ends-the-whole-session",
    "a cancel ends every process of the run, a setsid descendant included, as KilledByController",
)
@_with_world
def _cancel(r, w):
    pidfile = w.tmp / "daemon.pid"
    w.stdio("notes", "--spawn", str(pidfile))
    h = r.start(w.run(servers=["notes"], script=[{"hang": 30}]), w.gateway)
    w.handles.append((r, h))
    try:
        deadline = time.monotonic() + 20
        while not _pid_written(pidfile) and time.monotonic() < deadline:
            time.sleep(0.05)
        assert _pid_written(pidfile), "the session's stdio server never started its descendant"
        daemon = int(pidfile.read_text())
        r.cancel(h)
        out = r.wait(h, WAIT_S)
    finally:
        r.cancel(h)
    deadline = time.monotonic() + 5
    while _alive(daemon) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not _alive(daemon), f"a setsid descendant (pid {daemon}) outlived the cancel"
    assert out.cls == "KilledByController", f"a cancelled run ended {out.cls} ({out.detail})"


def _pid_written(path: Path) -> bool:
    try:
        return path.read_text().endswith("\n")
    except OSError:
        return False


def _alive(pid: int) -> bool:
    try:
        with open(f"/proc/{pid}/stat", encoding="ascii") as f:
            return f.read().rsplit(")", 1)[1].split()[0] not in ("Z", "X")
    except (OSError, IndexError):
        return False


# ---------------------------------------------------------------------------------- d. stall
@SUITE.check("stall-is-signalled", "a session with no progress for stall_timeout_s ends Stalled")
@_with_world
def _stall(r, w):
    _, out = _session(
        r, w, w.run(script=[{"hang": 30}], limits={"stall_timeout_s": 0.3, "liveness": "progress"})
    )
    assert out.cls == "Stalled", f"a session waiting on the gateway ended {out.cls} ({out.detail})"


@SUITE.check(
    "stall-counts-only-corroborated-progress",
    "progress counts only gateway-corroborated calls: written records alone are no progress, "
    "and records the gateway dropped or that lag are no progress either, however busy the body",
)
@_with_world
def _stall_fallback(r, w):
    lim = {"stall_timeout_s": 0.3, "liveness": "progress", "timeout_s": 0.9}
    _, out = _session(r, w, w.run(limits=lim), body=_probe("records", "40"))
    assert out.cls == "Stalled", (
        f"call records the gateway never answered counted as progress: {out.cls} ({out.detail})"
    )
    w.gateway.dropped_records = 1
    _, out = _session(r, w, w.run(limits=lim), body=_probe("spin"))
    assert out.cls == "Stalled", (
        "a session burning CPU while the gateway dropped records was judged alive: "
        f"{out.cls} ({out.detail})"
    )


# ----------------------------------------------------------------------------- e. classes
@SUITE.check(
    "progress-reads-any-json-spacing",
    "a record is a record however its JSON is spaced: a body writing json.dumps's default "
    "spacing makes progress and is not stopped as stalled",
)
@_with_world
def _spacing(r, w):
    lim = {"stall_timeout_s": 0.35, "liveness": "progress", "timeout_s": 5}
    _, out = _session(r, w, w.run(limits=lim), body=_probe("spaced", "5"))
    assert out.cls is None, f"a body making calls was judged {out.cls} ({out.detail})"


@SUITE.check(
    "context-refusal-is-context-exceeded",
    "the provider's own body, refused 400 upstream_rejected by the gateway, ends ContextExceeded, "
    "which the gateway's record corroborates",
)
@_with_world
def _context(r, w):
    _, out = _session(r, w, w.run(script=[{"status": 400}]))
    assert out.cls == "ContextExceeded", f"a context refusal ended {out.cls} ({out.detail})"


@SUITE.check(
    "gateway-url-is-pinned",
    "the body sends the run's key, tokens and prompt only to the gateway the deploy pinned: a "
    "spec naming another gateway makes no call and ends Internal",
)
@_with_world
def _pinned(r, w):
    elsewhere = FakeGateway()
    try:
        run = w.run(gateway_url=elsewhere.url, pinned_gateway=w.gateway.url)
        elsewhere.script(w.tag, [{"content": "the answer"}])
        _, out = _session(r, w, run)
        assert elsewhere.calls == [], (
            f"the run's key went to a gateway the spec named and the deploy did not: "
            f"{len(elsewhere.calls)} call(s)"
        )
        assert _calls(w) == [] and out.cls == "Internal", (
            f"a spec naming another gateway ran: {out.cls} ({out.detail})"
        )
    finally:
        elsewhere.close()


@SUITE.check("turn-cap-is-a-class", "a session at max_turns ends TurnCap from its end record")
@_with_world
def _turn_cap(r, w):
    _, out = _session(
        r, w, w.run(servers=["lake"], script=[{"tool": ["lake", "query"]}], limits={"max_turns": 2})
    )
    assert out.cls == "TurnCap", f"a session past max_turns ended {out.cls} ({out.detail})"


@SUITE.check(
    "exit-status-maps-to-class",
    "every exit status the provider maps is its class",
)
@_with_world
def _exit_maps(r, w):
    assert r.exit_classes, "the provider maps no exit status"
    for code, cls in sorted(r.exit_classes.items()):
        _, out = _session(r, w, w.run(), body=_probe("exit", str(code)))
        assert out.cls == cls, f"exit {code} is mapped to {cls}, the run ended {out.cls}"


@SUITE.check(
    "unmapped-exit-is-internal",
    "an exit status the provider does not map is Internal, which moves nothing",
)
@_with_world
def _unmapped(r, w):
    code = next(c for c in range(2, 120) if c not in r.exit_classes)
    _, out = _session(r, w, w.run(), body=_probe("exit", str(code)))
    assert out.cls == "Internal", f"the unmapped exit {code} ended {out.cls} ({out.detail})"


@SUITE.check(
    "unreachable-gateway-is-a-backend-fault",
    "a gateway that refuses connections reaches the pool as BackendFault",
)
@_with_world
def _unreachable(r, w):
    import socket

    s = socket.socket()
    s.bind((w.gateway.url.split("//")[1].split(":")[0], 0))
    port = s.getsockname()[1]
    s.close()  # nothing listens there now
    url = w.gateway.url.rsplit(":", 1)[0] + f":{port}"
    _, out = _session(r, w, w.run(gateway_url=url))
    assert out.cls == "BackendFault", f"an unreachable gateway ended {out.cls} ({out.detail})"


@SUITE.check(
    "self-reported-class-needs-the-gateway",
    "ContextExceeded counts only with a 400 "
    "upstream_rejected record later than every answered call, within the gateway wait; "
    "else Internal. ConcurrencyLimited is never corroborated",
)
@_with_world
def _corroborate(r, w):
    run = w.run(script=[{"content": "ok"}, {"status": 400}])
    _, out = _session(r, w, run, body=_probe("claim", "ContextExceeded", "ok", "rejected"))
    assert out.cls == "ContextExceeded", f"a corroborated claim ended {out.cls} ({out.detail})"
    run = w.run(script=[{"status": 400}, {"content": "ok"}])
    _, out = _session(r, w, run, body=_probe("claim", "ContextExceeded", "rejected", "ok"))
    assert out.cls == "Internal", (
        f"a 400 earlier than an answered call corroborated the claim: {out.cls} ({out.detail})"
    )
    _, out = _session(r, w, w.run(), body=_probe("claim", "ContextExceeded"))
    assert out.cls == "Internal", f"an uncorroborated claim ended {out.cls} ({out.detail})"
    w.gateway.dropped_records = 1
    run = w.run(script=[{"status": 400}])
    _, out = _session(r, w, run, body=_probe("claim", "ContextExceeded", "rejected"))
    assert out.cls == "Internal", (
        f"a claim judged while the gateway dropped records ended {out.cls} ({out.detail})"
    )
    w.gateway.dropped_records = 0
    w.gateway.lag_s = 300.0  # the records never cover the run's end within the wait
    run = w.run(script=[{"status": 400}])
    _, out = _session(r, w, run, body=_probe("claim", "ContextExceeded", "rejected"))
    assert out.cls == "Internal", f"a claim on lagging records ended {out.cls} ({out.detail})"
    w.gateway.lag_s = 0.0
    _, out = _session(r, w, w.run(), body=_probe("claim", "ConcurrencyLimited"))
    assert out.cls == "ConcurrencyLimited", (
        f"ConcurrencyLimited, which the gateway never records, ended {out.cls} ({out.detail})"
    )


# -------------------------------------------------------------------------- f. the run's key
@SUITE.check(
    "per-run-credential",
    "every model call carries the run's profile key, never a "
    "backend's or another profile's, and nothing of the run's inputs is left after it",
)
@_with_world
def _credential(r, w):
    h, out = _session(
        r, w, w.run(servers=["lake"], script=[{"tool": ["lake", "q"]}, {"content": "done"}])
    )
    assert out.cls is None, f"the session ended {out.cls} ({out.detail})"
    bearers = [c["bearer"] for c in _calls(w)]
    assert bearers and all(b == w.key for b in bearers), (
        f"a model call carried a key other than the run's ({sum(b != w.key for b in bearers)} "
        f"of {len(bearers)})"
    )
    left = r.leftovers(h)
    assert left == [], f"the run's inputs are left after it: {left}"


# ------------------------------------------------------------------------- g. trace and tag
@SUITE.check(
    "trace-propagation",
    "every model call carries the run's trace id; _meta."
    "traceparent goes to local MCP servers and to no other (ADR-0047 decision 2)",
)
@_with_world
def _trace(r, w):
    _, out = _session(
        r,
        w,
        w.run(
            servers=["lake", "web"],
            script=[{"tool": ["lake", "q"]}, {"tool": ["web", "get"]}, {"content": "done"}],
        ),
    )
    assert out.cls is None, f"the session ended {out.cls} ({out.detail})"
    tps = [c["traceparent"] for c in _calls(w)]
    assert tps and all(t.split("-")[1:2] == [w.trace_id] for t in tps), (
        f"model calls without the run's trace id: {tps}"
    )
    local = [c.get("_meta", {}).get("traceparent", "") for c in w.local_mcp.calls]
    assert local and all(t.split("-")[1:2] == [w.trace_id] for t in local), (
        f"a local MCP call without the run's traceparent: {w.local_mcp.calls}"
    )
    remote = [c for c in w.remote_mcp.calls if "traceparent" in (c.get("_meta") or {})]
    assert w.remote_mcp.calls and not remote, f"a non-local MCP server got the trace: {remote}"


@SUITE.check("gateway-tag-on-every-call", "every model call carries X-HNX-Tag, the run's tag")
@_with_world
def _tag(r, w):
    _, out = _session(
        r, w, w.run(servers=["lake"], script=[{"tool": ["lake", "q"]}, {"content": "done"}])
    )
    assert out.cls is None, f"the session ended {out.cls} ({out.detail})"
    tags = [c["tag"] for c in w.gateway.calls]
    assert len(tags) == 2 and set(tags) == {w.tag}, f"model calls tagged {tags}, run {w.tag}"


# -------------------------------------------------------------------------- h. tool records
@SUITE.check(
    "tool-call-records",
    "each tool call is a tool_call record by server id and tool name, never with its arguments",
)
@_with_world
def _tools(r, w):
    _, out = _session(
        r,
        w,
        w.run(
            servers=["lake", "web"],
            script=[{"tool": ["lake", "query"]}, {"tool": ["web", "get"]}, {"content": "done"}],
        ),
    )
    assert out.cls is None, f"the session ended {out.cls} ({out.detail})"
    tools = [
        (x["server"], x["tool"], x["outcome"]) for x in out.records if x["type"] == "tool_call"
    ]
    assert tools == [("lake", "query", "ok"), ("web", "get", "ok")], tools


@SUITE.check(
    "budget-exhausted-is-typed",
    "a gateway refusal run_budget_exhausted ends the run "
    "BudgetExhausted; a budget_exhausted claim with no refusal does not",
)
@_with_world
def _budget(r, w):
    _, out = _session(r, w, w.run(script=[{"status": 403, "budget": "tool_calls"}]))
    assert out.cls == "BudgetExhausted", f"a budget refusal ended {out.cls} ({out.detail})"
    assert out.records[-1].get("budget_exhausted") == "tool_calls", out.records


# ---------------------------------------------------------------------- i. the grants file
@SUITE.check(
    "servers-come-from-the-grants-file",
    "a server id the grants file lacks, a command "
    "in the spec or a grants file that does not match its pin starts nothing",
)
@_with_world
def _grants(r, w):
    mark = w.stdio("notes")
    ghost = w.tmp / "ghost.ran"
    cases = {
        "an id the grants file lacks": w.run(servers=["notes", "ghost"]),
        "a grants file that does not match its pin": w.run(
            servers=["notes"], grants_pin="sha256:" + "0" * 64
        ),
        "a command in the spec": w.run(
            servers=[{"id": "notes", "command": "/bin/sh", "args": ["-c", f"touch {ghost}"]}]
        ),
    }
    for why, run in cases.items():
        _, out = _session(r, w, run)
        ran = mark.exists() or ghost.exists() or _calls(w)
        assert not ran, f"{why}: something ran (servers {mark.exists()}, calls {len(_calls(w))})"
        assert out.cls == "Internal", f"{why}: the run ended {out.cls} ({out.detail})"


# -------------------------------------------------------------------------- j. stream bounds
@SUITE.check(
    "usage-stream-is-bounded",
    "a stream past its bound while running is ResourceLimit; "
    "a line over 16 KiB or nested past 8 is Internal",
)
@_with_world
def _bounded(r, w):
    _, out = _session(r, w, w.run(), body=_probe("oversize", str(2 << 20)))
    assert out.cls == "ResourceLimit", f"an oversized stream ended {out.cls} ({out.detail})"
    for mode in ("long-line", "deep"):
        _, out = _session(r, w, w.run(), body=_probe(mode))
        assert out.cls == "Internal", f"{mode}: the run ended {out.cls} ({out.detail})"


# --------------------------------------------------------------------------- k. no secrets
@SUITE.check(
    "spec-carries-no-secret",
    "the spec, argv and environment the body sees hold no key or token value",
)
@_with_world
def _no_secret(r, w):
    _, out = _session(r, w, w.run(), body=_probe("dump"))
    assert out.cls is None and out.answer, f"the probe did not run: {out.cls} ({out.detail})"
    seen = json.loads(out.answer)
    text = json.dumps({k: seen[k] for k in ("argv", "env", "spec")})
    for name, value in (("gateway key", w.key), ("run token", w.run_token)):
        assert value not in text, f"the body sees the {name} outside its credentials"
    assert {"spec", "prompt", "gateway-key"} <= set(seen["inputs"]), seen["inputs"]


# --------------------------------------------------------------------------- subjects
#: the reference launcher's gateway wait in these runs (the launcher's own default is
#: GATEWAY_WAIT_S): the fake gateway's records are in memory, so a tenth of a second covers them
FAKE_WAIT_S = 0.1


def make_fake() -> DevLauncher:
    return DevLauncher(gateway_wait_s=FAKE_WAIT_S)


def _body_mutant(name: str):
    from conformance.fakes.agent_runner_launcher import BODY

    return lambda: DevLauncher(
        [sys.executable, "-I", str(BODY), "--mutant", name], gateway_wait_s=FAKE_WAIT_S
    )


def _launcher_mutant(name: str):
    return lambda: DevLauncher(mutant=name, gateway_wait_s=FAKE_WAIT_S)


def _m(factory, check, description, features=()):
    return Mutant(factory, check, description, features=frozenset(features))


MUTANTS = {
    "follows-spec-url": _m(
        _body_mutant("follows-spec-url"),
        "gateway-url-is-pinned",
        "the body sends the run's key to whatever gateway the spec names",
    ),
    "drops-meta": _m(
        _body_mutant("drops-meta"),
        "trace-propagation",
        "the body sends no _meta.traceparent to a local MCP server",
    ),
    "meta-to-non-local": _m(
        _body_mutant("meta-to-non-local"),
        "trace-propagation",
        "the body sends _meta.traceparent to a non-local MCP server",
    ),
    "backend-key": _m(
        _body_mutant("backend-key"),
        "per-run-credential",
        "the body calls the gateway with the backend's key",
    ),
    "other-profile-key": _m(
        _body_mutant("other-profile-key"),
        "per-run-credential",
        "the body calls the gateway with another profile's key",
    ),
    "keeps-inputs": _m(
        _launcher_mutant("keeps-inputs"),
        "per-run-credential",
        "the launcher leaves the run's key and tokens after the run",
    ),
    "runs-spec-command": _m(
        lambda: DevLauncher(
            [
                sys.executable,
                "-I",
                str(HERE / "agent_runner_body.py"),
                "--mutant",
                "runs-spec-command",
            ],
            mutant="no-spec-check",
        ),
        "servers-come-from-the-grants-file",
        "the launcher passes a spec with a server command and the body runs it",
    ),
    "starts-unlisted-server": _m(
        _body_mutant("starts-unlisted-server"),
        "servers-come-from-the-grants-file",
        "the body starts the grants file's servers whatever the spec "
        "names, and does not refuse an id the file lacks",
    ),
    "unsized-call-omitted": _m(
        _body_mutant("unsized-call-omitted"),
        "usage-sizes-each-call",
        "the body leaves out a model call it could not size",
    ),
    "kills-only-process-group": _m(
        _launcher_mutant("kills-only-process-group"),
        "cancel-ends-the-whole-session",
        "the launcher kills only the body's process group, so a "
        "setsid descendant outlives the cancel",
    ),
}
