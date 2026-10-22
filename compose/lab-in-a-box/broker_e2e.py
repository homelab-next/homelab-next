#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: lab-broker-e2e
#   kind: tool
#   purpose: The broker end to end on real processes - socket peers, MCP agent, hub approval, audit.
#   owner: lab-in-a-box
#   trigger: [script:lab-smoke, compose:lab-in-a-box/status-hub]
#   inputs: a running broker socket and status hub (the lab's broker services, or a test's processes)
#   outputs: one line per step, or a JSON report with --json
#   exit:
#     "0": every step passed
#     "1": some step failed
#     "2": usage
"""The broker (ADR-0017, docs/broker.md) end to end, against real processes and a real socket.

In the lab-in-a-box this runs inside the ``broker-edge`` container, which plays two parts: the
**edge** in front of the status hub (its address is the hub's one trusted proxy, and it adds the
front-door headers the real edge would after a login) and the **launcher** of every other peer of
the broker socket, each as its own uid: the agent's ``hnx broker mcp`` (driven by a real MCP stdio
client), an unmapped uid, and the hub's uid reading the audit trail.  The broker and the hub run
in their own containers, as their own users (``docker-compose.yml``).

Subcommands:

    broker_e2e.py run [--json] [...]       the scenario (defaults: the lab's paths and uids)
    broker_e2e.py serve-hub --dir D ...    write the hub's registry/agents/views, run the hub
    broker_e2e.py ready                    exit 0 once the socket exists and the hub answers
    broker_e2e.py as UID:GID[:GROUP...] -- CMD ...   drop to that uid, then exec CMD

The scenario, step by step (each is one line of the report): the agent's MCP tools are listed;
``memory_write`` lands in its own lane directory, owner-only; ``proposal_file`` files a records
note named after the agent; an approval-gated action is submitted and refused before approval;
an unmapped uid is refused (``unknown-caller``); the agent cannot approve its own request
(``not-an-approval-relay``); the hub refuses a request without the front-door secret; the
approver reads the page (token and digest from the form) and approves through
``POST /approvals/decide``; the agent runs the request once; a second run is refused
(``not-pending``); with an events bus configured, the broker's outbox relay (as its own
uid) publishes the request's ``decision.requested`` and ``decision.returned`` to the bus, in order,
as ``svc:broker`` with the event id as the message id, and a second relay pass publishes nothing;
the audit trail holds every step, each with the peer's ``via``.

``tests/compose/test_lab_broker_e2e.py`` runs :func:`run_scenario` against local processes.
"""

from __future__ import annotations

import argparse
import base64
import html
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

#: the lab's broker layout (fakes in docker-compose.yml and broker/Dockerfile use the same numbers)
LAB_SOCKET = "/run/hnx-broker/broker.sock"
LAB_DATA_ROOT = "/srv/agents"
LAB_HUB = "http://status-hub.svc.example.internal:8099"  # no-raw-endpoint: allow the lab hub alias
LAB_UIDS = {"agent": 10011, "relay": 10012, "stranger": 10013}
LAB_CLIENTS_GID = 10020
#: the broker's own uid (the image's hnx-broker), and its outbox relay's (hnx-broker-relay): the
#: relay sees only <state>/outbox (read-only) and its own <state>/relay
LAB_BROKER_UID = 10010
LAB_RELAY_UID = 10015
LAB_STATE = "/var/lib/hnx-broker/state"
LAB_EVENTS_TARGET = "/src/compose/lab-in-a-box/broker/events-relay.yml"
LAB_EVENTS_STREAM, LAB_EVENTS_PREFIX = "HNXLAB_BROKER", "hnxlab"
BROKER_SOURCE = "svc:broker"  # homelabnext.broker.relay.BROKER_SOURCE (tests/compose pins it)
STREAM_MAX_BYTES = 64 << 20  # the lab's standing stream (its DLQ gets a quarter)
#: the lab's NATS users in the HNX account (config/nats/nats.conf) -> their password variables
LAB_BUS_USERS = {
    "hnx-broker": "HNX_SECRET_EVENTS_BROKER",
    "hnx-st2-bridge": "HNX_SECRET_EVENTS_ST2_BRIDGE",
    "hnx-lab-admin": "HNX_SECRET_EVENTS_ADMIN",
}
LAB_ADMIN = "hnx-lab-admin"
#: a consumer of the broker's decisions that must not be able to forge one
LAB_NOT_BROKER = "hnx-st2-bridge"
#: the hub's public name: the Host and Origin the edge passes on (registry public_hostname)
HUB_HOST = "status.lab.example"
SECRET_ENV = "HNX_SECRET_STATUS_FRONT_DOOR_SECRET"
APPROVER = "operator-one"
APPROVER_GROUP = "hub-approvers"
VIEWER_GROUP = "hub-private-viewers"
#: set in every process this script starts, naming its part (a unit test's broker reads it)
ROLE_ENV = "HNX_LAB_ROLE"
LOOPBACK = "127.0.0.1"  # no-raw-endpoint: allow the hub's default bind is loopback only
TIMEOUT = 60


class StepFailed(Exception):
    pass


@dataclass
class Relay:
    """The broker's outbox relay and the bus it publishes to.  ``launch`` is the argv prefix
    running a command as the relay's own uid.  ``wire_as(user)`` opens a connection to the bus as
    one of the lab's NATS users (``None``: no user at all); by default nats-py on
    ``HNX_ENDPOINT_EVENTS`` with the user's password from :data:`LAB_BUS_USERS`.  The operator
    (``hnx-lab-admin``) provisions the stream and reads back what the relay published."""

    state: str
    target: str
    stream: str
    prefix: str
    launch: Sequence[str] = ()
    #: runs one ``--once`` pass and returns (exit status, stdout); default: the CLI, as the relay's uid
    run_once: Callable[[], tuple[int, str]] | None = None
    #: the only ``HNX_SECRET_*`` variables the relay's process gets (its bus password)
    secrets: Sequence[str] = ("HNX_SECRET_EVENTS_BROKER",)
    wire_as: Callable[[str | None], Any] | None = None

    def wire(self, user: str | None) -> Any:
        if self.wire_as is not None:
            return self.wire_as(user)
        from homelabnext.conform.adapters import nats_jetstream as nj
        from homelabnext.conform.adapters._env import env_secret, resolve

        url = resolve("events", env_only=True).url
        if user is None:
            return nj.NatsPyWire(url, name="hnx-lab-anonymous")
        return nj.NatsPyWire(  # the lab's own network: plaintext nats:// by choice
            url,
            name=user,
            user=user,
            password=env_secret(LAB_BUS_USERS[user]),
            inbox_prefix=f"_INBOX.{user}",
        )

    def bus_as(self, user: str) -> Any:
        """The JetStream adapter on the standing stream as ``user``; it creates nothing."""
        from homelabnext.conform.adapters import nats_jetstream as nj

        wire = self.wire(user)
        try:
            return nj.JetStreamBus(
                wire, stream=self.stream, subject_prefix=self.prefix, provision=False
            )
        except Exception:
            wire.close()
            raise

    def provision(self) -> list[str]:
        """The operator's one-time step: the standing stream and its DLQ, bounded.  The relay
        never creates them (its bus user may not)."""
        from homelabnext.conform.adapters import nats_jetstream as nj

        wire = self.wire(LAB_ADMIN)
        try:
            return nj.provision_streams(
                wire, stream=self.stream, subject_prefix=self.prefix, max_bytes=STREAM_MAX_BYTES
            )
        finally:
            wire.close()

    def env(self, base: Mapping[str, str]) -> dict[str, str]:
        """``base`` without any secret the relay does not need (the edge holds the hub's)."""
        return {
            k: v for k, v in base.items() if not k.startswith("HNX_SECRET_") or k in self.secrets
        }

    def argv(self, hnx: Sequence[str]) -> list[str]:
        return [*self.launch, *hnx, "broker", "relay", "--state", self.state, "--events-target",
                self.target, "--stream", self.stream, "--subject-prefix", self.prefix,
                "--once"]  # fmt: skip

    def bus(self) -> Any:
        return self.bus_as(LAB_ADMIN)


@dataclass
class Setup:
    """Where the broker and the hub are, and how to start a process as one of the peers.

    ``uids`` are the uids the broker sees for ``agent``, ``relay`` and ``stranger``;
    ``launch(role)`` is the argv prefix that runs a command as that role (empty: as this
    process); ``hnx`` is the argv that runs the project's CLI."""

    socket: Path
    hub: str
    data_root: Path
    uids: Mapping[str, int]
    secret: str
    launch: Callable[[str], list[str]] = lambda role: []
    hnx: Sequence[str] = (sys.executable, "-m", "homelabnext.cli")
    env: Mapping[str, str] = field(default_factory=lambda: dict(os.environ))
    tag: str = field(default_factory=lambda: secrets.token_hex(4))
    relay: Relay | None = None  # None: no events bus here, the bus-relay step is not run

    def role_env(self, role: str) -> dict[str, str]:
        return {**self.env, ROLE_ENV: role}


# ---------------------------------------------------------------- the edge's HTTP
def edge_headers(secret: str | None, user: str = APPROVER) -> dict[str, str]:
    """What the lab's edge adds after a login: the front-door secret and the identity."""
    out = {
        "Host": HUB_HOST,
        "X-Authentik-Username": user,
        "X-Authentik-Groups": f"{VIEWER_GROUP}|{APPROVER_GROUP}",
    }
    if secret is not None:
        out["X-Hnx-Front-Door"] = secret
    return out


def http(
    method: str, url: str, headers: Mapping[str, str], body: bytes | None = None
) -> tuple[int, str]:
    req = urllib.request.Request(url, data=body, method=method)
    for k, v in headers.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def form_fields(page: str, request_id: str) -> dict[str, str]:
    """The hidden fields of the decide form for ``request_id`` on the Approvals page."""
    block = page.split(f'id="{html.escape(request_id)}"', 1)
    if len(block) != 2 or "<form" not in block[1].split('<div class="pane"', 1)[0]:
        raise StepFailed(f"no decide form for {request_id} on the page")
    form = block[1].split("</form>", 1)[0]
    found = dict(re.findall(r'<input type="hidden" name="(\w+)" value="([^"]*)">', form))
    out = {k: html.unescape(v) for k, v in found.items()}
    if not {"request_id", "digest", "token"} <= set(out) or out["request_id"] != request_id:
        raise StepFailed(f"the form for {request_id} lacks its hidden fields: {sorted(out)}")
    return out


# ---------------------------------------------------------------- spawned peers
def cli(setup: Setup, role: str, *args: str) -> subprocess.CompletedProcess[str]:
    """``hnx broker ARGS --socket S`` as ``role``."""
    argv = [*setup.launch(role), *setup.hnx, "broker", *args, "--socket", str(setup.socket)]
    return subprocess.run(
        argv, env=setup.role_env(role), capture_output=True, text=True, timeout=TIMEOUT
    )


def _refusal(proc: subprocess.CompletedProcess[str], reason: str) -> str:
    if proc.returncode != 1 or f"refused ({reason})" not in proc.stderr:
        raise StepFailed(
            f"expected refused ({reason}), got rc={proc.returncode} {proc.stderr[:200]}"
        )
    return f"refused ({reason})"


def _tool_text(result: Any) -> tuple[bool, str]:
    err = bool(getattr(result, "is_error", getattr(result, "isError", False)))
    return err, result.content[0].text if result.content else ""


async def _tool(session: Any, name: str, args: Mapping[str, Any]) -> Any:
    err, text = _tool_text(await session.call_tool(name, dict(args)))
    if err:
        raise StepFailed(f"{name}: {text[:200]}")
    return json.loads(text)


async def _tool_refused(session: Any, name: str, args: Mapping[str, Any], reason: str) -> str:
    err, text = _tool_text(await session.call_tool(name, dict(args)))
    if not err or f"refused ({reason})" not in text:
        raise StepFailed(f"{name}: expected refused ({reason}), got {text[:200]}")
    return f"refused ({reason})"


def _mcp_session(setup: Setup):
    """An MCP stdio client session with ``hnx broker mcp``, started as the agent."""
    import mcp
    from mcp import StdioServerParameters

    argv = [*setup.launch("agent"), *setup.hnx, "broker", "mcp", "--socket", str(setup.socket)]
    params = StdioServerParameters(command=argv[0], args=argv[1:], env=setup.role_env("agent"))
    if hasattr(mcp, "Client"):  # 2.x
        return _Session2(mcp.Client(params))
    return _Session1(params)


class _Session1:
    def __init__(self, params: Any) -> None:
        self.params = params

    async def __aenter__(self):
        from contextlib import AsyncExitStack

        from mcp import ClientSession, stdio_client

        self.stack = AsyncExitStack()
        r, w = await self.stack.enter_async_context(stdio_client(self.params))
        session = await self.stack.enter_async_context(ClientSession(r, w))
        await session.initialize()
        return session

    async def __aexit__(self, *exc: Any) -> None:
        await self.stack.aclose()


class _Session2:
    def __init__(self, client: Any) -> None:
        self.client = client

    async def __aenter__(self):
        return await self.client.__aenter__()

    async def __aexit__(self, *exc: Any) -> None:
        await self.client.__aexit__(*exc)


# ---------------------------------------------------------------- the scenario
def run_scenario(setup: Setup) -> list[dict[str, Any]]:
    """Every step of the scenario, in order: ``[{step, ok, detail, seconds}]``.  A failed step
    ends the run (later steps depend on it) and is the last row."""
    import anyio

    rows: list[dict[str, Any]] = []
    ctx: dict[str, Any] = {}
    tag = setup.tag
    target = f"svc:lab-e2e-{tag}"

    def slug() -> str:
        return str(ctx["profile"]).split(":", 1)[1]

    async def tools(s: Any) -> str:
        names = {t.name for t in (await s.list_tools()).tools}
        need = {"memory_write", "proposal_file", "broker_submit", "broker_run"}
        if not need <= names:
            raise StepFailed(f"missing tools {sorted(need - names)}")
        acts = await _tool(s, "broker_actions", {})
        ctx["profile"] = acts["caller"]
        return f"{len(names)} tools, acting as {acts['caller']} (from the peer uid)"

    async def memory(s: Any) -> str:
        name = f"lab-e2e-{tag}.md"
        out = await _tool(s, "memory_write", {"name": name, "content": "lab e2e\n"})
        if out["path"] != f"memory/{slug()}/{name}":
            raise StepFailed(f"landed at {out['path']}")
        st = (setup.data_root / out["path"]).stat()
        mode = stat.S_IMODE(st.st_mode)
        if mode & 0o077:
            raise StepFailed(f"mode {mode:o} is not owner-only")
        if st.st_uid == setup.uids["agent"]:
            raise StepFailed("the file is owned by the agent, not the broker")
        return f"{out['path']} mode {mode:o}, owned by the broker"

    async def proposal(s: Any) -> str:
        note = {"title": "Lab e2e proposal", "risk": "low", "rollback": "delete it"}
        args = {"note": note, "body": "From the lab.", "slug": f"lab-e2e-{tag}"}
        out = await _tool(s, "proposal_file", args)
        if not out["path"].startswith("records/inbox/") or f"-{slug()}-" not in out["path"]:
            raise StepFailed(f"filed as {out['path']}")
        if not (setup.data_root / out["path"]).is_file():
            raise StepFailed(f"{out['path']} is not in the data root")
        return f"{out['path']} (the requesting agent is the peer's profile)"

    async def submit(s: Any) -> str:
        args = {"action": "service.restart", "params": {"grace_s": 0}, "target": target}
        out = await _tool(s, "broker_submit", args)
        if out.get("awaiting_approval") is not True:
            raise StepFailed(f"not awaiting approval: {out}")
        ctx["rid"] = out["request_id"]
        return f"{ctx['rid']} awaiting approval"

    async def run_early(s: Any) -> str:
        return await _tool_refused(s, "broker_run", {"request_id": ctx["rid"]}, "approval-required")

    def stranger() -> str:
        return _refusal(cli(setup, "stranger", "actions", "--json"), "unknown-caller")

    def self_approve() -> str:
        proc = cli(setup, "agent", "approve", ctx["rid"], "--as", f"sso:{slug()}")
        return _refusal(proc, "not-an-approval-relay")

    def front_door() -> str:
        code, _ = http("GET", f"{setup.hub}/approvals?request={ctx['rid']}", edge_headers(None))
        if code != 403:
            raise StepFailed(f"without the front-door secret: HTTP {code}")
        return "no front-door secret: 403"

    def approve() -> str:
        rid = ctx["rid"]
        head = edge_headers(setup.secret)
        code, page = http("GET", f"{setup.hub}/approvals?request={rid}", head)
        if code != 200:
            raise StepFailed(f"GET /approvals: HTTP {code} {page[:200]}")
        fields = form_fields(page, rid)
        form = {**fields, "decision": "approve", "note": f"lab e2e {tag}"}
        post = {
            **head,
            "Origin": f"https://{HUB_HOST}",
            "Sec-Fetch-Site": "same-origin",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        body = urllib.parse.urlencode(form).encode()
        code, page = http("POST", f"{setup.hub}/approvals/decide", post, body)
        if code != 200:
            raise StepFailed(f"POST /approvals/decide: HTTP {code} {page[:200]}")
        return f"approved as sso:{APPROVER} with the page's token, digest {fields['digest'][:19]}"

    async def run_once(s: Any) -> str:
        out = await _tool(s, "broker_run", {"request_id": ctx["rid"]})
        if out.get("output", {}).get("would_restart") != target:
            raise StepFailed(f"unexpected result {out}")
        return f"ran once, exit {out.get('exit_code')}"

    async def run_again(s: Any) -> str:
        return await _tool_refused(s, "broker_run", {"request_id": ctx["rid"]}, "not-pending")

    def audit() -> str:
        return check_audit(setup, ctx["rid"], ctx["profile"])

    # (step, function, True when it blocks: run on a worker thread, the session stays served)
    session_steps: list[tuple[str, Callable[..., Any], bool]] = [
        ("mcp-tools", tools, False),
        ("memory-write", memory, False),
        ("proposal-file", proposal, False),
        ("submit", submit, False),
        ("run-before-approval", run_early, False),
        ("unknown-caller", stranger, True),
        ("agent-cannot-approve", self_approve, True),
        ("hub-front-door", front_door, True),
        ("hub-approve", approve, True),
        ("run-once", run_once, False),
        ("second-run-refused", run_again, False),
    ]

    async def one(name: str, fn: Callable[..., Any], blocking: bool, s: Any) -> bool:
        started = time.monotonic()
        try:
            detail = await (anyio.to_thread.run_sync(fn) if blocking else fn(s))
            ok = True
        except Exception as exc:  # every failure is a row, never a traceback
            detail, ok = f"{type(exc).__name__}: {exc}", False
        rows.append(
            {"step": name, "ok": ok, "detail": str(detail)[:300],
             "seconds": round(time.monotonic() - started, 2)}
        )  # fmt: skip
        return ok

    async def scenario() -> None:
        with anyio.fail_after(TIMEOUT * 4):
            async with _mcp_session(setup) as s:
                for name, fn, blocking in session_steps:
                    if not await one(name, fn, blocking, s):
                        return
            relayed = setup.relay is not None and await one(
                "bus-relay", lambda: check_relay(setup, ctx["rid"]), True, None
            )
            if relayed:
                await one("bus-acl", lambda: check_bus_acl(setup, ctx["rid"]), True, None)
            await one("audit", audit, True, None)

    try:
        anyio.run(scenario)
    except BaseException as exc:  # the session itself (the MCP server did not start, a timeout)
        if isinstance(exc, KeyboardInterrupt):
            raise
        rows.append({"step": "session", "ok": False, "detail": f"{type(exc).__name__}: {exc}"[:300],
                     "seconds": 0.0})  # fmt: skip
    return rows


STEPS = ("mcp-tools", "memory-write", "proposal-file", "submit", "run-before-approval",
         "unknown-caller", "agent-cannot-approve", "hub-front-door", "hub-approve", "run-once",
         "second-run-refused", "audit")  # fmt: skip


def steps(setup: Setup) -> tuple[str, ...]:
    """The steps a complete run of ``setup`` reports: ``bus-relay`` and ``bus-acl`` only with a
    bus."""
    return (*STEPS[:-1], "bus-relay", "bus-acl", STEPS[-1]) if setup.relay is not None else STEPS


def check_relay(setup: Setup, rid: str) -> str:
    """``hnx broker relay --once`` as the relay's uid publishes the request's decision events, in
    order, as the broker's source with the event id as the message id; a second pass publishes
    nothing (delivered markers on the broker's state)."""
    from homelabnext.conform.adapters.nats_jetstream import parse_headers

    relay = setup.relay
    assert relay is not None
    argv = relay.argv(setup.hnx)

    def once() -> str:
        if relay.run_once is not None:
            rc, out, err = (*relay.run_once(), "")
        else:
            proc = subprocess.run(
                argv, env=relay.env(setup.env), capture_output=True, text=True, timeout=TIMEOUT
            )
            rc, out, err = proc.returncode, proc.stdout, proc.stderr
        if rc != 0:
            raise StepFailed(f"relay --once: rc={rc} {out[-200:]} {err[-200:]}")
        return out.strip()

    relay.provision()  # idempotent: what exists is left alone
    first = once()
    bus = relay.bus()
    seqs = {}
    try:
        for kind in ("decision.requested", "decision.returned"):
            got = bus.api(
                f"STREAM.MSG.GET.{relay.stream}",
                {"last_by_subj": f"{relay.prefix}.homelabnext.{kind}"},
                missing="message",
            )
            if got is None:
                raise StepFailed(f"no homelabnext.{kind} on the bus")
            msg = got["message"]
            event = json.loads(base64.b64decode(msg.get("data") or ""))
            msg_id = parse_headers(base64.b64decode(msg.get("hdrs") or "")).get("Nats-Msg-Id")
            if event.get("subject") != rid or event.get("source") != BROKER_SOURCE:
                raise StepFailed(f"the last {kind} is not the broker's for {rid}")
            if msg_id != event.get("id"):
                raise StepFailed(f"{kind}: Nats-Msg-Id is not the event id")
            seqs[kind] = int(msg["seq"])
    finally:
        bus.close()
    if not seqs["decision.requested"] < seqs["decision.returned"]:
        raise StepFailed(f"published out of order: {seqs}")
    second = once()
    if "published 0, 0 pending" not in second:
        raise StepFailed(f"the second pass republished: {second}")
    return f"{first}; requested seq {seqs['decision.requested']} < returned seq " + str(
        seqs["decision.returned"]
    )


def check_bus_acl(setup: Setup, rid: str) -> str:
    """Only the broker's user may publish the broker's subjects: a client with no user is
    refused, and the StackStorm bridge's user (which reads ``decision.returned``) cannot publish
    a forged ``decision.returned`` for ``rid`` with source ``svc:broker`` -- what A03 would act
    on -- nor purge the stream; the stream's last ``decision.returned`` is still the broker's."""
    from homelabnext.events.envelope import build_event, canonical_body

    relay = setup.relay
    assert relay is not None
    subject = f"{relay.prefix}.homelabnext.decision.returned"

    def last_returned() -> int:
        bus = relay.bus()
        try:
            got = bus.api(f"STREAM.MSG.GET.{relay.stream}", {"last_by_subj": subject})
            return int(got["message"]["seq"])
        finally:
            bus.close()

    before = last_returned()
    try:
        relay.wire(None).close()
    except Exception as exc:
        anonymous = type(exc).__name__
    else:
        raise StepFailed("a client without a user connected to the bus")
    forged = build_event(
        "homelabnext.decision.returned",
        BROKER_SOURCE,
        {"decision_id": rid, "verdict": "accept", "confidence": 1.0, "tier_used": "human"},
        dedupe_key=f"forged-{secrets.token_hex(4)}",
        subject=rid,
    )
    bus = relay.bus_as(LAB_NOT_BROKER)
    try:
        try:
            seq = bus.publish(forged["type"], canonical_body(forged), msg_id=forged["id"])
        except Exception as exc:
            if not getattr(exc, "permanent", False):
                raise StepFailed(f"the forged publish failed, but not as refused: {exc}") from None
        else:
            raise StepFailed(f"{LAB_NOT_BROKER} published a decision.returned (seq {seq})")
        try:
            bus.api(f"STREAM.PURGE.{relay.stream}", {})
        except Exception:
            pass
        else:
            raise StepFailed(f"{LAB_NOT_BROKER} purged the stream")
    finally:
        bus.close()
    after = last_returned()
    if after != before:
        raise StepFailed(f"the last decision.returned moved: {before} -> {after}")
    return (
        f"no user: refused ({anonymous}); {LAB_NOT_BROKER}: forged decision.returned and "
        f"purge refused; last decision.returned still seq {after}"
    )


def check_audit(setup: Setup, rid: str, profile: str) -> str:
    """Every step above is in the audit trail, read by the relay, each with its peer's ``via``."""
    proc = cli(setup, "relay", "audit", "--json", "--tail", "500")
    if proc.returncode != 0:
        raise StepFailed(f"audit as the relay: rc={proc.returncode} {proc.stderr[:200]}")
    records = json.loads(proc.stdout)
    if isinstance(records, dict):
        records = records.get("records", [])
    if not records or any(not r.get("via") for r in records):
        raise StepFailed("an audit record has no via")
    via = {role: f"uid:{uid}" for role, uid in setup.uids.items()}
    want = [
        ("call", "memory.write", "ok", None, "agent", None),
        ("call", "proposal.file", "ok", None, "agent", None),
        ("submit", "service.restart", "ok", None, "agent", rid),
        ("run", "service.restart", "denied", "approval-required", "agent", rid),
        ("connect", None, "denied", "unknown-caller", "stranger", None),
        ("approve", None, "denied", "not-an-approval-relay", "agent", None),
        ("approve", "service.restart", "ok", None, "relay", rid),
        ("run", "service.restart", "ok", None, "agent", rid),
        ("run", "service.restart", "invalid", "not-pending", "agent", rid),
    ]
    missing = []
    for op, action, outcome, reason, role, request in want:
        hit = [
            r
            for r in records
            if r.get("operation") == op
            and r.get("outcome") == outcome
            and r.get("via") == via[role]
            and (action is None or r.get("action") == action)
            and (reason is None or r.get("reason") == reason)
            and (request is None or r.get("request_id") == request)
        ]
        if not hit:
            missing.append(f"{op}/{action or '-'}/{outcome}/{reason or '-'} via {via[role]}")
    if missing:
        raise StepFailed(f"not in the audit trail: {missing}")
    mine = [r for r in records if r.get("request_id") == rid]
    if any(
        r.get("caller") not in (profile, f"sso:{APPROVER}")
        for r in mine
        if r.get("outcome") == "ok"
    ):
        raise StepFailed("an ok record for the request names another caller")
    return f"{len(want)} expected records found, each with via ({len(records)} read)"


# ---------------------------------------------------------------- the hub's configuration
def hub_files(directory: Path, *, edge_address: str, socket_path: str) -> dict[str, Path]:
    """The hub's registry, agents.yml and views.yml under ``directory``: one lab host (the
    edge's address, so the edge is the one trusted proxy), the status hub with its front door,
    and the Approvals page over ``socket_path``."""
    import ipaddress

    addr = str(ipaddress.ip_address(edge_address))
    directory.mkdir(parents=True, exist_ok=True)
    svc = {"owner": "lab-in-a-box", "host": "lab-edge"}
    registry = {
        "registry_version": 1,
        "lab": {"name": "lab-in-a-box", "domain": "example.internal", "svc_label": "svc",
                "owner": "lab-in-a-box"},
        "zones": {"lab": {"cidr": f"{addr}/32", "description": "the lab's edge"}},
        "hosts": {"lab-edge": {"address": addr, "zone": "lab", "role": "edge"}},
        "services": {
            "edge-proxy": {**svc, "capability": "edge-proxy", "impl": "caddy", "protocol": "https",
                           "port": 443, "health": {"kind": "tcp"}, "upstreams": ["status-hub"],
                           "version": "0.0.0", "tls": "public"},
            "idp": {**svc, "capability": "idp", "impl": "authentik", "protocol": "https",
                    "port": 9443, "health": {"kind": "tcp"}, "version": "0.0.0", "tls": "internal"},
            "status-hub": {**svc, "capability": "status-hub", "impl": "homelabnext",
                           "protocol": "http", "port": 8099,
                           "health": {"kind": "http", "path": "/status.json", "expect_status": 200},
                           "version": "0.1.0", "tls": "none", "auth": "idp",
                           "public_hostname": HUB_HOST,
                           "front_door": {"header": "X-Hnx-Front-Door",
                                          "secret": "secret:status/front-door-secret"}},
        },
    }  # fmt: skip
    agents = {
        "agents_version": 1,
        "store": "activity.db",
        "retention_days": 1,
        "detail": False,
        "private": {"service": "status-hub", "viewer_group": VIEWER_GROUP,
                    "access_log": "access.jsonl"},
        "approvals": {
            "socket": socket_path,
            "issuer": "sso",
            "approver_group": APPROVER_GROUP,
            "public_origin": f"https://{HUB_HOST}",
        },
    }  # fmt: skip
    views = {
        "views_version": 1,
        "shell": {"title": "Lab broker hub", "main": "overview"},
        "menu": [{"id": "overview", "title": "Overview", "panel": "exceptions"}],
    }
    out = {}
    for name, doc in (("services", registry), ("agents", agents), ("views", views)):
        out[name] = directory / f"{name}.yml"
        out[name].write_text(json.dumps(doc, indent=1) + "\n")  # JSON is YAML
    return out


def hub_argv(hnx: Sequence[str], files: Mapping[str, Path], *, bind: str, port: int) -> list[str]:
    argv = [*hnx, "status", "serve", "--registry", str(files["services"]), "--agents",
            str(files["agents"]), "--views", str(files["views"]), "--state",
            str(files["services"].parent / "state.json"), "--bind", bind, "--port", str(port),
            "--allowed-host", HUB_HOST]  # fmt: skip
    if bind not in (LOOPBACK, "localhost", "::1"):
        argv.append("--allow-remote")
    return argv


# ---------------------------------------------------------------- command line
def _as(spec: str, argv: list[str]) -> int:
    uid, gid, *groups = (int(x) for x in spec.split(":"))
    os.setgroups(groups)
    os.setgid(gid)
    os.setuid(uid)
    os.execvp(argv[0], argv)
    return 127  # not reached


def lab_launch(role: str) -> list[str]:
    """Inside the broker-edge container: run as the role's uid, in the socket's group."""
    uid = LAB_UIDS[role]
    return [sys.executable, os.path.abspath(__file__), "as", f"{uid}:{uid}:{LAB_CLIENTS_GID}", "--"]


def relay_launch() -> list[str]:
    """Inside the broker-edge container: run as the outbox relay's own uid."""
    uid = LAB_RELAY_UID
    return [sys.executable, os.path.abspath(__file__), "as", f"{uid}:{uid}", "--"]


def _ready(args) -> int:
    if not Path(args.socket).is_socket():
        return 1
    try:
        code, _ = http("GET", f"{args.hub}/status.json", {"Host": HUB_HOST})
    except OSError:
        return 1
    return 0 if code == 200 else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="the scenario")
    r.add_argument("--socket", default=LAB_SOCKET)
    r.add_argument("--hub", default=LAB_HUB)
    r.add_argument("--data-root", default=LAB_DATA_ROOT)
    r.add_argument("--json", action="store_true")
    r.add_argument(
        "--events-target",
        default=os.environ.get("LAB_BROKER_EVENTS_TARGET"),
        help="with a bus: the events target file the broker's relay uses (bus-relay step)",
    )
    r.add_argument("--state", default=LAB_STATE, help="the broker's state directory")
    r.add_argument("--stream", default=LAB_EVENTS_STREAM)
    r.add_argument("--subject-prefix", default=LAB_EVENTS_PREFIX)
    h = sub.add_parser("serve-hub", help="write the hub's configuration and run the hub")
    h.add_argument("--dir", required=True)
    h.add_argument("--edge-address", default=os.environ.get("LAB_BROKER_EDGE_ADDRESS"))
    h.add_argument("--socket", default=LAB_SOCKET)
    h.add_argument("--bind", default=LOOPBACK)
    h.add_argument("--port", type=int, default=8099)
    rd = sub.add_parser("ready", help="exit 0 once the socket exists and the hub answers")
    rd.add_argument("--socket", default=LAB_SOCKET)
    rd.add_argument("--hub", default=LAB_HUB)
    a = sub.add_parser("as", help="drop to UID:GID[:GROUP...] and exec the command after --")
    a.add_argument("spec")
    a.add_argument("command", nargs=argparse.REMAINDER)
    args = ap.parse_args(argv)
    if args.cmd == "as":
        cmd = args.command[1:] if args.command[:1] == ["--"] else args.command
        if not cmd:
            ap.error("as: no command")
        return _as(args.spec, cmd)
    if args.cmd == "ready":
        return _ready(args)
    if args.cmd == "serve-hub":
        if not args.edge_address:
            ap.error("serve-hub: --edge-address (or LAB_BROKER_EDGE_ADDRESS) is required")
        directory = Path(args.dir).resolve()
        files = hub_files(directory, edge_address=args.edge_address, socket_path=args.socket)
        cmd = hub_argv((sys.executable, "-m", "homelabnext.cli"), files, bind=args.bind,
                       port=args.port)  # fmt: skip
        os.chdir(directory)  # the agents config's store and access log are relative to it
        os.execvp(cmd[0], cmd)
    setup = Setup(
        socket=Path(args.socket),
        hub=args.hub,
        data_root=Path(args.data_root),
        uids=LAB_UIDS,
        secret=os.environ.get(SECRET_ENV, ""),
        launch=lab_launch,
        env={**os.environ, "HOME": "/tmp"},
    )
    if args.events_target:
        setup.relay = Relay(
            args.state,
            args.events_target,
            args.stream,
            args.subject_prefix,
            launch=relay_launch(),
        )
    rows = run_scenario(setup)
    ok = [r["step"] for r in rows] == list(steps(setup)) and all(r["ok"] for r in rows)
    if args.json:
        print(json.dumps({"ok": ok, "steps": rows}))
    else:
        for row in rows:
            print(f"{'PASS' if row['ok'] else 'FAIL'} {row['step']:<21} {row['detail']}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
