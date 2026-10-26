# SPDX-License-Identifier: Apache-2.0
"""``hnx broker mcp``: the agent-facing tools, end to end through a running broker socket.

The broker runs in this process on a real socket; the MCP server talks to it as this process's
uid (``profile:triage``), in memory and as a stdio subprocess.  Skipped without the ``mcp``
extra, and off Linux (the socket authenticates peers with ``SO_PEERCRED``)."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest
from test_broker_server import RELAY_UID, _service

from homelabnext.broker.client import BrokerClient
from homelabnext.broker.mcp_tools import SERVER_NAME, TOOLS
from homelabnext.broker.server import BrokerServer, handle_request, supported

ROOT = Path(__file__).resolve().parents[2]

pytestmark = pytest.mark.skipif(
    not supported(), reason="SO_PEERCRED: the broker socket authenticates peers on Linux only"
)

#: the whole tool list, pinned: adding a tool is a reviewed change to this set
BROKER_TOOLS = {
    "broker_actions",
    "broker_call",
    "broker_submit",
    "broker_status",
    "broker_run",
    "broker_cancel",
    "broker_pending",
    "memory_write",
    "finding_write",
    "proposal_file",
}


@pytest.fixture
def running(tmp_path, monkeypatch):
    monkeypatch.setenv("HNX_BROKER_SECRET_DEMO_API_TOKEN", "fake-mcp-token")
    srv = BrokerServer(_service(tmp_path), tmp_path / "run" / "broker.sock").start()
    yield srv
    srv.close()


def _relay_approve(srv: BrokerServer, rid: str) -> None:
    body = {
        "op": "approve",
        "request_id": rid,
        "approver": {"issuer": "sso", "subject": "operator-one"},
    }
    resp = handle_request(srv.service, srv.peers, RELAY_UID, json.dumps(body).encode())
    assert resp["ok"], resp


def _client(server):
    import mcp

    if hasattr(mcp, "Client"):  # 2.x
        return mcp.Client(server)
    from mcp.shared.memory import create_connected_server_and_client_session

    return create_connected_server_and_client_session(server)


def _is_error(result) -> bool:
    return bool(getattr(result, "is_error", getattr(result, "isError", False)))


def _json(result):
    assert not _is_error(result), result.content[0].text
    return json.loads(result.content[0].text)


def test_tool_list_is_pinned_and_registered():
    from homelabnext.agent.readers import default_classes

    assert set(TOOLS) == BROKER_TOOLS
    assert default_classes().classify("mcp", SERVER_NAME) is not None


def test_tools_end_to_end_in_memory(running, tmp_path):
    pytest.importorskip("mcp")
    import anyio

    from homelabnext.broker.mcp_tools import build_server

    async def run():
        async with _client(build_server(BrokerClient(running.path))) as s:
            tools = {t.name: t for t in (await s.list_tools()).tools}
            assert set(tools) == BROKER_TOOLS
            for name, t in tools.items():
                hints = t.annotations.model_dump(by_alias=True)
                assert hints["openWorldHint"] is False
                assert hints["readOnlyHint"] is (
                    name in {"broker_actions", "broker_status", "broker_pending"}
                )
                schema = getattr(t, "input_schema", None) or t.inputSchema
                assert not {"actor", "caller", "as", "profile"} & set(schema.get("properties", {}))

            acts = _json(await s.call_tool("broker_actions", {}))
            assert acts["caller"] == "profile:triage"
            assert {a["action"] for a in acts["actions"]} >= {"memory.write", "service.restart"}

            out = _json(await s.call_tool("memory_write", {"name": "m.md", "content": "hello\n"}))
            assert out["path"] == "memory/triage/m.md"
            assert (tmp_path / "data/memory/triage/m.md").read_text() == "hello\n"
            out = _json(
                await s.call_tool(
                    "finding_write", {"name": "2026-01-15-queue.md", "content": "slow\n"}
                )
            )
            assert out["path"] == "findings/triage/2026-01-15-queue.md"
            note = {"title": "Raise the drain timeout", "risk": "low", "rollback": "set it back"}
            out = _json(await s.call_tool("proposal_file", {"note": note, "body": "Seen twice."}))
            assert out["path"].startswith("records/inbox/")

            bad = await s.call_tool("memory_write", {"name": "../../x.md", "content": "x"})
            assert _is_error(bad) and "refused (lane-name-invalid)" in bad.content[0].text
            bad = await s.call_tool(
                "broker_call",
                {"action": "service.restart", "params": {"grace_s": 1}, "target": "svc:queue"},
            )
            assert _is_error(bad) and "approval-required" in bad.content[0].text

            sub = _json(
                await s.call_tool(
                    "broker_submit",
                    {"action": "service.restart", "params": {"grace_s": 1}, "target": "svc:queue"},
                )
            )
            rid = sub["request_id"]
            assert sub["awaiting_approval"] is True
            pend = _json(await s.call_tool("broker_pending", {}))
            assert [p["request_id"] for p in pend] == [rid]
            _relay_approve(running, rid)
            ran = _json(await s.call_tool("broker_run", {"request_id": rid}))
            assert ran["output"]["would_restart"] == "svc:queue"
            st = _json(await s.call_tool("broker_status", {"request_id": rid}))
            assert st["state"] == "done"

            other = _json(
                await s.call_tool(
                    "broker_submit",
                    {"action": "service.status", "params": {}, "target": "svc:queue"},
                )
            )
            assert (
                _json(await s.call_tool("broker_cancel", {"request_id": other["request_id"]}))[
                    "state"
                ]
                == "cancelled"
            )
            status = _json(
                await s.call_tool(
                    "broker_call", {"action": "service.status", "target": "svc:queue"}
                )
            )
            assert status["exit_code"] == 0

    anyio.run(run)
    vias = {r.get("via") for r in running.service.audit_documents()}
    assert vias == {f"uid:{os.getuid()}", f"uid:{RELAY_UID}"}


def test_mcp_server_over_stdio_acts_as_its_own_uid(running, tmp_path):
    pytest.importorskip("mcp")
    import anyio
    from mcp import ClientSession, StdioServerParameters, stdio_client

    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "homelabnext.cli", "broker", "mcp", "--socket", str(running.path)],
        env={**os.environ, "PYTHONPATH": str(ROOT)},
        cwd=str(ROOT),
    )

    async def run():
        import mcp

        with anyio.fail_after(60):
            if hasattr(mcp, "Client"):  # 2.x
                async with mcp.Client(params) as s:
                    names = {t.name for t in (await s.list_tools()).tools}
                    res = await s.call_tool("memory_write", {"name": "stdio.md", "content": "x"})
            else:
                async with stdio_client(params) as (r, w), ClientSession(r, w) as s:
                    await s.initialize()
                    names = {t.name for t in (await s.list_tools()).tools}
                    res = await s.call_tool("memory_write", {"name": "stdio.md", "content": "x"})
        assert names == BROKER_TOOLS
        assert _json(res)["path"] == "memory/triage/stdio.md"

    anyio.run(run)
    assert (tmp_path / "data/memory/triage/stdio.md").exists()


def test_mcp_command_needs_a_socket(monkeypatch, capsys):
    from homelabnext.broker.cli import main

    monkeypatch.delenv("HNX_BROKER_SOCKET", raising=False)
    assert main(["mcp"]) == 2
    assert "--socket" in capsys.readouterr().err
