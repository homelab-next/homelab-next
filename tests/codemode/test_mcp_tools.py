# SPDX-License-Identifier: Apache-2.0
"""``codemode_search`` and ``codemode_describe`` (CM-5b): the calling profile's index only,
narrowed to what the broker grants it now; the catalog record and the tool class."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from homelabnext.codemode.mcp_tools import SERVER_NAME, TOOLS, CodemodeIndex, IndexRefused

ROOT = Path(__file__).resolve().parents[2]
INDEX = ROOT / "examples" / "codemode"
TRIAGE = {"service.status", "service.restart", "memory.write", "finding.write", "proposal.file"}


def _index(profile="profile:triage", names=frozenset(TRIAGE)):
    return CodemodeIndex(INDEX, lambda: (profile, set(names)))


def test_search_lists_only_the_callers_granted_actions():
    got = _index().search("")
    assert {a["name"] for a in got["actions"]} == TRIAGE and got["total"] == len(TRIAGE)
    narrowed = _index(names={"service.status"}).search("")
    assert [a["name"] for a in narrowed["actions"]] == ["service.status"], (
        "an action the broker no longer grants is still listed"
    )
    reader = _index("profile:reader", {"service.status", "service.restart"}).search("")
    assert [a["name"] for a in reader["actions"]] == ["service.status"], (
        "the reader's index names only its own actions, whatever the broker says"
    )


def test_search_ranks_by_words_and_describe_gives_the_schema():
    got = _index().search("restart service", limit=1)
    assert [a["name"] for a in got["actions"]] == ["service.restart"]
    row = got["actions"][0]
    assert row["needs_approval"] is True and set(row) == {
        "name",
        "call",
        "summary",
        "tier",
        "kind",
        "needs_approval",
    }
    assert _index().search("nothing-matches-this")["actions"] == []
    entry = _index().describe("service.status")
    assert entry["params"]["type"] == "object" and entry["result"]["type"] == "ServiceStatusResult"
    assert "python" in entry["signatures"]
    with pytest.raises(IndexRefused):
        _index(names={"memory.write"}).describe("service.status")
    with pytest.raises(IndexRefused):
        _index("profile:nobody").search("")


def test_the_catalog_record_classes_the_tools_and_acts_on_nothing():
    from homelabnext.agent.readers import default_classes
    from homelabnext.mcp.servers import load

    rec = yaml.safe_load((ROOT / "examples" / "mcp" / f"{SERVER_NAME}.yml").read_text())
    assert {t["name"] for t in rec["tools"]} == set(TOOLS)
    assert all(set(t["classes"]) == {"read", "codemode"} for t in rec["tools"])
    assert "acts_via" not in rec, "no tool here acts: execute is codemode.execute on hnx-broker"
    table = yaml.safe_load((ROOT / "homelabnext" / "agent" / "tool_classes.yml").read_text())
    assert "codemode" in table["classes"] and "codemode" in table["reader_forbidden"]
    assert "codemode" not in table["broker_only"]
    assert table["capabilities"]["cap:codemode-runner"] == ["exec"]
    assert default_classes().classify("mcp", SERVER_NAME) is not None
    assert load(ROOT / "examples" / "mcp").classes()[SERVER_NAME] == ["codemode", "read"]


def test_tools_in_memory():
    pytest.importorskip("mcp")
    import anyio

    from homelabnext.codemode.mcp_tools import build_server

    def client(server):
        import mcp

        if hasattr(mcp, "Client"):  # 2.x
            return mcp.Client(server)
        from mcp.shared.memory import create_connected_server_and_client_session

        return create_connected_server_and_client_session(server)

    async def run():
        async with client(build_server(_index())) as s:
            tools = {t.name: t for t in (await s.list_tools()).tools}
            assert set(tools) == set(TOOLS)
            for t in tools.values():
                hints = t.annotations.model_dump(by_alias=True)
                assert hints["readOnlyHint"] is True and hints["openWorldHint"] is False
                schema = getattr(t, "input_schema", None) or t.inputSchema
                assert not {"actor", "caller", "profile"} & set(schema.get("properties", {}))
            res = await s.call_tool("codemode_search", {"query": "status"})
            assert json.loads(res.content[0].text)["actions"][0]["name"] == "service.status"
            bad = await s.call_tool("codemode_describe", {"name": "codemode.execute"})
            assert getattr(bad, "is_error", getattr(bad, "isError", False))

    anyio.run(run)


def test_the_mcp_command_needs_a_socket(monkeypatch, capsys):
    from homelabnext.codemode.cli import main

    monkeypatch.delenv("HNX_BROKER_SOCKET", raising=False)
    assert main(["mcp", "--index", str(INDEX)]) == 2
    assert "--socket" in capsys.readouterr().err


def test_an_actor_may_hold_search_and_execute_through_the_broker_and_a_reader_neither():
    """G-13 with the new record and action: an actor holding hnx-codemode (search, describe) and
    hnx-broker (whose broker_call runs codemode.execute) acts only through the broker; a reader
    may hold neither the codemode class nor cap:codemode-runner (G-03), and no profile holds
    cap:codemode-runner directly (it is exec, broker-only, and not cap:broker)."""
    from homelabnext.agent.readers import broker_problems, reader_problems

    actor = {"mcp": ["hnx-codemode", "hnx-broker"], "capabilities": ["cap:broker"]}
    assert broker_problems(actor) == []
    assert reader_problems({"mcp": ["hnx-codemode"], "capabilities": []}), (
        "a reader was allowed the codemode class"
    )
    direct = {"mcp": [], "capabilities": ["cap:codemode-runner"]}
    assert broker_problems(direct), "cap:codemode-runner was granted outside the broker"
