# SPDX-License-Identifier: Apache-2.0
"""A third party's hosted MCP server: ``transport.type: remote`` (round 4, F5).

A lab server is reached by registry name (``endpoint: svc:<name>``); a vendor's hosted server
(a tracker, a notes service, a code host's hosted MCP) has no registry entry, so its record names
an explicit https URL: no userinfo, no query, a public DNS host, internet egress, credentials only
as headers' ``secret:`` names.  Every value is fictional."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
import yaml

from homelabnext.mcp import clients, servers
from homelabnext.registry.model import load

ROOT = Path(__file__).resolve().parents[2]
REMOTE = yaml.safe_load((ROOT / "schemas/platform/examples/mcp_server.remote.yml").read_text())
REGISTRY = load(ROOT / "examples" / "services.yml")


def _problems(rec: dict, registry=None) -> list[str]:
    return servers._schema_problems(rec, "x") or (
        servers.remote_problems(rec, "x", registry)
        + servers._egress_problems(rec, "x")
        + servers._literal_problems(rec, "x")
    )


def _edit(**changes) -> dict:
    rec = copy.deepcopy(REMOTE)
    for path, value in changes.items():
        *head, last = path.split("__")
        d = rec
        for k in head:
            d = d[k]
        if value is None:
            d.pop(last, None)
        else:
            d[last] = value
    return rec


def test_a_hosted_server_with_an_https_url_is_a_valid_record():
    assert _problems(REMOTE, REGISTRY) == []


@pytest.mark.parametrize(
    ("changes", "phrase"),
    [
        ({"transport__url": "http://mcp.tracker.example.com/mcp"}, "does not match"),
        ({"transport__url": "https://fakeuser:fakepw@mcp.tracker.example.com/mcp"}, "does not match"),
        ({"transport__url": "https://mcp.tracker.example.com/mcp?api_key=fake1"}, "does not match"),
        ({"transport__url": "https://mcp.tracker.example.com/mcp#x"}, "does not match"),
        ({"transport__url": "https://192.0.2.10/mcp"}, "names a public host"),
        ({"transport__url": "https://localhost/mcp"}, "does not match"),
        # private suffixes, assembled so the repository holds no private host name
        ({"transport__url": "https://mcp.tracker." + "internal/mcp"}, "names a public host"),
        ({"transport__url": "https://tracker." + "home.arpa/mcp"}, "names a public host"),
        ({"transport__url": "https://mcp.example/mcp"}, "names a public host"),
        ({"egress": "none"}, "egress names internet"),
        ({"egress": ["svc:notify"]}, "egress names internet"),
        ({"runtime": "agent-local"}, "runtime hosted goes with a remote transport"),
        ({"origin": {"kind": "image", "image": "registry.example/x", "digest": None}},
         "a hosted origin goes with a remote transport"),
        ({"headers__Authorization": "Bearer fakeTok3nAbC9xYz12345"}, "does not match"),
        ({"env": {"TOKEN": "secret:mcp/x"}}, "env is for a stdio server"),
    ],
    ids=lambda v: str(v)[:60],
)  # fmt: skip
def test_a_hosted_server_is_https_public_internet_and_secret_headers_only(changes, phrase):
    problems = _problems(_edit(**changes), REGISTRY)
    assert any(phrase in p for p in problems), problems


def test_a_lab_host_is_reached_by_registry_name_not_a_remote_url():
    host = sorted(REGISTRY.hosts)[0]
    rec = _edit(transport__url=f"https://{host}.tools.example.com/mcp")
    assert any("names a lab host" in p for p in _problems(rec, REGISTRY))
    rec = _edit(transport__url=f"https://mcp.{REGISTRY.domain}/mcp")
    assert any("names a lab host" in p or "public host" in p for p in _problems(rec, REGISTRY))


def test_a_hosted_origin_is_not_a_stdio_server():
    rec = _edit(transport={"type": "stdio"}, headers=None, runtime="hosted")
    assert any("a hosted origin goes with a remote transport" in p for p in _problems(rec))


def _inst(rec: dict) -> clients.Instance:
    return clients.Instance(name=rec["id"], server=rec["id"], profile="p", lane="real",
                            record=rec, params={})  # fmt: skip


def test_a_hosted_server_renders_for_the_clients_that_speak_http():
    inst = _inst({**REMOTE, "status": "active"})
    assert clients.definition(inst, "claude-code") == {
        "type": "http",
        "url": "https://mcp.tracker.example.com/mcp",
        "headers": {"Authorization": "Bearer ${HNX_SECRET_MCP_TRACKER_TOKEN}"},
    }
    assert clients.definition(inst, "generic")["transport"] == "streamable-http"
    assert clients.definition(inst, "hermes")["url"] == "https://mcp.tracker.example.com/mcp"
    assert clients.definition(inst, "claude-desktop") is None  # stdio only: reported, left out
    sse = _inst(_edit(transport__protocol="sse"))
    assert clients.definition(sse, "claude-code")["type"] == "sse"
    with pytest.raises(clients.RenderError, match="legacy sse"):
        clients.definition(sse, "hermes")
    plain = _inst(_edit(transport__url="http://mcp.tracker.example.com/mcp"))
    with pytest.raises(clients.RenderError, match="never plaintext"):
        clients.definition(plain, "claude-code")
    entry, why = clients.orch_kind("tracker", REMOTE)
    assert entry is None and "remote is skipped" in why[0]
    json.dumps(clients.definition(inst, "claude-code"))  # a plain JSON value
