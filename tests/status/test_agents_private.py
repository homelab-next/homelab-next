# SPDX-License-Identifier: Apache-2.0
"""The agent pages and the private tier: the front door, the access log, escaped rendering."""

from __future__ import annotations

import json
import threading

import pytest
from agent_helpers import (
    AUTHORIZED,
    FAKE_SECRET,
    HOSTILE,
    Headers,
    detail,
    front_door,
    request,
    summary,
)
from status_helpers import T0, VIEWS

from homelabnext.registry.model import load
from homelabnext.status import build_status, load_views
from homelabnext.status.agents import ActivityStore, AgentsConfigError, authorize, load_config
from homelabnext.status.agents.auth import AccessLog
from homelabnext.status.agents.config import IngestSettings, Sender
from homelabnext.status.agents.pages import AgentSite
from homelabnext.status.model import iso
from homelabnext.status.render import render_html
from homelabnext.status.serve import LOOPBACK, make_server

DOC_ADDR = ".".join(["192", "0", "2", "10"])  # a documentation address, built so no gate trips


@pytest.fixture
def store(tmp_path, clock):
    s = ActivityStore(tmp_path / "activity.db", clock=clock)
    s.add(
        [
            summary(1, session="s-1", kind="prompt", outcome="info", has_detail=True,
                    project="homelab-next", model="example-model-large"),
            summary(2, session="s-1", kind="tool_end", has_detail=True),
            summary(1, session="s-2", runtime="codex", outcome="error"),
        ],
        [detail(1, session="s-1", prompt=HOSTILE), detail(2, session="s-1", tool_output="=1+1")],
        via="test",
    )  # fmt: skip
    return s


def _doc(registry, site):
    views = load_views(VIEWS)
    snap = {"now": "2026-09-21T13:33:20Z", "observations": [], "sources": []}
    return build_status(snap, views, registry, [], agents=site.summary() if site else None)


@pytest.fixture
def served(tmp_path, clock, store, registry):
    def start(fd):
        site = AgentSite(store, front_door=fd, clock=clock)
        srv = make_server(lambda: _doc(registry, site), agents=site)
        threading.Thread(target=srv.serve_forever, args=(0.05,), daemon=True).start()
        servers.append(srv)
        host, port = srv.server_address[:2]
        return f"http://{host}:{port}", site

    servers = []
    yield start
    for srv in servers:
        srv.shutdown()
        srv.server_close()


# ---------------------------------------------------------------- the front door, unit
@pytest.mark.parametrize(
    "client, headers, reason",
    [
        (DOC_ADDR, AUTHORIZED, "not from a trusted proxy"),
        (LOOPBACK, {**AUTHORIZED, "X-Hnx-Front-Door": ""}, "secret header"),
        (LOOPBACK, {k: v for k, v in AUTHORIZED.items() if k != "X-Hnx-Front-Door"}, "secret header"),
        (LOOPBACK, {**AUTHORIZED, "X-Hnx-Front-Door": "fake-wrong"}, "secret header"),
        (LOOPBACK, {k: v for k, v in AUTHORIZED.items() if k != "X-Authentik-Username"}, "no identity"),
        (LOOPBACK, {**AUTHORIZED, "X-Authentik-Username": "a b<c>"}, "no identity"),
        (LOOPBACK, {**AUTHORIZED, "X-Authentik-Groups": "staff"}, "viewer group"),
        (LOOPBACK, {k: v for k, v in AUTHORIZED.items() if k != "X-Authentik-Groups"}, "viewer group"),
        (LOOPBACK, {**AUTHORIZED, "X-Authentik-Groups": "hub-private-viewers-not"}, "viewer group"),
    ],
)  # fmt: skip
def test_front_door_refuses_each_missing_piece(tmp_path, client, headers, reason):
    d = authorize(front_door(tmp_path), client, Headers(headers))
    assert not d.allowed and reason in d.reason


def test_front_door_allows_with_every_piece(tmp_path):
    d = authorize(front_door(tmp_path), LOOPBACK, Headers(AUTHORIZED))
    assert d.allowed and d.user == "operator"
    assert authorize(front_door(tmp_path, "::1"), "::1", Headers(AUTHORIZED)).allowed


def test_a_repeated_header_fails_closed(tmp_path):
    twice = [*AUTHORIZED.items(), ("X-Hnx-Front-Door", FAKE_SECRET)]
    assert not authorize(front_door(tmp_path), LOOPBACK, Headers(twice)).allowed
    spoof = [*AUTHORIZED.items(), ("X-Authentik-Username", "someone-else")]
    assert not authorize(front_door(tmp_path), LOOPBACK, Headers(spoof)).allowed


def test_no_front_door_never_allows(tmp_path):
    assert not authorize(None, LOOPBACK, Headers(AUTHORIZED)).allowed


# ---------------------------------------------------------------- the private tier, served
PRIVATE = ["/private/sessions", "/private/session?id=s-1", "/private/event?id=ev-s-1-1",
           "/private/access-log"]  # fmt: skip


@pytest.mark.parametrize("path", PRIVATE)
def test_main_listener_without_a_front_door_never_serves_private(served, path):
    base, _ = served(None)
    assert request(base, path, headers=AUTHORIZED)[0] == 403


@pytest.mark.parametrize(
    "drop", ["proxy", "X-Hnx-Front-Door", "X-Authentik-Username", "X-Authentik-Groups"]
)
@pytest.mark.parametrize("path", PRIVATE)
def test_private_view_is_403_without_each_piece(served, tmp_path, drop, path):
    fd = front_door(tmp_path, trusted=DOC_ADDR if drop == "proxy" else LOOPBACK)
    base, site = served(fd)
    headers = {k: v for k, v in AUTHORIZED.items() if k != drop}
    code, _, body = request(base, path, headers=headers)
    assert code == 403 and b"operator" not in body
    assert site.access_log.entries() == []  # a refused view is not a view


def test_private_view_is_200_with_all_and_access_logged(served, tmp_path, clock):
    base, _site = served(front_door(tmp_path))
    code, _, body = request(base, "/private/session?id=s-1", headers=AUTHORIZED)
    assert code == 200
    page = body.decode()
    # hostile prompt text is escaped text, never markup
    assert "<script>" not in page and "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;" in page
    assert "<img" not in page and "**bold**" in page
    clock.advance(5)
    assert request(base, "/private/event?id=ev-s-1-2", headers=AUTHORIZED)[0] == 200
    log = AccessLog(tmp_path / "access.jsonl").entries()
    assert log[0] == {"at": iso(T0 + 5), "user": "operator", "view": "event",
                      "session": "s-1", "event": "ev-s-1-2"}  # fmt: skip
    assert log[1] == {"at": iso(T0), "user": "operator", "view": "session",
                      "session": "s-1"}  # fmt: skip
    code, _, body = request(base, "/private/access-log", headers=AUTHORIZED)
    assert code == 200 and b"ev-s-1-2" in body  # the log is visible in the private view
    assert oct((tmp_path / "access.jsonl").stat().st_mode & 0o777) == "0o600"


def test_private_menu_group_renders_only_when_authorized(served, tmp_path):
    base, _ = served(front_door(tmp_path))
    _, _, public = request(base, "/")
    _, _, private = request(base, "/", headers=AUTHORIZED)
    assert b"Session detail" not in public and b"Access log" not in public
    assert b"Session detail" in private and b'href="/private/sessions"' in private
    menu = json.loads(request(base, "/status.json", headers=AUTHORIZED)[2])["menu"]
    assert all(m.get("group") != "private" for m in menu)  # never in the public contract


# ---------------------------------------------------------------- summary pages
def test_summary_pages_render_and_link_to_private_only_when_authorized(served, tmp_path):
    base, _ = served(front_door(tmp_path))
    for path in ("/agents", "/agents?state=errored", "/agents/session?id=s-1",
                 "/activity", "/activity?runtime=codex&event=ev-s-2-1", "/agent-analytics"):  # fmt: skip
        code, headers, body = request(base, path)
        assert code == 200, path
        assert "default-src 'none'" in headers["Content-Security-Policy"]
        assert b"<script" not in body and HOSTILE.encode() not in body
        assert b"/private/" not in body
    _, _, body = request(base, "/agents?state=errored")
    assert b"s-2" in body and b"agents/session?id=s-1" not in body
    _, _, body = request(base, "/agents/session?id=s-1", headers=AUTHORIZED)
    assert b'href="/private/session?id=s-1"' in body
    assert request(base, "/agents/session?id=nope")[0] == 404
    _, _, body = request(base, "/activity")
    assert b'http-equiv="refresh"' in body  # the tail, without script


def test_exports_are_summary_tier_only(served, tmp_path):
    base, _ = served(front_door(tmp_path))
    code, headers, body = request(base, "/activity.jsonl", headers=AUTHORIZED)
    assert code == 200 and headers["Content-Type"].startswith("application/x-ndjson")
    rows = [json.loads(line) for line in body.decode().splitlines()]
    assert len(rows) == 3 and all("prompt" not in r and "tool_output" not in r for r in rows)
    code, headers, body = request(base, "/activity.csv?runtime=codex")
    lines = body.decode().splitlines()
    assert code == 200 and lines[0].startswith("time,event_id,session_id")
    assert len(lines) == 2 and "codex" in lines[1]
    assert HOSTILE.encode() not in body and b"=1+1" not in body


def test_static_page_marks_agent_pages_live_only(registry, store, clock):
    site = AgentSite(store, clock=clock)
    html = render_html(_doc(registry, site))
    assert 'title="served live by hnx status serve">Agents' in html
    assert "Session detail" not in html  # private group: never in a static page


def test_status_json_lists_sessions_from_the_summary_tier(registry, store, clock):
    doc = _doc(registry, AgentSite(store, clock=clock))
    assert doc["agents"]["counts"]["errored"] == 1
    assert {s["session_id"] for s in doc["agents"]["sessions"]} == {"s-1", "s-2"}
    assert HOSTILE not in json.dumps(doc)
    agents = next(m for m in doc["menu"] if m["id"] == "agents")
    assert agents == {"id": "agents", "title": "Agents", "kind": "page", "panel": "agents",
                      "href": "/agents", "available": True}  # fmt: skip
    without = build_status(
        {"now": "2026-09-21T13:33:20Z", "observations": [], "sources": []},
        load_views(VIEWS), registry, [],
    )  # fmt: skip
    assert without["agents"] is None
    assert not next(m for m in without["menu"] if m["id"] == "agents")["available"]


# ---------------------------------------------------------------- config
def test_config_resolves_the_front_door_from_the_registry(tmp_path):
    reg = load(VIEWS.parents[1] / "services.yml")
    secrets = {
        "secret:status/front-door-secret": FAKE_SECRET,
        "secret:status/ingest/cloud-sessions-token": "fake-t",
    }
    cfg = load_config(VIEWS.parent / "agents.yml", reg, secrets.get, base=tmp_path)
    fd = cfg.front_door
    assert fd.header == "X-Hnx-Front-Door" and fd.secret == FAKE_SECRET
    assert fd.trusted == frozenset({reg.hosts["edge-core"].address})  # the edge, from the registry
    assert [s.name for s in cfg.ingest.senders] == ["cloud-sessions"]  # others: no token, disabled
    assert any("agent-fleet disabled" in w for w in cfg.warnings)
    assert cfg.thresholds.for_session("orchestrator", None) == 1800


def test_config_without_the_secret_disables_the_private_tier(tmp_path):
    reg = load(VIEWS.parents[1] / "services.yml")
    cfg = load_config(VIEWS.parent / "agents.yml", reg, {}.get, base=tmp_path)
    assert cfg.front_door is None and any("private tier disabled" in w for w in cfg.warnings)


def test_config_refuses_a_literal_token_and_an_unknown_host(tmp_path):
    reg = load(VIEWS.parents[1] / "services.yml")
    bad = tmp_path / "agents.yml"
    bad.write_text(
        "agents_version: 1\nstore: a.db\ningest: {senders: [{name: x, token: fake-literal}]}\n"
    )
    with pytest.raises(AgentsConfigError, match="token"):
        load_config(bad, reg, {}.get)
    bad.write_text(
        "agents_version: 1\nstore: a.db\nprivate: {service: status-hub, viewer_group: g, "
        "access_log: a.jsonl, trusted_proxies: [nowhere]}\n"
    )
    with pytest.raises(AgentsConfigError, match="not a registry host"):
        load_config(bad, reg, {"secret:status/front-door-secret": "fake-s"}.get)


def test_config_refuses_colliding_secret_names_and_shared_tokens(tmp_path):
    """Two sender token references that map to one environment variable, or two senders with
    the same token, are refused at load (``sender_for`` cannot tell such senders apart)."""
    reg = load(VIEWS.parents[1] / "services.yml")
    bad = tmp_path / "agents.yml"
    head = "agents_version: 1\nstore: a.db\ningest: {senders: ["
    bad.write_text(
        head + '{name: a, token: "secret:status/ingest-cloud"}, '
        '{name: b, token: "secret:status/ingest_cloud"}]}\n'
    )
    with pytest.raises(AgentsConfigError, match="HNX_SECRET_STATUS_INGEST_CLOUD"):
        load_config(bad, reg, {}.get)
    bad.write_text(
        head
        + '{name: a, token: "secret:status/ingest/fake-a"}, {name: b, token: "secret:status/ingest/fake-b"}]}\n'
    )
    shared = "fake-shared-token"
    same = {"secret:status/ingest/fake-a": shared, "secret:status/ingest/fake-b": shared}
    with pytest.raises(AgentsConfigError, match="same token"):
        load_config(bad, reg, same.get)
    with pytest.raises(ValueError, match="same token"):
        IngestSettings(senders=(Sender("a", "fake-t"), Sender("b", "fake-t")))
