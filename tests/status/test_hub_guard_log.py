# SPDX-License-Identifier: Apache-2.0
"""The hub's host guard says what it refused (LL-565): one sanitised, rate-limited line per
refusal on stderr and an ``outcome: refused`` record in the access log, never a credential."""

from __future__ import annotations

import json
import socket
import threading
from pathlib import Path

import pytest
from agent_helpers import AUTHORIZED, FAKE_SECRET, front_door, request
from status_helpers import T0, VIEWS

from homelabnext.status import build_status, load_views
from homelabnext.status.agents.config import ApprovalsSettings
from homelabnext.status.approvals import ApprovalsSite
from homelabnext.status.model import iso
from homelabnext.status.serve import (
    LOOPBACK,
    REFUSAL_VALUE_MAX,
    RefusalLimiter,
    clean_value,
    make_server,
)

SETTINGS = ApprovalsSettings(
    socket=Path("/run/x.sock"), issuer="sso", approver_groups=frozenset({"hub-approvers"})
)


class _Broker:
    def pending(self):
        return []

    def audit(self, **_):
        return []


@pytest.fixture
def hub(tmp_path, registry, clock):
    servers = []

    def start():
        fd = front_door(tmp_path, LOOPBACK)
        site = ApprovalsSite(_Broker(), SETTINGS, fd, clock=clock, key=b"k" * 32)
        doc = build_status(
            {"now": iso(T0), "observations": [], "sources": []}, load_views(VIEWS), registry, []
        )
        srv = make_server(lambda: doc, approvals=site)
        threading.Thread(target=srv.serve_forever, args=(0.05,), daemon=True).start()
        servers.append(srv)
        host, port = srv.server_address[:2]
        return f"http://{host}:{port}", tmp_path / "access.jsonl"

    yield start
    for srv in servers:
        srv.shutdown()
        srv.server_close()


def _records(path):
    if not path.exists():
        return []
    return [json.loads(x) for x in path.read_text().splitlines()]


def test_a_refused_host_is_logged_with_what_the_guard_saw(hub, capsys):
    base, access = hub()
    hdrs = {
        **AUTHORIZED,
        "Host": "status-hub.svc.example.internal:8099",
        "X-Forwarded-Host": "hub.example.internal",
        "Origin": "https://sso.example.internal",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "cross-site",
        "Cookie": "session=COOKIE-SECRET",
        "Authorization": "Bearer BEARER-SECRET",
    }
    status, _, body = request(base, "/approvals?token=QUERY-SECRET", headers=hdrs)
    assert status == 403 and b"host not allowed" in body
    err = capsys.readouterr().err
    assert 'refused host not allowed: GET "/approvals"' in err
    for seen in ("status-hub.svc.example.internal:8099", "hub.example.internal", "cors",
                 "cross-site", "https://sso.example.internal", "client=127.0.0.1"):  # fmt: skip
        assert seen in err
    (rec,) = _records(access)
    assert rec["outcome"] == "refused" and rec["reason"] == "host not allowed"
    assert rec["method"] == "GET" and rec["view"] == "approvals" and rec["client"] == "127.0.0.1"
    assert rec["host"] == "status-hub.svc.example.internal:8099"
    assert rec["x_forwarded_host"] == "hub.example.internal"
    assert rec["sec_fetch_site"] == "cross-site"
    everything = err + access.read_text()
    for secret in ("QUERY-SECRET", "COOKIE-SECRET", "BEARER-SECRET", FAKE_SECRET, "token="):
        assert secret not in everything


def test_an_allowed_request_logs_nothing(hub, capsys):
    base, access = hub()
    assert request(base, "/")[0] == 200
    assert capsys.readouterr().err == "" and _records(access) == []


def test_other_methods_are_logged_too(hub, capsys):
    base, access = hub()
    status, _, _ = request(base, "/status.json", method="PUT", headers={"Host": "evil.example"})
    assert status == 403
    assert "PUT" in capsys.readouterr().err
    assert _records(access)[-1]["method"] == "PUT"


def test_a_hostile_header_cannot_forge_or_split_a_line(hub, capsys):
    base, access = hub()
    host, port = base.removeprefix("http://").split(":")
    evil = b"evil.example\x1b[31m\x7f\x85\xc2\x85" + b"X" * 500
    raw = b"GET /x HTTP/1.1\r\nHost: " + evil + b"\r\nOrigin: a\tb\r\nConnection: close\r\n\r\n"
    with socket.create_connection((host, int(port)), timeout=5) as s:
        s.sendall(raw)
        data = b""
        while chunk := s.recv(4096):
            data += chunk
    assert b" 403 " in data
    err = capsys.readouterr().err
    assert err.count("\n") == 1  # one refusal, one line
    assert "\x1b" not in err and "\x7f" not in err and "\x85" not in err and "\t" not in err
    (rec,) = _records(access)
    assert len(rec["host"]) <= REFUSAL_VALUE_MAX and rec["host"].startswith("evil.example")
    assert rec["origin"] == "ab"
    assert access.read_text().count("\n") == 1


def test_clean_value():
    assert clean_value("a\r\nb\x00c\u2028d") == "abcd"
    assert clean_value("x" * 999) == "x" * REFUSAL_VALUE_MAX
    assert clean_value(None) == "None"[:REFUSAL_VALUE_MAX]


def test_refusals_are_rate_limited_per_client():
    now = [0.0]
    lim = RefusalLimiter(3, clock=lambda: now[0])
    assert [lim.take("a")[0] for _ in range(5)] == [True, True, True, False, False]
    assert lim.take("b") == (True, 0)  # another client has its own budget
    now[0] = 61.0
    assert lim.take("a") == (True, 2)  # the window passed; the suppressed count is reported once
    assert lim.take("a") == (True, 0)


def test_the_limiter_remembers_a_bounded_number_of_clients():
    lim = RefusalLimiter(1, clients=4, clock=lambda: 0.0)
    for i in range(50):
        lim.take(f"c{i}")
        lim.take(f"c{i}")  # suppressed once
    assert len(lim._seen) <= 4 and len(lim._dropped) <= 4


def test_a_flood_writes_a_bounded_number_of_lines(hub, capsys):
    base, access = hub()
    for _ in range(40):
        assert request(base, "/", headers={"Host": "evil.example"})[0] == 403
    assert capsys.readouterr().err.count("\n") == 10
    assert len(_records(access)) == 10


def test_the_post_route_still_logs_one_access_record(hub, capsys):
    base, access = hub()
    status, _, _ = request(
        base, "/approvals/decide", method="POST", headers={**AUTHORIZED, "Host": "evil.example"},
        body=b"x=1",
    )  # fmt: skip
    assert status == 403
    assert capsys.readouterr().err.count("refused host not allowed: POST") == 1
    recs = _records(access)
    assert len(recs) == 1 and recs[0]["reason"] == "host not allowed"
