# SPDX-License-Identifier: Apache-2.0
"""Fakes and builders for the agent-activity tests: summary/detail records, a header bag with
``get_all`` like ``http.server``'s, the hook module loaded from ``hooks/``, and a loopback
request helper.  Nothing here reads the wall clock."""

from __future__ import annotations

import http.client
import importlib.util
import json
import urllib.parse
from pathlib import Path

from status_helpers import ROOT, T0

from homelabnext.status.agents.config import FrontDoor
from homelabnext.status.model import iso
from homelabnext.status.serve import LOOPBACK

#: the secret every redaction test plants; it must never reach the disk
FAKE_BEARER = "fake0bearer0token0abcdef0123456789"
FAKE_SECRET = "fake-front-door-secret-0123456789"
HOSTILE = '<script>alert("x")</script><img src=x onerror=alert(1)> **bold** [link](javascript:x)'


def summary(n: int = 1, *, session: str = "s-1", t: float = T0, **kw) -> dict:
    doc = {
        "event_id": f"ev-{session}-{n}",
        "session_id": session,
        "runtime": "claude-code",
        "time": iso(t),
        "kind": "tool_end",
        "tool": "Bash",
        "outcome": "success",
    }
    doc.update(kw)
    return {k: v for k, v in doc.items() if v is not None}


def detail(n: int = 1, *, session: str = "s-1", t: float = T0, **kw) -> dict:
    doc = {"event_id": f"ev-{session}-{n}", "session_id": session, "time": iso(t)}
    doc.update(kw)
    return doc


class Headers:
    """A header bag with ``get``/``get_all`` (``http.client.HTTPMessage``-like)."""

    def __init__(self, pairs: list[tuple[str, str]] | dict[str, str] = ()):
        items = list(pairs.items()) if isinstance(pairs, dict) else list(pairs)
        self.items = [(k.lower(), v) for k, v in items]

    def get_all(self, name: str, failobj=None):
        vals = [v for k, v in self.items if k == name.lower()]
        return vals or failobj

    def get(self, name: str, default=None):
        vals = self.get_all(name)
        return vals[0] if vals else default


def front_door(tmp_path: Path, trusted: str = LOOPBACK) -> FrontDoor:
    return FrontDoor(
        trusted=frozenset({trusted}),
        header="X-Hnx-Front-Door",
        secret=FAKE_SECRET,
        identity_header="X-Authentik-Username",
        groups_header="X-Authentik-Groups",
        viewer_group="hub-private-viewers",
        access_log=tmp_path / "access.jsonl",
    )


AUTHORIZED = {
    "X-Hnx-Front-Door": FAKE_SECRET,
    "X-Authentik-Username": "operator",
    "X-Authentik-Groups": "staff|hub-private-viewers",
}


def load_hook():
    path = ROOT / "hooks" / "claude_code_activity.py"
    spec = importlib.util.spec_from_file_location("claude_code_activity", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def request(base: str, path: str, *, method: str = "GET", headers=None, body: bytes | None = None):
    """``(status, headers, body)`` for one loopback request with exactly these headers."""
    u = urllib.parse.urlsplit(base)
    conn = http.client.HTTPConnection(u.hostname, u.port, timeout=5)
    hdrs = {"Host": u.netloc, **(headers or {})}
    conn.request(method, path, body=body, headers=hdrs)
    resp = conn.getresponse()
    out = resp.status, dict(resp.getheaders()), resp.read()
    conn.close()
    return out


def post_json(base: str, doc, token: str | None, **kw):
    headers = {"Content-Type": "application/json", **kw.pop("headers", {})}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    raw = doc if isinstance(doc, bytes) else json.dumps(doc).encode()
    return request(
        base, kw.pop("path", "/ingest/agent-activity"), method="POST", headers=headers, body=raw
    )
