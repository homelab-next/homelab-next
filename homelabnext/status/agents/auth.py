# SPDX-License-Identifier: Apache-2.0
"""The private tier's door: who may see agent details, and the log of everyone who did.

``hnx status serve`` has no login of its own.  The private tier is served **only** when the hub is
configured with a trusted front door (``agents.yml`` ``private:`` naming a registry service whose
``front_door`` the edge adds), and then only to a request that passes every check, in order:

1. it arrives **from a trusted proxy address** (the edge's registry host; a local process talking
   to the loopback listener is not one);
2. it carries the front door's **shared-secret header** with the right value (constant-time
   compare; the edge adds it with ``header_up`` from the secret store, so a process that can reach
   the listener cannot forge the identity header below without also holding the secret);
3. it carries the **identity header** the forward-auth proxy sets (Authentik:
   ``X-Authentik-Username``);
4. that identity is in the **viewer group** (Authentik: ``X-Authentik-Groups``, ``|``-separated),
   or in the group the caller names (the Approvals page's approver group,
   :mod:`homelabnext.status.approvals`).

Anything missing, repeated or malformed is ``403`` -- fail closed -- and the reason is never
"open".  Every private view that is served is appended to the access log
(:class:`AccessLog`): who, which session or event, when.
"""

from __future__ import annotations

import hmac
import ipaddress
import json
import os
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from ..model import iso
from .config import FrontDoor

_IDENTITY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@+-]{0,127}$")


class _Headers(Protocol):
    def get_all(self, name: str, failobj: Any = None) -> list[str] | None: ...


@dataclass(frozen=True)
class Decision:
    allowed: bool
    user: str | None = None
    reason: str = ""


def _one(headers: _Headers, name: str) -> str | None:
    """The single value of a header; None when absent or sent more than once."""
    vals = headers.get_all(name) or []
    return vals[0].strip() if len(vals) == 1 else None


def _addr(text: str | None) -> str | None:
    try:
        return str(ipaddress.ip_address((text or "").strip("[]")))
    except ValueError:
        return None


def authorize(
    front_door: FrontDoor | None,
    client: str | None,
    headers: _Headers,
    *,
    group: str | None = None,
) -> Decision:
    """The front-door decision for one request (see the module docstring).  ``group``: the
    group the identity must be in (default: the front door's viewer group)."""
    if front_door is None or not front_door.secret:
        return Decision(False, reason="no trusted front door is configured")
    if _addr(client) not in front_door.trusted:
        return Decision(False, reason="not from a trusted proxy")
    sent = _one(headers, front_door.header)
    if sent is None or not hmac.compare_digest(sent.encode(), front_door.secret.encode()):
        return Decision(False, reason="front-door secret header missing or wrong")
    user = _one(headers, front_door.identity_header)
    if not user or not _IDENTITY_RE.match(user):
        return Decision(False, reason="no identity from the forward-auth proxy")
    groups = _one(headers, front_door.groups_header) or ""
    need = front_door.viewer_group if group is None else group
    if not need or need not in {g.strip() for g in re.split(r"[|,]", groups)}:
        which = "viewer" if group is None else "required"
        return Decision(False, user=user, reason=f"identity is not in the {which} group")
    return Decision(True, user=user)


class AccessLog:
    """Append-only JSONL of private-tier views: ``{"at", "user", "view", "session", "event"}``,
    plus, for the Approvals page's decisions, ``request``, ``decision``, ``outcome`` and
    ``reason``.

    One ``write`` per line on an ``O_APPEND`` descriptor (atomic for a line this size), fsynced,
    mode 0600.  Nothing here rewrites or truncates the file."""

    def __init__(self, path: str | Path, *, clock: Callable[[], float] = time.time):
        self.path = Path(path)
        self.clock = clock

    def append(
        self,
        user: str,
        view: str,
        *,
        session: str | None = None,
        event: str | None = None,
        **fields: str | None,
    ) -> dict[str, Any]:
        entry = {"at": iso(self.clock()), "user": user, "view": view}
        if session:
            entry["session"] = session
        if event:
            entry["event"] = event
        entry.update({k: v for k, v in fields.items() if v})
        line = (json.dumps(entry, sort_keys=True) + "\n").encode("utf-8")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.write(fd, line)
            os.fsync(fd)
        finally:
            os.close(fd)
        return entry

    def entries(self, limit: int = 500) -> list[Mapping[str, Any]]:
        """The newest ``limit`` entries, newest first (a corrupt line is skipped, not fatal)."""
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            return []
        out = []
        for line in reversed(lines):
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
            if len(out) >= limit:
                break
        return out
