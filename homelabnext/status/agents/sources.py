# SPDX-License-Identifier: Apache-2.0
"""Agent activity as status sources (kind ``agent-activity``, registry ``service.json`` 2.2).

Each source drains its input into the activity store and then reports the sessions it fed:

* ``agent-spool`` -- a spool directory (``target.file``) of one-record JSON files
  ``{"summary": {...}, "detail": {...}}`` (detail optional).  The Claude Code hook
  (``hooks/claude_code_activity.py``) writes them; so can any other runtime: this is the generic
  file spool.  A file is ingested and deleted; an invalid one is moved to ``rejected/``.
* ``agentmetry-jsonl`` -- an Agentmetry canonical JSONL trail (``target.file``), read from the
  last offset; each canonical event maps to one summary event (:func:`map_agentmetry`).  The trail
  hashes tool arguments, so it has no detail tier.
* ``agent-push`` -- nothing to drain: the push ingest (:mod:`.ingest`) writes the store; this
  source reports the pushed sessions.

The drafts are exceptions-first: one ``fail`` item per errored session, one ``warn`` item per
stuck session, and two live-work counts (``working``, ``waiting``).  A done or healthy session
is not an item, so the main page stays one green number while agents simply work.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ..collectors import CollectContext, CollectError, _inside
from ..mapping import Draft, age_text, clean_item, clean_summary
from ..model import SourceSpec, iso, parse_iso
from .store import ActivityError, ActivityStore

MAX_SPOOL_FILE = 1 << 20
MAX_TRAIL_READ = 8 << 20  # per poll; the rest is read next time
HEAD_BYTES = 4096  # how much of a trail's start identifies it (with its inode) across polls
PUSH_VIA = "push"
_log = logging.getLogger(__name__)

# ---------------------------------------------------------------- Agentmetry canonical -> ours
_AM_KIND = {
    "session_start": ("session_start", None),
    "session_end": ("session_end", None),
    "approval_request": ("approval_request", "pending"),
    "approval_response": ("approval_response", None),
    "tool_called": ("tool_end", None),
    "tool_failed": ("tool_end", "error"),
    "detection": ("notification", "info"),
}
_AM_OUTCOME = {
    "success": "success",
    "error": "error",
    "denied": "denied",
    "pending": "pending",
}
_PATTERNS = {
    "id": re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"),
    "host": re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$"),
    "model": re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,99}$"),
    "agent": re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$"),
    "tool": re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$"),
    "runtime": re.compile(r"^[a-z][a-z0-9-]{0,31}$"),
}


def _fit(value: Any, kind: str) -> str | None:
    """``value`` as text if it fits the summary field's pattern, else None (never forced)."""
    if not isinstance(value, str) or not value:
        return None
    text = value.strip()
    return text if _PATTERNS[kind].match(text) else None


def _time(value: Any) -> str | None:
    try:
        return iso(parse_iso(str(value)))
    except (TypeError, ValueError):
        return None


def map_agentmetry(ev: Mapping[str, Any]) -> dict[str, Any] | None:
    """One Agentmetry canonical event (``docs/agentmetry-event-schema.md`` 1.1) as a summary
    event, or None for what has no counterpart (``config_change``) or cannot be identified."""
    action = ev.get("action") if isinstance(ev.get("action"), Mapping) else {}
    atype = action.get("type")
    if atype not in _AM_KIND:
        return None
    kind, forced = _AM_KIND[atype]
    event_id = _fit(ev.get("event_id"), "id")
    session = _fit(ev.get("session_id") or ev.get("correlation_id"), "id")
    when = _time(ev.get("timestamp_utc"))
    if not (event_id and session and when):
        return None
    outcome = forced or _AM_OUTCOME.get(str(action.get("outcome") or ""), "info")
    if atype == "approval_response" and outcome == "success":
        outcome = "approved"
    if atype == "detection":
        outcome = "info"
    source = ev.get("source") if isinstance(ev.get("source"), Mapping) else {}
    agent = ev.get("agent") if isinstance(ev.get("agent"), Mapping) else {}
    tool = ev.get("tool") if isinstance(ev.get("tool"), Mapping) else {}
    model = ev.get("model") if isinstance(ev.get("model"), Mapping) else {}
    out: dict[str, Any] = {
        "event_id": f"am-{event_id}"[:128],
        "session_id": session,
        "runtime": _fit(str(source.get("app") or "").lower(), "runtime") or "agentmetry",
        "time": when,
        "kind": kind,
        "outcome": outcome,
    }
    optional = {
        "host": _fit(ev.get("host_id"), "host"),
        "model": _fit(model.get("id"), "model"),
        "agent": _fit(agent.get("skill_id") or agent.get("name"), "agent"),
        "tool": _fit(tool.get("qualified") or tool.get("name"), "tool"),
        "parent_session_id": _fit(ev.get("correlation_id"), "id")
        if ev.get("session_id") and ev.get("correlation_id") != ev.get("session_id")
        else None,
    }
    out.update({k: v for k, v in optional.items() if v})
    if source.get("tier") == "external":
        out["surface"] = "local"
    return out


# ---------------------------------------------------------------- draining
def drain_spool(store: ActivityStore, spool: Path, via: str) -> tuple[int, int]:
    """Ingest every ``*.json`` record in ``spool`` (oldest name first); returns (ok, rejected).
    Ingested files are deleted, invalid ones moved to ``rejected/`` (kept for a look, never
    re-read)."""
    if not spool.is_dir():
        return 0, 0
    ok = bad = 0
    for f in sorted(spool.glob("*.json")):
        try:
            if f.stat().st_size > MAX_SPOOL_FILE:
                raise ValueError("record larger than 1 MiB")
            rec = json.loads(f.read_text(encoding="utf-8"))
            if not isinstance(rec, Mapping) or not isinstance(rec.get("summary"), Mapping):
                raise ValueError("not a {summary, detail} record")
            detail = rec.get("detail")
            store.add([rec["summary"]], [detail] if isinstance(detail, Mapping) else [], via=via)
            f.unlink()
            ok += 1
        except (OSError, ValueError, ActivityError):
            bad += 1
            rej = spool / "rejected"
            rej.mkdir(exist_ok=True)
            with contextlib.suppress(OSError):
                f.replace(rej / f.name)
    return ok, bad


def _position(raw: str | None) -> dict[str, Any]:
    """The stored read position of a trail (an older plain-integer offset still reads)."""
    try:
        pos = json.loads(raw) if raw else {}
    except ValueError:
        pos = {}
    if isinstance(pos, int) and not isinstance(pos, bool):
        pos = {"offset": pos}
    return pos if isinstance(pos, dict) and isinstance(pos.get("offset"), int) else {"offset": 0}


def _head(fh, n: int) -> str:
    fh.seek(0)
    return hashlib.sha256(fh.read(n)).hexdigest()


def drain_agentmetry(store: ActivityStore, trail: Path, via: str) -> tuple[int, int]:
    """Read the trail from the stored position, in one store batch per poll.

    The position carries the file's identity (device and inode) and a hash of its first bytes
    (up to ``HEAD_BYTES`` already read), so a rotated trail -- a new file, or one truncated and
    written again -- is read from 0 even when it has already grown past the old offset.  A line
    longer than ``MAX_TRAIL_READ`` is skipped to its newline and counted (as rejected) once."""
    key = f"offset:{via}"
    try:
        fh = trail.open("rb")
    except FileNotFoundError:
        return 0, 0
    with fh:
        st = os.fstat(fh.fileno())
        ident = f"{st.st_dev}:{st.st_ino}"
        pos = _position(store.get_meta(key))
        offset = pos["offset"]
        head_len = min(int(pos.get("head_len") or 0), st.st_size)
        if (
            st.st_size < offset
            or pos.get("id", ident) != ident
            or (
                pos.get("head")
                and (head_len < pos["head_len"] or _head(fh, head_len) != pos["head"])
            )
        ):
            pos, offset = {"offset": 0}, 0  # rotated or truncated: read the new file from 0
        fh.seek(offset)
        chunk = fh.read(MAX_TRAIL_READ)
        ok = bad = 0
        start, skip = 0, bool(pos.get("skip"))
        if skip:  # inside an over-long line: drop up to its newline
            nl = chunk.find(b"\n")
            start, skip = (len(chunk), True) if nl < 0 else (nl + 1, False)
        end = max(chunk.rfind(b"\n") + 1, start)  # whole lines only; a half-written one waits
        if end == start and not skip and len(chunk) - start >= MAX_TRAIL_READ:
            _log.warning("%s: a line longer than %d bytes is skipped", trail.name, MAX_TRAIL_READ)
            bad, start, end, skip = 1, len(chunk), len(chunk), True
        events = []
        for raw in chunk[start:end].splitlines():
            try:
                ev = json.loads(raw)
            except ValueError:
                bad += 1
                continue
            mapped = map_agentmetry(ev) if isinstance(ev, Mapping) else None
            if mapped is None:
                bad += 1
            else:
                events.append(mapped)
        try:
            store.add(events, via=via)  # one transaction, one purge
            ok += len(events)
        except ActivityError:  # one bad record: find it without losing the others
            for ev in events:
                try:
                    store.add([ev], via=via)
                    ok += 1
                except ActivityError:
                    bad += 1
        new = offset + end
        n = min(new, HEAD_BYTES)
        store.set_meta(
            key,
            json.dumps(
                {"offset": new, "id": ident, "head_len": n, "head": _head(fh, n), "skip": skip},
                sort_keys=True,
            ),
        )
    return ok, bad


# ---------------------------------------------------------------- sessions -> drafts
def _who(s: Mapping[str, Any]) -> str:
    where = "/".join(x for x in (s.get("host"), s.get("project")) if x)
    return f"{s.get('runtime')} session{' on ' + where if where else ''}"


def session_drafts(sessions: list[Mapping[str, Any]], module: str | None) -> list[Draft]:
    out: list[Draft] = []
    for s in sessions:
        item = clean_item(f"session:{s['session_id']}", "session")
        tool = f" (last tool {s['last_tool']})" if s.get("last_tool") else ""
        if s["state"] == "errored":
            out.append(
                Draft(
                    item=item,
                    state="fail",
                    summary=clean_summary(f"{_who(s)} errored{tool}"),
                    module=module,
                )
            )
        elif s["state"] == "stuck":
            out.append(
                Draft(
                    item=item,
                    state="warn",
                    summary=clean_summary(
                        f"{_who(s)} stuck: no event for {age_text(s['idle_s'])}{tool}"
                    ),
                    module=module,
                )
            )
    for state in ("working", "waiting"):
        n = sum(1 for s in sessions if s["state"] == state)
        noun = "session" if n == 1 else "sessions"
        out.append(
            Draft(
                item=state,
                state="ok",
                summary=f"{n} {noun} {state}",
                module=module,
                value=n,
                work=True,
            )
        )
    return out


def collect(spec: SourceSpec, ctx: CollectContext) -> list[Draft]:
    """The ``agent-activity`` collector (see the module docstring)."""
    store = getattr(ctx, "activity", None)
    if store is None:
        raise CollectError("no activity store configured (hnx status collect --agents FILE)")
    builtin = spec.mapping.get("builtin")
    via = spec.id
    if builtin == "agent-spool":
        drain_spool(store, _inside(ctx.root, spec.file or ""), via)
    elif builtin == "agentmetry-jsonl":
        drain_agentmetry(store, _inside(ctx.root, spec.file or ""), via)
    elif builtin == "agent-push":
        via = PUSH_VIA
    else:
        raise CollectError(f"unknown agent-activity mapping {builtin!r}")
    return session_drafts(store.sessions(ctx.clock(), via=via), spec.mapping.get("module"))
