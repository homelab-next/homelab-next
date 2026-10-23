#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Portions derived from Agentmetry (Apache-2.0), Copyright 2026 blitzcrieg1; modified.
# hnx-script:
#   id: claude-code-activity-hook
#   kind: tool
#   purpose: Report Claude Code (or a CLI with the same hook shape) session activity to the status hub, both tiers.
#   owner: status-hub
#   trigger: [manual]
#   inputs: one hook event as JSON on stdin (SessionStart, SessionEnd, UserPromptSubmit, PreToolUse, PostToolUse, PermissionRequest, Notification, Stop, SubagentStop)
#   outputs: one record file in the spool directory (--spool) or one POST to the hub's ingest (--post); nothing on stdout
#   exit:
#     "0": always -- a reporting failure never blocks or alters the agent
"""Claude Code hook -> status hub agent activity (ADR-0013 stage 1b, ``docs/status.md``).

Standard library only, so it can be copied to any workstation or cloud session.  Install it as a
``command`` hook for every event in ``settings.json`` (snippet in ``docs/status.md``).  Each event
becomes one record ``{"summary": {...}, "detail": {...}}``:

==================== ===================== ===================================================
hook event           summary ``kind``      detail
==================== ===================== ===================================================
SessionStart         session_start         --
SessionEnd           session_end           --
UserPromptSubmit     prompt                ``prompt``
PreToolUse           tool_start            ``tool_input``, ``command`` (Bash)
PostToolUse          tool_end (+ outcome)  ``tool_input``, ``command``, ``tool_output``/``error``
PermissionRequest    approval_request      ``approval`` (ask + the gated tool input)
Notification         approval_request if   ``approval`` (ask + the message) for a permission
                     it asks permission,   prompt; nothing otherwise
                     else notification
Stop                 stop                  --
SubagentStop         subagent_stop         --
==================== ===================== ===================================================

**Where it goes.**  ``--post URL`` sends it to the hub's push ingest with the bearer token from
the environment variable ``--token-env`` names (the hub redacts and caps before storing); the URL
must be ``https://`` (plain ``http://`` only to a loopback address) and a redirect is refused, so
the token never reaches another host.
``--spool DIR`` writes one file per event (atomic rename, mode 0600) for the hub's
``agent-spool`` source; because that file is on disk, the detail tier is spooled **only** when
the shared screener (``homelabnext.agent.screen``) is importable to redact secrets first --
otherwise the record is spooled without its detail.  ``--no-detail`` never sends the detail.

**It never talks back.**  Nothing is printed: some hook events add stdout to the agent's context,
and this hook must not feed anything (least of all a prompt or a tool output) back into it.  Every
error is swallowed and the exit code is 0, so reporting can never block or change the agent.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

MAX_FIELD = 65536  # the hub caps again (smaller) after redaction
_ID_BAD = re.compile(r"[^A-Za-z0-9._:-]")
_NAME_BAD = re.compile(r"[^A-Za-z0-9._@-]")
_TOOL_BAD = re.compile(r"[^A-Za-z0-9._:/-]")
_MODEL_BAD = re.compile(r"[^A-Za-z0-9._:/@-]")


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _clean(value: Any, bad: re.Pattern[str], limit: int) -> str | None:
    s = bad.sub("-", str(value or "")).strip("-._:/@")[:limit]
    return s or None


def decode_stdin(raw: bytes) -> dict[str, Any]:
    """The hook's JSON object, tolerating a BOM or UTF-16 (some Windows shells re-encode
    stdin); ``{}`` when it is not a JSON object.  (After Agentmetry's ``read_hook_stdin``.)"""
    if not raw.strip():
        return {}
    blobs = [(raw, "utf-8")]
    if raw.startswith(b"\xef\xbb\xbf"):
        blobs.insert(0, (raw[3:], "utf-8"))
    elif raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        blobs.insert(0, (raw, "utf-16"))
    elif len(raw) >= 4 and raw[1:2] == b"\x00" and raw[3:4] == b"\x00":
        blobs.insert(0, (raw, "utf-16-le"))
    for blob, enc in blobs:
        try:
            doc = json.loads(blob.decode(enc).strip("﻿\x00"))
        except (UnicodeDecodeError, ValueError):
            continue
        if isinstance(doc, dict):
            return doc
    return {}


def tool_failed(response: Any) -> bool:
    """Whether a PostToolUse ``tool_response`` reports a failure: a non-zero exit code, an error
    flag or text, ``success: false`` or an interrupt.  Never assume success.  (After Agentmetry's
    ``_after_outcome``.)"""
    if not isinstance(response, Mapping):
        return False
    code = response.get("exit_code", response.get("exitCode"))
    err = response.get("error", response.get("is_error", response.get("isError")))
    return (
        (isinstance(code, int) and not isinstance(code, bool) and code != 0)
        or response.get("success") is False
        or response.get("interrupted") is True
        or err is True
        or (isinstance(err, str) and err.strip() != "")
    )


def _text(value: Any) -> str | None:
    if value is None or value == "" or value == {}:
        return None
    s = value if isinstance(value, str) else json.dumps(value, sort_keys=True, default=str)
    return s[:MAX_FIELD]


def _output(response: Any) -> str | None:
    if isinstance(response, Mapping):
        parts = [response.get(k) for k in ("stdout", "stderr", "output", "content", "result")]
        joined = "\n".join(str(p) for p in parts if isinstance(p, str) and p)
        return _text(joined or response)
    return _text(response)


def map_event(
    data: Mapping[str, Any],
    *,
    runtime: str = "claude-code",
    surface: str | None = None,
    host: str | None = None,
    now: float,
) -> tuple[dict[str, Any], dict[str, Any] | None] | None:
    """One hook payload -> ``(summary, detail or None)``; None for an unknown event."""
    hook = str(data.get("hook_event_name") or "")
    session = _clean(data.get("session_id"), _ID_BAD, 128)
    if not session:
        return None
    tool = _clean(data.get("tool_name"), _TOOL_BAD, 128)
    tin = data.get("tool_input")
    command = tin.get("command") if isinstance(tin, Mapping) else None
    detail: dict[str, Any] = {}
    kind: str
    outcome: str | None = None
    if hook == "SessionStart":
        kind, outcome = "session_start", "info"
    elif hook == "SessionEnd":
        kind, outcome = "session_end", "info"
    elif hook == "UserPromptSubmit":
        kind, outcome = "prompt", "info"
        detail["prompt"] = _text(data.get("prompt"))
    elif hook == "PreToolUse":
        kind = "tool_start"
        detail.update(tool_input=_text(tin), command=_text(command))
    elif hook == "PostToolUse":
        response = data.get("tool_response")
        failed = tool_failed(response)
        kind, outcome = "tool_end", "error" if failed else "success"
        detail.update(tool_input=_text(tin), command=_text(command))
        detail["error" if failed else "tool_output"] = _output(response)
    elif hook == "PermissionRequest":
        kind, outcome = "approval_request", "pending"
        detail["approval"] = {"decision": "ask", "payload": _text(tin) or ""}
    elif hook == "Notification":
        message = str(data.get("message") or "")
        if "permission" in message.lower():
            kind, outcome = "approval_request", "pending"
            detail["approval"] = {"decision": "ask", "payload": message[:MAX_FIELD]}
        else:
            kind, outcome = "notification", "info"
    elif hook == "Stop":
        kind = "stop"
    elif hook == "SubagentStop":
        kind = "subagent_stop"
    else:
        return None
    when = _iso(now)
    digest = hashlib.sha256(
        json.dumps([session, hook, data.get("tool_use_id"), repr(now)], default=str).encode()
    ).hexdigest()[:24]
    summary: dict[str, Any] = {
        "event_id": f"{runtime[:8]}-{digest}",
        "session_id": session,
        "runtime": runtime,
        "time": when,
        "kind": kind,
    }
    optional = {
        "surface": surface,
        "host": _clean((host or "").split(".")[0], _NAME_BAD, 63),
        "project": _clean(Path(str(data.get("cwd") or "")).name, _NAME_BAD, 63),
        "model": _clean(
            (data.get("model") or {}).get("id")
            if isinstance(data.get("model"), Mapping)
            else data.get("model"),
            _MODEL_BAD,
            100,
        ),
        "agent": _clean(data.get("agent_type") or data.get("subagent_type"), _ID_BAD, 64),
        "tool": tool,
        "outcome": outcome,
    }
    summary.update({k: v for k, v in optional.items() if v})
    detail = {k: v for k, v in detail.items() if v}
    if not detail:
        return summary, None
    summary["has_detail"] = True
    return summary, {"event_id": summary["event_id"], "session_id": session, "time": when, **detail}


def _screen(detail: dict[str, Any]) -> dict[str, Any] | None:
    """The detail with secrets redacted by the shared screener, or None when it is unavailable
    (then the detail is not written to disk at all)."""
    try:
        from homelabnext.agent.screen import Screener
    except ImportError:
        return None
    sc = Screener(types=("private-key", "jwt", "token", "secret"))
    out = dict(detail)
    for k in ("prompt", "command", "tool_input", "tool_output", "error"):
        if isinstance(out.get(k), str):
            out[k] = sc.screen(out[k])[0]
    if isinstance(out.get("approval"), Mapping):
        appr = dict(out["approval"])
        if isinstance(appr.get("payload"), str):
            appr["payload"] = sc.screen(appr["payload"])[0]
        out["approval"] = appr
    return out


def write_spool(spool: Path, record: Mapping[str, Any], now: float) -> Path:
    """One record file, written to a temporary name and renamed (the collector never sees half a
    file), mode 0600."""
    spool.mkdir(parents=True, exist_ok=True)
    name = f"{int(now * 1000):015d}-{record['summary']['event_id']}.json"
    tmp = spool / f".{name}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(record, fh, sort_keys=True)
    final = spool / name
    os.replace(tmp, final)
    return final


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect: urllib would follow a 301/302/303 on a POST and copy the bearer
    token to whatever host the ``Location`` names.  The ingest answers directly, never with one."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        raise urllib.error.HTTPError(req.full_url, code, f"refusing redirect ({msg})", headers, fp)


def _loopback(host: str | None) -> bool:
    if not host:
        return False
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def post_url_problem(url: str) -> str | None:
    """Why the bearer token may not be sent to ``url`` (None when it may): only ``https://``, or
    plain ``http://`` to a loopback address, where nothing on the path can read it."""
    parts = urllib.parse.urlsplit(url)
    if parts.username is not None or parts.password is not None:
        return "the ingest URL may not carry credentials"
    if parts.scheme == "https" and parts.hostname:
        return None
    if parts.scheme == "http" and _loopback(parts.hostname):
        return None
    return "the ingest URL must be https:// (plain http:// only to a loopback address)"


def post(url: str, token: str, record: Mapping[str, Any], timeout: float = 3.0) -> int:
    problem = post_url_problem(url)
    if problem:
        raise ValueError(problem)
    body = {"summary": [record["summary"]]}
    if record.get("detail"):
        body["detail"] = [record["detail"]]
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
        method="POST",
    )
    with urllib.request.build_opener(_NoRedirect).open(req, timeout=timeout) as resp:
        return resp.status


def main(
    argv: list[str] | None = None,
    *,
    stdin: bytes | None = None,
    env: Mapping[str, str] | None = None,
    clock: Callable[[], float] = time.time,
) -> int:
    environ = os.environ if env is None else env
    ap = argparse.ArgumentParser(prog="claude_code_activity.py")
    ap.add_argument("--runtime", default="claude-code")
    ap.add_argument("--surface", choices=["local", "cloud"])
    where = ap.add_mutually_exclusive_group(required=True)
    where.add_argument("--spool", help="spool directory of the hub's agent-spool source")
    where.add_argument("--post", help="the hub's ingest URL (.../ingest/agent-activity)")
    ap.add_argument("--token-env", default="HNX_STATUS_INGEST_TOKEN")
    ap.add_argument("--no-detail", action="store_true", help="never send the private tier")
    try:
        args = ap.parse_args(argv)
        raw = sys.stdin.buffer.read() if stdin is None else stdin
        surface = args.surface or (
            "cloud" if environ.get("CLAUDE_CODE_REMOTE") == "true" else "local"
        )
        now = clock()
        mapped = map_event(
            decode_stdin(raw),
            runtime=args.runtime,
            surface=surface,
            host=socket.gethostname(),
            now=now,
        )
        if mapped is None:
            return 0
        summary, detail = mapped
        if args.no_detail:
            detail = None
        if args.spool and detail is not None:
            detail = _screen(detail)  # never write an unredacted detail to disk
        if detail is None:  # --no-detail, or no screener: the summary must not claim one
            summary.pop("has_detail", None)
        if args.spool:
            write_spool(Path(args.spool), {"summary": summary, "detail": detail}, now)
        else:
            token = environ.get(args.token_env, "")
            if token:
                post(args.post, token, {"summary": summary, "detail": detail})
    except SystemExit:
        return 0
    except Exception:  # reporting must never break the agent
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
