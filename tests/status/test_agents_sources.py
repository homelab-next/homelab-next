# SPDX-License-Identifier: Apache-2.0
"""Agent activity collectors: the Claude Code hook, the spool, the Agentmetry trail, and the
agent-activity source on the hub's main page."""

from __future__ import annotations

import builtins
import json

import pytest
from agent_helpers import FAKE_BEARER, load_hook, summary
from status_helpers import T0

from homelabnext.status import CollectContext, Scheduler, SourceSpec
from homelabnext.status.agents import ActivityStore, map_agentmetry, summary_problems
from homelabnext.status.agents.model import detail_problems
from homelabnext.status.agents.sources import drain_agentmetry, drain_spool

hook = load_hook()
BASE = {"session_id": "6b1f0c2e-4d7a", "cwd": "/home/someone/work/homelab-next"}


def _map(event: str, **kw):
    return hook.map_event({**BASE, "hook_event_name": event, **kw}, host="devbox.lab", now=T0)


# ---------------------------------------------------------------- the Claude Code hook
@pytest.mark.parametrize(
    "event, extra, kind, outcome, detail_keys",
    [
        ("SessionStart", {"source": "startup", "model": "example-model-large"}, "session_start", "info", None),
        ("SessionEnd", {"reason": "exit"}, "session_end", "info", None),
        ("UserPromptSubmit", {"prompt": "fix the tests"}, "prompt", "info", {"prompt"}),
        ("PreToolUse", {"tool_name": "Bash", "tool_input": {"command": "make check"}}, "tool_start", None, {"tool_input", "command"}),
        ("PostToolUse", {"tool_name": "Bash", "tool_input": {"command": "ls"}, "tool_response": {"stdout": "a b", "exit_code": 0}}, "tool_end", "success", {"tool_input", "command", "tool_output"}),
        ("PostToolUse", {"tool_name": "Bash", "tool_input": {"command": "false"}, "tool_response": {"stderr": "boom", "exit_code": 1}}, "tool_end", "error", {"tool_input", "command", "error"}),
        ("PermissionRequest", {"tool_name": "Bash", "tool_input": {"command": "rm -r build"}}, "approval_request", "pending", {"approval"}),
        ("Notification", {"message": "Claude needs your permission to use Bash"}, "approval_request", "pending", {"approval"}),
        ("Notification", {"message": "Claude is waiting for your input"}, "notification", "info", None),
        ("Stop", {"stop_hook_active": False}, "stop", None, None),
        ("SubagentStop", {"stop_hook_active": False}, "subagent_stop", None, None),
    ],
)  # fmt: skip
def test_hook_maps_each_event_type_to_both_tiers(event, extra, kind, outcome, detail_keys):
    summary_doc, detail_doc = _map(event, **extra)
    assert summary_problems(summary_doc) == []
    assert summary_doc["kind"] == kind and summary_doc.get("outcome") == outcome
    assert (summary_doc["host"], summary_doc["project"]) == ("devbox", "homelab-next")
    if detail_keys is None:
        assert detail_doc is None and "has_detail" not in summary_doc
    else:
        assert detail_problems(detail_doc) == []
        assert set(detail_doc) - {"event_id", "session_id", "time"} == detail_keys
        assert detail_doc["event_id"] == summary_doc["event_id"] and summary_doc["has_detail"]
    if event == "SessionStart":
        assert summary_doc["model"] == "example-model-large"


def test_hook_ignores_what_it_does_not_know():
    assert _map("SomethingNew") is None
    assert hook.map_event({"hook_event_name": "Stop"}, now=T0) is None  # no session
    assert hook.decode_stdin(b"not json") == {}
    assert hook.decode_stdin('{"a": 1}'.encode("utf-16")) == {"a": 1}
    assert hook.decode_stdin(b'\xef\xbb\xbf{"a": 2}') == {"a": 2}


def test_hook_spools_redacted_and_prints_nothing(tmp_path, capsys):
    spool = tmp_path / "spool"
    raw = json.dumps(
        {**BASE, "hook_event_name": "PreToolUse", "tool_name": "Bash",
         "tool_input": {"command": f"curl -H 'Authorization: Bearer {FAKE_BEARER}' x"}}
    ).encode()  # fmt: skip
    assert hook.main(["--spool", str(spool)], stdin=raw, env={}, clock=lambda: T0) == 0
    (f,) = spool.glob("*.json")
    assert FAKE_BEARER not in f.read_text() and "[REDACTED:token:1]" in f.read_text()
    assert oct(f.stat().st_mode & 0o777) == "0o600"
    assert capsys.readouterr().out == ""  # nothing fed back into the agent's context


def test_hook_spools_no_detail_when_the_screener_is_missing(tmp_path, monkeypatch):
    real = builtins.__import__

    def no_screen(name, *a, **kw):
        if name == "homelabnext.agent.screen":
            raise ImportError(name)
        return real(name, *a, **kw)

    monkeypatch.setattr(builtins, "__import__", no_screen)
    raw = json.dumps({**BASE, "hook_event_name": "UserPromptSubmit", "prompt": "p"}).encode()
    hook.main(["--spool", str(tmp_path)], stdin=raw, env={}, clock=lambda: T0)
    rec = json.loads(next(tmp_path.glob("*.json")).read_text())
    assert rec["detail"] is None and "has_detail" not in rec["summary"]


def test_hook_posts_with_the_token_from_the_environment(monkeypatch):
    sent = []
    monkeypatch.setattr(hook, "post", lambda url, token, rec: sent.append((url, token, rec)))
    raw = json.dumps({**BASE, "hook_event_name": "UserPromptSubmit", "prompt": "p"}).encode()
    url = "https://status.example.invalid/ingest/agent-activity"
    env = {"HNX_STATUS_INGEST_TOKEN": "fake-token", "CLAUDE_CODE_REMOTE": "true"}
    assert hook.main(["--post", url], stdin=raw, env=env, clock=lambda: T0) == 0
    ((u, tok, rec),) = sent
    assert (u, tok) == (url, "fake-token") and rec["summary"]["surface"] == "cloud"
    assert rec["detail"]["prompt"] == "p"
    sent.clear()
    hook.main(["--post", url, "--no-detail"], stdin=raw, env=env, clock=lambda: T0)
    assert sent[0][2]["detail"] is None
    assert "has_detail" not in sent[0][2]["summary"]  # regression: it said True with no detail
    sent.clear()
    hook.main(["--post", url], stdin=raw, env={}, clock=lambda: T0)  # no token: nothing sent
    assert sent == []


def test_hook_never_fails_the_agent(monkeypatch):
    def boom(*a, **kw):
        raise OSError("hub unreachable")

    monkeypatch.setattr(hook, "post", boom)
    raw = json.dumps({**BASE, "hook_event_name": "Stop"}).encode()
    env = {"HNX_STATUS_INGEST_TOKEN": "fake-token"}
    assert hook.main(["--post", "https://x.invalid/"], stdin=raw, env=env, clock=lambda: T0) == 0
    assert hook.main([], stdin=raw, env=env, clock=lambda: T0) == 0  # usage error, still 0


# ---------------------------------------------------------------- the spool and the hub
def test_spool_drains_and_rejects(tmp_path, clock):
    store = ActivityStore(tmp_path / "activity.db", clock=clock)
    spool = tmp_path / "spool"
    raw = json.dumps({**BASE, "hook_event_name": "UserPromptSubmit", "prompt": "hello"}).encode()
    hook.main(["--spool", str(spool)], stdin=raw, env={}, clock=clock)
    (spool / "bad.json").write_text('{"summary": {"event_id": "x"}}')
    assert drain_spool(store, spool, "agent-spool") == (1, 1)
    assert list(spool.glob("*.json")) == [] and (spool / "rejected" / "bad.json").exists()
    (ev,) = store.events()
    assert store.detail(ev["event_id"])["prompt"] == "hello"


def _spec(builtin: str, file: str | None = None) -> SourceSpec:
    return SourceSpec(
        id=f"src-{builtin}", kind="agent-activity", service="status-hub",
        capability="status-hub", interval_s=30, what="agent activity", file=file,
        timeout_s=5, mapping={"builtin": builtin, "module": "agents"},
    )  # fmt: skip


def test_agent_source_puts_stuck_and_errored_sessions_on_the_main_page(
    tmp_path, clock, make_hub, registry
):
    from status_helpers import VIEWS

    from homelabnext.status import build_status, load_views

    store = ActivityStore(tmp_path / "activity.db", clock=clock)
    spec = _spec("agent-push")
    store.add(
        [
            summary(1, session="ok", kind="tool_start", outcome=None),
            summary(1, session="bad", outcome="error"),
            summary(1, session="slow", kind="tool_start", outcome=None, t=T0 - 3600),
            summary(1, session="human", kind="stop", outcome=None, t=T0 - 3600),
        ],
        via="push:cloud",
    )
    store.add([summary(1, session="local", outcome="error")], via="agent-spool")  # not pushed
    hub = make_hub([spec])
    ctx = CollectContext(clock=clock, root=tmp_path, activity=store)
    for r in Scheduler().run([spec], ctx):
        hub.record(r)
    items = {o["item"]: o for o in hub.observations()}
    assert items["session:bad"]["state"] == "fail" and items["session:slow"]["state"] == "warn"
    assert "stuck: no event for 1h" in items["session:slow"]["summary"]
    assert "session:ok" not in items and "session:human" not in items
    assert "session:local" not in items  # each source reports the sessions it fed
    assert (items["working"]["value"], items["waiting"]["value"]) == (1, 1)
    doc = build_status(hub.snapshot(), load_views(VIEWS), registry, [spec])
    attention = [r["item"] for r in doc["views"]["overview"]["attention"]]
    assert attention == ["session:bad", "session:slow"]  # fail first
    live = {r["item"] for r in doc["views"]["overview"]["live"]}
    assert live == {"working", "waiting"}


def test_agent_source_without_a_store_is_an_error_for_itself(tmp_path, clock):
    (res,) = Scheduler().run([_spec("agent-push")], CollectContext(clock=clock, root=tmp_path))
    assert not res.ok and "no activity store" in res.error


# ---------------------------------------------------------------- Agentmetry
AM_TOOL = {
    "schema_version": "1.1.0",
    "event_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
    "session_id": "sess-abc",
    "correlation_id": "thread-8892",
    "timestamp_utc": "2026-07-12T09:14:22.041+00:00",
    "host_id": "dev-laptop",
    "action": {"type": "tool_called", "outcome": "denied", "reason": "dlp:rule-1"},
    "agent": {"name": "agentmetry", "skill_id": "customer_reply"},
    "tool": {"name": "read_file", "qualified": "files.read_file", "input_hash": "e3b0"},
    "model": {"id": "example-model-small", "provider": "example"},
    "source": {"tier": "external", "app": "cursor", "adapter": "cursor_hook"},
}


@pytest.mark.parametrize(
    "atype, outcome, kind, ours",
    [
        ("session_start", "success", "session_start", "success"),
        ("session_end", "error", "session_end", "error"),
        ("approval_request", "pending", "approval_request", "pending"),
        ("approval_response", "success", "approval_response", "approved"),
        ("approval_response", "denied", "approval_response", "denied"),
        ("tool_called", "denied", "tool_end", "denied"),
        ("tool_failed", "error", "tool_end", "error"),
        ("detection", "critical", "notification", "info"),
    ],
)
def test_agentmetry_canonical_events_map_to_ours(atype, outcome, kind, ours):
    ev = {**AM_TOOL, "action": {"type": atype, "outcome": outcome}}
    out = map_agentmetry(ev)
    assert summary_problems(out) == [] and (out["kind"], out["outcome"]) == (kind, ours)


def test_agentmetry_fields_and_what_is_skipped():
    out = map_agentmetry(AM_TOOL)
    assert out == {
        "event_id": "am-f47ac10b-58cc-4372-a567-0e02b2c3d479",
        "session_id": "sess-abc",
        "parent_session_id": "thread-8892",
        "runtime": "cursor",
        "surface": "local",
        "time": "2026-07-12T09:14:22Z",
        "kind": "tool_end",
        "outcome": "denied",
        "host": "dev-laptop",
        "model": "example-model-small",
        "agent": "customer_reply",
        "tool": "files.read_file",
    }
    assert map_agentmetry({**AM_TOOL, "action": {"type": "config_change"}}) is None
    assert map_agentmetry({**AM_TOOL, "timestamp_utc": "yesterday"}) is None
    native = {k: v for k, v in AM_TOOL.items() if k != "source"}
    assert map_agentmetry(native)["runtime"] == "agentmetry"


def test_agentmetry_trail_is_read_from_its_offset(tmp_path, clock):
    store = ActivityStore(tmp_path / "activity.db", clock=clock)
    trail = tmp_path / "audit-forward.jsonl"
    lines = [
        json.dumps({**AM_TOOL, "event_id": f"e-{i}", "timestamp_utc": "2026-09-21T13:00:00Z"})
        for i in range(3)
    ]
    trail.write_text("\n".join(lines[:2]) + "\n" + lines[2][:20])  # a half-written last line
    assert drain_agentmetry(store, trail, "am") == (2, 0)
    trail.write_text("\n".join(lines) + "\n" + "garbage\n")
    assert drain_agentmetry(store, trail, "am") == (1, 1)
    assert len(store.events()) == 3
    trail.write_text(lines[0] + "\n")  # rotated: shorter than the offset, read from the start
    assert drain_agentmetry(store, trail, "am") == (1, 0)  # a duplicate, counted as read
    assert len(store.events()) == 3


def _am_lines(prefix: str, n: int) -> list[str]:
    return [
        json.dumps(
            {**AM_TOOL, "event_id": f"{prefix}-{i}", "timestamp_utc": "2026-09-21T13:00:00Z"}
        )
        for i in range(n)
    ]


def test_a_rotated_trail_that_grew_past_the_offset_is_read_from_the_start(tmp_path, clock):
    """Regression: rotation was detected only when the new file was shorter than the old offset;
    one that had already grown past it was read from the middle (a torn line, lost events)."""
    store = ActivityStore(tmp_path / "activity.db", clock=clock)
    trail = tmp_path / "audit-forward.jsonl"
    trail.write_text("\n".join(_am_lines("old", 2)) + "\n")
    assert drain_agentmetry(store, trail, "am") == (2, 0)
    rotated = tmp_path / "next.jsonl"  # a new file (new inode) renamed into place
    rotated.write_text("\n".join(_am_lines("new", 6)) + "\n")
    rotated.replace(trail)
    assert drain_agentmetry(store, trail, "am") == (6, 0)
    trail.write_text("\n".join(_am_lines("cut", 8)) + "\n")  # truncated in place, then regrown
    assert drain_agentmetry(store, trail, "am") == (8, 0)
    assert len(store.events()) == 16
    assert drain_agentmetry(store, trail, "am") == (0, 0)


def test_a_line_longer_than_one_read_is_skipped_once(tmp_path, clock, monkeypatch):
    """Regression: a line longer than MAX_TRAIL_READ never advanced the offset (stuck forever)."""
    from homelabnext.status.agents import sources

    monkeypatch.setattr(sources, "MAX_TRAIL_READ", 1024)
    store = ActivityStore(tmp_path / "activity.db", clock=clock)
    trail = tmp_path / "audit-forward.jsonl"
    good = _am_lines("ok", 1)[0]
    assert len(good) < 1024
    trail.write_text("x" * 2500 + "\n" + good + "\n")
    got = [drain_agentmetry(store, trail, "am") for _ in range(5)]
    assert sum(b for _, b in got) == 1  # reported once, not every poll
    assert sum(o for o, _ in got) == 1 and len(store.events()) == 1


def test_a_large_trail_drains_in_one_batch(tmp_path, clock):
    """Regression: one store.add (two connections, a commit, a purge) per event; 2,000 events
    must drain in one quick pass and advance the offset to the end."""
    import time as _time

    store = ActivityStore(tmp_path / "activity.db", clock=clock)
    trail = tmp_path / "audit-forward.jsonl"
    trail.write_text("\n".join(_am_lines("bulk", 2000)) + "\n")
    t0 = _time.perf_counter()
    assert drain_agentmetry(store, trail, "am") == (2000, 0)
    assert _time.perf_counter() - t0 < 5
    assert len(store.events(limit=None)) == 2000
    assert drain_agentmetry(store, trail, "am") == (0, 0)  # the offset is at the end
