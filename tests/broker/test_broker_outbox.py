# SPDX-License-Identifier: Apache-2.0
"""The broker's outbox (:class:`homelabnext.broker.state.StateDir`): emit order.

``queued`` is the next value of the persisted counter ``outbox.seq``, taken and linked under one
``flock``, so a relay pass never sees a later event before an earlier one that is still being
written, and no clock (stepped back, or another process's) can reorder events.
"""

from __future__ import annotations

import json
import threading
import time

import homelabnext.broker.state as state_mod
from homelabnext.broker.relay import BROKER_SOURCE
from homelabnext.broker.state import OUTBOX_SEQ, StateDir
from homelabnext.events.envelope import build_event

REQ = "homelabnext.decision.requested"
RET = "homelabnext.decision.returned"


def ev(etype: str, i: int = 0) -> dict:
    data = {"decision_id": f"req-{i:04d}", "verdict": "accept", "confidence": 1.0,
            "tier_used": "human"}  # fmt: skip
    if etype == REQ:
        data = {"decision_id": f"req-{i:04d}", "spec": "broker-approval",
                "subject": f"requests/req-{i:04d}.json", "action": "service.restart",
                "actor": "profile:triage", "request_digest": "sha256:" + "0" * 64}  # fmt: skip
    return build_event(etype, BROKER_SOURCE, data, dedupe_key=f"{etype}{i}", subject=f"req-{i:04d}")


def types(events: list[dict]) -> list[str]:
    return [e["type"] for e in events]


def test_an_event_in_flight_is_never_overtaken(tmp_path, monkeypatch):
    """The reviewer's exp2 F: ``queued`` was taken under the lock and the file linked after it,
    so a pass between the two published a later event first."""
    a, b = StateDir(tmp_path), StateDir(tmp_path)  # two processes' instances
    real, gate, entered = state_mod.write_exclusive, threading.Event(), threading.Event()

    def slow(path, data, **kw):
        if b"decision.requested" in data:
            entered.set()
            assert gate.wait(5)
        return real(path, data, **kw)

    monkeypatch.setattr(state_mod, "write_exclusive", slow)
    first = threading.Thread(target=a.put_outbox, args=(ev(REQ),))
    first.start()
    assert entered.wait(5)
    second = threading.Thread(target=b.put_outbox, args=(ev(RET),))
    second.start()
    time.sleep(0.2)
    seen = types(StateDir(tmp_path).outbox_pending())  # a relay pass, mid-write
    gate.set()
    first.join(5)
    second.join(5)
    assert seen == []  # not the later event alone
    assert types(StateDir(tmp_path).outbox_pending()) == [REQ, RET]


def test_a_clock_stepped_back_cannot_reorder_events(tmp_path):
    """The reviewer's exp1 D: ``queued`` was wall-clock ns, so a broker restarted after the clock
    went back had its new event published before an older pending one."""
    StateDir(tmp_path, clock_ns=lambda: 2_000_000_000_000_000_000).put_outbox(ev(REQ))
    StateDir(tmp_path, clock_ns=lambda: 1_999_999_999_000_000_000).put_outbox(ev(RET))
    assert types(StateDir(tmp_path).outbox_pending()) == [REQ, RET]


def test_the_counter_is_persisted_and_recovers(tmp_path):
    s = StateDir(tmp_path)
    s.put_outbox(ev(REQ, 1))
    s.put_outbox(ev(RET, 1))
    queued = [json.loads(p.read_text())["queued"] for p in (tmp_path / "outbox").glob("*.json")]
    assert sorted(queued) == [1, 2] and int((tmp_path / OUTBOX_SEQ).read_text()) == 2
    (tmp_path / OUTBOX_SEQ).write_text("garbage")  # unreadable: the outbox's largest wins
    StateDir(tmp_path).put_outbox(ev(REQ, 2))
    (tmp_path / OUTBOX_SEQ).unlink()
    StateDir(tmp_path).put_outbox(ev(RET, 2))
    got = [(e["type"], e["subject"]) for e in StateDir(tmp_path).outbox()]
    assert got == [(REQ, "req-0001"), (RET, "req-0001"), (REQ, "req-0002"), (RET, "req-0002")]


def test_outbox_files_are_group_readable_and_the_rest_stays_private(tmp_path):
    s = StateDir(tmp_path)
    s.put_outbox(ev(REQ))
    [path] = (tmp_path / "outbox").glob("*.json")
    assert path.stat().st_mode & 0o777 == 0o640
    assert (tmp_path / OUTBOX_SEQ).stat().st_mode & 0o777 == 0o600


def test_files_from_before_queued_sort_first_by_time_then_id(tmp_path):
    s = StateDir(tmp_path)
    s.put_outbox(ev(RET, 5))  # a current event
    later, earlier = ev(REQ, 2), ev(REQ, 1)
    later["time"], earlier["time"] = "2030-01-01T00:00:01Z", "2030-01-01T00:00:00Z"
    twin = dict(earlier, id="0" * 16)  # same second, smaller id
    for old in (later, earlier, twin):
        (tmp_path / "outbox" / f"{old['id']}.json").write_text(json.dumps(old))
    assert [e["id"] for e in s.outbox()][:3] == [twin["id"], earlier["id"], later["id"]]
    assert s.outbox()[3]["type"] == RET  # an old file is older than any queued one
