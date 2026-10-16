# SPDX-License-Identifier: Apache-2.0
import copy

from homelabnext.notify.core import Message
from homelabnext.parity import (
    EventRules,
    NotifyRules,
    compare_event_streams,
    compare_notifications,
)


def stream(n=8):
    return [
        {
            "specversion": "1.0",
            "id": f"evt-{i:03d}",
            "source": "svc:sensor",
            "type": "homelabnext.alert.created",
            "time": f"2026-03-01T00:00:{i:02d}Z",
            "subject": f"host-{i % 2}",
            "data": {"n": i},
        }
        for i in range(n)
    ]


def check(rep, name):
    return next(c for c in rep.checks if c.name == name)


def test_identical_streams_and_delivery_time_differences_ignored():
    a = stream()
    b = copy.deepcopy(a)
    for e in b:
        e["time"] = "2026-03-01T00:09:00Z"
    assert compare_event_streams(a, b).ok


def test_drop_duplicate_reorder_payload_drift_caught():
    a = stream()
    b = copy.deepcopy(a)
    del b[2]
    rep = compare_event_streams(a, b)
    assert not check(rep, "membership").ok and not check(rep, "counts-by-type").ok

    b = [*copy.deepcopy(a), copy.deepcopy(a[1])]
    assert not check(compare_event_streams(a, b), "duplicates").ok

    b = copy.deepcopy(a)
    b[0], b[2] = b[2], b[0]  # same partition (host-0), swapped
    rep = compare_event_streams(a, b)
    assert not check(rep, "ordering").ok and check(rep, "membership").ok
    assert check(compare_event_streams(a, b, EventRules(check_order=False)), "payloads").ok

    b = copy.deepcopy(a)
    b[4]["data"]["n"] = 999
    assert not check(compare_event_streams(a, b), "payloads").ok


def test_dup_on_both_paths_is_not_a_regression_and_lag_budget():
    a = [*stream(), stream()[0]]
    b = copy.deepcopy(a)
    assert check(compare_event_streams(a, b), "duplicates").ok
    c = copy.deepcopy(a)
    c[3]["time"] = "2026-03-01T00:05:00Z"
    assert not check(compare_event_streams(a, c, EventRules(max_lag_s=10)), "lag").ok
    assert check(compare_event_streams(a, c, EventRules(max_lag_s=600)), "lag").ok


def test_malformed_envelope_fails():
    a = stream()
    b = copy.deepcopy(a)
    del b[1]["type"]
    assert not check(compare_event_streams(a, b), "envelopes").ok


def msgs():
    return [
        Message("disk:a", "Disk full", "99%", "crit", tags=("disk",)),
        Message("disk:a", "Disk recovered", "ok", "info"),
        Message("svc:b", "Down", "b down", "warn"),
    ]


def test_notifications_identical_and_body_only_when_asked():
    a = msgs()
    b = copy.deepcopy(a)
    b[0] = Message("disk:a", "Disk full", "99 percent used", "crit", tags=("disk",))
    assert compare_notifications(a, b).ok
    assert not compare_notifications(a, b, NotifyRules(compare_body=True)).ok


def test_lost_extra_and_downgraded_pages_caught():
    a = msgs()
    lost = compare_notifications(a, a[:2])
    assert not check(lost, "pages").ok and check(lost, "pages").detail["missing"]
    extra = compare_notifications(a, [*a, Message("x", "Noise", "n")])
    assert not check(extra, "pages").ok
    down = copy.deepcopy(a)
    down[0] = Message("disk:a", "Disk full", "99%", "crit", priority=2, tags=("disk",))
    assert not check(compare_notifications(a, down), "priority").ok
    routed = copy.deepcopy(a)
    routed[2] = Message("svc:b", "Down", "b down", "warn", topic="elsewhere")
    assert not check(compare_notifications(a, routed), "routing").ok
    assert compare_notifications(a, routed, NotifyRules(compare_routing=False)).ok


def test_recovery_order_swap_caught():
    a = msgs()
    b = [a[1], a[0], a[2]]
    assert not check(compare_notifications(a, b), "problem-recovery-order").ok
