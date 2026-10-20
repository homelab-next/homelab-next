# SPDX-License-Identifier: Apache-2.0
"""Scheduler isolation (O-07), staleness from expiry (O-06), the state service, state-diffed
notifications through the shared Notifier (O-08) and status.observed on the bus."""

from __future__ import annotations

import threading
import time

import pytest
from status_helpers import endpoint, spec

from homelabnext.events import FakeForwarder, Publisher, build_event, validate_event
from homelabnext.notify import FakeSender, Notifier
from homelabnext.state import StateStore
from homelabnext.status import (
    OBSERVED_EVENT,
    CollectContext,
    Draft,
    HubError,
    Scheduler,
    SourceResult,
    due,
    observation_problems,
)
from homelabnext.status.model import iso


class Hang:
    """A collector that blocks until released (a blackholed source)."""

    def __init__(self) -> None:
        self.release = threading.Event()
        self.calls = 0

    def collect(self, s, ctx):
        self.calls += 1
        self.release.wait(30)
        return [Draft(item="late", state="ok", summary="too late")]


class Boom:
    def collect(self, s, ctx):
        raise RuntimeError("source exploded\nwith a multi-line message")


class Quick:
    def collect(self, s, ctx):
        return [Draft(item=s.id, state="ok", summary="fine")]


def test_a_hung_source_does_not_delay_the_others_and_is_not_restarted():
    hang = Hang()
    sch = Scheduler({"poll-http-json": Quick(), "poll-file": hang, "push-event": Boom()})
    specs = [
        spec("a"),
        spec("hung", kind="poll-file", file="x.json", path=None, timeout_s=0.2),
        spec("b"),
        spec("boom", kind="push-event", path=None),
    ]
    try:
        t0 = time.monotonic()
        res = {r.source: r for r in sch.run(specs, CollectContext())}
        elapsed = time.monotonic() - t0
        assert elapsed < 2.0, f"a pass with one hung source took {elapsed:.2f}s"
        assert res["a"].ok and res["b"].ok and res["a"].drafts[0].item == "a"
        assert res["hung"].error == "timeout after 0.2s"
        assert res["boom"].error == "RuntimeError: source exploded with a multi-line message"
        assert sch.running() == ["hung"]
        again = {r.source: r for r in sch.run(specs, CollectContext())}
        assert again["hung"].error == "previous poll still running (hung source)"
        assert hang.calls == 1 and again["a"].ok
    finally:
        hang.release.set()
    for _ in range(200):  # the released thread finishes; the late result is dropped
        if not sch.running():
            break
        time.sleep(0.01)
    assert sch.running() == []


def test_due_follows_each_interval(clock):
    a, b, p = (
        spec("a", interval_s=60),
        spec("b", interval_s=600),
        spec("p", kind="push-event", path=None),
    )
    last = {"a": clock() - 61, "b": clock() - 61, "p": None}
    assert [s.id for s in due([a, b, p], last, clock())] == ["a"]
    assert [s.id for s in due([a, b], {}, clock())] == ["a", "b"]


def _ok(sid, *items, state="ok"):
    return SourceResult(sid, tuple(Draft(item=i, state=state, summary=state) for i in items))


def test_a_source_that_stops_reporting_goes_stale_after_stale_after_s(make_hub, clock):
    s = spec("probe", interval_s=60)  # stale_after_s defaults to 180
    hub = make_hub([s])
    hub.record(_ok("probe", "disk"))
    clock.advance(179)
    (row,) = hub.observations()
    assert row["state"] == "ok" and hub.sources()[0]["state"] == "ok"
    clock.advance(1)
    (row,) = hub.observations()
    assert row["state"] == "stale" and row["reported_state"] == "ok"
    assert hub.sources()[0]["state"] == "stale"


def test_a_failing_poll_ages_items_into_stale_unless_the_source_is_a_liveness_probe(
    make_hub, clock
):
    soft, probe = spec("soft"), spec("probe", on_error="fail")
    hub = make_hub([soft, probe])
    hub.record(_ok("soft", "x"))
    hub.record(_ok("probe", "probe"))
    clock.advance(30)
    hub.record(SourceResult("soft", error="ConnectionRefusedError: down"))
    hub.record(SourceResult("probe", error="ConnectionRefusedError: down"))
    rows = {r["source"]: r for r in hub.observations()}
    assert rows["soft"]["state"] == "ok"  # still within its window
    assert rows["probe"]["state"] == "fail" and "down" in rows["probe"]["summary"]
    srcs = {s["id"]: s["state"] for s in hub.sources()}
    assert srcs == {"probe": "fail", "soft": "warn"}
    clock.advance(151)
    assert {r["source"]: r["state"] for r in hub.observations()}["soft"] == "stale"


def test_items_a_source_stops_listing_are_dropped_and_history_is_bounded(make_hub, clock):
    hub = make_hub([spec("alerts")], history=3)
    hub.record(_ok("alerts", "a", "b"))
    hub.record(_ok("alerts", "a"))
    assert [r["item"] for r in hub.observations()] == ["a"]
    for st in ("fail", "ok", "warn", "fail", "ok"):
        clock.advance(1)
        hub.record(_ok("alerts", "a", state=st))
    (row,) = hub.observations()
    assert [h[1] for h in row["history"]] == ["warn", "fail", "ok"]


def test_state_persists_across_hub_instances(tmp_path, clock, make_hub):
    s = spec("p")
    make_hub([s]).record(_ok("p", "x"))
    from homelabnext.status import StatusHub

    again = StatusHub([s], StateStore(tmp_path / "state.json", clock=clock), clock=clock)
    assert [r["item"] for r in again.observations()] == ["x"]
    assert again.last_attempts() == {"p": clock()}


def test_every_recorded_observation_matches_the_schema(make_hub):
    hub = make_hub([spec("p")])
    (obs,) = hub.record(SourceResult("p", (Draft("x", "warn", "w", value=3, work=True),)))
    assert observation_problems(obs.to_dict()) == []
    bad = {**obs.to_dict(), "link": "https://x.example.invalid/"}
    assert observation_problems(bad)


def test_push_events_are_ingested_and_capped_by_the_registry(make_hub, clock):
    push = spec(
        "runs", kind="push-event", path=None, interval_s=300, service="agent-runtime"
    )  # stale after 900
    hub = make_hub([push, spec("polled")])
    data = {
        "source": "runs", "module": "agent-runtime", "item": "nightly", "state": "ok",
        "summary": "done", "observed_at": "2026-09-21T13:33:20Z", "expires_at": "2027-01-01T00:00:00Z",
    }  # fmt: skip
    ev = build_event(
        OBSERVED_EVENT, "svc:agent-runtime", data, dedupe_key="r1", time=data["observed_at"]
    )
    obs = hub.ingest_event(ev)
    assert obs.expires_at == "2026-09-21T13:48:20Z"  # observed_at + 900, not the pusher's claim
    assert {s["id"]: s["state"] for s in hub.sources()} == {"polled": "unknown", "runs": "ok"}
    with pytest.raises(HubError):
        hub.ingest({**data, "source": "polled"})
    with pytest.raises(HubError):
        hub.ingest({**data, "source": "unregistered"})
    clock.advance(900)
    assert hub.observations()[0]["state"] == "stale"


def _push_hub(make_hub, **kw):
    push = spec("runs", kind="push-event", path=None, interval_s=300, service="agent-runtime", **kw)
    return make_hub([push])


def _push_data(**kw):
    data = {
        "source": "runs", "module": "agent-runtime", "item": "nightly", "state": "ok",
        "summary": "done", "observed_at": "2026-09-21T13:33:20Z", "expires_at": "2099-01-01T00:00:00Z",
    }  # fmt: skip
    data.update(kw)
    return data


def test_a_future_observed_at_is_clamped_and_still_goes_stale(make_hub, clock):
    # regression: the cap was relative to the pusher's observed_at, so a reading dated 2099
    # never went stale (O-06)
    hub = _push_hub(make_hub)
    obs = hub.ingest(_push_data(observed_at="2099-01-01T00:00:00Z"))
    assert obs.observed_at == iso(clock()) and obs.expires_at == iso(clock() + 900)
    assert hub.sources()[0]["clock_skew_s"] > 0  # recorded, not silently dropped
    clock.advance(900)
    assert hub.observations()[0]["state"] == "stale"
    hub.ingest(_push_data(observed_at=iso(clock())))
    assert "clock_skew_s" not in hub.sources()[0]


def test_only_the_declaring_service_may_publish_a_push_source(make_hub, clock):
    # regression: the envelope source was ignored, so any publisher could feed any push source
    hub = _push_hub(make_hub)
    data = _push_data()
    for publisher in ("svc:notify", "svc:agent-runtime-2"):
        ev = build_event(
            OBSERVED_EVENT, publisher, data, dedupe_key=publisher, time=data["observed_at"]
        )
        with pytest.raises(HubError, match="may not report"):
            hub.ingest_event(ev)
    ev = build_event(OBSERVED_EVENT, "svc:agent-runtime", {**data, "module": "metrics"},
                     dedupe_key="m", time=data["observed_at"])  # fmt: skip
    with pytest.raises(HubError, match="reports module"):
        hub.ingest_event(ev)
    assert hub.observations() == []
    ok = build_event(
        OBSERVED_EVENT, "svc:agent-runtime", data, dedupe_key="ok", time=data["observed_at"]
    )
    assert hub.ingest_event(ok).item == "nightly"


def test_a_source_mapping_module_is_the_module_it_may_report(make_hub):
    hub = _push_hub(make_hub, mapping={"module": "runs-module"})
    with pytest.raises(HubError, match="reports module"):
        hub.ingest(_push_data())
    assert hub.ingest(_push_data(module="runs-module")).module == "runs-module"


def test_notifications_fire_once_per_transition(make_hub, clock):
    hub = make_hub([spec("p", interval_s=60)])
    sender = FakeSender()
    notifier = Notifier(sender, hub.store, clock=clock)
    hub.record(_ok("p", "x"))
    assert hub.notify(notifier) == []
    hub.record(_ok("p", "x", state="fail"))
    assert hub.notify(notifier) == ["status/p/svc-a/x"]
    assert hub.notify(notifier) == []  # same state twice sends once
    hub.record(_ok("p", "x", state="warn"))  # warn does not page: this is the recovery
    assert hub.notify(notifier) == ["status/p/svc-a/x"]
    assert hub.notify(notifier) == []
    assert sender.titles == ["Status item needs attention", "Status item recovered"]


def test_a_dead_source_pages_once_and_its_items_do_not_flood_or_falsely_recover(make_hub, clock):
    hub = make_hub([spec("p", interval_s=60)])
    sender = FakeSender()
    notifier = Notifier(sender, hub.store, clock=clock)
    hub.record(_ok("p", "a", "b", state="fail"))
    assert len(hub.notify(notifier)) == 2
    clock.advance(180)  # nothing reports: the source and its items are stale
    assert hub.notify(notifier) == ["status/p/svc-a/_source"]
    assert hub.notify(notifier) == []
    hub.record(_ok("p", "a"))  # back, b no longer listed
    sent = hub.notify(notifier)
    assert sorted(sent) == ["status/p/svc-a/_source", "status/p/svc-a/a", "status/p/svc-a/b"]
    assert sender.titles[-3:] == ["Status item recovered"] * 3


def test_observations_publish_as_valid_idempotent_events(make_hub):
    hub = make_hub([spec("p")])
    obs = hub.record(_ok("p", "x", "y"))
    fwd = FakeForwarder()
    pub = Publisher(fwd, _Mem())
    first = hub.publish(pub, obs, "svc:svc-a")
    assert [r.status for r in first] == ["sent", "sent"]
    assert [r.status for r in hub.publish(pub, obs, "svc:svc-a")] == ["duplicate", "duplicate"]
    assert len(fwd.accepted) == 2
    for ev in fwd.accepted.values():
        validate_event(ev)
        assert ev["type"] == OBSERVED_EVENT and ev["data"]["source"] == "p"


class _Mem(dict):
    def put(self, k, v):
        self[k] = v

    def keys(self):
        return list(super().keys())


def test_record_refuses_an_unknown_source(make_hub):
    with pytest.raises(HubError):
        make_hub([spec("p")]).record(SourceResult("nope"))


def test_endpoint_helper_is_not_routable():
    assert endpoint("svc-a").endswith(".invalid")
