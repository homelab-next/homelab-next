# SPDX-License-Identifier: Apache-2.0
"""Product collectors (stage 2): each mapping against the product's real response shape, the
credential header, and a hung product reading per its ``on_error``.

Fixtures (``tests/status/fixtures/``): ``prometheus-*`` and ``uptime-kuma-*`` were recorded from a
real Prometheus 2.54.1 and Uptime Kuma 1.23.16 (scrape-target ``instance`` labels renamed);
``stackstorm-*``, ``nifi-*``, ``orchestrator-*`` and ``agentmetry-*`` follow the products' source
(StackStorm ``ActionExecutionAPI`` + ``openapi.yaml``, NiFi ``ControllerStatusDTO`` and
``BulletinBoardEntity``, the orchestrator's ``store.QueueSummary``, Agentmetry's
``GET /api/v1/audit/status``), because those products do not fit the lab.
"""

from __future__ import annotations

import copy
import threading
from urllib.parse import parse_qs, urlsplit

import pytest
import yaml
from status_helpers import REGISTRY, T0, FakeHttp, endpoint, fixture, spec

from homelabnext.registry.model import RegistryError, build_registry
from homelabnext.status import CollectContext, Scheduler, SourceResult, apply_mapping
from homelabnext.status.collectors import COLLECTORS, CollectError
from homelabnext.status.mapping import MappingError
from homelabnext.status.model import iso, parse_iso
from homelabnext.status.products import (
    kuma_heartbeat_path,
    nifi,
    nifi_bulletin_path,
    prometheus_alerts,
    prometheus_query,
    stackstorm,
    threshold_state,
    uptime_kuma,
)

FAKE_KEY = "fake-st2-api-key-0000"
RAW_QUERY = 'up{instance="localhost:9090"}'  # no-raw-endpoint: allow the input the registry refuses
UP_QUERY = {"query": "up", "item": "instance", "thresholds": {"fail": 0, "direction": "below"}}


def _items(drafts):
    return {d.item: d.state for d in drafts}


def _ctx(http, clock=lambda: T0, secrets=None):
    return CollectContext(clock=clock, http=http, endpoint=endpoint, secret=(secrets or {}).get)


def _query(url: str) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}


# ---------------------------------------------------------------- Prometheus
@pytest.mark.parametrize(
    "value, thresholds, want",
    [
        (0.0, {"fail": 0, "direction": "below"}, "fail"),
        (1.0, {"fail": 0, "direction": "below"}, "ok"),
        (85.0, {"warn": 80, "fail": 95}, "warn"),
        (95.0, {"warn": 80, "fail": 95}, "fail"),
        (10.0, {"warn": 80, "fail": 95}, "ok"),
        (float("nan"), {"fail": 1}, "unknown"),
        (5.0, None, "unknown"),  # a number alone is never read as healthy
    ],
)
def test_thresholds(value, thresholds, want):
    assert threshold_state(value, thresholds)[0] == want


def test_prometheus_query_names_items_by_label_and_judges_each_value():
    drafts = prometheus_query(fixture("prometheus-query-up"), UP_QUERY, "metrics-targets")
    assert _items(drafts) == {
        "dead-target:9": "fail",
        # two series share instance self:9090 (jobs node and prometheus): told apart, stably
        **{d.item: "ok" for d in drafts if d.item.startswith("self:9090@")},
    }
    assert len(drafts) == 3 and len({d.item for d in drafts}) == 3
    dead = next(d for d in drafts if d.item == "dead-target:9")
    assert dead.summary == "instance=dead-target:9: 0 (fail at or below 0)" and dead.value == 0
    again = prometheus_query(fixture("prometheus-query-up"), UP_QUERY, "metrics-targets")
    assert [d.item for d in again] == [d.item for d in drafts]


def test_prometheus_query_scalar_empty_and_errors():
    m = {"query": "scalar(count(up))", "thresholds": {"warn": 3}}
    (d,) = prometheus_query(fixture("prometheus-query-scalar"), m, "targets")
    assert (d.item, d.state, d.value) == ("targets", "warn", 3.0)
    empty = {"status": "success", "data": {"resultType": "vector", "result": []}}
    assert prometheus_query(empty, UP_QUERY, "src") == []  # nothing matched: no items
    (e,) = prometheus_query(empty, {**UP_QUERY, "empty": "fail"}, "src")
    assert (e.item, e.state) == ("src", "fail")
    with pytest.raises(MappingError, match="bad_data: invalid parameter"):
        prometheus_query(fixture("prometheus-query-error"), UP_QUERY, "src")
    matrix = {"status": "success", "data": {"resultType": "matrix", "result": []}}
    with pytest.raises(MappingError, match="vector or scalar, not matrix"):
        prometheus_query(matrix, UP_QUERY, "src")


def test_prometheus_collector_sends_the_query_url_encoded(http):
    s = spec(
        kind="poll-prometheus",
        path="/api/v1/query",
        mapping={**UP_QUERY, "query": 'up{job="node"} == 0'},
    )
    http.routes['http://svc-a.status.invalid/api/v1/query?query=up%7Bjob%3D%22node%22%7D+%3D%3D+0'] = (
        200, fixture("prometheus-query-up"))  # fmt: skip
    drafts = COLLECTORS["poll-prometheus"].collect(s, _ctx(http))
    assert len(drafts) == 3 and _query(http.calls[0]) == {"query": 'up{job="node"} == 0'}
    assert http.headers == [{}]  # no auth declared, no credential sent


def test_prometheus_alerts_firing_by_severity_resolved_drop_out(make_hub, clock):
    payload = fixture("prometheus-alerts")
    drafts = prometheus_alerts(payload, {"builtin": "prometheus-alerts"}, "metrics-alerts")
    assert _items(drafts) == {"LabSmokeWarning": "warn", "LabSmokeCritical": "fail"}
    crit = next(d for d in drafts if d.item == "LabSmokeCritical")
    assert crit.summary.startswith("critical: lab smoke critical, always firing (since 2026-")
    # the warning resolves: Prometheus stops listing it, and the hub drops the item
    s = spec("metrics-alerts", kind="poll-prometheus", path="/api/v1/alerts",
             mapping={"builtin": "prometheus-alerts"})  # fmt: skip
    hub = make_hub([s])
    hub.record(SourceResult(s.id, tuple(drafts)))
    later = copy.deepcopy(payload)
    later["data"]["alerts"] = [
        a for a in later["data"]["alerts"] if a["labels"]["severity"] == "critical"
    ]
    hub.record(SourceResult(s.id, tuple(prometheus_alerts(later, s.mapping, s.id))))
    assert {o["item"]: o["state"] for o in hub.observations()} == {"LabSmokeCritical": "fail"}


def test_prometheus_alerts_pending_unlabelled_overrides_and_duplicates():
    def alert(name, state="firing", **labels):
        return {"labels": {"alertname": name, **labels}, "annotations": {}, "state": state,
                "activeAt": "2026-09-21T13:00:00Z", "value": "1e+00"}  # fmt: skip

    doc = {"status": "success", "data": {"alerts": [
        alert("Slow", "pending", severity="critical"),  # inside its for: not reported
        alert("NoSeverity"),  # unmapped is never healthy: fail
        alert("Watchdog", severity="none"),  # always firing by design
        alert("Disk", severity="warning", instance="a"),
        alert("Disk", severity="warning", instance="b"),
        alert("Ticket", severity="ticket"),
    ]}}  # fmt: skip
    got = _items(prometheus_alerts(doc, {"states": {"ticket": "warn"}}, "src"))
    assert got["NoSeverity"] == "fail" and got["Watchdog"] == "ok" and got["Ticket"] == "warn"
    assert "Slow" not in got
    disks = sorted(k for k in got if k.startswith("Disk@"))
    assert len(disks) == 2 and all(got[k] == "warn" for k in disks)
    by_instance = _items(prometheus_alerts(doc, {"item": "instance"}, "src"))
    assert by_instance["Disk:a"] == by_instance["Disk:b"] == "warn"


# ---------------------------------------------------------------- Uptime Kuma
def _kuma_now():
    beats = fixture("uptime-kuma-heartbeat")["heartbeatList"]["1"]
    return parse_iso(beats[-1]["time"].replace(" ", "T")) + 90


def test_uptime_kuma_maps_each_public_monitor():
    page, beats = fixture("uptime-kuma-status-page"), fixture("uptime-kuma-heartbeat")
    drafts = uptime_kuma(page, beats, {}, _kuma_now(), "uptime-monitors")
    assert _items(drafts) == {"metrics": "ok", "unreachable": "fail"}
    up = next(d for d in drafts if d.item == "metrics")
    assert up.summary.startswith("up, 100.00% over 24h, ") and up.summary.endswith(
        "ms, last beat 1m ago"
    )
    down = next(d for d in drafts if d.item == "unreachable")
    assert down.summary == "down, 0.00% over 24h, last beat 1m ago"


@pytest.mark.parametrize("status, want", [(2, "warn"), (3, "unknown"), (7, "unknown")])
def test_uptime_kuma_pending_maintenance_and_unknown_codes(status, want):
    page, beats = fixture("uptime-kuma-status-page"), fixture("uptime-kuma-heartbeat")
    beats["heartbeatList"]["1"][-1]["status"] = status
    assert _items(uptime_kuma(page, beats, {}, _kuma_now(), "src"))["metrics"] == want


def test_uptime_kuma_no_heartbeat_duplicate_group_and_incident():
    page, beats = fixture("uptime-kuma-status-page"), fixture("uptime-kuma-heartbeat")
    page["publicGroupList"].append(copy.deepcopy(page["publicGroupList"][0]))  # same monitors
    del beats["heartbeatList"]["2"]
    page["incident"] = {"id": 1, "style": "danger", "title": "core switch replaced", "pin": True}
    drafts = uptime_kuma(page, beats, {"states": {"up": "ok"}}, _kuma_now(), "src")
    assert [d.item for d in drafts] == ["metrics", "unreachable", "incident"]
    assert _items(drafts) == {"metrics": "ok", "unreachable": "unknown", "incident": "fail"}
    with pytest.raises(MappingError, match="publicGroupList and heartbeatList"):
        uptime_kuma({"config": {}}, beats, {}, _kuma_now(), "src")


def test_uptime_kuma_collector_reads_both_public_endpoints_without_a_login():
    http = FakeHttp(by_path=True)
    http.routes["/kuma/api/status-page/lab"] = (200, fixture("uptime-kuma-status-page"))
    http.routes["/kuma/api/status-page/heartbeat/lab"] = (200, fixture("uptime-kuma-heartbeat"))
    s = spec(kind="poll-uptime-kuma", path="/kuma/api/status-page/lab", mapping={})
    drafts = COLLECTORS["poll-uptime-kuma"].collect(s, _ctx(http, clock=_kuma_now))
    assert _items(drafts) == {"metrics": "ok", "unreachable": "fail"}
    assert [urlsplit(u).path for u in http.calls] == [
        "/kuma/api/status-page/lab", "/kuma/api/status-page/heartbeat/lab"
    ]  # fmt: skip
    assert http.headers == [{}, {}]
    with pytest.raises(MappingError):
        kuma_heartbeat_path("/api/status-page/")


# ---------------------------------------------------------------- StackStorm
def _st2_http():
    http = FakeHttp(by_path=True)
    http.routes["/api/v1/executions"] = (200, fixture("stackstorm-executions"))
    return http


def test_stackstorm_failed_and_timed_out_executions_are_fail_items_per_action():
    drafts = stackstorm(
        fixture("stackstorm-executions"), fixture("stackstorm-running"), {}, T0, "automation"
    )
    assert _items(drafts) == {
        "backup.nightly": "fail",
        "linux.check_disk": "fail",
        "executions": "ok",
        "running": "ok",
    }  # a canceled execution is an operator's choice, not a failure
    nightly = next(d for d in drafts if d.item == "backup.nightly")
    assert nightly.summary.startswith("1 failed, 1 timeout in the last 1h 0m; latest timeout ")
    assert nightly.value == 2
    running = next(d for d in drafts if d.item == "running")
    assert running.work and running.value == 2
    executions = next(d for d in drafts if d.item == "executions")
    assert executions.summary == "5 execution(s) in the last 1h 0m, 3 failed"


def test_stackstorm_window_and_state_overrides():
    m = {"window_s": 1800, "states": {"canceled": "warn"}}
    got = _items(stackstorm(fixture("stackstorm-executions"), [], m, T0, "src"))
    assert "linux.check_disk" not in got  # started 43 minutes before T0: outside 30 minutes
    assert got["backup.nightly"] == "fail"
    m = {"states": {"canceled": "warn"}}
    assert (
        _items(stackstorm(fixture("stackstorm-executions"), [], m, T0, "src"))["core.echo"]
        == "warn"
    )
    with pytest.raises(MappingError, match="list of executions"):
        stackstorm({"faultstring": "nope"}, [], {}, T0, "src")


def test_stackstorm_sends_the_api_key_from_the_secret_store_and_the_window_query():
    http = _st2_http()
    s = spec(kind="poll-stackstorm", path="/api/v1/executions", mapping={"limit": 50},
             auth={"secret": "secret:stackstorm/status-token", "header": "St2-Api-Key"})  # fmt: skip
    ctx = _ctx(http, secrets={"secret:stackstorm/status-token": FAKE_KEY})
    drafts = COLLECTORS["poll-stackstorm"].collect(s, ctx)
    assert _items(drafts)["backup.nightly"] == "fail"
    assert http.headers == [{"St2-Api-Key": FAKE_KEY}] * 2
    recent, running = (_query(u) for u in http.calls)
    assert recent == {
        "limit": "50", "sort_desc": "true", "timestamp_gt": iso(T0 - 3600),
        "exclude_attributes": "result,trigger_instance",
    }  # fmt: skip
    assert running["status"] == "running"


def test_an_unresolved_credential_is_an_error_and_nothing_is_sent():
    http = _st2_http()
    s = spec(kind="poll-stackstorm", path="/api/v1/executions", mapping={},
             auth={"secret": "secret:stackstorm/status-token", "header": "St2-Api-Key"})  # fmt: skip
    with pytest.raises(CollectError, match="auth credential did not resolve"):
        COLLECTORS["poll-stackstorm"].collect(s, _ctx(http))
    assert http.calls == []


# ---------------------------------------------------------------- NiFi
NIFI_MAP = {"thresholds": {"warn": 10000, "fail": 100000}}


def test_nifi_queue_components_and_bulletins():
    drafts = nifi(fixture("nifi-flow-status"), fixture("nifi-bulletin-board"), NIFI_MAP, "dataflow")
    assert _items(drafts) == {
        "queued": "warn",
        "running": "ok",
        "invalid": "fail",
        "stopped": "warn",
        "disabled": "ok",
        "sync-failure": "ok",
        "bulletin:PutDatabaseRecord": "fail",
        "bulletin:InvokeHTTP": "warn",
        "bulletins": "ok",
    }  # INFO bulletins are not attention; an unreadable one is only counted
    by = {d.item: d for d in drafts}
    assert by["queued"].work and by["queued"].value == 12500
    assert (
        by["queued"].summary
        == "12500 flowfile(s) queued (12,500 / 4.2 MB) (warn at or above 10000)"
    )
    assert by["bulletin:PutDatabaseRecord"].summary.endswith("Failed to put Records: timeout")
    assert (
        by["bulletins"].summary == "5 bulletin(s) on the board, 1 not readable by this credential"
    )
    quiet = _items(nifi(fixture("nifi-flow-status"), fixture("nifi-bulletin-board"), {}, "d"))
    assert quiet["queued"] == "ok"  # without thresholds a queue is live work, not a problem


def test_nifi_collector_bearer_token_and_bulletin_path():
    http = FakeHttp(by_path=True)
    http.routes["/nifi-api/flow/status"] = (200, fixture("nifi-flow-status"))
    http.routes["/nifi-api/flow/bulletin-board"] = (200, fixture("nifi-bulletin-board"))
    s = spec(kind="poll-nifi", path="/nifi-api/flow/status", mapping=NIFI_MAP,
             auth={"secret": "secret:nifi/status-token"})  # fmt: skip
    ctx = _ctx(http, secrets={"secret:nifi/status-token": "fake-nifi-token"})
    assert _items(COLLECTORS["poll-nifi"].collect(s, ctx))["invalid"] == "fail"
    assert http.headers == [{"Authorization": "Bearer fake-nifi-token"}] * 2
    assert _query(http.calls[1]) == {"limit": "100"}
    assert nifi_bulletin_path("/nifi/nifi-api/flow/status") == "/nifi/nifi-api/flow/bulletin-board"
    with pytest.raises(MappingError, match="flowFilesQueued"):
        nifi({"controllerStatus": {}}, fixture("nifi-bulletin-board"), {}, "d")


# ---------------------------------------------------------------- orchestrator and Agentmetry
def _builtin(payload, name, **kw):
    return apply_mapping(payload, {"builtin": name, **kw}, now=T0, fallback_item="src")


def test_orchestrator_queue_summary():
    drafts = _builtin(
        fixture("orchestrator-queue-summary"), "orchestrator-queue", warn_after_s=3600
    )
    by = {d.item: d for d in drafts}
    assert _items(drafts) == {"queued": "warn", "running": "ok", "history": "ok"}
    assert by["queued"].summary == "3 queued jobs, oldest 1h 30m (over the limit)"
    assert by["running"].summary == "2 running jobs: actor-analyst 1, j6-lead 1"
    assert by["history"].summary == "all time: cancelled 2, done 120, failed 4"
    assert by["queued"].work and by["running"].work and by["running"].value == 2
    idle = _builtin(fixture("orchestrator-queue-summary-idle"), "orchestrator-queue")
    assert _items(idle) == {"queued": "ok", "running": "ok", "history": "ok"}  # active: null
    with pytest.raises(MappingError, match="by_state"):
        _builtin({"queues": []}, "orchestrator-queue")


def test_agentmetry_audit_freshness():
    payload = fixture("agentmetry-audit-status")
    (d,) = _builtin(payload, "agentmetry-audit", warn_after_s=3600)
    assert (d.item, d.state) == ("audit-trail", "ok")
    assert d.summary == "last event 11m ago; recent 500: claude-code 320, hermes 180"
    assert "/var/lib" not in d.summary  # the export path is never shown
    (late,) = _builtin(payload, "agentmetry-audit", warn_after_s=300)
    assert late.state == "warn" and "(over the limit)" in late.summary
    (off,) = _builtin({"enabled": False, "last_event_utc": None}, "agentmetry-audit")
    (empty,) = _builtin({"enabled": True, "last_event_utc": None}, "agentmetry-audit")
    assert off.state == empty.state == "warn"


def test_agentmetry_collector_sends_its_api_key_header():
    http = FakeHttp(by_path=True)
    http.routes["/api/v1/audit/status"] = (200, fixture("agentmetry-audit-status"))
    s = spec(path="/api/v1/audit/status", mapping={"builtin": "agentmetry-audit"},
             auth={"secret": "secret:agentmetry/api-token", "header": "X-API-Key"})  # fmt: skip
    ctx = _ctx(http, secrets={"secret:agentmetry/api-token": "fake-agentmetry-key"})
    assert COLLECTORS["poll-http-json"].collect(s, ctx)[0].state == "ok"
    assert http.headers == [{"X-API-Key": "fake-agentmetry-key"}]


# ---------------------------------------------------------------- a hung product
class HangingHttp(FakeHttp):
    def __init__(self):
        super().__init__(by_path=True)
        self.release = threading.Event()

    def get(self, url, timeout, headers=None):
        self.release.wait(5)
        return super().get(url, timeout, headers)


@pytest.mark.parametrize("on_error, want", [("unknown", "warn"), ("fail", "fail")])
def test_a_hung_product_times_out_and_reads_per_on_error(make_hub, clock, on_error, want):
    s = spec("prom", kind="poll-prometheus", path="/api/v1/alerts", timeout_s=0.2,
             on_error=on_error, mapping={"builtin": "prometheus-alerts"})  # fmt: skip
    ok = FakeHttp(by_path=True)
    ok.routes["/api/v1/alerts"] = (200, fixture("prometheus-alerts"))
    hub = make_hub([s])
    sch = Scheduler()
    for r in sch.run([s], _ctx(ok, clock=clock)):
        hub.record(r)
    hung = HangingHttp()
    clock.advance(60)
    try:
        (res,) = sch.run([s], _ctx(hung, clock=clock))
        assert res.error == "timeout after 0.2s"
        hub.record(res)
        states = {o["item"]: o["state"] for o in hub.observations()}
        if on_error == "fail":  # a liveness probe: not answering IS the reading
            assert states == {"LabSmokeWarning": "fail", "LabSmokeCritical": "fail"}
        else:  # the last good reading stands until it expires
            assert states == {"LabSmokeWarning": "warn", "LabSmokeCritical": "fail"}
        assert hub.sources()[0]["state"] == want  # an erroring source: fail or warn
        clock.advance(s.stale_after_s)  # no good read for a whole staleness window
        states = {o["item"]: o["state"] for o in hub.observations()}
        assert states == {"LabSmokeWarning": "stale", "LabSmokeCritical": "stale"}
        assert hub.sources()[0]["state"] == "stale"
    finally:
        hung.release.set()


# ---------------------------------------------------------------- the registry
@pytest.fixture
def doc():
    return yaml.safe_load(REGISTRY.read_text())


def _problems(doc, service, **src):
    d = copy.deepcopy(doc)
    base = {"id": "extra", "interval_s": 60, "timeout_s": 5, "what": "an extra source"}
    d["services"][service].setdefault("status_sources", []).append({**base, **src})
    try:
        build_registry(d)
    except RegistryError as exc:
        return exc.problems
    return []


def test_the_example_registers_every_product_kind(doc):
    from homelabnext.status import sources_from_registry

    kinds = {s.id: s.kind for s in sources_from_registry(build_registry(doc))}
    assert {"poll-prometheus", "poll-uptime-kuma", "poll-stackstorm", "poll-nifi"} <= set(
        kinds.values()
    )
    assert kinds["orchestrator-queues"] == kinds["agentmetry-audit"] == "poll-http-json"


GOOD = {
    "metrics": {"kind": "poll-prometheus", "target": {"path": "/api/v1/query"}, "mapping": UP_QUERY},
    "uptime": {"kind": "poll-uptime-kuma", "target": {"path": "/api/status-page/lab"}},
    "automation": {"kind": "poll-stackstorm", "target": {"path": "/api/v1/executions"},
                   "auth": {"secret": "secret:stackstorm/status-token", "header": "St2-Api-Key"}},
    "dataflow": {"kind": "poll-nifi", "target": {"path": "/nifi-api/flow/status"}},
}  # fmt: skip


@pytest.mark.parametrize("service", sorted(GOOD))
def test_a_valid_product_source_passes(doc, service):
    assert _problems(doc, service, **GOOD[service]) == []


@pytest.mark.parametrize(
    "service, change, needle",
    [
        ("metrics", {"mapping": {"query": "up"}}, "needs thresholds"),
        ("metrics", {"mapping": {"thresholds": {"fail": 1}}}, "needs mapping.query"),
        ("metrics", {"mapping": {}}, "poll-prometheus needs a mapping"),
        ("metrics", {"target": {"path": "/api/v1/alerts"}}, "reads /api/v1/query"),
        ("metrics", {"mapping": {**UP_QUERY, "query": RAW_QUERY}}, "raw address"),
        (
            "metrics",
            {"mapping": {"builtin": "records-lanes"}},
            "builtin prometheus-alerts or a query",
        ),
        (
            "metrics",
            {"mapping": {"builtin": "prometheus-alerts", "query": "up"}},
            "mapping takes only",
        ),
        (
            "uptime",
            {"target": {"path": "/status/lab"}},
            "needs target.path /api/status-page/<slug>",
        ),
        ("uptime", {"mapping": {"states": {"degraded": "warn"}}}, "states key 'degraded'"),
        ("automation", {"target": {"path": "/api/v1/executions?limit=5"}}, "builds its own query"),
        ("automation", {"mapping": {"query": "up"}}, "mapping takes only"),
        ("dataflow", {"target": {"path": "/nifi-api/flow/about"}}, "ending in /flow/status"),
        ("dataflow", {"mapping": {"thresholds": {"direction": "below"}}}, "need warn or fail"),
    ],
)
def test_bad_product_sources_are_refused(doc, service, change, needle):
    problems = _problems(doc, service, **{**GOOD[service], **change})
    assert any(needle in p for p in problems), problems


@pytest.mark.parametrize(
    "src, needle",
    [
        ({"kind": "poll-http-json", "target": {"path": "/x"}, "mapping": {"builtin": "prometheus-alerts"}},
         "is for poll-prometheus only"),
        ({"kind": "poll-file", "target": {"file": "a.json"}, "mapping": {"builtin": "orchestrator-queue"}},
         "is for poll-http-json only"),
        ({"kind": "poll-file", "target": {"file": "a.json"}, "mapping": {"state": "s"},
          "auth": {"secret": "secret:a/b"}}, "auth is for the HTTP kinds only"),
        ({"kind": "poll-http-json", "target": {"path": "/x"}, "mapping": {"state": "s", "window_s": 60}},
         "for the product kinds only"),
        ({"kind": "poll-http-json", "target": {"path": "/x"}, "mapping": {"state": "s"},
          "auth": {"secret": "fake-literal-token"}}, "schema"),
    ],
)  # fmt: skip
def test_builtins_and_auth_belong_to_their_kinds(doc, src, needle):
    problems = _problems(doc, "metrics", **src)
    assert any(needle in p for p in problems), problems
