# SPDX-License-Identifier: Apache-2.0
"""The alert-intake service script (``modules/alert-intake``): validation, the source rule,
idempotency by event id, dedup, resume after a downstream failure, the promotion policy, paging
(a new alert at or above the threshold, once; never a repeat, never a canary), and the webhook
end to end on loopback with the cases contract's recorded stand-in behind it."""

from __future__ import annotations

import copy
import importlib.util
import json
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar

import pytest

from conformance.fakes.case_store import FakeCaseStore

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = (
    ROOT / "modules" / "alert-intake" / "roles" / "alert_intake" / "files" / "hnx_alert_intake.py"
)
SPEC = importlib.util.spec_from_file_location("hnx_alert_intake", SCRIPT)
ai = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ai)

SIEM = "svc:siem"


def event(eid="evt-1", severity="high", detection="det:auth-failure-burst", **data):
    return {
        "specversion": "1.0",
        "id": eid,
        "source": SIEM,
        "type": "homelabnext.alert.created",
        "time": "2026-01-01T00:00:00Z",
        "severity": severity,
        "data": {
            "alert_id": "ALT-" + eid,
            "detection": detection,
            "title": "Burst of failed logins",
            "severity": severity,
            "observed_at": "2026-01-01T00:00:00Z",
            "entities": [
                {"kind": "domain", "value": "bad.example.internal"},
                {"kind": "host", "value": "app-01"},
            ],
            **data,
        },
    }


class Pages:
    def __init__(self):
        self.sent, self.fail = [], 0

    def __call__(self, data, alert_id):
        if self.fail:
            self.fail -= 1
            raise RuntimeError("page failed")
        self.sent.append((data["detection"], alert_id))


@pytest.fixture
def parts(tmp_path):
    store, pages = FakeCaseStore(), Pages()
    intake = ai.Intake(store, pages, ai.State(str(tmp_path / "state.json")), allowed_source=SIEM)
    return intake, store, pages, tmp_path


def test_a_valid_event_becomes_one_alert_and_one_page(parts):
    intake, store, pages, _ = parts
    out = intake.handle(event())
    assert out["paged"] is True and out["count"] == 1 and out["duplicate"] is False
    assert [a.status for a in store.list_alerts()] == ["new"] and store.list_alerts()[
        0
    ].severity == "high"
    assert pages.sent == [("det:auth-failure-burst", out["alert"])]


@pytest.mark.parametrize(
    "mutate",
    [
        lambda e: e.pop("id"),
        lambda e: e.update(type="homelabnext.alert.closed"),
        lambda e: e.update(specversion="0.3"),
        lambda e: e["data"].update(severity="catastrophic"),
        lambda e: e["data"].update(detection="rule:123"),
        lambda e: e["data"].update(title=""),
        lambda e: e["data"].update(entities=[{"kind": "domain"}]),
        lambda e: e["data"].update(entities=[{"kind": "ip", "value": "x"}] * 51),
        lambda e: e.update(data=None),
    ],
)
def test_a_malformed_event_is_refused_with_400_and_touches_nothing(parts, mutate):
    intake, store, pages, _ = parts
    bad = event()
    mutate(bad)
    with pytest.raises(ai.Refused) as exc:
        intake.handle(bad)
    assert exc.value.status == 400 and store.list_alerts() == [] and pages.sent == []


def test_an_event_from_a_foreign_source_is_refused_with_403(parts):
    intake, store, pages, _ = parts
    forged = event()
    forged["source"] = "svc:other"
    with pytest.raises(ai.Refused) as exc:
        intake.handle(forged)
    assert exc.value.status == 403 and store.list_alerts() == [] and pages.sent == []


def test_a_redelivery_runs_nothing_again_and_a_changed_body_is_a_collision(parts):
    intake, store, pages, tmp = parts
    first = intake.handle(event())
    again = intake.handle(event())
    assert again["duplicate"] is True and again["alert"] == first["alert"]
    assert store.list_alerts()[0].count == 1 and len(pages.sent) == 1
    with pytest.raises(ai.Refused) as exc:
        intake.handle(event(title="another title"))
    assert exc.value.status == 409
    # the answer survives a restart: the state is the file's
    reloaded = ai.Intake(store, pages, ai.State(str(tmp / "state.json")), allowed_source=SIEM)
    assert reloaded.handle(event())["duplicate"] is True and len(pages.sent) == 1


def test_a_repeat_detection_collapses_into_the_open_alert_and_never_pages(parts):
    intake, store, pages, _ = parts
    a = intake.handle(event("evt-1"))
    b = intake.handle(event("evt-2"))
    assert b["alert"] == a["alert"] and b["count"] == 2 and b["paged"] is False
    assert len(store.list_alerts()) == 1 and store.list_alerts()[0].count == 2
    assert len(pages.sent) == 1


def test_the_dedup_key_is_the_detection_and_the_sorted_entities():
    k = ai.dedup_key
    e1, e2 = event()["data"], copy.deepcopy(event()["data"])
    e2["entities"].reverse()
    assert k(e1) == k(e2)
    e2["entities"][0]["value"] = "other.example.internal"
    assert k(e1) != k(e2)
    e3 = copy.deepcopy(e1)
    e3["detection"] = "det:other"
    assert k(e1) != k(e3)


def test_below_the_paging_threshold_an_alert_is_recorded_and_not_paged(parts):
    intake, store, pages, _ = parts
    out = intake.handle(event(severity="medium"))
    assert out["paged"] is False and pages.sent == [] and len(store.list_alerts()) == 1


def test_a_downstream_failure_is_502_and_the_retry_resumes_without_double_counting(parts):
    intake, store, pages, _ = parts
    pages.fail = 1
    with pytest.raises(ai.Downstream):
        intake.handle(event())
    assert store.list_alerts()[0].count == 1 and pages.sent == []
    out = intake.handle(event())  # the sender's retry
    assert out["paged"] is True and store.list_alerts()[0].count == 1 and len(pages.sent) == 1
    assert len(store.list_alerts()) == 1


def test_the_case_store_being_down_is_502_and_nothing_is_marked_done(tmp_path):
    class Down:
        def create_alert(self, *a, **k):
            raise ConnectionError("down")

    intake = ai.Intake(Down(), Pages(), ai.State(str(tmp_path / "s.json")), allowed_source=SIEM)
    with pytest.raises(ai.Downstream):
        intake.handle(event())
    assert intake.state.get("evt-1")["done"] is False


def test_the_promotion_policy_promotes_at_its_threshold_and_not_below(tmp_path):
    store = FakeCaseStore()
    intake = ai.Intake(
        store, Pages(), ai.State(str(tmp_path / "s.json")), allowed_source=SIEM, promote_min="high"
    )
    low = intake.handle(event("a", severity="medium", detection="det:one"))
    high = intake.handle(event("b", severity="high", detection="det:two"))
    assert low["case"] is None and high["case"] is not None
    assert {a.id: a.status for a in store.list_alerts()} == {
        low["alert"]: "new",
        high["alert"]: "promoted",
    }


def test_the_default_policy_never_promotes(parts):
    intake, store, _, _ = parts
    intake.handle(event(severity="critical"))
    assert [a.status for a in store.list_alerts()] == ["new"]


def test_a_canary_is_recorded_dismissed_and_never_pages(parts):
    intake, store, pages, _ = parts
    out = intake.handle(event("c1", severity="critical", detection="det:canary-daily"))
    alert = store.get_alert(out["alert"])
    assert alert.status == "dismissed" and alert.reason == "canary"
    assert pages.sent == [] and out["paged"] is False


def test_the_thresholds_are_validated(tmp_path):
    for kw in ({"page_min": "urgent"}, {"promote_min": "urgent"}):
        with pytest.raises(ValueError):
            ai.Intake(
                FakeCaseStore(),
                Pages(),
                ai.State(str(tmp_path / "s.json")),
                allowed_source=SIEM,
                **kw,
            )


# -- the webhook, end to end on loopback ------------------------------------------------------


class _Notify(BaseHTTPRequestHandler):
    got: ClassVar[list] = []

    def do_POST(self):
        n = int(self.headers["Content-Length"])
        body = self.rfile.read(n).decode()
        _Notify.got.append(
            (self.headers.get("Authorization"), self.headers["Title"], body, self.path)
        )
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *a):
        pass


@pytest.fixture
def served(tmp_path):
    from homelabnext.conform.adapters.cases_iris import make_recorded

    notify = ThreadingHTTPServer(("localhost", 0), _Notify)
    threading.Thread(target=notify.serve_forever, daemon=True).start()
    _Notify.got = []
    store = make_recorded()
    pager = ai.make_pager(
        f"http://localhost:{notify.server_address[1]}", "alerts", "page-token", None, False
    )
    intake = ai.Intake(store, pager, ai.State(str(tmp_path / "s.json")), allowed_source=SIEM)
    srv = ThreadingHTTPServer(("localhost", 0), ai._handler(intake, "hook-token"))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://localhost:{srv.server_address[1]}", store
    srv.shutdown()
    notify.shutdown()
    store.close()


def _post(url, doc, token="hook-token"):
    req = urllib.request.Request(
        url + "/v1/alerts", data=json.dumps(doc).encode(), method="POST",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )  # fmt: skip
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def test_webhook_to_case_store_alert_and_page(served):
    url, store = served
    status, out = _post(url, event())
    assert status == 202 and out["paged"] is True
    alert = store.get_alert(out["alert"])
    assert alert.status == "new" and alert.severity == "high" and alert.source == SIEM
    assert len(_Notify.got) == 1 and _Notify.got[0][0] == "Bearer page-token"
    assert _Notify.got[0][3] == "/alerts"
    assert "det:auth-failure-burst" in _Notify.got[0][2]
    status, again = _post(
        url, event("evt-2")
    )  # a repeat of the detection: one alert, count 2, no page
    assert (
        status == 202
        and again["alert"] == out["alert"]
        and store.get_alert(out["alert"]).count == 2
    )
    assert len(_Notify.got) == 1


def test_webhook_refuses_a_bad_token_a_bad_body_and_a_foreign_source(served):
    url, store = served
    assert _post(url, event(), token="wrong")[0] == 401
    assert _post(url, {"nope": 1})[0] == 400
    forged = event()
    forged["source"] = "svc:other"
    assert _post(url, forged)[0] == 403
    assert store.list_alerts() == [] and _Notify.got == []
    with urllib.request.urlopen(url + "/healthz", timeout=5) as r:
        assert json.loads(r.read()) == {"status": "ok"}
