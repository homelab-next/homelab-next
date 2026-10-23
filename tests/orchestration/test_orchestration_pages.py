# SPDX-License-Identifier: Apache-2.0
"""The hub's Orchestration page and the ``hnx orchestration`` command line: per profile and
backend, the trend, one job's turns; names and numbers only, served read-only by the hub."""

from __future__ import annotations

import copy
import json
import sqlite3
import threading
import urllib.request

import pytest
from orch_helpers import KEY_ENV, NEVER, ROOT, T0, FakeSpendLogs, body, examples

from homelabnext.orchestration import cli
from homelabnext.orchestration.gateway import SpendLogReader, sync_turns
from homelabnext.orchestration.pages import OrchestrationSite
from homelabnext.orchestration.store import TelemetryStore
from homelabnext.registry.model import load
from homelabnext.status.model import iso
from homelabnext.status.serve import make_server
from homelabnext.status.views import build_status

VIEWS = {
    "views_version": 1,
    "shell": {"title": "Test lab", "main": "overview"},
    "menu": [
        {"id": "overview", "title": "Overview", "panel": "exceptions"},
        {"id": "orchestration", "title": "Orchestration", "panel": "orchestration"},
    ],
}


def _doc(orchestration: bool = True) -> dict:
    snapshot = {"now": iso(T0), "observations": [], "sources": []}
    registry = load(ROOT / "examples" / "services.yml")
    return build_status(
        snapshot, VIEWS, registry, [], capability_pages=set(), orchestration=orchestration
    )


@pytest.fixture
def site(filled) -> OrchestrationSite:
    with FakeSpendLogs() as gw:
        sync_turns(filled, SpendLogReader(gw.url, env=KEY_ENV).rows, now=T0)
    return OrchestrationSite(filled, clock=lambda: T0)


def _page(site, route, query="") -> str:
    code, ctype, raw = site.handle(route, query, _doc())
    assert (code, ctype) == (200, "text/html; charset=utf-8")
    return raw.decode()


def test_the_menu_lists_the_page_available_only_with_a_store():
    menu = {m["id"]: m for m in _doc()["menu"]}
    assert menu["orchestration"] == {
        "id": "orchestration", "title": "Orchestration", "kind": "page",
        "panel": "orchestration", "href": "/orchestration", "available": True,
    }  # fmt: skip
    assert not {m["id"]: m for m in _doc(False)["menu"]}["orchestration"]["available"]


def test_the_overview_shows_each_profile_backend_and_lane(site):
    html = _page(site, "/orchestration")
    assert "<h2>Orchestration</h2>" in html and "4 jobs" in html
    for cell in (
        "<td>local-large</td><td>real</td><td>2</td>",  # run-0001 and run-0002
        "<td>local-small</td><td>shadow</td><td>1</td>",
        "<td>-</td><td>real</td><td>1</td>",  # run-0004 never reached a backend
        "300.0s / 570.0s",  # wall p50 / p95
        "50000/3600",  # tokens in/out
        "68.3%",  # cache-read share
        "3 in 2 of 2 jobs",  # gateway turns joined by tag
        "no gateway data",  # run-0004: not a zero
        "2.0 KiB / 6.0 KiB",  # input vs output p50
    ):
        assert cell in html, cell
    assert '<a href="/orchestration/job?run=run-0001">' in html
    assert [n for n in NEVER if n in html] == []


def test_filters_and_the_window_narrow_the_page(site):
    shadow = _page(site, "/orchestration", "lane=shadow")
    assert "1 jobs" in shadow and "local-large" not in shadow.split("<h3>By profile")[1]
    assert "<b>shadow</b>" in shadow  # the active chip
    assert "1 jobs" in _page(site, "/orchestration", "outcome=cancelled")
    assert "0 jobs" in _page(site, "/orchestration", "days=1&backend=nope")
    assert "4 jobs" in _page(site, "/orchestration", "days=<script>")  # refused, default kept


def test_an_unknown_sum_is_shown_as_unknown_never_as_zero(site):
    """run-0004 wrote no usage file: its trend row shows ``?``, not 0 tokens at $0."""
    unknown = '<span class="muted">?</span>'
    trend = _page(site, "/orchestration", "outcome=cancelled").split("<h3>Trend by day")[1]
    trend = trend.split("<h3>Latest jobs")[0]
    assert f"{unknown}/{unknown}" in trend and "$0.0000" not in trend
    # all four jobs: the sums of the known values, with the unknown ones counted
    trend = _page(site, "/orchestration").split("<h3>Trend by day")[1].split("<h3>Latest")[0]
    assert '89000 <span class="muted">(1 unknown)</span>' in trend
    assert '$0.0000 <span class="muted">(2 unknown)</span>' in trend


def test_filters_and_links_take_every_value_the_schema_allows(filled):
    """``backend=-`` (no backend), a dotted backend and a run id that starts with a dot are
    values the record allows: the filter narrows to them and the job link opens the job."""
    ev = copy.deepcopy(examples()[0]) | {"id": "evt-dotted"}
    ev["data"].update(run_id=".abc", gateway_tag=".abc", backend=".vllm-a")
    assert filled.consume(body(ev)).status == "processed"
    site = OrchestrationSite(filled, clock=lambda: T0)
    assert "1 jobs" in _page(site, "/orchestration", "backend=-")  # run-0004 alone
    dotted = _page(site, "/orchestration", "backend=.vllm-a")
    assert "1 jobs" in dotted and "<b>.vllm-a</b>" in dotted
    assert '<a href="/orchestration/job?run=.abc">' in dotted
    job = _page(site, "/orchestration/job", "run=.abc")
    assert "<h2>Job <code>.abc</code></h2>" in job and "no such job" not in job
    assert "5 jobs" in _page(site, "/orchestration", "backend=a%0A")  # still shape-checked


def test_one_job_shows_its_record_and_its_gateway_turns(site):
    html = _page(site, "/orchestration/job", "run=run-0001")
    assert "<h2>Job <code>run-0001</code></h2>" in html
    for cell in ("req-a1", "req-a2", "mdl:triage-large", "example-27b", "400ms", "read_file"):
        assert cell in html, cell
    assert "The gateway saw 2 turn(s): 41000 tokens in, 3200 out" in html
    assert [n for n in NEVER if n in html] == []
    assert "no gateway data</span>: none of this job" in _page(
        site, "/orchestration/job", "run=run-0004"
    )
    assert "no such job" in _page(site, "/orchestration/job", "run=run-9999")
    assert "no such job" in _page(site, "/orchestration/job", "run=<b>")
    assert site.handle("/orchestration/other", "", _doc()) is None


def test_the_hub_serves_the_page_read_only(site):
    srv = make_server(_doc, orchestration=site)
    threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True).start()
    host, port = srv.server_address[:2]
    try:
        with urllib.request.urlopen(f"http://{host}:{port}/orchestration", timeout=5) as r:
            assert r.status == 200 and "default-src 'none'" in r.headers["Content-Security-Policy"]
            assert b"By profile and backend" in r.read()
        req = urllib.request.Request(f"http://{host}:{port}/orchestration", method="POST")
        with pytest.raises(urllib.error.HTTPError) as err:
            urllib.request.urlopen(req, timeout=5)
        assert err.value.code == 405
    finally:
        srv.shutdown()
        srv.server_close()


# ------------------------------------------------------------------------------ the CLI
def test_cli_ingest_turns_and_report(tmp_path, monkeypatch, capsys):
    db, events = tmp_path / "t.db", tmp_path / "events.jsonl"
    lines = [body(e).decode() for e in examples()]
    events.write_text("\n".join([*lines, lines[0], "not json", ""]) + "\n", encoding="utf-8")
    run = lambda *a: cli.main([*a, "--db", str(db)], clock=lambda: T0)  # noqa: E731
    assert run("ingest", str(events)) == 1  # the garbage line is refused, the rest stored
    out, err = capsys.readouterr()
    assert "4 processed, 1 duplicate, 1 refused" in out and "events.jsonl:6: " in err
    monkeypatch.delenv("HNX_ENDPOINT_LLM_GATEWAY", raising=False)
    assert run("turns") == 2
    monkeypatch.setenv(*next(iter(KEY_ENV.items())))
    with FakeSpendLogs() as gw:
        assert run("turns", "--gateway-url", gw.url) == 0
    assert "4 turn(s) for 4 job(s), 4 settled" in capsys.readouterr().out
    assert run("report", "--days", "7") == 0
    roll = json.loads(capsys.readouterr().out)
    assert roll["schema"] == "homelabnext.orchestration.rollup/1"
    assert sum(g["turns"]["count"] for g in roll["groups"]) == 4
    assert run("report", "--days", "0") == 2


def test_cli_ingest_refuses_only_the_record_with_an_impossible_date(tmp_path, capsys):
    evs = examples()
    bad = json.loads(body(evs[0])) | {"id": "evt-bad-date"}
    bad["data"].update(run_id="run-bad-date", finished_at="2026-02-30T00:00:00Z")
    events = tmp_path / "events.jsonl"
    events.write_text("\n".join([json.dumps(bad), *(body(e).decode() for e in evs)]) + "\n")
    argv = ["ingest", str(events), "--db", str(tmp_path / "t.db")]
    assert cli.main(argv, clock=lambda: T0) == 1
    out, err = capsys.readouterr()
    assert "4 processed, 0 duplicate, 1 refused" in out
    assert "events.jsonl:1: invalid event" in err


def test_cli_consume_without_a_bus_is_a_configuration_error(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("HNX_ENDPOINT_EVENTS", raising=False)
    argv = ["consume", "--db", str(tmp_path / "t.db"), "--stream", "S", "--subject-prefix", "p"]
    assert cli.main(argv, clock=lambda: T0) == 2
    assert "hnx orchestration consume:" in capsys.readouterr().err


def test_hnx_status_serve_builds_the_page_from_orchestration(tmp_path):
    """``hnx status serve --orchestration DB`` gives the site and marks the menu entry served."""
    import argparse

    from homelabnext.status import cli as status_cli

    assert status_cli._orchestration_site(argparse.Namespace(), lambda: T0) is None
    TelemetryStore(tmp_path / "t.db", clock=lambda: T0)
    args = argparse.Namespace(orchestration=str(tmp_path / "t.db"))
    site = status_cli._orchestration_site(args, lambda: T0)
    assert isinstance(site, OrchestrationSite) and site.store.path == tmp_path / "t.db"


def test_the_hub_opens_the_store_read_only_and_never_creates_one(tmp_path, capsys):
    """The hub's open creates nothing (no directory, file or table), purges nothing and writes
    nothing; a missing store is an error when the hub starts, not a new empty database."""
    import argparse

    from homelabnext.status import cli as status_cli

    missing = tmp_path / "nowhere" / "t.db"
    with pytest.raises(FileNotFoundError):
        status_cli._orchestration_site(argparse.Namespace(orchestration=str(missing)), lambda: T0)
    assert not missing.parent.exists()
    argv = ["serve", "--orchestration", str(missing), "--port", "0"]
    assert status_cli.main(argv) == 2 and "no telemetry store" in capsys.readouterr().err
    assert not missing.parent.exists()
    (tmp_path / "empty.db").write_bytes(b"")
    with pytest.raises(ValueError, match="not a telemetry store"):
        TelemetryStore(tmp_path / "empty.db", clock=lambda: T0, read_only=True)
    assert (tmp_path / "empty.db").read_bytes() == b""  # no tables were created in it
    db = tmp_path / "t.db"
    TelemetryStore(db, clock=lambda: T0).consume(body(examples()[0]))
    late = lambda: T0 + 400 * 86400  # noqa: E731  long past retention
    site = status_cli._orchestration_site(argparse.Namespace(orchestration=str(db)), late)
    assert site.store.job("run-0001") is not None  # the read-only open purged nothing
    with pytest.raises(sqlite3.OperationalError, match="readonly"):
        site.store.purge()
    assert TelemetryStore(db, clock=lambda: T0).job("run-0001") is not None
