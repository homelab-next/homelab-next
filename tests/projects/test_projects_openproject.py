# SPDX-License-Identifier: Apache-2.0
"""The OpenProject adapter against a loopback fake shaped after OpenProject 17.9's API
(``conformance/fakes/openproject_api.py``, fictional data): the client, ``doctor``, the contract
(the whole conformance suite), the strategy sync and the change feed."""

import hashlib
import hmac
import json
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from conformance.fakes.openproject_api import (
    EXT_CF,
    STATE_CF,
    TOKEN,
    FakeOpenProject,
    recorded_setup,
)
from conformance.fakes.project_store import RECORDS
from conformance.suites.projects import SUITE
from homelabnext.conform.core import run_checks
from homelabnext.events.envelope import event_problems
from homelabnext.identity import UidGenerator
from homelabnext.projects import Conflict, NotFound, strategy_records
from homelabnext.projects.cli import main as cli
from homelabnext.projects.openproject import (
    ApiError,
    ChangeFeed,
    OpenProjectBackend,
    OpenProjectClient,
    OpenProjectConfig,
    SetupError,
    adopt,
    discover,
    doctor,
    load_config,
    make_webhook_server,
    openproject_store,
    sync_strategy,
    verify_signature,
)

REPO = Path(__file__).resolve().parents[2]
ENV = {"HNX_SECRET_OPENPROJECT_API_TOKEN": TOKEN}
WEBHOOK_SECRET = "fake-webhook-secret"


def by_code(root=REPO / "examples/strategy"):
    """legacy code (aliases.yml, history only) -> the record, to name records in assertions"""
    import yaml

    codes = yaml.safe_load((Path(root) / "aliases.yml").read_text())["aliases"]
    recs = {r.uid: r for r in strategy_records(root)}
    return {code: recs[uid] for code, uid in codes.items() if uid in recs}


DOC_HOST = "192.0.2.10"  # no-raw-endpoint: allow RFC 5737 documentation address, never bound


@pytest.fixture
def op():
    with FakeOpenProject() as fake:
        yield fake


def cfg_for(fake, **kw):
    return OpenProjectConfig(base_url=fake.url, **kw)


def client_for(fake, **kw):
    return cfg_for(fake).client(env=ENV, **kw)


def seed_records(fake, uids=RECORDS):
    c = client_for(fake)
    st = discover(c, cfg_for(fake))
    for uid in uids:
        c.post(
            f"/api/v3/projects/{st.strategy_project}/work_packages",
            {
                "subject": "record",
                EXT_CF: uid,
                "_links": {
                    "type": {"href": f"/api/v3/types/{st.types['SO']}"},
                    "status": {"href": f"/api/v3/statuses/{st.statuses['Active']}"},
                },
            },
        )


def store_for(fake):
    return openproject_store(cfg_for(fake), client=client_for(fake))


# --- the client ---------------------------------------------------------------------------------


def test_the_token_is_read_by_name_sent_as_apikey_and_never_echoed(op):
    c = client_for(op)
    assert c.get("/api/v3/users/me")["login"] == "hnx-sync"
    wrong = OpenProjectClient(op.url, env={"HNX_SECRET_OPENPROJECT_API_TOKEN": "fake-wrong"})
    with pytest.raises(ApiError) as exc:
        wrong.get("/api/v3/users/me")
    assert exc.value.status == 401 and "fake-wrong" not in str(exc.value)
    unset = OpenProjectClient(op.url, env={})
    with pytest.raises(Exception, match="HNX_SECRET_OPENPROJECT_API_TOKEN"):
        unset.get("/api/v3/users/me")
    with pytest.raises(ValueError, match="secret reference"):
        OpenProjectClient(op.url, token="opapi-fake-literal")


def test_plain_http_is_refused_off_loopback():
    with pytest.raises(ValueError, match="plaintext"):
        OpenProjectClient("http://openproject.example.internal", env=ENV)
    OpenProjectClient("https://openproject.example.internal", env=ENV)  # https: fine


def test_retries_5xx_with_backoff_but_not_4xx(op):
    sleeps = []
    c = client_for(op, sleep=sleeps.append, backoff=0.5, retries=3)
    op.fail_next(2, 503)
    assert c.get("/api/v3/users/me")["id"] == 5
    assert sleeps == [0.5, 1.0]
    op.fail_next(4, 503)
    with pytest.raises(ApiError):
        c.get("/api/v3/users/me")
    with pytest.raises(NotFound):
        c.get("/api/v3/work_packages/999")
    op.fail_next(1, 503)
    with pytest.raises(ApiError):  # a POST is not retried after the server answered
        c.post("/api/v3/projects/3/work_packages", {"subject": "x"})


def test_pagination_reads_every_page(op):
    op.max_page = 2
    seed_records(op, RECORDS)
    c = client_for(op)
    got = list(c.collect("/api/v3/projects/2/work_packages"))
    assert [w[EXT_CF] for w in got] == list(RECORDS)
    assert c.requests >= 2


def test_a_patch_needs_and_checks_the_lock_version(op):
    seed_records(op, RECORDS[:1])
    c = client_for(op)
    wp = next(iter(op.wps.values()))
    with pytest.raises(ValueError, match="lockVersion"):
        c.patch(f"/api/v3/work_packages/{wp['id']}", {"subject": "x"})
    c.patch(f"/api/v3/work_packages/{wp['id']}", {"subject": "x", "lockVersion": 0})
    with pytest.raises(Conflict):
        c.patch(f"/api/v3/work_packages/{wp['id']}", {"subject": "y", "lockVersion": 0})


# --- doctor --------------------------------------------------------------------------------------


def test_doctor_passes_on_a_finished_setup(op):
    findings = doctor(client_for(op), cfg_for(op))
    assert findings and all(f.ok for f in findings), [f.what for f in findings if not f.ok]


def test_doctor_names_each_missing_admin_step():
    setup = recorded_setup()
    setup["types"] = [t for t in setup["types"] if t["name"] != "FFIR"]
    for s in setup["statuses"]:
        if s["name"] == "Done":
            s["isClosed"] = False
    setup["fields"][EXT_CF]["filterable"] = False
    del setup["fields"][STATE_CF]
    setup["projects"]["lab"]["types"].remove("Task")
    setup["memberships"][1]["_links"]["roles"] = [{"href": "/api/v3/roles/2", "title": "Member"}]
    with FakeOpenProject(setup=setup) as fake:
        bad = {f.what: f.step for f in doctor(client_for(fake), cfg_for(fake)) if not f.ok}
        with pytest.raises(SetupError, match="no type 'FFIR'"):
            discover(client_for(fake), cfg_for(fake))
    steps = "\n".join(f"{w} -> {s}" for w, s in bad.items())
    assert "work package type 'FFIR' -> Admin > Work packages > Types: create 'FFIR'" in steps
    assert "status 'Done' (closed) -> " in steps and "with 'closed' ticked" in steps
    assert "custom field 'hnx state' on 'SO' in 'strategy'" in steps
    assert "type 'Task' enabled in 'lab'" in steps
    assert "External key is filterable -> " in steps and "used as a filter" in steps
    assert "not: Example Operator: Member" in steps


def test_doctor_reports_a_token_that_does_not_work(op):
    c = OpenProjectClient(op.url, env={"HNX_SECRET_OPENPROJECT_API_TOKEN": "fake-wrong"})
    (only,) = doctor(c, cfg_for(op))
    assert not only.ok and "API tokens" in only.step


def test_config_file(tmp_path):
    f = tmp_path / "openproject.yml"
    f.write_text(
        "base_url: https://openproject.example.internal\nviewer_roles: [Reader, Watcher]\n"
    )
    cfg = load_config(f)
    assert cfg.viewer_roles == ("Reader", "Watcher") and cfg.token == "secret:openproject/api-token"
    f.write_text("base_url: https://openproject.example.internal\ntoken_value: x\n")
    with pytest.raises(ValueError, match="unknown"):
        load_config(f)


# --- the contract ----------------------------------------------------------------------------------


def test_the_conformance_suite_passes_on_openproject():
    fakes = []

    def subject():
        fake = FakeOpenProject().start()
        fakes.append(fake)
        seed_records(fake)
        return store_for(fake)

    try:
        results = run_checks(SUITE, subject)
    finally:
        for f in fakes:
            f.stop()
    failed = [(r.check, r.evidence) for r in results if r.status != "pass"]
    assert not failed and len(results) == len(SUITE.ids())


def test_items_are_work_packages_and_a_concurrent_ui_edit_is_a_conflict(op):
    seed_records(op)
    s = store_for(op)
    p = s.create("project", "Edge move")
    step = s.create("step", "Build", project=p.uid)
    s.link(step.uid, RECORDS[0], "supports")
    wp = next(w for w in op.wps.values() if w.get(EXT_CF) == step.uid)
    assert wp["_links"]["parent"]["href"].endswith(f"/{next(w['id'] for w in op.wps.values() if w.get(EXT_CF) == p.uid)}")  # fmt: skip
    rel = next(iter(op.relations.values()))
    assert (rel["type"], rel["description"]) == ("relates", "supports")
    # someone edits the work package in the UI between our read and our write
    client_for(op).patch(f"/api/v3/work_packages/{wp['id']}", {"subject": "edited", "lockVersion": wp["lockVersion"]})  # fmt: skip
    with pytest.raises(Conflict):
        s.update(step.uid, 2, title="mine")  # quotes version 2; the UI made it 3
    assert s.get(step.uid).title == "edited"


# --- strategy sync ---------------------------------------------------------------------------------


def records():
    return list(strategy_records(REPO / "examples/strategy"))


def test_sync_dry_run_writes_nothing_then_apply_mirrors_the_tree(op):
    c, cfg = client_for(op), cfg_for(op)
    st = discover(c, cfg)
    plan = sync_strategy(c, cfg, st, records(), apply=False)
    assert op.writes() == 0 and len(plan.created) == len(records()) and not plan.applied
    done = sync_strategy(c, cfg, st, records(), apply=True)
    assert done.problems == [] and len(done.created) == len(records())
    by_key = {w[EXT_CF]: w for w in op.wps.values()}
    recs = by_code()
    to, oo = by_key[recs["TO-001"].uid], by_key[recs["OO-001"].uid]
    assert to["_links"]["parent"]["href"].endswith(f"/{oo['id']}")
    labels = {r["description"] for r in op.relations.values()}
    assert {"supports", "serves", "raised_by"} <= labels  # a measure hangs from its objective
    assert "Mirrored from the strategy repository" in to["description"]["raw"]


def test_an_unchanged_repository_makes_zero_writes(op):
    c, cfg = client_for(op), cfg_for(op)
    st = discover(c, cfg)
    sync_strategy(c, cfg, st, records(), apply=True)
    before = op.writes()
    again = sync_strategy(c, cfg, st, records(), apply=True)
    assert op.writes() == before and again.writes == 0 and len(again.unchanged) == len(records())


def test_an_edit_in_openproject_is_reverted_and_reported_and_the_repo_wins(op):
    c, cfg = client_for(op), cfg_for(op)
    st = discover(c, cfg)
    sync_strategy(c, cfg, st, records(), apply=True)
    recs = by_code()
    wp = next(w for w in op.wps.values() if w[EXT_CF] == recs["SO-001"].uid)
    closed = st.statuses["Achieved"]
    c.patch(f"/api/v3/work_packages/{wp['id']}", {"lockVersion": wp["lockVersion"], "subject": "renamed in the UI", "_links": {"status": {"href": f"/api/v3/statuses/{closed}"}}})  # fmt: skip
    rep = sync_strategy(c, cfg, st, records(), apply=True)
    assert rep.reverted == [f"{recs['SO-001'].label} ({recs['SO-001'].uid})"] and not rep.updated
    now = op.wps[wp["id"]]
    assert now["subject"] == recs["SO-001"].title
    assert now["_links"]["status"]["href"].endswith(f"/{st.statuses['Active']}")  # never closed


def test_a_repo_change_is_an_update_and_a_vanished_record_an_orphan(op):
    c, cfg = client_for(op), cfg_for(op)
    st = discover(c, cfg)
    sync_strategy(c, cfg, st, records(), apply=True)
    codes = by_code()
    tt, rfi = codes["TT-001"].uid, codes["RFI-001"].uid
    changed = [r if r.uid != tt else type(r)(**{**r.__dict__, "title": "Renamed"}) for r in records()]  # fmt: skip
    changed = [r for r in changed if r.uid != rfi]
    rep = sync_strategy(c, cfg, st, changed, apply=True)
    assert rep.updated == [f"{codes['TT-001'].label} ({tt})"]
    assert len(rep.orphans) == 1 and rep.reverted == []
    assert any("raised_by" in x for x in rep.relations_removed)  # RFI-001's edge is gone
    orphan_wp = int(rep.orphans[0].split()[0].removeprefix("wp:"))
    assert orphan_wp in op.wps  # reported, never deleted or closed


def test_sync_never_touches_relations_to_execution_work(op):
    c, cfg = client_for(op), cfg_for(op)
    st = discover(c, cfg)
    sync_strategy(c, cfg, st, records(), apply=True)
    s = store_for(op)
    t = s.create("task", "Work on the objective")
    so = by_code()["SO-001"].uid
    s.link(t.uid, so, "supports")
    rep = sync_strategy(c, cfg, st, records(), apply=True)
    assert rep.relations_removed == [] and s.get(t.uid).links[0].target == so


# --- the CLI ------------------------------------------------------------------------------------


def test_openproject_commands_need_a_config(tmp_path, capsys):
    bad = tmp_path / "op.yml"
    bad.write_text("base_url: https://openproject.example.internal\ncolour: red\n")
    assert cli(["doctor", "--target", "openproject", "--config", str(bad)]) == 2
    with pytest.raises(SystemExit):
        cli(["sync-strategy", "--target", "openproject", "--config", str(bad)])  # no mode


def test_cli_drives_doctor_and_sync_against_the_fake(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("HNX_SECRET_OPENPROJECT_API_TOKEN", TOKEN)
    with FakeOpenProject() as fake:
        cfg = tmp_path / "openproject.yml"
        cfg.write_text(f"base_url: {fake.url}\n")
        base = [
            "--target",
            "openproject",
            "--config",
            str(cfg),
            "--strategy",
            str(REPO / "examples/strategy"),
        ]
        assert cli(["doctor", *base]) == 0
        assert "ok    work package type 'SO'" in capsys.readouterr().out
        assert cli(["sync-strategy", *base, "--dry-run"]) == 0 and fake.writes() == 0
        capsys.readouterr()
        assert cli(["sync-strategy", *base, "--apply"]) == 0
        assert capsys.readouterr().out.count("created:") == len(records())


# --- the change feed ---------------------------------------------------------------------------------


def _feed(fake, sink):
    c, cfg = client_for(fake), cfg_for(fake)
    return ChangeFeed(OpenProjectBackend(c, cfg, discover(c, cfg)), sink.append)


def test_poll_is_complete_even_within_one_second_and_dedupes():
    with FakeOpenProject(tick=0) as fake:  # every write in the same second
        s, out = store_for(fake), []
        feed = _feed(fake, out)
        _, cur = feed.poll(None)
        a = s.create("task", "a")
        evs, cur = feed.poll(cur)
        assert [e["data"]["uid"] for e in evs] == [a.uid]
        b = s.create("task", "b")
        s.update(a.uid, 1, status="in_progress")
        evs, cur2 = feed.poll(cur)
        assert sorted((e["data"]["uid"], e["data"]["version"]) for e in evs) == sorted([(a.uid, 2), (b.uid, 1)])  # fmt: skip
        assert feed.poll(cur2)[0] == [] and feed.poll(cur)[0] == []  # replays emit nothing new
        assert all(event_problems(e) == [] for e in out) and len(out) == 3


def test_webhook_and_poll_converge_on_one_event(op):
    s, out = store_for(op), []
    feed = _feed(op, out)
    _, cur = feed.poll(None)
    t = s.create("task", "t")
    wp = next(w for w in op.wps.values() if w.get(EXT_CF) == t.uid)
    hook = feed.on_webhook({"action": "work_package:created", "work_package": wp, "actor": {"id": 5}})  # fmt: skip
    polled, _ = feed.poll(cur)
    assert hook is not None and polled == [] and len(out) == 1
    from homelabnext.events.envelope import derive_event_id

    assert out[0]["id"] == derive_event_id("homelabnext.project.changed", "svc:openproject", f"wp:{wp['id']}:v0", subject=f"project:{t.uid}")  # fmt: skip


def test_a_strategy_edit_by_someone_else_is_noted(op):
    seed_records(op, RECORDS[:1])
    feed = _feed(op, [])
    wp = next(iter(op.wps.values()))
    assert feed.on_webhook({"action": "work_package:updated", "work_package": wp, "actor": {"id": 6}}) is None  # fmt: skip
    assert feed.strategy_edits == [f"wp:{wp['id']} by user 6"]
    assert feed.on_webhook({"action": "project:updated"}) is None


def test_work_made_by_hand_is_adopted_with_a_fresh_uid(op):
    c, cfg = client_for(op), cfg_for(op)
    st = discover(c, cfg)
    c.post(f"/api/v3/projects/{st.work_project}/work_packages", {"subject": "made in the UI", "_links": {"type": {"href": f"/api/v3/types/{st.types['Task']}"}, "status": {"href": f"/api/v3/statuses/{st.statuses['To do']}"}}})  # fmt: skip
    s = store_for(op)
    assert s.list() == []
    backend = OpenProjectBackend(c, cfg, st)
    assert len(adopt(backend, UidGenerator())) == 1
    (item,) = s.list()
    assert item.title == "made in the UI" and item.status == "todo"


def _post(url, body, sig):
    req = urllib.request.Request(url, data=body, method="POST")
    if sig:
        req.add_header("X-OP-Signature", sig)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:  # loopback
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def test_the_webhook_receiver_refuses_a_bad_signature(op):
    s, out = store_for(op), []
    feed = _feed(op, out)
    t = s.create("task", "t")
    wp = next(w for w in op.wps.values() if w.get(EXT_CF) == t.uid)
    body = json.dumps({"action": "work_package:created", "work_package": wp}).encode()
    good = "sha1=" + hmac.new(WEBHOOK_SECRET.encode(), body, hashlib.sha1).hexdigest()
    srv = make_webhook_server(feed, env={"HNX_SECRET_OPENPROJECT_WEBHOOK_SECRET": WEBHOOK_SECRET})
    threading.Thread(target=srv.serve_forever, args=(0.05,), daemon=True).start()
    url = f"http://{srv.server_address[0]}:{srv.server_address[1]}/openproject/webhook"
    try:
        assert _post(url, body, None) == 401
        assert _post(url, body, "sha1=" + "0" * 40) == 401
        assert _post(url, body + b" ", good) == 401  # the body was altered
        assert out == []
        assert _post(url, body, good) == 204 and len(out) == 1
        assert _post(url, b"[1]", "sha1=" + hmac.new(WEBHOOK_SECRET.encode(), b"[1]", hashlib.sha1).hexdigest()) == 400  # fmt: skip
        assert _post(url.replace("/openproject/webhook", "/other"), body, good) == 404
    finally:
        srv.shutdown()
        srv.server_close()
    unsigned = make_webhook_server(feed, env={})
    try:
        threading.Thread(target=unsigned.serve_forever, args=(0.05,), daemon=True).start()
        u = f"http://{unsigned.server_address[0]}:{unsigned.server_address[1]}/openproject/webhook"
        assert _post(u, body, good) == 401  # no secret configured: nothing is accepted
    finally:
        unsigned.shutdown()
        unsigned.server_close()
    with pytest.raises(ValueError, match="loopback"):
        make_webhook_server(feed, host=DOC_HOST)


def test_verify_signature_is_exact():
    body = b'{"action":"work_package:updated"}'
    sig = "sha1=" + hmac.new(b"fake-k", body, hashlib.sha1).hexdigest()
    assert verify_signature(b"fake-k", body, sig) and verify_signature(b"fake-k", body, sig.upper().replace("SHA1=", "sha1="))  # fmt: skip
    assert not verify_signature(b"fake-k", body, sig.replace("sha1=", "sha256="))
    assert not verify_signature(b"", body, sig) and not verify_signature(b"fake-k", body, None)
