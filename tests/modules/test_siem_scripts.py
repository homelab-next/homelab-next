# SPDX-License-Identifier: Apache-2.0
"""The SIEM module's three scripts, driven without a product: a fake ``docker`` on the path stands in
for the manager's container (the configuration test, the restart, the process table), a loopback
HTTP server for the events forwarder and for the indexer.

* rules sync: files land as ``hnx-<name>.xml`` (0660), only those are ever touched, an unchanged set
  restarts nothing, a set the configuration test refuses is put back, a daemon that does not come back
  puts it back too, and an unsafe path is refused;
* alert webhook: the event is the schema's, its id is the library's, a 2xx is delivery, a transient
  refusal is held in the outbox and flushed in order, a permanent one is dropped, a redirect is never
  followed, and the credential is only in the Authorization header;
* index export and restore: one file per index with every document, a second restore changes nothing,
  a source with no index file is refused, the password never leaves the environment.
"""

from __future__ import annotations

import http.server
import importlib.util
import json
import os
import socket
import stat
import threading
from pathlib import Path
from typing import ClassVar

import pytest

from homelabnext.events import derive_event_id, validate_event

ROOT = Path(__file__).resolve().parents[2]
FILES = next((ROOT / "modules").glob("*/roles/*/files/hnx_*_rules.py")).parent
MID = FILES.parents[2].name  # the module id, which prefixes the stock detection ids


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


rules = _load(next(FILES.glob("hnx_*_rules.py")), "siem_rules")
index = _load(next(FILES.glob("hnx_*_index.py")), "siem_index")
alert = _load(FILES / "custom-hnx-alert.py", "siem_alert")


# ----------------------------------------------------------------------------- rules sync


@pytest.fixture
def stack(tmp_path, monkeypatch):
    """A fake container runtime and the three directories the sync works on."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "calls.log"
    state = tmp_path / "state"
    state.mkdir()
    (bindir / "docker").write_text(
        "#!/bin/sh\n"
        f'echo "$@" >> {log}\n'
        'case "$*" in\n'
        f'  *"analysisd -t"*) [ -e {state}/test-fails ] && {{ echo "bad rule" >&2; exit 1; }}; exit 0;;\n'
        f'  *"pgrep -x"*) [ -e {state}/dead ] && exit 1; exit 0;;\n'
        f'  *"control restart"*) [ -e {state}/restart-fails ] && exit 1; [ -e {state}/dead ] && {{ if [ -e {state}/dead-seen ]; then rm -f {state}/dead {state}/dead-seen; else touch {state}/dead-seen; fi; }}; exit 0;;\n'
        "esac\nexit 0\n"
    )
    (bindir / "docker").chmod(0o755)
    monkeypatch.setenv("PATH", f"{bindir}:{os.environ['PATH']}")
    stage = tmp_path / "data" / "config" / "native"
    etc = tmp_path / "data" / "manager" / "etc"
    prev = tmp_path / "data" / "config" / "native-previous"
    for d in (stage / "rules", stage / "decoders", etc / "rules", etc / "decoders"):
        d.mkdir(parents=True)
    (etc / "rules" / "local_rules.xml").write_text("<group name='local'/>")
    return {"stage": stage, "etc": etc, "prev": prev, "log": log, "state": state,
            "compose": tmp_path / "data" / "compose.yml"}  # fmt: skip


def _sync(s, force=False):
    return rules.sync(s["stage"], s["etc"], str(s["compose"]), s["prev"], force, wait=0)


def test_a_new_set_is_installed_as_prefixed_files_tested_and_restarted(stack):
    (stack["stage"] / "rules" / "ssh-off.xml").write_text(
        "<group name='a'><rule id='900200' level='5'/></group>"
    )
    (stack["stage"] / "decoders" / "edge.xml").write_text("<decoder name='edge'/>")
    code, report = _sync(stack)
    assert code == 0 and report["changed"] is True
    assert report["files"] == ["decoders/hnx-edge.xml", "rules/hnx-ssh-off.xml"]
    mode = stat.S_IMODE((stack["etc"] / "rules" / "hnx-ssh-off.xml").stat().st_mode)
    assert mode == 0o660
    calls = stack["log"].read_text()
    assert calls.index("analysisd -t") < calls.index("control restart")  # tested BEFORE the restart


def test_an_unchanged_set_restarts_nothing_unless_forced(stack):
    (stack["stage"] / "rules" / "a.xml").write_text("<group name='a'/>")
    _sync(stack)
    stack["log"].write_text("")
    code, report = _sync(stack)
    assert code == 0 and report["changed"] is False and stack["log"].read_text() == ""
    code, report = _sync(stack, force=True)
    assert code == 0 and "control restart" in stack["log"].read_text()


def test_only_prefixed_files_are_touched_and_a_removed_rule_is_removed(stack):
    (stack["stage"] / "rules" / "a.xml").write_text("<group name='a'/>")
    (stack["stage"] / "rules" / "b.xml").write_text("<group name='b'/>")
    _sync(stack)
    (stack["stage"] / "rules" / "b.xml").unlink()
    _code, report = _sync(stack)
    assert report["files"] == ["rules/hnx-a.xml"]
    assert (stack["etc"] / "rules" / "local_rules.xml").read_text() == "<group name='local'/>"


def test_a_set_the_configuration_test_refuses_is_put_back_and_nothing_restarts(stack):
    (stack["stage"] / "rules" / "a.xml").write_text("<group name='good'/>")
    _sync(stack)
    (stack["stage"] / "rules" / "a.xml").write_text("<group name='broken'")
    (stack["stage"] / "rules" / "new.xml").write_text("<group name='new'/>")
    stack["state"].joinpath("test-fails").write_text("")
    stack["log"].write_text("")
    code, report = _sync(stack)
    assert code == 1 and report["changed"] is False
    assert (stack["etc"] / "rules" / "hnx-a.xml").read_text() == "<group name='good'/>"
    assert not (stack["etc"] / "rules" / "hnx-new.xml").exists()
    assert "control restart" not in stack["log"].read_text()


def test_daemons_that_do_not_come_back_put_the_previous_set_back(stack):
    (stack["stage"] / "rules" / "a.xml").write_text("<group name='good'/>")
    _sync(stack)
    (stack["stage"] / "rules" / "a.xml").write_text("<group name='kills'/>")
    stack["state"].joinpath("dead").write_text("")
    code, _report = _sync(stack)
    assert code == 1
    assert (stack["etc"] / "rules" / "hnx-a.xml").read_text() == "<group name='good'/>"
    assert stack["log"].read_text().count("control restart") >= 2  # the new set, then the old one


def test_the_digest_of_the_stage_equals_the_digest_of_what_is_installed(stack, capsys):
    (stack["stage"] / "rules" / "a.xml").write_text("<group name='a'/>")
    (stack["stage"] / "decoders" / "d.xml").write_text("<decoder name='d'/>")
    _sync(stack)
    assert rules.main(["digest", "--etc", str(stack["etc"])]) == 0
    installed = json.loads(capsys.readouterr().out)["digest"]
    assert rules.main(["digest", "--stage", str(stack["stage"])]) == 0
    assert json.loads(capsys.readouterr().out)["digest"] == installed
    (stack["etc"] / "rules" / "hnx-a.xml").write_text("<group name='tampered'/>")
    rules.main(["digest", "--etc", str(stack["etc"])])
    assert json.loads(capsys.readouterr().out)["digest"] != installed


@pytest.mark.parametrize("bad", ["relative/dir", "/tmp", "/a/../b/c"])
def test_an_unsafe_path_is_refused(bad, stack, capsys):
    assert rules.main(["sync", "--stage", bad, "--etc", str(stack["etc"]), "--compose", "/a/b/c.yml",
                       "--prev", str(stack["prev"])]) == 2  # fmt: skip


def test_a_symlinked_input_is_refused(stack, tmp_path):
    (tmp_path / "outside.xml").write_text("<group name='x'/>")
    (stack["stage"] / "rules" / "a.xml").symlink_to(tmp_path / "outside.xml")
    with pytest.raises(rules.Refused):
        rules.desired(stack["stage"])


# ----------------------------------------------------------------------------- alert webhook

CFG = {"source": "svc:siem", "tlp": "red", "detections": {"900200": "det:ssh-offbaseline"}}
ALERT = {
    "timestamp": "2026-11-22T10:00:00.123+0000", "id": "1700000000.654321",
    "rule": {"id": "900200", "level": 12, "description": "Off-baseline SSH login"},
    "agent": {"name": "hnx-agents-01"},
    "data": {"srcip": "203.0.113.9", "srcuser": "root"},
}  # fmt: skip


def test_the_event_is_the_schemas_and_its_id_is_the_librarys():
    event = alert.build(ALERT, CFG)
    validate_event(event)
    assert event["id"] == derive_event_id(
        "homelabnext.alert.created", "svc:siem", "1700000000.654321"
    )
    assert event["data"]["detection"] == "det:ssh-offbaseline"
    assert event["data"]["observed_at"] == "2026-11-22T10:00:00.123+00:00"
    assert event["tlp"] == "red" and event["severity"] == "high"
    assert {"kind": "host", "value": "hnx-agents-01"} in event["data"]["entities"]
    assert {"kind": "ip", "value": "203.0.113.9"} in event["data"]["entities"]


def test_a_rule_the_site_did_not_map_is_a_stock_detection_id():
    other = {**ALERT, "rule": {"id": "5710", "level": 5, "description": "x"}}
    event = alert.build(other, CFG)
    validate_event(event)
    assert event["data"]["detection"] == f"det:{MID}-rule-5710"
    assert event["severity"] == "low"


@pytest.mark.parametrize("level,severity", [(15, "critical"), (14, "high"), (12, "high"), (11, "medium"),
                                            (8, "medium"), (7, "low"), (5, "low"), (4, "info"), (0, "info")])  # fmt: skip
def test_the_level_maps_to_the_severity(level, severity):
    assert alert.severity(level) == severity


class _Forwarder(http.server.BaseHTTPRequestHandler):
    seen: ClassVar[list] = []
    script: ClassVar[list] = []

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        type(self).seen.append({"headers": dict(self.headers), "body": json.loads(body)})
        code = type(self).script.pop(0) if type(self).script else 202
        self.send_response(code)
        if code == 302:
            self.send_header("Location", "http://elsewhere.invalid/")
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *a):
        return None


@pytest.fixture
def forwarder(tmp_path, monkeypatch):
    _Forwarder.seen, _Forwarder.script = [], []
    srv = http.server.HTTPServer(("127.0.0.1", 0), _Forwarder)
    threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True).start()
    monkeypatch.setattr(alert, "OUTBOX", str(tmp_path / "outbox"))
    yield f"http://127.0.0.1:{srv.server_address[1]}/ingest"
    srv.shutdown()


def _post(url, event=None):
    return alert.post(url, "Bearer " + "x" * 24, event or alert.build(ALERT, CFG))


def test_a_2xx_is_delivery_and_the_headers_carry_the_id_and_the_credential(forwarder):
    assert _post(forwarder) == "sent"
    seen = _Forwarder.seen[0]
    assert seen["headers"]["Content-Type"] == "application/cloudevents+json"
    assert seen["headers"]["Idempotency-Key"] == seen["body"]["id"]
    assert seen["headers"]["Authorization"].startswith("Bearer ")
    assert "Bearer" not in json.dumps(seen["body"])  # the credential is only in the header


@pytest.mark.parametrize("code,outcome", [(500, "held"), (503, "held"), (429, "held"), (401, "held"),
                                          (302, "held"), (409, "dropped"), (400, "dropped"), (422, "dropped")])  # fmt: skip
def test_transient_refusals_are_held_and_permanent_ones_dropped(forwarder, code, outcome):
    _Forwarder.script = [code]
    assert _post(forwarder) == outcome
    assert len(_Forwarder.seen) == 1  # a redirect is not followed


def test_an_unreachable_forwarder_holds_the_event_in_a_bounded_outbox(forwarder, tmp_path):
    with socket.socket() as s:  # a port nothing listens on
        s.bind(("127.0.0.1", 0))
        dead = s.getsockname()[1]
    url = f"http://127.0.0.1:{dead}/ingest"
    assert alert.post(url, "Bearer " + "x" * 24, alert.build(ALERT, CFG)) == "held"
    for i in range(alert.OUTBOX_MAX + 5):
        alert._spool({**alert.build(ALERT, CFG), "id": f"evt-{i:08d}"})
    assert len(os.listdir(alert.OUTBOX)) <= alert.OUTBOX_MAX


def test_the_outbox_is_flushed_in_order_when_the_forwarder_is_back(forwarder):
    first = {**alert.build(ALERT, CFG), "id": "evt-aaa"}
    second = {**alert.build(ALERT, CFG), "id": "evt-bbb"}
    alert._spool(second)
    alert._spool(first)
    alert.flush(forwarder, "Bearer " + "x" * 24)
    assert [s["body"]["id"] for s in _Forwarder.seen] == ["evt-aaa", "evt-bbb"]
    assert os.listdir(alert.OUTBOX) == []


def test_flush_stops_at_the_first_held_event_to_keep_order(forwarder):
    alert._spool({**alert.build(ALERT, CFG), "id": "evt-aaa"})
    alert._spool({**alert.build(ALERT, CFG), "id": "evt-bbb"})
    _Forwarder.script = [503]
    alert.flush(forwarder, "Bearer " + "x" * 24)
    assert len(_Forwarder.seen) == 1 and sorted(os.listdir(alert.OUTBOX)) == [
        "evt-aaa.json",
        "evt-bbb.json",
    ]


def test_main_reads_the_alert_file_and_the_settings_beside_the_script(
    forwarder, tmp_path, monkeypatch
):
    (tmp_path / "hnx-alert.json").write_text(json.dumps(CFG))
    (tmp_path / "hnx-alert.auth").write_text("Bearer " + "x" * 24 + "\n")
    (tmp_path / "a.json").write_text(json.dumps(ALERT))
    monkeypatch.setattr(alert, "HERE", str(tmp_path))
    assert alert.main(["x", str(tmp_path / "a.json"), "ignored", forwarder]) == 0
    assert _Forwarder.seen[0]["body"]["data"]["alert_id"] == "1700000000.654321"
    assert alert.main(["x"]) == 2
    assert alert.main(["x", str(tmp_path / "missing.json"), "k", forwarder]) == 2


# ----------------------------------------------------------------------------- index export and restore


class _Indexer(http.server.BaseHTTPRequestHandler):
    docs: ClassVar[dict] = {}
    bulk: ClassVar[list] = []
    auths: ClassVar[list] = []

    def _json(self, obj, code=200):
        self.send_response(code)
        self.end_headers()
        self.wfile.write(json.dumps(obj).encode())

    def do_GET(self):
        type(self).auths.append(self.headers.get("Authorization"))
        self._json([{"index": n} for n in sorted(type(self).docs)])

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        type(self).auths.append(self.headers.get("Authorization"))
        if self.path.startswith("/_bulk"):
            type(self).bulk.append(body.decode())
            return self._json({"errors": False})
        if self.path.startswith("/_search/scroll"):
            return self._json({"_scroll_id": "s", "hits": {"hits": []}})
        name = self.path.split("/")[1]
        hits = [{"_id": i, "_source": s} for i, s in type(self).docs[name].items()]
        self._json({"_scroll_id": "s", "hits": {"hits": hits}})

    def do_DELETE(self):
        self._json({})

    def log_message(self, *a):
        return None


@pytest.fixture
def indexer(monkeypatch):
    _Indexer.docs = {"idx-alerts-4.x-2026.11.21": {"a1": {"n": 1}, "a2": {"n": 2}},
                     "idx-alerts-4.x-2026.11.22": {}}  # fmt: skip
    _Indexer.bulk, _Indexer.auths = [], []
    srv = http.server.HTTPServer(("127.0.0.1", 0), _Indexer)
    threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True).start()
    monkeypatch.setenv("HNX_INDEXER_PASSWORD", "p" * 24)
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_export_writes_one_file_per_index_with_every_document(indexer, tmp_path, capsys):
    out = tmp_path / "ex" / "index"
    assert index.main(["export", "--url", indexer, "--dir", str(out)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert {f["key"]: f["docs"] for f in report["files"]} == {
        "idx-alerts-4.x-2026.11.21.jsonl": 2, "idx-alerts-4.x-2026.11.22.jsonl": 0}  # fmt: skip
    lines = (out / "idx-alerts-4.x-2026.11.21.jsonl").read_text().splitlines()
    assert [json.loads(x)["_id"] for x in lines] == ["a1", "a2"]
    assert stat.S_IMODE((out / "idx-alerts-4.x-2026.11.21.jsonl").stat().st_mode) == 0o600
    assert not list(out.glob(".*.tmp"))


def test_restore_loads_every_document_by_its_own_id_and_refuses_an_empty_source(
    indexer, tmp_path, capsys
):
    out = tmp_path / "ex" / "index"
    index.main(["export", "--url", indexer, "--dir", str(out)])
    capsys.readouterr()
    assert index.main(["restore", "--url", indexer, "--dir", str(out)]) == 0
    assert json.loads(capsys.readouterr().out) == {"docs": 2, "indices": 2}
    sent = "".join(_Indexer.bulk)
    assert '"_id": "a1"' in sent and '"_id": "a2"' in sent
    empty = tmp_path / "empty" / "index"
    empty.mkdir(parents=True)
    assert index.main(["restore", "--url", indexer, "--dir", str(empty)]) == 1


def test_the_password_is_only_read_from_the_environment_and_sent_as_basic_auth(
    indexer, tmp_path, monkeypatch
):
    index.main(["export", "--url", indexer, "--dir", str(tmp_path / "a" / "b")])
    assert _Indexer.auths and all(a.startswith("Basic ") for a in _Indexer.auths)
    monkeypatch.delenv("HNX_INDEXER_PASSWORD")
    assert index.main(["export", "--url", indexer, "--dir", str(tmp_path / "a" / "c")]) == 2


@pytest.mark.parametrize("bad", ["relative", "/tmp", "/a/../b/c"])
def test_an_unsafe_export_directory_is_refused(bad, indexer):
    assert index.main(["export", "--url", indexer, "--dir", bad]) == 2


def test_the_webhook_script_runs_on_the_products_python_3_10():
    # the manager's own interpreter is 3.10: no datetime.UTC (a formatter's "modernise" breaks it)
    source = (FILES / "custom-hnx-alert.py").read_text()
    assert "import UTC" not in source and "datetime.UTC" not in source
