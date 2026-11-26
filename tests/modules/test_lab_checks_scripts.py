# SPDX-License-Identifier: Apache-2.0
"""The scripts of module lab-checks against loopback fakes (nothing leaves the machine):

* ``hnx-lab-probe``: an HTTP status, a TCP connect, a DNS answer, a metrics value and a last-run record each
  pass, fail or cannot be measured as the runner's exit semantics say;
* ``hnx-lab-notify``: one POST with the token from a file, a failed delivery exits non-zero;
* the whole loop (the positive control): a deliberately broken criterion pages ONCE, a standing red is not
  re-paged, and a recovery pages once, through ``hnx invariants run`` and the pager.
"""

from __future__ import annotations

import http.server
import importlib.machinery
import importlib.util
import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import ClassVar

import pytest

ROOT = Path(__file__).resolve().parents[2]
FILES = ROOT / "modules" / "lab-checks" / "roles" / "lab_checks" / "files"
LOOP = ".".join(["127", "0", "0", "1"])
ADDR = ".".join(["198", "51", "100", "7"])  # documentation range, built here
OTHER = ".".join(["198", "51", "100", "8"])


def _load(name: str, path: Path):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


probe = _load("hnx_lab_probe", FILES / "hnx-lab-probe")
notify = _load("hnx_lab_notify", FILES / "hnx-lab-notify")


class _Handler(http.server.BaseHTTPRequestHandler):
    log: ClassVar[list] = []
    routes: ClassVar[dict] = {}

    def log_message(self, *a):
        pass

    def _answer(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b""
        _Handler.log.append((self.command, self.path, dict(self.headers), body))
        status, text = _Handler.routes.get(self.path.split("?")[0], (404, b""))
        self.send_response(status)
        self.send_header("Content-Length", str(len(text)))
        self.end_headers()
        self.wfile.write(text)

    do_GET = do_POST = _answer


@pytest.fixture
def server():
    _Handler.log = []
    _Handler.routes = {}
    srv = http.server.ThreadingHTTPServer((LOOP, 0), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://{LOOP}:{srv.server_address[1]}"
    srv.shutdown()


def test_http_probe_passes_on_the_wanted_status_and_fails_otherwise(server, capsys):
    _Handler.routes = {"/ok": (200, b"x"), "/down": (503, b""), "/moved": (302, b"")}
    assert probe.main(["http", server + "/ok"]) == 0
    assert probe.main(["http", server + "/down"]) == 1
    assert "HTTP 503" in capsys.readouterr().out
    assert (
        probe.main(["http", server + "/moved", "--status", "302"]) == 0
    )  # a redirect is not followed
    assert probe.main(["http", server + "/ok", "--status", "204"]) == 1


def test_http_probe_fails_when_nothing_answers_and_cannot_measure_a_bad_url():
    with socket.socket() as s:
        s.bind((LOOP, 0))
        port = s.getsockname()[1]
    assert probe.main(["http", f"http://{LOOP}:{port}/", "--timeout", "2"]) == 1
    assert probe.main(["http", "ftp://example.invalid/"]) == 100
    assert probe.main(["nonsense"]) == 100


def test_tcp_probe():
    with socket.socket() as s:
        s.bind((LOOP, 0))
        s.listen(1)
        assert probe.main(["tcp", LOOP, str(s.getsockname()[1])]) == 0
        port = s.getsockname()[1]
    assert probe.main(["tcp", LOOP, str(port), "--timeout", "2"]) == 1


def _dns_server(answers: list[str], rcode: int = 0):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((LOOP, 0))
    sock.settimeout(5)

    def serve():
        try:
            data, addr = sock.recvfrom(512)
        except OSError:
            return
        q = data[12:]
        reply = data[:2] + struct.pack(">HHHHH", 0x8180 | rcode, 1, len(answers), 0, 0) + q
        for a in answers:
            reply += b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + socket.inet_aton(a)
        sock.sendto(reply, addr)

    threading.Thread(target=serve, daemon=True).start()
    return sock


def test_dns_answers_are_parsed_and_judged():
    for answers, rcode, expect, want in [
        ([ADDR], 0, None, 0),
        ([ADDR], 0, ADDR, 0),
        ([ADDR], 0, OTHER, 1),
        ([], 3, None, 1),  # NXDOMAIN
    ]:
        sock = _dns_server(answers, rcode)
        args = ["dns", LOOP, "host.example.internal", "--port", str(sock.getsockname()[1])]
        assert probe.main(args + (["--expect", expect] if expect else [])) == want, (answers, rcode)
        sock.close()


def test_dns_probe_fails_on_silence():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:  # nobody reads it
        s.bind((LOOP, 0))
        args = [
            "dns",
            LOOP,
            "a.example.internal",
            "--timeout",
            "1",
            "--port",
            str(s.getsockname()[1]),
        ]
        assert probe.main(args) == 1


def _prom(result):
    return json.dumps(
        {"status": "success", "data": {"resultType": "vector", "result": result}}
    ).encode()


def test_prom_probe_compares_the_summed_value_and_distinguishes_empty_from_unreachable(server):
    _Handler.routes = {
        "/api/v1/query": (
            200,
            _prom([{"metric": {}, "value": [0, "2"]}, {"metric": {}, "value": [0, "1"]}]),
        )
    }
    assert probe.main(["prom", server, "up", "--eq", "3"]) == 0
    assert probe.main(["prom", server, "up", "--max", "2"]) == 1
    assert probe.main(["prom", server, "up", "--min", "3"]) == 0
    _Handler.routes["/api/v1/query"] = (200, _prom([]))
    assert probe.main(["prom", server, "up == 0", "--eq", "0"]) == 1  # no series is not zero
    assert probe.main(["prom", server, "up == 0", "--eq", "0", "--empty", "zero"]) == 0
    _Handler.routes["/api/v1/query"] = (
        200,
        json.dumps({"status": "error", "error": "bad"}).encode(),
    )
    assert (
        probe.main(["prom", server, "x", "--eq", "0"]) == 100
    )  # the metrics API refused: cannot measure
    with socket.socket() as s:
        s.bind((LOOP, 0))
        dead = f"http://{LOOP}:{s.getsockname()[1]}"
    assert probe.main(["prom", dead, "up", "--eq", "0", "--timeout", "2"]) == 100


def _record(d: Path, job: str, **kw):
    rec = {"running": False, "result": "success", "exit_status": "0",
           "started_at": "2026-11-22T10:00:00Z", "finished_at": "2026-11-22T10:00:05Z"}  # fmt: skip
    rec.update(kw)
    (d / (job.replace(":", "%3A").replace("/", "%2F") + ".json")).write_text(json.dumps(rec))


def test_lastrun_probe(tmp_path):
    now = 1_795_000_000  # 2026-11-18, so every record above is old unless rewritten
    import calendar

    now = calendar.timegm(time.strptime("2026-11-22T11:00:00Z", "%Y-%m-%dT%H:%M:%SZ"))
    _record(tmp_path, "timer:a/ok")
    _record(tmp_path, "timer:a/failed", result="failure", exit_status="1")
    _record(tmp_path, "timer:a/running", running=True, started_at="2026-11-22T10:59:00Z")
    _record(tmp_path, "timer:a/stuck", running=True, started_at="2026-11-22T01:00:00Z")
    (tmp_path / "timer%3Aa%2Fbroken.json").write_text("{not json")

    def run(job, age=7200):
        return probe.main(["lastrun", str(tmp_path), job, str(age), "--now", str(now)])

    assert run("timer:a/ok") == 0
    assert run("timer:a/ok", 600) == 1  # a success, but too long ago
    assert run("timer:a/failed") == 1
    assert run("timer:a/running") == 0  # in progress and young: not a failure
    assert run("timer:a/stuck") == 1
    assert run("timer:a/never") == 1
    assert run("timer:a/broken") == 100


def _lake_table_metadata(**overrides):
    # a minimal lake-catalog REST `loadTable` response
    meta = {
        "format-version": 2,
        "last-updated-ms": int(time.time() * 1000),
        "current-snapshot-id": 1_234_567,
        "snapshots": [{"snapshot-id": 1_234_567, "timestamp-ms": int(time.time() * 1000)}],
        "statistics": [{"snapshot-id": 1_234_567, "statistics-path": "s3://w/.../file.puffin"}],
    }
    meta.update(overrides)
    return json.dumps({"metadata-location": "s3://w/ns/t.metadata.json",
                       "metadata": meta}).encode()


def test_lake_table_fresh_probe_passes_within_the_window_and_fails_past_it(server):
    # reference-catalog style: base ends in "/v1", probe appends "/namespaces/<ns>/tables/<t>"
    base = server + "/v1"
    now_s = time.time()
    last_fresh = int((now_s - 60) * 1000)   # 1 min ago
    last_stale = int((now_s - 7200) * 1000)  # 2 h ago
    _Handler.routes = {
        "/v1/namespaces/soc/tables/raw_archive": (
            200, _lake_table_metadata(**{"last-updated-ms": last_fresh}))
    }
    assert probe.main(
        ["lake-table-fresh", base, "soc", "raw_archive", "--max-age-s", "3600"]
    ) == 0
    _Handler.routes["/v1/namespaces/soc/tables/raw_archive"] = (
        200, _lake_table_metadata(**{"last-updated-ms": last_stale}))
    assert probe.main(
        ["lake-table-fresh", base, "soc", "raw_archive", "--max-age-s", "3600"]
    ) == 1


def test_lake_table_fresh_probe_is_fail_on_an_unknown_table_and_cant_on_network_error(server):
    base = server + "/v1"
    assert probe.main(
        ["lake-table-fresh", base, "soc", "nonesuch", "--max-age-s", "3600"]
    ) == 1   # 404 is a failure (not "cant measure")
    with socket.socket() as s:
        s.bind((LOOP, 0))
        dead = f"http://{LOOP}:{s.getsockname()[1]}/v1"
    assert probe.main(
        ["lake-table-fresh", dead, "soc", "raw_archive", "--max-age-s", "3600", "--timeout", "2"]
    ) == 100


def test_lake_table_fresh_probe_refuses_an_unsafe_namespace_or_table(server):
    base = server + "/v1"
    assert probe.main(
        ["lake-table-fresh", base, "SOC", "raw_archive", "--max-age-s", "3600"]
    ) == 100
    assert probe.main(
        ["lake-table-fresh", base, "soc", "raw archive", "--max-age-s", "3600"]
    ) == 100


def test_lake_table_probe_works_against_a_named_warehouse_prefix(server):
    # a named-warehouse catalog mounts each warehouse under /catalog/v1/<warehouse-id>:
    # a non-"/v1" base works too.
    base = server + "/catalog/v1/01a2097c-6262-7575-96f7-6db9b51cd1d9"
    now_s = time.time()
    _Handler.routes = {
        "/catalog/v1/01a2097c-6262-7575-96f7-6db9b51cd1d9/namespaces/soc/tables/raw_archive": (
            200, _lake_table_metadata(**{"last-updated-ms": int((now_s - 60) * 1000)}))
    }
    assert probe.main(
        ["lake-table-fresh", base, "soc", "raw_archive", "--max-age-s", "3600"]
    ) == 0


def test_lake_table_stats_probe_fails_on_missing_stats_for_the_current_snapshot(server):
    base = server + "/v1"
    _Handler.routes = {
        "/v1/namespaces/soc/tables/raw_archive": (200, _lake_table_metadata()),
        "/v1/namespaces/soc/tables/no_stats": (
            200, _lake_table_metadata(statistics=[])),
        "/v1/namespaces/soc/tables/empty_table": (
            200, _lake_table_metadata(**{"current-snapshot-id": None, "snapshots": [],
                                         "statistics": []})),
        "/v1/namespaces/soc/tables/stale_stats": (
            200, _lake_table_metadata(statistics=[{"snapshot-id": 99,
                                                   "statistics-path": "s3://w/.../old.puffin"}])),
    }
    assert probe.main(["lake-table-stats", base, "soc", "raw_archive"]) == 0
    assert probe.main(["lake-table-stats", base, "soc", "no_stats"]) == 1
    assert probe.main(["lake-table-stats", base, "soc", "stale_stats"]) == 1
    # an empty table is not a failure: nothing to collect
    assert probe.main(["lake-table-stats", base, "soc", "empty_table"]) == 0


def test_notify_posts_the_message_with_the_token_and_a_failed_delivery_exits_non_zero(
    server, tmp_path
):
    tok = tmp_path / "token"
    tok.write_text("tk-test-fake\n")
    cfg = tmp_path / "notify.json"
    cfg.write_text(json.dumps({"url": server, "topic": "lab checks", "token_file": str(tok)}))
    _Handler.routes = {"/lab%20checks": (200, b"{}")}
    assert notify.main(["--config", str(cfg), "Invariant newly broken", "N-01 fail: x"]) == 0
    method, path, headers, body = _Handler.log[-1]
    assert (method, path, body) == ("POST", "/lab%20checks", b"N-01 fail: x")
    assert headers["Authorization"] == "Bearer tk-test-fake" and headers["Priority"] == "4"
    _Handler.routes = {"/lab%20checks": (500, b"")}
    assert notify.main(["--config", str(cfg), "Invariant recovered", "N-01 recovered"]) == 1
    assert notify.main(["--config", str(tmp_path / "missing.json"), "t", "b"]) == 2
    assert notify.main(["only-one-arg"]) == 2


REGISTER = """\
pillars:
- {letter: N, title: Lab}
criteria:
- id: N-01
  owner: lab-checks
  statement: A deliberately breakable criterion.
  evidence: auto
  observable: test ! -e SWITCH
  expected: the switch file is absent
  remediation: remove the switch file
- id: N-02
  owner: lab-checks
  statement: A criterion that always holds.
  evidence: auto
  observable: echo fine
  expected: fine
  remediation: nothing to do, it always holds
"""


def test_a_deliberately_broken_criterion_pages_once_stays_quiet_while_red_and_pages_its_recovery(
    server, tmp_path
):
    tok = tmp_path / "token"
    tok.write_text("tk-test-fake\n")
    cfg = tmp_path / "notify.json"
    cfg.write_text(json.dumps({"url": server, "topic": "lab-checks", "token_file": str(tok)}))
    _Handler.routes = {"/lab-checks": (200, b"{}")}
    switch = tmp_path / "switch"
    reg = tmp_path / "invariants.yml"
    reg.write_text(REGISTER.replace("SWITCH", str(switch)))
    env = dict(os.environ, PYTHONPATH=str(ROOT))

    def run():
        n = len(_Handler.log)
        r = subprocess.run(
            [sys.executable, "-m", "homelabnext.invariants", "run", str(reg),
             "--root", str(tmp_path), "--out", str(tmp_path / "results.json"),
             "--state", str(tmp_path / "state.json"),
             "--notify-cmd", f"{FILES / 'hnx-lab-notify'} --config {cfg}", "--notify-ceiling", "red"],
            capture_output=True, text=True, env=env, check=False,
        )  # fmt: skip
        return r, [b.decode() for _, _, _, b in _Handler.log[n:]]

    r, pages = run()  # all green: no page
    assert r.returncode == 0 and pages == [], r.stdout + r.stderr
    switch.write_text("break")  # the deliberately broken criterion
    r, pages = run()
    assert r.returncode == 1 and len(pages) == 1 and pages[0].startswith("N-01 fail"), (
        r.stdout,
        pages,
    )
    r, pages = run()  # still red: not re-paged
    assert r.returncode == 1 and pages == []
    switch.unlink()
    r, pages = run()  # recovered: once
    assert r.returncode == 0 and pages == ["N-01 recovered"], (r.stdout, r.stderr, pages)
    r, pages = run()
    assert r.returncode == 0 and pages == []
