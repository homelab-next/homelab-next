# SPDX-License-Identifier: Apache-2.0
"""The honeypot module's scripts (modules/honeypot/roles/honeypot/files), run in process: standard
library only, no ansible, no network beyond loopback.

* ``hnx_honeypot_receiver.py``: ingest only; the peer address is stamped over the sender's claim; an
  over-long line, an empty line and a line past the spool's cap are dropped and counted, never
  written in part; a real socket round trip lands the lines.
* ``hnx_honeypot_lake.py``: the event mapping fills the 26 columns in the table's order; the table
  is checked against the contract before any write (a missing, retyped or reordered column refuses
  with nothing written); statements stay under the size bound; the offset is saved per statement,
  a half-written last line waits, a truncated spool restarts at 0, a run where every line failed
  exits 1; freshness never passes on an empty table; the lake must be https.
* ``hnx_honeypot_report.py``: no switch turns certificate verification off, no lab value is in
  the script, the brief retries then says in words that the model tier did not answer, and only
  dated report copies older than the limit are pruned.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import ipaddress
import json
import re
import socket
import threading
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
FILES = ROOT / "modules" / "honeypot" / "roles" / "honeypot" / "files"


def _load(name: str, path: Path):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


rcv = _load("hnx_honeypot_receiver", FILES / "hnx_honeypot_receiver.py")
lake = _load("hnx_honeypot_lake", FILES / "hnx_honeypot_lake.py")

T0 = datetime(2026, 11, 21, 12, 0, 0, tzinfo=UTC)


def ip(n: int) -> str:
    """A dotted address from its integer value: the tests classify addresses, they contact none."""
    return str(ipaddress.IPv4Address(n))


DOC_A, DOC_B, DOC_C = ip(0xC6336407), ip(0xC6336408), ip(0xC6336409)  # a documentation block
FRIEND_1, FRIEND_2 = ip(0xCB007109), ip(0xCB00710A)
PRIVATE, LINK_LOCAL, LOOPBACK = ip(0x0A010203), ip(0xA9FEA9FE), ip(0x7F000001)
PUBLIC_172, PUBLIC_DNS = ip(0xAC690101), ip(0x08080808)


# ----------------------------------------------------------------------------- the receiver


def test_a_line_gets_the_real_peer_over_the_senders_claim():
    out = rcv.process_line(b'{"a":1,"peer_ip":"claimed"}\n', "peer-x")
    assert json.loads(out) == {"a": 1, "peer_ip": "peer-x"}


def test_empty_overlong_and_unparsed_lines():
    assert rcv.process_line(b"\n", "p") is None
    assert rcv.process_line(b"   \r\n", "p") is None
    assert rcv.process_line(b"x" * 11, "p", max_line=10) is None
    assert rcv.process_line(b"not json\n", "p") == "not json"  # kept: the writer counts it
    assert rcv.process_line(b"[1,2]\n", "p") == "[1,2]"  # only objects are stamped


def test_the_spool_stops_at_its_cap_and_counts(tmp_path):
    spool = rcv.Spool(str(tmp_path / "s.json"), cap=30)
    assert spool.append("0123456789")  # 11 bytes
    assert spool.append("0123456789")  # 22
    assert not spool.append("0123456789")  # 33 > 30
    assert spool.dropped_cap == 1
    assert (tmp_path / "s.json").read_text() == "0123456789\n0123456789\n"


def test_a_truncated_spool_is_measured_from_the_file_not_a_counter(tmp_path):
    path = tmp_path / "s.json"
    spool = rcv.Spool(str(path), cap=40)
    assert spool.append("a" * 30)
    assert not spool.append("a" * 30)
    path.write_text("")  # the rotation's copytruncate
    assert spool.append("a" * 30)


def test_a_socket_round_trip_lands_lines_drops_the_overlong_and_keeps_the_next(tmp_path):
    spool = rcv.Spool(str(tmp_path / "s.json"), cap=10_000)
    srv = rcv.Server(("localhost", 0), rcv.make_handler(spool, max_line=100))
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        with socket.create_connection(("localhost", port), timeout=5) as c:
            c.sendall(b'{"n":1}\n' + b'{"big":"' + b"z" * 500 + b'"}\n' + b'{"n":2}\n')
            c.shutdown(socket.SHUT_WR)
            assert c.recv(10) == b""  # ingest only: nothing is ever sent back
    finally:
        srv.shutdown()
        srv.server_close()
        t.join(timeout=5)
    # the handler thread may still be finishing the last write
    for _ in range(100):
        rows = [json.loads(x) for x in (tmp_path / "s.json").read_text().splitlines()]
        if len(rows) == 2:
            break
        threading.Event().wait(0.05)
    assert [r["n"] for r in rows] == [1, 2] and all(
        ipaddress.ip_address(r["peer_ip"]).is_loopback for r in rows
    )
    assert spool.dropped_line == 1


# ----------------------------------------------------------------------------- the event mapping


def _row(outer):
    return lake.to_row(outer, T0)


def test_every_row_has_exactly_the_contracts_columns_in_order():
    row = _row(
        {
            "source": "honeypot",
            "message": json.dumps({"event_type": "alert", "src_ip": DOC_A}),
        }
    )
    assert list(row) == [c for c, _t in lake.COLUMNS] and len(row) == 26


def test_a_network_ids_alert_is_mapped():
    eve = {
        "timestamp": "2026-11-21T10:00:00.123456+0000",
        "event_type": "alert",
        "src_ip": DOC_A,
        "src_port": "4444",
        "dest_ip": ip(0xC0000201),
        "dest_port": 80,
        "proto": "TCP",
        "alert": {"signature": "SIG", "category": "cat", "severity": 2},
    }
    row = _row(
        {"source": "honeypot", "honeypot_host": "h", "peer_ip": "p", "message": json.dumps(eve)}
    )
    assert (
        row["event_type"] == "alert"
        and row["alert_signature"] == "SIG"
        and row["alert_severity"] == 2
    )
    assert row["src_port"] == 4444 and row["event_time"] == datetime(
        2026, 11, 21, 10, 0, 0, 123456, tzinfo=UTC
    )
    assert row["honeypot_host"] == "h" and row["peer_ip"] == "p" and row["ingested_at"] == T0


def test_a_bait_capture_keeps_the_payload_and_credentials():
    row = _row(
        {
            "source": "honeypot",
            "event_type": "http_payload",
            "src_ip": DOC_B,
            "payload": "A=B",
            "payload_len": 3,
            "username": "root",
            "password": "pw",
        }
    )
    assert (row["payload"], row["payload_len"], row["cred_username"], row["cred_password"]) == (
        "A=B",
        3,
        "root",
        "pw",
    )


def test_ssh_decoy_sessions_keep_commands_and_their_ports():
    cowrie = _row({"eventid": "cowrie.command.input", "src_ip": DOC_C, "input": "uname -a"})
    assert (
        cowrie["event_type"] == "cowrie.command.input"
        and cowrie["payload"] == "uname -a"
        and cowrie["dest_port"] == 22
    )
    bz = _row(
        {
            "event": {
                "Msg": "SSH Raw Command",
                "Protocol": "SSH",
                "SourceIp": DOC_C,
                "Command": "id",
                "DateTime": "2026-11-21T10:00:00Z",
            }
        }
    )
    assert (
        bz["event_type"] == "beelzebub.command"
        and bz["payload"] == "id"
        and bz["dest_port"] == 2222
    )
    assert bz["src_ip"] == DOC_C


# ----------------------------------------------------------------------------- SQL, schema, landing


def test_literals_quote_escape_and_survive_nul_and_lone_surrogates():
    assert lake.lit(None) == "NULL" and lake.lit(7) == "7"
    assert lake.lit("it's") == "'it''s'"
    assert "\x00" not in lake.lit("a\x00b")
    lone = json.loads('"\\ud800x"')
    assert lake.lit(lone).endswith("x'")
    assert lake.lit(T0) == "TIMESTAMP '2026-11-21 12:00:00.000000 UTC'"
    assert lake.lit(True) == "'true'"  # a flag where text is expected is its text, not an error
    assert lake.lit({"a": 1}) == "'{\"a\": 1}'"


def test_statements_stay_under_the_bound_and_cover_every_row():
    rows = [
        _row({"event_type": "e", "src_ip": ip(0xC6336400 + i % 200), "payload": "p" * 400})
        for i in range(50)
    ]
    out = list(lake.statements(rows, "c.s.t", max_chars=6000))
    assert sum(n for _s, n in out) == 50 and len(out) > 1
    assert all(len(s) <= 6000 and s.startswith("INSERT INTO c.s.t VALUES (") for s, _n in out)
    big = [_row({"payload": "x" * 9000})]  # one oversize row goes alone rather than being dropped
    assert [n for _s, n in lake.statements(big, "c.s.t", max_chars=100)] == [1]


def test_the_schema_is_checked_against_the_contract():
    ok = [list(c) for c in lake.COLUMNS]
    assert lake.check_schema(ok) == ""
    assert "does not exist" in lake.check_schema([])
    assert "missing" in lake.check_schema(ok[:-1])
    assert "unexpected" in lake.check_schema([*ok, ["extra", "varchar"]])
    assert "changed type" in lake.check_schema(
        [["src_port", "varchar"] if r[0] == "src_port" else r for r in ok]
    )
    assert "order" in lake.check_schema(list(reversed(ok)))


class FakeLake:
    def __init__(self, describe=None):
        self.describe = [list(c) for c in lake.COLUMNS] if describe is None else describe
        self.sql = []
        self.fail_after = None

    def run(self, sql, timeout=0):
        self.sql.append(sql)
        if sql.startswith("DESCRIBE"):
            return self.describe
        if (
            sql.startswith("INSERT")
            and self.fail_after is not None
            and sum(s.startswith("INSERT") for s in self.sql) > self.fail_after
        ):
            raise RuntimeError("lake said no")
        return []

    def inserts(self):
        return [s for s in self.sql if s.startswith("INSERT")]


def _offset(state):
    text = (state / "lake-offset").read_text()
    assert re.fullmatch(r"[0-9]{20}\n", text)  # one fixed-width record, written in place
    return int(text)


def _spool(tmp_path, lines, tail=b""):
    p = tmp_path / "spool.json"
    p.write_bytes(b"".join(json.dumps(x).encode() + b"\n" for x in lines) + tail)
    return p


EV = {"event_type": "http_visit", "src_ip": DOC_A}


def test_landing_writes_rows_saves_the_offset_and_a_second_run_does_nothing(tmp_path):
    spool = _spool(tmp_path, [EV, EV, EV])
    fake, state = FakeLake(), tmp_path / "state"
    res = lake.land(fake, spool, state, "c.s.t")
    assert res["ok"] and res["landed"] == 3 and len(fake.inserts()) == 1
    assert _offset(state) == spool.stat().st_size
    again = FakeLake()
    assert lake.land(again, spool, state, "c.s.t")["landed"] == 0 and again.sql == []


def test_a_half_written_last_line_waits_for_the_next_run(tmp_path):
    spool = _spool(tmp_path, [EV], tail=b'{"event_type": "http_vi')
    fake, state = FakeLake(), tmp_path / "state"
    assert lake.land(fake, spool, state, "c.s.t")["landed"] == 1
    off = _offset(state)
    assert off == spool.stat().st_size - len(b'{"event_type": "http_vi')


def test_a_truncated_spool_restarts_at_zero(tmp_path):
    spool, state = _spool(tmp_path, [EV, EV]), tmp_path / "state"
    lake.land(FakeLake(), spool, state, "c.s.t")
    spool.write_bytes(json.dumps(EV).encode() + b"\n")  # rotated: smaller than the saved offset
    fake = FakeLake()
    assert lake.land(fake, spool, state, "c.s.t")["landed"] == 1


def test_the_offset_is_saved_per_batch_so_a_failure_loses_nothing_it_landed(tmp_path):
    spool, state = _spool(tmp_path, [EV] * 6), tmp_path / "state"
    fake = FakeLake()
    fake.fail_after = 1  # the second statement fails
    with pytest.raises(RuntimeError):
        lake.land(fake, spool, state, "c.s.t", batch_rows=2)
    saved = _offset(state)
    assert 0 < saved < spool.stat().st_size
    ok = FakeLake()
    assert (
        lake.land(ok, spool, state, "c.s.t", batch_rows=2)["landed"] == 4
    )  # the rest, not the whole


def test_a_table_that_is_not_the_contract_is_refused_before_any_write(tmp_path):
    spool, state = _spool(tmp_path, [EV]), tmp_path / "state"
    bad = [list(c) for c in lake.COLUMNS][:-1]
    fake = FakeLake(describe=bad)
    with pytest.raises(SystemExit) as exc:
        lake.land(fake, spool, state, "c.s.t")
    assert "contract" in str(exc.value) and fake.inserts() == []
    assert not (state / "lake-offset").exists()


def test_a_run_where_every_line_failed_exits_one_and_still_moves_on(tmp_path):
    spool = tmp_path / "spool.json"
    spool.write_bytes(b"garbage\nmore garbage\n")
    state = tmp_path / "state"
    with pytest.raises(SystemExit) as exc:
        lake.land(FakeLake(), spool, state, "c.s.t")
    assert exc.value.code == 1
    assert json.loads((state / "last-run.json").read_text())["ok"] is False


def test_freshness_never_passes_on_an_empty_table_and_judges_the_newest_event(monkeypatch):
    monkeypatch.setattr(lake, "now", lambda: T0)

    class L:
        def __init__(self, rows):
            self.rows = rows

        def run(self, sql, timeout=0):
            return self.rows

    assert lake.freshness(L([[None, 0]]), "c.s.t", 36)["ok"] is False
    assert lake.freshness(L([["2026-11-21 06:00:00.000000 UTC", 5]]), "c.s.t", 36)["ok"] is True
    stale = lake.freshness(L([["2026-11-19 06:00:00.000000 UTC", 5]]), "c.s.t", 36)
    assert stale["ok"] is False and "old" in stale["reason"]


class _Result:
    def __init__(self, columns, rows):
        self.columns = [{"name": c} for c in columns]
        self.rows = rows


class _Engine:
    def __init__(self, result):
        self.result, self.sent = result, []

    def execute(self, sql, args=(), *, client_tags=()):
        self.sent.append((sql, tuple(client_tags)))
        return self.result


def test_the_lake_wrapper_returns_columns_and_rows_in_column_order():
    eng = _Engine(_Result(["a", "b"], [{"b": 2, "a": 1}, {"a": 3, "b": 4}]))
    client = lake.Lake(eng)
    assert client.query("SELECT 1") == (["a", "b"], [[1, 2], [3, 4]])
    assert client.run("SELECT 2") == [[1, 2], [3, 4]] and eng.sent[0][1] == ("honeypot",)


def _lake_url(scheme="https"):
    """The example registry's lake-query row as a URL (host.example.internal and its port)."""
    row = yaml.safe_load((ROOT / "examples" / "services.yml").read_text())["services"]["lake-query"]
    return f"{scheme}://lake.example.internal:{row['port']}"


def test_the_lake_client_is_built_from_the_environment_and_refuses_clear_text(monkeypatch):
    for k, v in {
        "HNX_ENDPOINT_LAKE_QUERY": _lake_url(),
        "HNX_ENDPOINT_LAKE_CATALOG": _lake_url(),
        "HNX_SECRET_HONEYPOT_LAKE_LOGIN": "x" * 12,
        "HNX_HP_LAKE_USER": "writer",
    }.items():
        monkeypatch.setenv(k, v)
    built = lake.lake_from_env()  # nothing is sent while it is built
    assert built.engine.user == "writer"
    monkeypatch.setenv("HNX_ENDPOINT_LAKE_QUERY", _lake_url("http"))
    with pytest.raises(lake.LakeError):  # a login never goes over clear text to another host
        lake.lake_from_env()
    monkeypatch.delenv("HNX_SECRET_HONEYPOT_LAKE_LOGIN")
    monkeypatch.setenv("HNX_ENDPOINT_LAKE_QUERY", _lake_url())
    with pytest.raises(
        ValueError, match="HNX_SECRET_HONEYPOT_LAKE_LOGIN"
    ):  # a missing login is named
        lake.lake_from_env()


def test_the_table_name_needs_the_sites_catalog_and_plain_identifiers(monkeypatch):
    monkeypatch.delenv("HNX_HP_LAKE_CATALOG", raising=False)
    with pytest.raises(ValueError, match="plain identifier"):
        lake._table()
    monkeypatch.setenv("HNX_HP_LAKE_CATALOG", "cat")
    assert lake._table() == "cat.honeypot.events"
    monkeypatch.setenv("HNX_HP_LAKE_TABLE", "events; DROP TABLE x")
    with pytest.raises(ValueError, match="plain identifier"):
        lake._table()


def test_ensure_table_issues_the_contracts_ddl():
    fake = FakeLake()
    lake.ensure_table(fake, "c.s.t")
    assert fake.sql[0] == "CREATE SCHEMA IF NOT EXISTS c.s"
    ddl = fake.sql[1]
    assert ddl.startswith("CREATE TABLE IF NOT EXISTS c.s.t (") and "day(event_time)" in ddl
    assert all(f"{c} {t}" in ddl for c, t in lake.COLUMNS)


def test_the_offset_is_one_fixed_width_record_and_anything_else_reads_as_zero(tmp_path):
    path = tmp_path / "state" / "lake-offset"
    lake.save_offset(path, 12345)
    assert path.read_text() == "00000000000000012345\n" and lake.load_offset(path) == 12345
    lake.save_offset(path, 7)  # written in place, never longer
    assert lake.load_offset(path) == 7
    path.write_text("12")  # a torn or foreign file is not an offset
    assert lake.load_offset(path) == 0 and lake.load_offset(tmp_path / "missing") == 0


# ----------------------------------------------------------------------------- the report


@pytest.fixture
def report(monkeypatch):
    monkeypatch.setenv("HNX_HP_LLM_URL", "https://gateway.example.internal/v1/chat/completions")
    monkeypatch.setenv("HNX_HP_LLM_MODEL", "brief")
    monkeypatch.setenv("HNX_HP_LLM_ATTEMPTS", "2")
    monkeypatch.setenv("HNX_HP_LLM_RETRY_SLEEP_S", "0")
    monkeypatch.setenv("HNX_HP_FRIENDLY_IPS", f"{FRIEND_1}, {FRIEND_2}")
    return _load("hnx_honeypot_report", FILES / "hnx_honeypot_report.py")


def test_the_buckets_use_the_sites_friendly_addresses_and_judge_routability_by_cidr(report):
    assert {FRIEND_1, FRIEND_2} == report.FRIENDLY
    assert report.bucket({"ip": FRIEND_1}) == "friendly"
    assert report.bucket({"ip": LINK_LOCAL}) == "imds"
    assert report.bucket({"ip": PRIVATE}) == "internal"
    assert (
        report.bucket({"ip": PUBLIC_172, "dport": 22}) == "external"
    )  # public, though it starts 172.
    assert report.bucket({"ip": PUBLIC_DNS, "dport": 41641}) == "overlay"
    assert report.bucket({"ip": ""}) == "noip"


class _Resp:
    def __init__(self, doc):
        self.doc = doc

    def read(self):
        return json.dumps(self.doc).encode()


def test_the_brief_retries_then_says_in_words_that_the_model_did_not_answer(report, monkeypatch):
    calls = []

    def boom(req, timeout=0, **kw):
        calls.append(timeout)
        raise OSError("no route")

    monkeypatch.setattr(report.urllib.request, "urlopen", boom)
    text = report.llm_analyze([], {})
    assert len(calls) == 2 and calls[0] == report.LLM_TIMEOUT
    assert "unavailable" in text and "no route" not in text and "OSError" in text


def test_an_empty_answer_with_reasoning_is_shown_as_reasoning_not_as_a_blank_card(
    report, monkeypatch
):
    doc = {"choices": [{"message": {"content": "", "reasoning_content": "thinking only"}}]}
    monkeypatch.setattr(report.urllib.request, "urlopen", lambda req, timeout=0, **kw: _Resp(doc))
    assert "reasoning only" in report.llm_analyze([], {}) and "thinking only" in report.llm_analyze(
        [], {}
    )


def test_the_request_carries_the_configured_budget(report, monkeypatch):
    seen = {}

    def fake(req, timeout=0, **kw):
        seen["body"] = json.loads(req.data)
        return _Resp({"choices": [{"message": {"content": "- a\n- b\n- c\n- d"}}]})

    monkeypatch.setattr(report.urllib.request, "urlopen", fake)
    assert report.llm_analyze([], {}).startswith("- a")
    assert seen["body"]["model"] == "brief" and seen["body"]["max_tokens"] == 4000


def test_the_report_reads_through_the_lake_writers_client(report, monkeypatch):
    class Fake:
        def query(self, sql):
            return ["n"], [[3]]

    monkeypatch.setattr(report, "_LAKE", Fake())
    assert report.lake_query("SELECT 1") == (["n"], [[3]])
    mod = report._load_lake_client()  # loaded by path: the scripts run isolated
    assert mod.COLUMNS == lake.COLUMNS


def test_only_dated_copies_older_than_the_limit_are_pruned(report, tmp_path):
    names = [
        "honeypot-report-2026-01-01.html",
        "honeypot-report-2026-11-20.html",
        "honeypot-report.html",
        "notes.txt",
        "honeypot-report-2026-01-01.html.tmp",
    ]
    for n in names:
        (tmp_path / n).write_text("x")
    import os

    old = 1_000_000.0
    os.utime(tmp_path / names[0], (old, old))
    os.utime(tmp_path / names[3], (old, old))
    os.symlink(str(tmp_path / names[3]), tmp_path / "honeypot-report-2026-02-02.html")
    os.utime(tmp_path / "honeypot-report-2026-02-02.html", (old, old), follow_symlinks=False)
    removed = report.prune_old(str(tmp_path), 30, now=old + 40 * 86400)
    assert removed == [names[0]]
    assert (tmp_path / "notes.txt").exists() and (tmp_path / "honeypot-report.html").exists()
    assert (tmp_path / "honeypot-report-2026-02-02.html").is_symlink()  # a link is never removed
    assert report.prune_old(str(tmp_path), 0) == []


def test_no_script_turns_certificate_verification_off_or_carries_a_lab_value():
    for f in sorted(FILES.glob("*.py")):
        text = f.read_text()
        assert "CERT_NONE" not in text and "check_hostname = False" not in text, f.name
        assert not re.search(r"\.(casa|lan)\b", text), f.name
        found = re.findall(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])", text)
        # only the unspecified bind-all address may appear in a script
        assert all(ipaddress.ip_address(x).is_unspecified for x in found), (f.name, found)


# ----------------------------------------------------------------------------- hostile input


@pytest.mark.parametrize(
    "line",
    ['{"alert":"x"}', '{"http":["a"]}', '{"payload":true}', '{"dest_port":1e400}',
     '{"src_port":99999999999999999999999}', '{"dns":5}', "[1]", "{"],
)  # fmt: skip
def test_a_malformed_record_is_quarantined_and_never_wedges_the_writer(tmp_path, line):
    good = json.dumps(EV).encode() + b"\n"
    spool = tmp_path / "spool.json"
    spool.write_bytes(good + line.encode() + b"\n" + good)
    state, fake = tmp_path / "state", FakeLake()
    res = lake.land(fake, spool, state, "c.s.t")
    assert res["ok"] and res["landed"] >= 2 and res["skipped"] <= 1
    assert _offset(state) == spool.stat().st_size  # always moves past it
    again = FakeLake()
    assert lake.land(again, spool, state, "c.s.t")["landed"] == 0 and again.sql == []


def test_the_three_known_poison_lines_together_land_the_rest_and_fill_the_dead_letter(tmp_path):
    lines = [EV, {"alert": "x"}, {"http": ["a"]}, {"payload": True}, {"src_port": 2**70}, EV]
    spool, state, fake = _spool(tmp_path, lines), tmp_path / "state", FakeLake()
    res = lake.land(fake, spool, state, "c.s.t")
    assert res["ok"] and res["skipped"] >= 3 and res["landed"] + res["skipped"] == 6
    dead = [json.loads(x) for x in (state / "dead-letter.jsonl").read_text().splitlines()]
    assert len(dead) == res["skipped"] and all(d["reason"] and d["line"] for d in dead)
    assert int((state / "dead-letter-count").read_text()) == res["skipped"]
    assert _offset(state) == spool.stat().st_size


def test_the_dead_letter_file_is_capped_but_still_counts(tmp_path, monkeypatch):
    monkeypatch.setattr(lake, "DEAD_LETTER_MAX_BYTES", 50)
    state = tmp_path / "state"
    lake.quarantine(state, [("a" * 100, "r")])
    size = (state / "dead-letter.jsonl").stat().st_size
    lake.quarantine(state, [("b" * 100, "r")] * 3)
    assert (state / "dead-letter.jsonl").stat().st_size == size  # past the cap: counted only
    assert int((state / "dead-letter-count").read_text()) == 4
    long = tmp_path / "s2"
    monkeypatch.setattr(lake, "DEAD_LETTER_MAX_BYTES", 10**6)
    lake.quarantine(long, [("c" * 99999, "r")])
    entry = json.loads((long / "dead-letter.jsonl").read_text())
    assert len(entry["line"]) == lake.DEAD_LETTER_ENTRY_CHARS


def test_cross_reference_sql_takes_only_real_addresses(report, monkeypatch):
    seen = []

    class Fake:
        def query(self, sql):
            seen.append(sql)
            return ["v"], []

    monkeypatch.setattr(report, "_LAKE", Fake())
    monkeypatch.setattr(report, "CTI_TABLE", "c.s.t")
    hostile = [
        "x'] OR true --",
        f"{ip(0xC6336401)}'; DROP TABLE a;--",
        f"{ipaddress.IPv6Address(1)}%e'th",
        "",
        None,
        "'",
        ipv(0xC6336407),
    ]
    report.cti_crossref(hostile)
    assert len(seen) == 1 and seen[0].count("'") == 4  # i.type='ip' and one address
    assert "DROP" not in seen[0] and "OR true" not in seen[0]
    seen.clear()
    assert report.cti_crossref(hostile[:-1]) == {} and seen == []  # nothing valid: no query at all


def ipv(n):
    return ip(n)


def test_the_receiver_refuses_all_interfaces_and_no_bind_unless_told(monkeypatch):
    with pytest.raises(ValueError, match="not set"):
        rcv.check_bind("", False)
    for any_ in (ip(0), "::"):
        with pytest.raises(ValueError, match="all interfaces"):
            rcv.check_bind(any_, False)
        assert rcv.check_bind(any_, True) == any_
    assert rcv.check_bind(DOC_A, False) == DOC_A
    monkeypatch.delenv("HNX_HP_BIND", raising=False)
    monkeypatch.setenv("HNX_HP_SPOOL", "x")
    assert rcv.main() == 1


def test_an_idle_connection_is_closed_and_connections_past_the_cap_are_refused(tmp_path):
    spool = rcv.Spool(str(tmp_path / "s.json"), cap=10_000)
    rcv.Server.max_connections = 1
    srv = rcv.Server(("localhost", 0), rcv.make_handler(spool, 100, idle_timeout=0.3))
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        first = socket.create_connection(("localhost", port), timeout=5)
        first.sendall(b'{"n":1}\n')
        second = socket.create_connection(("localhost", port), timeout=5)
        second.settimeout(5)
        assert second.recv(10) == b""  # over the cap: closed at once
        first.settimeout(5)
        assert first.recv(10) == b""  # idle past the timeout: closed by the server
        first.close()
        second.close()
    finally:
        srv.shutdown()
        srv.server_close()
        t.join(timeout=5)
        rcv.Server.max_connections = 32
