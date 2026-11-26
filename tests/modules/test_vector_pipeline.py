# SPDX-License-Identifier: Apache-2.0
"""The log-pipeline provider's code (modules/vector/roles/vector/files): the enrichment sidecar and the OCSF
remap, proved without any container.

* The label rules the sidecar runs are the core's own files: the role copies exactly the closure of
  ``homelabnext.logpipeline`` (standard library only), and a deployed layout built from those
  copies labels a corpus exactly as the core does.
* The sidecar takes the observed address from the collector's own evidence (the connection's peer,
  the address the manager recorded for an agent, the client a trusted router recorded), never from
  the event, and a self-set label of any spelling changes nothing (the evasion fixtures run
  through it, then the detection rule).
* A route the configuration does not hold, a line that is not an envelope, and a table that does
  not read are refused or kept out, never guessed; a line that does not parse is archived whole.
* The OCSF remap's goldens (an agent stream, router CEF, sensor alerts and flows), severity from
  the source's own grade through OCSF's ``severity_id`` and never a copied rule level, the rows of
  the pinned classes validating against their lake schemas, and ids that are stable.
"""

from __future__ import annotations

import ast
import contextlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

MODULE_CODE = (
    Path(__file__).resolve().parents[2] / "modules" / "vector" / "roles" / "vector" / "files"
)
sys.path.insert(0, str(MODULE_CODE))  # the module's own package, as the deployment puts it

from hnx_modules.vector import log_pipeline as adapter
from hnx_modules.vector import ocsf, sidecar

from conformance.protocols.log_pipeline import Observed
from conformance.suites import log_pipeline as suite
from homelabnext import tlp
from homelabnext.conform.core import run_checks
from homelabnext.detections.runner import FakeGenericEngine
from homelabnext.detections.sigma import load_mapping, load_rules
from homelabnext.lake import rows as lake_rows
from homelabnext.lake import tables as lake_tables
from homelabnext.lake import validate as lake_validate
from homelabnext.logpipeline import RuntimeTable, SourceTable, enrich, table_doc
from homelabnext.logpipeline import tlp_labels as tl
from tests.modules.vector_addrs import (
    DEST,
    DOC_A,
    DOC_B,
    LAKE,
    MODEL,
    OTHER_DEST,
    OTHER_PEER,
    ROUTER_ADDR,
    UNLISTED,
)

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "modules" / "vector"
GOLDEN = Path(__file__).resolve().parent / "golden" / "log-pipeline"
EVASION = sorted((ROOT / "tests" / "logpipeline" / "evasion").glob("*.json"))
EXAMPLE_TABLE = ROOT / "examples" / "log-pipeline" / "runtime-labels.json"
DET = ROOT / "detections"
NOW = datetime(2026, 11, 22, 12, 0, tzinfo=UTC)

ROWS = [
    (MODEL, "model", "guest:infer-core", "cap:inference"),
    (LAKE, "none", "guest:lake-core", "cap:lake-query"),
]
ROUTER = ROUTER_ADDR  # a documentation address standing for the trusted router


def tables() -> tuple[RuntimeTable, SourceTable]:
    rt = RuntimeTable.from_doc(table_doc(ROWS))
    st = SourceTable.from_doc(
        tl.table_doc(
            [("vector/siem-alerts", tlp.Label.AMBER, False),
             ("vector/siem-archives", tlp.Label.GREEN, False)]
        )
    )  # fmt: skip
    return rt, st


def config() -> dict:
    return sidecar.load_config(
        {
            "schema": sidecar.CONFIG_SCHEMA,
            "routes": {
                "vector/siem-alerts": {"kind": "siem", "observe": "agent"},
                "vector/siem-archives": {"kind": "siem", "observe": "agent"},
                "vector/syslog-udp": {"kind": "syslog", "observe": "recorded", "trusted": [ROUTER]},
                "vector/sensor-stream": {"kind": "sensor", "observe": "recorded"},
            },
            "detection_ids": {"5712": "det:ssh-auth-failure-burst"},
        }
    )


def run(envelope, counters=None) -> list[dict]:
    rt, st = tables()
    lines = sidecar.handle_line(json.dumps(envelope), config(), rt, st, NOW, counters)
    return [json.loads(line) for line in lines]


# ---------------------------------------------------------------- the rules are the core's own
def _closure() -> set[str]:
    """Every ``homelabnext`` file the label rules import, from the package's ``__init__``."""
    seen: set[Path] = set()
    todo = [ROOT / "homelabnext" / "logpipeline" / "__init__.py"]
    while todo:
        path = todo.pop()
        if path in seen:
            continue
        seen.add(path)
        pkg = path.parent.relative_to(ROOT).as_posix().replace("/", ".")
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            mods = []
            if isinstance(node, ast.ImportFrom):
                base = node.module or ""
                if node.level:
                    base = ".".join(
                        pkg.split(".")[: len(pkg.split(".")) - node.level + 1]
                        + ([base] if base else [])
                    )
                mods = [base] + [f"{base}.{a.name}" for a in node.names]
            elif isinstance(node, ast.Import):
                mods = [a.name for a in node.names]
            for m in mods:
                if m == "homelabnext" or not m.startswith("homelabnext."):
                    continue
                rel = ROOT / m.replace(".", "/")
                for cand in (rel.with_suffix(".py"), rel / "__init__.py"):
                    if cand.is_file():
                        todo.append(cand)
    return {p.relative_to(ROOT / "homelabnext").as_posix() for p in seen}


def _stdlib_only(path: Path) -> list[str]:
    bad = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        names = []
        if isinstance(node, ast.Import):
            names = [a.name.split(".")[0] for a in node.names]
        elif isinstance(node, ast.ImportFrom) and not node.level:
            names = [(node.module or "").split(".")[0]]
        bad += [n for n in names if n not in sys.stdlib_module_names and n != "homelabnext"]
    return bad


CODE = MODULE / "roles" / "vector" / "files" / "hnx_modules" / "vector"


def _code_files() -> list[str]:
    """The files the role's task copies to the guest, read from the task's own loop."""
    tasks = yaml.safe_load((MODULE / "roles" / "vector" / "tasks" / "files.yml").read_text())
    (task,) = [t for t in tasks if t["name"] == "The module's own sidecar and remap code"]
    return list(task["loop"])


def _role_vars() -> dict:
    return yaml.safe_load((MODULE / "roles" / "vector" / "vars" / "main.yml").read_text())


@pytest.mark.static
def test_the_role_copies_exactly_the_closure_of_the_label_rules():
    copied = set(_role_vars()["vector_lib_files"])
    assert copied == _closure() - {"__init__.py"}, (
        "a file the rules import is not copied (or one extra is)"
    )
    for rel in copied:
        assert _stdlib_only(ROOT / "homelabnext" / rel) == [], (
            f"{rel} imports more than the standard library"
        )


@pytest.mark.static
def test_the_sidecar_and_the_remap_need_only_the_standard_library_and_the_rules():
    for name in _code_files():
        assert _stdlib_only(CODE / name) == [], name
    # and the role copies every file of the package (a caller found for each, M-02)
    own = {p.name for p in CODE.glob("*.py")}
    assert set(_code_files()) == own


CORPUS = [
    (
        {"labels": {"hnx_runtime": "none", "hnx_tlp": "clear"}, "host": {"ip": LAKE}},
        MODEL,
        "vector/siem-alerts",
    ),
    (
        {"Labels.HNX_RUNTIME": "none", "labels.hnx_tlp": "clear", "tlp": "clear"},
        LAKE,
        "vector/siem-archives",
    ),
    ({"tags": ["tlp:red"], "message": "x"}, f"::ffff:{MODEL}", "vector/siem-alerts"),
    ({"osint": [{"tlp": "amber+strict"}]}, f"{MODEL}:22", "vector/siem-alerts"),
    ({"a": 1}, None, None),
    ({"a": 1}, OTHER_DEST, "vector/unknown"),
]


def test_a_layout_built_from_the_copies_labels_exactly_like_the_core(tmp_path):
    """The deployed layout (the role's copies and its stand-in package marker) run in a fresh
    interpreter that sees nothing else of the checkout gives the core's own answers."""
    lib = tmp_path / "lib" / "homelabnext"
    (lib / "logpipeline").mkdir(parents=True)
    (lib / "__init__.py").write_text("")
    for rel in _role_vars()["vector_lib_files"]:
        (lib / rel).write_bytes((ROOT / "homelabnext" / rel).read_bytes())
    code = tmp_path / "code" / "hnx_modules" / "vector"
    code.mkdir(parents=True)
    for name in _code_files():
        (code / name).write_bytes((CODE / name).read_bytes())
    rt = tables()[0]
    (tmp_path / "rt.json").write_text(json.dumps(table_doc(ROWS)))
    (tmp_path / "st.json").write_text(
        json.dumps(
            tl.table_doc(
                [
                    ("vector/siem-alerts", tlp.Label.AMBER, False),
                    ("vector/siem-archives", tlp.Label.GREEN, True),
                ]
            )
        )
    )
    (tmp_path / "corpus.json").write_text(json.dumps(CORPUS))
    script = (
        "import json, sys\n"
        f"sys.path[:0] = [{str(tmp_path / 'lib')!r}, {str(tmp_path / 'code')!r}]\n"
        "import homelabnext, hnx_modules.vector.sidecar as sc\n"
        "from homelabnext.logpipeline import RuntimeTable, SourceTable\n"
        f"assert homelabnext.__file__.startswith({str(tmp_path / 'lib')!r}), homelabnext.__file__\n"
        f"rt = RuntimeTable.load({str(tmp_path / 'rt.json')!r}); st = SourceTable.load({str(tmp_path / 'st.json')!r})\n"
        f"print(json.dumps([sc.label_event(e, o, r, rt, st) for e, o, r in json.load(open({str(tmp_path / 'corpus.json')!r}))]))\n"
    )
    out = subprocess.run(
        [sys.executable, "-I", "-c", script], capture_output=True, text=True, cwd=tmp_path
    )
    assert out.returncode == 0, out.stderr
    src2 = SourceTable.load(tmp_path / "st.json")
    want = [adapter_label(e, o, r, rt, src2) for e, o, r in CORPUS]
    assert json.loads(out.stdout) == want


def adapter_label(event, observed, route, rt, st):
    """The contract composed from the library directly (the conformance suite's own fake)."""
    from conformance.fakes.log_pipeline import FakeLogPipeline

    fake = FakeLogPipeline()
    fake.load_runtimes(rt)
    fake.load_sources(st)
    return fake.process([Observed(event, observed, route)])[0]


# ---------------------------------------------------------------- the conformance suite
def test_the_suite_passes_through_the_adapter():
    results = run_checks(suite.SUITE, adapter.make)
    assert [r.check for r in results if r.status != "pass"] == []
    assert len([r for r in results if r.status == "pass"]) >= 24


@pytest.mark.parametrize(
    "defect",
    ["trusts_self_none", "joins_on_event_source", "no_tlp_for_unknown_route", "keeps_flat_key"],
)
def test_the_suite_catches_a_defective_sidecar(monkeypatch, defect):
    """The adapter is the sidecar's own path: a defect planted in the sidecar fails the suite."""
    real_label, real_observed = sidecar.label_event, sidecar.observed_for

    def trusts_self_none(event, observed, route, rt, st):
        if isinstance(event, dict) and (event.get("labels") or {}).get("hnx_runtime") == "none":
            return real_label(event, observed, route, rt, st) | {
                "labels": {**event["labels"], "hnx_tlp": "red"}
            }
        return real_label(event, observed, route, rt, st)

    def no_tlp_for_unknown_route(event, observed, route, rt, st):
        out = real_label(event, observed, route, rt, st)
        if isinstance(out, dict) and route is None:
            out["labels"].pop("hnx_tlp", None)
        return out

    def keeps_flat_key(event, observed, route, rt, st):
        out = real_label(event, observed, route, rt, st)
        if isinstance(event, dict) and "labels.hnx_runtime" in event:
            out["labels.hnx_runtime"] = event["labels.hnx_runtime"]
        return out

    def joins_on_event_source(policy, envelope, event):
        src = (event.get("source") or {}).get("ip") if isinstance(event, dict) else None
        return src or real_observed(policy, envelope, event)

    plant = {
        "trusts_self_none": ("label_event", trusts_self_none),
        "no_tlp_for_unknown_route": ("label_event", no_tlp_for_unknown_route),
        "keeps_flat_key": ("label_event", keeps_flat_key),
        "joins_on_event_source": ("observed_for", joins_on_event_source),
    }[defect]
    monkeypatch.setattr(sidecar, plant[0], plant[1])
    results = run_checks(suite.SUITE, adapter.make)
    assert [r for r in results if r.status != "pass"], f"the suite did not catch {defect}"


# ---------------------------------------------------------------- the evasion fixtures
MODEL_RULES = (
    "model-runtime-egress-drop",
    "model-runtime-object-store-lookup",
    "model-runtime-object-store-request",
)


@pytest.mark.parametrize("path", EVASION, ids=lambda p: p.stem)
def test_evasion_fixture_through_the_sidecar(path):
    """The fixture's event arrives on a sensor route, whose peer the collector saw; whatever the
    event says about itself, the labelled event is the table's answer, and the rule fires or not."""
    fx = json.loads(path.read_text(encoding="utf-8"))
    runtimes = RuntimeTable.load(EXAMPLE_TABLE)
    cfg = {
        "routes": {"vector/sensor-stream": {"kind": "sensor", "observe": "peer"}},
        "detection_ids": {},
    }
    envelope = {"route": "vector/sensor-stream", "peer": fx["observed"], "event": fx["event"]}
    lines = sidecar.handle_line(json.dumps(envelope), cfg, runtimes, SourceTable(), NOW)
    raw = next(
        json.loads(line)["row"] for line in lines if json.loads(line)["table"] == "raw_archive"
    )
    labelled = {**json.loads(raw["raw"]), "labels": raw["labels"]}
    labelled.pop("labels.hnx_runtime", None)
    assert raw["labels"].get("hnx_runtime") == fx["label"], raw
    rule = next(r for r in load_rules(DET) if r.slug == fx["rule"])
    engine = FakeGenericEngine(load_mapping(DET / "mappings" / "generic.yml"))
    out = enrich(fx["event"], fx["observed"], runtimes)
    assert engine.matches(rule, {**out, "labels": raw["labels"]}) is fx["fires"], (fx["name"], raw)


# ---------------------------------------------------------------- the observed address
def alert(agent_ip, **extra):
    return {
        "timestamp": "2026-11-22T10:00:00.000+0000",
        "rule": {"level": 3, "id": "1", "description": "x", "groups": []},
        "agent": {"id": "001", "name": "a", "ip": agent_ip},
        "decoder": {"name": "json"},
        **extra,
    }


def labels_of(rows) -> dict:
    return next(r["row"]["labels"] for r in rows if r["table"] == "raw_archive")


def test_a_siem_route_takes_the_address_the_manager_recorded_never_a_host_field():
    rows = run(
        {
            "route": "vector/siem-alerts",
            "event": alert(MODEL, host={"ip": LAKE}, source={"ip": LAKE}),
        }
    )
    assert labels_of(rows)["hnx_runtime"] == "model"
    rows = run(
        {"route": "vector/siem-alerts", "event": {"rule": {"id": "1"}, "host": {"ip": MODEL}}}
    )
    assert "hnx_runtime" not in labels_of(
        rows
    )  # no agent address: no label, whatever the host field says


def test_a_syslog_route_from_a_trusted_router_takes_the_client_it_recorded():
    line = (
        "<14>Nov 22 10:10:00 r CEF:0|Example Router Co|Router OS|8.0|400|Firewall Drop|5|src=198.51.100."
        "130 dst=203.0.113."
        "5 rt=1795389000000"
    )
    assert (
        labels_of(run({"route": "vector/syslog-udp", "peer": ROUTER, "line": line}))["hnx_runtime"]
        == "model"
    )


def test_a_syslog_route_from_any_other_peer_is_held_to_the_peer_not_the_record():
    line = (
        "<14>Nov 22 10:10:00 r CEF:0|Example Router Co|Router OS|8.0|400|Firewall Drop|5|src=198.51.100."
        "130 dst=203.0.113."
        "5"
    )
    assert "hnx_runtime" not in labels_of(
        run({"route": "vector/syslog-udp", "peer": OTHER_PEER, "line": line})
    )
    assert (
        labels_of(run({"route": "vector/syslog-udp", "peer": LAKE, "line": line}))["hnx_runtime"]
        == "none"
    )
    assert "hnx_runtime" not in labels_of(
        run({"route": "vector/syslog-udp", "line": line})
    )  # no peer at all


def test_a_sensor_route_takes_the_client_its_capture_recorded_not_a_forged_host():
    ev = {
        "event_type": "flow",
        "src_ip": MODEL,
        "dest_ip": DEST,
        "host": LAKE,
        "source_ip": LAKE,
    }
    assert labels_of(run({"route": "vector/sensor-stream", "event": ev}))["hnx_runtime"] == "model"
    flow = {"id.orig_h": LAKE, "host": MODEL}
    assert labels_of(run({"route": "vector/sensor-stream", "event": flow}))["hnx_runtime"] == "none"
    nested = {"id": {"orig_h": MODEL}}
    assert (
        labels_of(run({"route": "vector/sensor-stream", "event": nested}))["hnx_runtime"] == "model"
    )


@pytest.mark.parametrize("bad", [f"{MODEL}:22", f" {MODEL}", "infer-core", f"{MODEL}%eth0", ""])
def test_an_observed_value_that_is_not_a_bare_address_labels_nothing(bad):
    rows = run({"route": "vector/siem-alerts", "event": alert(bad)})
    assert "hnx_runtime" not in labels_of(rows)


def test_a_self_set_label_of_any_spelling_is_replaced():
    ev = alert(
        MODEL,
        labels={"hnx_runtime": "none", "hnx_tlp": "clear"},
        **{"labels.hnx_runtime": "none", "Labels.HNX_TLP": "clear", "tlp": "clear"},
    )
    rows = run({"route": "vector/siem-alerts", "event": ev})
    lab = labels_of(rows)
    assert lab == {"hnx_runtime": "model", "hnx_tlp": "amber"}
    raw = next(r["row"]["raw"] for r in rows if r["table"] == "raw_archive")
    assert "labels" not in json.loads(
        raw
    )  # the raw column is the event minus any label it brought... and ours rides beside it


# ---------------------------------------------------------------- refusals and counters
def test_an_envelope_for_an_unknown_route_is_refused_and_counted():
    c = sidecar.Counters()
    assert run({"route": "vector/other", "line": "x"}, c) == []
    assert run({"line": "x"}, c) == [] and c["-"]["refused"] == 2


def test_a_line_that_is_not_an_envelope_is_refused():
    rt, st = tables()
    c = sidecar.Counters()
    for line in ("", "not json", "[1, 2]", '"x"', "null"):
        assert sidecar.handle_line(line, config(), rt, st, NOW, c) == []
    assert c["-"]["refused"] == 5


def test_a_line_that_does_not_parse_is_archived_whole_never_dropped():
    c = sidecar.Counters()
    rows = run({"route": "vector/siem-alerts", "line": "{truncated json"}, c)
    assert [r["table"] for r in rows] == ["raw_archive"]
    assert (
        rows[0]["row"]["decoder_name"] == "unparsed"
        and rows[0]["row"]["full_log"] == "{truncated json"
    )
    assert c["vector/siem-alerts"]["unparsed"] == 1


def test_unlabelled_events_are_counted_per_route():
    c = sidecar.Counters()
    run({"route": "vector/siem-alerts", "event": alert(UNLISTED)}, c)
    run({"route": "vector/siem-alerts", "event": alert(MODEL)}, c)
    assert c["vector/siem-alerts"] == {"in": 2, "unlabelled": 1, "rows": 4}


def test_an_event_the_remap_cannot_map_keeps_its_raw_row(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("odd record")

    monkeypatch.setitem(ocsf.MAPPERS, "siem", boom)
    c = sidecar.Counters()
    rows = run({"route": "vector/siem-alerts", "event": alert(MODEL)}, c)
    assert [r["table"] for r in rows] == ["raw_archive"] and c["vector/siem-alerts"][
        "unmapped"
    ] == 1


@pytest.mark.parametrize(
    "doc",
    [
        None,
        {"schema": "other", "routes": {"a/b": {"kind": "siem", "observe": "agent"}}},
        {"schema": sidecar.CONFIG_SCHEMA, "routes": {}},
        {"schema": sidecar.CONFIG_SCHEMA, "routes": {"nope": {"kind": "siem", "observe": "agent"}}},
        {"schema": sidecar.CONFIG_SCHEMA, "routes": {"a/b": {"kind": "other", "observe": "agent"}}},
        {
            "schema": sidecar.CONFIG_SCHEMA,
            "routes": {"a/b": {"kind": "sensor", "observe": "agent"}},
        },
        {
            "schema": sidecar.CONFIG_SCHEMA,
            "routes": {"a/b": {"kind": "siem", "observe": "agent", "x": 1}},
        },
        {
            "schema": sidecar.CONFIG_SCHEMA,
            "routes": {"a/b": {"kind": "syslog", "observe": "recorded", "trusted": "x"}},
        },
        {
            "schema": sidecar.CONFIG_SCHEMA,
            "routes": {"a/b": {"kind": "siem", "observe": "agent"}},
            "detection_ids": {"1": 2},
        },
    ],
)
def test_a_configuration_that_is_not_valid_is_refused(doc):
    with pytest.raises(sidecar.ConfigError):
        sidecar.load_config(doc)


# ---------------------------------------------------------------- the tables the daemon reloads
def _write_tables(d: Path, rows=ROWS, sources=None) -> None:
    (d / "runtime-labels.json").write_text(json.dumps(table_doc(rows)))
    (d / "tlp-sources.json").write_text(
        json.dumps(tl.table_doc(sources or [("vector/siem-alerts", tlp.Label.AMBER, False)]))
    )
    (d / "enrich.json").write_text(
        json.dumps(
            {
                "schema": sidecar.CONFIG_SCHEMA,
                "routes": {"vector/siem-alerts": {"kind": "siem", "observe": "agent"}},
            }
        )
    )


def test_a_changed_table_replaces_the_earlier_one_and_a_bad_one_is_kept_out(tmp_path):
    _write_tables(tmp_path)
    t = sidecar.Tables(tmp_path)
    assert t.refresh() and t.errors == {} and len(t.digests) == 3
    assert t.runtimes.lookup(MODEL) == "model"
    first = dict(t.digests)
    time.sleep(0.01)
    _write_tables(tmp_path, rows=[(MODEL, "none", "guest:g", "cap:x")])
    assert t.refresh() and t.runtimes.lookup(MODEL) == "none"  # replaced, not merged
    assert t.digests["runtime-labels.json"] != first["runtime-labels.json"]
    good = t.digests["runtime-labels.json"]
    time.sleep(0.01)
    (tmp_path / "runtime-labels.json").write_text('{"schema": "wrong"}')
    t.refresh()
    assert "runtime-labels.json" in t.errors  # reported ...
    assert (
        t.runtimes.lookup(MODEL) == "none" and t.digests["runtime-labels.json"] == good
    )  # ... and the last good kept


def test_a_missing_table_is_an_error_not_an_empty_table(tmp_path):
    t = sidecar.Tables(tmp_path)
    t.refresh()
    assert set(t.errors) == {"runtime-labels.json", "tlp-sources.json", "enrich.json"}


# ---------------------------------------------------------------- the daemon, over real sockets
def _serve(tmp_path):
    _write_tables(tmp_path)
    run_dir = Path(tempfile.mkdtemp(prefix="hnxv"))  # a short path: a unix socket's is limited
    listen, forward, status = (
        str(run_dir / "in.sock"),
        str(run_dir / "out.sock"),
        run_dir / "status.json",
    )
    stop = threading.Event()
    th = threading.Thread(
        target=sidecar.serve, args=(tmp_path, listen, forward, status, 0.2, stop), daemon=True
    )
    return run_dir, listen, forward, status, th, stop


def test_the_daemon_labels_what_it_is_sent_and_hands_every_row_on_even_when_vector_is_late(
    tmp_path,
):
    _, listen, forward, status, th, stop = _serve(tmp_path)
    th.start()
    try:
        deadline = time.monotonic() + 10
        while not os.path.exists(listen) and time.monotonic() < deadline:
            time.sleep(0.02)
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.connect(listen)
        env = {"route": "vector/siem-alerts", "event": alert(MODEL)}
        client.sendall((json.dumps(env) + "\n").encode())
        time.sleep(0.5)  # the receiving socket does not exist yet: the sidecar holds the line
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(forward)
        srv.listen(1)
        srv.settimeout(10)
        conn, _ = srv.accept()
        got, buf = [], b""
        conn.settimeout(10)
        while len(got) < 2:
            buf += conn.recv(65536)
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                got.append(json.loads(line))
        assert {g["table"] for g in got} == {"raw_archive", "detection_finding"}
        assert all(g["row"]["labels"] == {"hnx_runtime": "model", "hnx_tlp": "amber"} for g in got)
        doc = {}
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and "vector/siem-alerts" not in doc.get("counters", {}):
            time.sleep(0.1)  # the status is written every interval (0.2 s here)
            doc = json.loads(status.read_text()) if status.exists() else {}
        assert sidecar.healthcheck(status, 30) == 0
        assert doc["counters"]["vector/siem-alerts"]["in"] == 1 and doc["errors"] == {}
        client.close()
        conn.close()
        srv.close()
    finally:
        stop.set()
        th.join(timeout=10)
        assert not th.is_alive()


def test_the_status_stays_fresh_while_a_stream_never_pauses(tmp_path):
    """A backlog arrives without a pause long enough for the socket timeout: the status is still
    written every interval while the rows flow."""
    _, listen, forward, status, th, stop = _serve(tmp_path)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(forward)
    srv.listen(1)
    drained = threading.Event()

    def drain():
        conn, _ = srv.accept()
        conn.settimeout(0.5)
        while not drained.is_set():
            with contextlib.suppress(TimeoutError):
                if not conn.recv(65536):
                    break
        conn.close()

    dt = threading.Thread(target=drain, daemon=True)
    dt.start()
    th.start()
    try:
        deadline = time.monotonic() + 10
        while not os.path.exists(listen) and time.monotonic() < deadline:
            time.sleep(0.02)
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.connect(listen)
        line = (json.dumps({"route": "vector/siem-alerts", "event": alert(MODEL)}) + "\n").encode()
        seen = set()
        end = time.monotonic() + 2.0
        while time.monotonic() < end:  # a line every 20 ms: never a 1 s pause
            client.sendall(line)
            if status.exists():
                seen.add(json.loads(status.read_text())["time"])
            time.sleep(0.02)
        assert len(seen) >= 3, seen  # rewritten while the stream ran (interval 0.2 s)
        assert sidecar.healthcheck(status, 1) == 0
        client.close()
    finally:
        drained.set()
        stop.set()
        th.join(timeout=10)
        srv.close()
        assert not th.is_alive()


def test_the_health_check_fails_on_a_stale_or_errored_or_missing_status(tmp_path):
    t0 = 1_800_000_000.0  # a frozen clock: the check's own "now"
    p = tmp_path / "s.json"
    assert sidecar.healthcheck(p, clock=lambda: t0) == 1
    for written, errors, listening, want in (
        (t0, {}, True, 0),
        (t0 - 3600, {}, True, 1),
        (t0, {"x": "y"}, True, 1),
        (t0, {}, False, 1),
    ):
        p.write_text(json.dumps({"time": written, "errors": errors, "listening": listening}))
        assert sidecar.healthcheck(p, clock=lambda: t0) == want


# ---------------------------------------------------------------- the OCSF remap: goldens
def _golden_run():
    g = lambda name: json.loads((GOLDEN / name).read_text())  # noqa: E731
    out = {}
    out["agent-stream"] = [
        run({"route": "vector/siem-alerts" if "rule" in e else "vector/siem-archives", "event": e})
        for e in g("agent-stream.in.json")
    ]
    out["router-cef"] = [
        run({"route": "vector/syslog-udp", "peer": ROUTER, "line": line})
        for line in g("router-cef.in.json")
    ]
    out["router-cef-untrusted"] = [
        run({"route": "vector/syslog-udp", "peer": OTHER_PEER, "line": line})
        for line in g("router-cef.in.json")[:1]
    ]
    out["sensor-stream"] = [
        run({"route": "vector/sensor-stream", "event": e}) for e in g("sensor-stream.in.json")
    ]
    return json.loads(json.dumps(out))


@pytest.mark.static
def test_the_goldens():
    """Regenerate with ``HNX_UPDATE_GOLDEN=1`` and read the diff: it is the pipeline's whole output."""
    got = _golden_run()
    path = GOLDEN / "expected.json"
    if os.environ.get("HNX_UPDATE_GOLDEN") == "1":
        path.write_text(json.dumps(got, indent=1, sort_keys=True) + "\n")
    assert got == json.loads(path.read_text())


def rows_of(group, idx, table):
    return [
        r["row"]
        for r in json.loads((GOLDEN / "expected.json").read_text())[group][idx]
        if r["table"] == table
    ]


@pytest.mark.static
def test_every_event_keeps_a_labelled_raw_row_and_each_class_one_row():
    exp = json.loads((GOLDEN / "expected.json").read_text())
    for group in exp.values():
        for event_rows in group:
            tbls = [r["table"] for r in event_rows]
            assert tbls[0] == "raw_archive" and len(tbls) == len(set(tbls))
            assert all(
                set(r["row"]["labels"]) <= {"hnx_runtime", "hnx_tlp"}
                and "hnx_tlp" in r["row"]["labels"]
                for r in event_rows
            )


@pytest.mark.parametrize(
    ("level", "want"),
    [
        (0, 1),
        (3, 1),
        (4, 2),
        (6, 2),
        (7, 3),
        (11, 3),
        (12, 4),
        (14, 4),
        (15, 5),
        (-1, 0),
        ("x", 0),
        (None, 0),
        (True, 0),
        (99, 5),
    ],
)
def test_severity_from_a_rule_level_is_oceans_scale_not_the_level(level, want):
    assert ocsf.siem_severity(level) == want


def test_a_level_12_alert_is_severity_4_so_the_paging_line_is_the_old_one():
    rows = rows_of("agent-stream", 0, "detection_finding")
    assert [r["severity_id"] for r in rows] == [4] and rows[0]["severity_id"] != 12


@pytest.mark.parametrize(
    ("alert", "want"),
    [
        ({"severity": 1, "metadata": {"signature_severity": ["Informational"]}}, 2),
        ({"severity": 3, "metadata": {"signature_severity": ["Major"]}}, 4),
        ({"severity": 3, "metadata": {"signature_severity": ["Critical"]}}, 5),
        ({"severity": 3, "metadata": {"signature_severity": ["Minor"]}}, 3),
        ({"severity": 1}, 4),
        ({"severity": 2}, 3),
        ({"severity": 3}, 2),
        ({"severity": "x"}, 2),
        ({}, 2),
        ({"severity": True}, 2),
        ({"severity": 1, "metadata": {"signature_severity": ["Unknown"]}}, 4),
    ],
)
def test_a_sensor_alert_takes_the_signatures_own_grade_before_its_numeric_severity(alert, want):
    assert ocsf.ids_severity(alert) == want


@pytest.mark.parametrize(
    ("sev", "want"),
    [
        ("0", 1),
        ("1", 2),
        ("3", 2),
        ("4", 3),
        ("6", 3),
        ("7", 4),
        ("8", 4),
        ("9", 5),
        ("10", 5),
        ("11", 0),
        ("x", 0),
        ("High", 4),
        ("Very-High", 5),
    ],
)
def test_cef_severity(sev, want):
    assert ocsf.cef_severity(sev) == want


def test_the_sensor_goldens_use_the_signature_grade():
    sev = [rows_of("sensor-stream", i, "detection_finding")[0]["severity_id"] for i in range(3)]
    assert sev == [2, 4, 3]


def test_a_detection_id_is_never_a_rule_number_and_a_mapping_names_it():
    mapped = rows_of("agent-stream", 0, "detection_finding")[0]
    other = rows_of("agent-stream", 1, "detection_finding")[0]
    assert (
        mapped["detection_id"] == "det:ssh-auth-failure-burst" and mapped["finding_uid"] == "5712"
    )
    assert other["detection_id"] == ocsf.UNMAPPED_DETECTION
    rt, st = tables()
    bad = {"routes": config()["routes"], "detection_ids": {"5712": "det:Not Valid"}}
    lines = sidecar.handle_line(
        json.dumps(
            {"route": "vector/siem-alerts", "event": alert(MODEL, rule={"level": 3, "id": "5712"})}
        ),
        bad,
        rt,
        st,
        NOW,
    )
    assert any(
        json.loads(line)["row"].get("detection_id") == ocsf.UNMAPPED_DETECTION for line in lines
    )


@pytest.mark.parametrize("table", sorted(ocsf.PINNED))
def test_the_rows_of_every_pinned_class_validate_against_their_lake_schema(table):
    exp = json.loads((GOLDEN / "expected.json").read_text())
    schema = lake_tables.get_schema(table)
    seen = 0
    for group in exp.values():
        for event_rows in group:
            for r in event_rows:
                if r["table"] != table:
                    continue
                row = lake_rows.row_from_event(r["row"], schema)  # tlp from labels.hnx_tlp
                assert row["tlp"] == r["row"]["labels"]["hnx_tlp"]
                lake_validate.normalize_rows(schema, [row])
                seen += 1
    assert seen >= 1, f"no golden row exercises {table}"


@pytest.mark.parametrize("table", sorted(set(ocsf.CLASSES) - ocsf.PINNED))
def test_the_unpinned_classes_carry_the_common_ocsf_columns(table):
    exp = json.loads((GOLDEN / "expected.json").read_text())
    rows = [r["row"] for g in exp.values() for ev in g for r in ev if r["table"] == table]
    assert rows, f"no golden row exercises {table}"
    cls, cat = ocsf.CLASSES[table]
    for r in rows:
        assert (
            r["class_uid"] == cls
            and r["category_uid"] == cat
            and r["type_uid"] == cls * 100 + r["activity_id"]
        )
        assert (
            0 <= r["severity_id"] <= 6
            and r["metadata"]["version"] == ocsf.OCSF_VERSION
            and r["uid"]
            and r["time"].endswith("Z")
        )


@pytest.mark.static
def test_all_nine_classes_and_the_raw_archive_are_produced():
    exp = json.loads((GOLDEN / "expected.json").read_text())
    tbls = {r["table"] for g in exp.values() for ev in g for r in ev}
    assert tbls == set(ocsf.CLASSES) | {ocsf.RAW_TABLE}


def test_a_replayed_event_has_the_same_ids_and_each_class_its_own():
    a = run({"route": "vector/siem-alerts", "event": alert(MODEL)})
    b = run({"route": "vector/siem-alerts", "event": alert(MODEL)})
    assert a == b
    uids = [r["row"]["uid"] for r in a]
    assert len(uids) == len(set(uids))
    other = run({"route": "vector/siem-archives", "event": alert(MODEL)})
    assert {r["row"]["uid"] for r in other}.isdisjoint(uids)  # another route is another event


def test_the_time_is_the_events_own_else_the_receive_time():
    assert (
        ocsf.event_time({"timestamp": "2026-11-22T10:00:00.000+0000"}, "siem", NOW)
        == "2026-11-22T10:00:00.000000Z"
    )
    assert ocsf.event_time({"ts": 1795390802.5}, "sensor", NOW) == "2026-11-22T23:40:02.500000Z"
    assert ocsf.event_time({"timestamp": "garbage"}, "siem", NOW) == "2026-11-22T12:00:00.000000Z"
    assert ocsf.event_time({}, "sensor", NOW) == "2026-11-22T12:00:00.000000Z"


@pytest.mark.parametrize(
    ("line", "ok"),
    [
        (f"<14>x CEF:0|a|b|1|2|n|5|src={DOC_A} dst={DOC_B} msg=hello world dpt=80", True),
        ("<14>x CEF:0|a\\|b|b|1|2|n|5|k=v", True),
        ("<14>x CEF:0|a|b|1|2|n", False),
        ("plain syslog line", False),
        ("", False),
    ],
)
def test_cef_parsing(line, ok):
    got = ocsf.parse_cef(line)
    assert (got is not None) is ok
    if ok and "dpt" in line:
        assert got["ext"] == {"src": DOC_A, "dst": DOC_B, "msg": "hello world", "dpt": "80"}
    if ok and "a\\|b" in line:
        assert got["vendor"] == "a|b"


def test_the_remap_never_trusts_a_severity_the_event_brings():
    ev = alert(MODEL, severity_id=6, severity=6)
    rows = run({"route": "vector/siem-alerts", "event": ev})
    assert [r["row"]["severity_id"] for r in rows if r["table"] == "detection_finding"] == [1]
