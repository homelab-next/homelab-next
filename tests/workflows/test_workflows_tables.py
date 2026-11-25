# SPDX-License-Identifier: Apache-2.0
"""Lookup tables read from a file (``homelabnext.workflows.tables``), the lab-check watcher packs
that look one up, and the ``notify.page`` handler they call.

* ``read_table`` fails closed: a missing, linked, special, too large, stale, unparseable or
  wrongly shaped table raises, never reads as "no row".
* ``invariants-results`` rows are ok only when every criterion of the key passed.
* The watcher packs are pinned, validate, and page on a red or a missing row only.
* The page handler is pinned, takes every page a pack sends, keeps its token out of argv, speaks
  https only, and fails on anything but a 2xx.
"""

from __future__ import annotations

import json
import os
import subprocess

import pytest
from wf_support import PACKS, ROOT, manifest

from homelabnext.workflows import load_doc, pack_digest, run_fixture
from homelabnext.workflows.tables import (
    INVARIANTS_RESULTS_SCHEMA,
    TABLE_MAX_BYTES,
    TableError,
    invariants_rows,
    read_table,
)
from homelabnext.workflows.validate import handler_problem

WATCHERS = ("watch-cti-freshness", "watch-llm-server", "watch-honeypot-lake")
KEYS = {"watch-honeypot-lake": ["N-22"]}


def _results(tmp_path, statuses: dict[str, str], name: str = "results.json"):
    res = {
        cid: {"status": st, "evidence": "e", "checked_at": "2026-01-15"}
        for cid, st in statuses.items()
    }
    path = tmp_path / name
    path.write_text(json.dumps({"schema": INVARIANTS_RESULTS_SCHEMA, "results": res}))
    return path


def _decl(path, fmt="invariants-results", **kw) -> dict:
    d = {"path": str(path), "format": fmt} | kw
    if fmt == "invariants-results":
        d.setdefault("keys", KEYS)
    return d


# ---------------------------------------------------------------- the reader
def test_a_fresh_results_document_reads_as_one_row_per_key(tmp_path):
    good = _results(tmp_path, {"N-22": "pass", "N-01": "fail"})
    now = good.stat().st_mtime
    assert read_table(_decl(good, max_age_s=600), clock=lambda: now + 599) == {
        "watch-honeypot-lake": {
            "ok": True,
            "criteria": {"N-22": "pass"},
            "red": [],
            "summary": "watch-honeypot-lake: N-22 pass",
        }
    }


@pytest.mark.parametrize(
    ("statuses", "criteria", "summary"),
    [
        ({"A-1": "pass", "A-2": "fail"}, {"A-1": "pass", "A-2": "fail"}, "k: A-2 fail"),
        (
            {"A-1": "error", "A-2": "skip"},
            {"A-1": "error", "A-2": "skip"},
            "k: A-1 error, A-2 skip",
        ),
        ({"A-1": "pass", "X": "pass"}, {"A-1": "pass", "A-2": "missing"}, "k: A-2 missing"),
        (
            {"A-1": "PASS", "A-2": "pass"},
            {"A-1": "unrecognised", "A-2": "pass"},
            "k: A-1 unrecognised",
        ),
    ],
)
def test_a_row_is_ok_only_when_every_criterion_passed(statuses, criteria, summary):
    doc = {
        "schema": INVARIANTS_RESULTS_SCHEMA,
        "results": {c: {"status": s} for c, s in statuses.items()},
    }
    [row] = invariants_rows(doc, {"k": ["A-1", "A-2"]}).values()
    assert row["ok"] is False and row["criteria"] == criteria and row["summary"] == summary
    assert row["red"] == [c for c, s in criteria.items() if s != "pass"]


def test_read_table_refuses_every_malformed_or_stale_table(tmp_path):
    good = _results(tmp_path, {"N-22": "pass"})
    now = good.stat().st_mtime

    def refused(decl, match, clock=lambda: now):
        with pytest.raises(TableError, match=match):
            read_table(decl, clock=clock)

    refused(_decl(good, max_age_s=600), "older than 600", clock=lambda: now + 601)
    refused(_decl("relative/x.json"), "absolute")
    refused(_decl(str(tmp_path) + "/../x.json"), "canonical")
    refused(_decl(tmp_path / "nope.json"), "cannot be opened")
    refused(_decl(good, fmt="csv"), "unknown table format")
    refused(_decl(good, keys={}), "needs its keys")
    refused(_decl(good, keys={"k": []}), "names no criteria")
    refused("not a mapping", "not a mapping")
    refused(_decl(tmp_path), "not a regular file")
    link = tmp_path / "link.json"
    link.symlink_to(good)
    refused(_decl(link), "cannot be opened")  # never follows a link
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    refused(_decl(fifo), "not a regular file")  # and never blocks on one
    big = tmp_path / "big.json"
    big.write_text(" " * (TABLE_MAX_BYTES + 1))
    refused(_decl(big), "larger than")
    for text, match in [
        ("[]", "not an invariants results"),
        ('{"schema": "other/1", "results": {}}', "not an invariants results"),
        (json.dumps({"schema": INVARIANTS_RESULTS_SCHEMA, "results": {}}), "no results"),
        ("[" * 100000, "not JSON"),
        (b"\xff\xfe".decode("latin-1"), "not JSON"),
    ]:
        good.write_text(text, encoding="latin-1")
        refused(_decl(good), match)
    good.write_text('{"a": {"x": 1}, "b": 2}')
    refused(_decl(good, fmt="json-map"), "not a JSON object of rows")
    good.write_text('{"a": {"x": 1}}')
    assert read_table(_decl(good, fmt="json-map")) == {"a": {"x": 1}}


# ---------------------------------------------------------------- the watcher packs
@pytest.mark.parametrize("name", WATCHERS)
def test_a_watcher_is_pinned_and_pages_only_on_a_red_or_missing_row(name):
    doc = load_doc(PACKS / f"{name}.yml")
    pins = {p["pack"]: p["digest"] for p in load_doc(ROOT / "workflows/deploy.yml")["pins"]}
    assert pins[name] == pack_digest(doc)
    assert doc["trigger"]["where"] == [{"ref": "$event.data.schedule", "equals": name}]
    check = doc["steps"][0]
    assert (check["op"], check["table"], check["key"]) == (
        "lookup",
        "table:lab.checks",
        "$event.data.schedule",
    )
    assert {s["action"] for s in doc["steps"][1:]} == {"notify.page"}
    fixtures = {f["name"]: f for f in doc["fixtures"]}
    assert set(fixtures) == {
        "red-pages",
        "green-is-quiet",
        "missing-row-pages",
        "another-schedule-ignored",
    }
    for fname, fx in fixtures.items():
        res = run_fixture(doc, fx, manifest=manifest())
        assert not res.problems, (fname, res.problems)
        assert len(res.calls) == (1 if fname.endswith("-pages") else 0), fname


# ---------------------------------------------------------------- the page handler
HANDLER = ROOT / "workflows" / "handlers" / "notify-page.sh"
TOKEN = "-".join(["fake", "notify", "publish", "0001"])


def test_the_page_handler_is_pinned_and_takes_every_page_a_pack_sends():
    from homelabnext.broker.validation import inline_errors

    assert (
        handler_problem(ROOT, "workflows/broker.manifest.json", "handlers/notify-page.sh") is None
    )
    doc = json.loads(HANDLER.with_name("notify-page.handler.json").read_text())
    assert doc["secrets"] == ["NOTIFY_PAGE_URL", "NOTIFY_PAGE_TOKEN"] and doc["tier"] == "write"
    table = load_doc(ROOT / "workflows" / "broker.manifest.json")
    assert "handlers/notify-page.handler.json" in table["handler_docs"]
    seen = 0
    for path in sorted(PACKS.glob("*.yml")):
        for fx in load_doc(path)["fixtures"]:
            for call in fx.get("expect", {}).get("calls", []):
                if call["action"] == "notify.page":
                    assert inline_errors(doc["params_schema"], call["params"]) == [], path.name
                    seen += 1
    assert seen >= 6
    base = {"alert_id": "watch-llm-server", "title": "x"}
    for bad in (
        {"title": "x"},
        base | {"title": None},
        base | {"title": ""},
        base | {"title": "{{ kv.leak }}"},
        base | {"alert_id": "a b"},
        base | {"extra": 1},
    ):
        assert inline_errors(doc["params_schema"], bad), bad


def _fake_curl(tmp_path, code) -> dict:
    fake = tmp_path / "bin" / "curl"
    fake.parent.mkdir()
    if code is None:
        script = "#!/bin/sh\ncat >/dev/null\necho 'curl: (7) refused' >&2\nexit 7\n"
    else:
        script = (
            f'#!/bin/sh\nprintf "%s\\n" "$@" > "{tmp_path}/args"\ncat > "{tmp_path}/stdin"\n'
            f'for a in "$@"; do case $a in @-) ;; @*) cat "${{a#@}}" >> "{tmp_path}/hdrs"; '
            f'stat -c %a "${{a#@}}" > "{tmp_path}/mode";; esac; done\n'
            f"printf '%s\\n%s' '{{\"id\": \"m1\"}}' '{code}'\n"
        )
    fake.write_text(script)
    fake.chmod(0o755)
    run_tmp = tmp_path / "run-tmp"
    run_tmp.mkdir()
    return {
        "PATH": f"{fake.parent}{os.pathsep}/usr/bin{os.pathsep}/bin",
        "NOTIFY_PAGE_URL": "https://notify.example.invalid/lab-watch",
        "NOTIFY_PAGE_TOKEN": TOKEN,
        "TMPDIR": str(run_tmp),
    }


@pytest.mark.parametrize(
    ("code", "exit_code"),
    [(200, 0), (202, 0), (401, 1), (403, 1), (429, 1), (500, 1), (None, 1)],
)
def test_the_page_handler_maps_the_notify_services_answers(tmp_path, code, exit_code):
    env = _fake_curl(tmp_path, code)
    params = b'{"alert_id": "watch-llm-server", "rota": "lab-watch", "title": "N-08 \\"fail\\""}'
    got = subprocess.run(["/bin/sh", str(HANDLER)], input=params, env=env, capture_output=True)
    assert got.returncode == exit_code, got.stderr
    if code is not None:
        args = (tmp_path / "args").read_text().splitlines()
        assert "Title: page watch-llm-server" in args and "=https" in args
        assert (tmp_path / "stdin").read_bytes() == params  # the message is the params, unchanged
        # the token travels in a private header file: never in argv, never on stderr
        assert (tmp_path / "hdrs").read_text() == f"Authorization: Bearer {TOKEN}\n"
        assert (tmp_path / "mode").read_text().strip() == "600"
        assert TOKEN not in "".join(args)
        assert TOKEN.encode() not in got.stderr + got.stdout
        assert list((tmp_path / "run-tmp").iterdir()) == []  # removed after the POST
    if code in (401, 403):
        assert b"refused the token" in got.stderr
    if exit_code == 0:
        assert json.loads(got.stdout) == {"id": "m1"}


@pytest.mark.parametrize(
    ("token", "params", "why"),
    [
        (None, b'{"alert_id": "a", "title": "t"}', b"NOTIFY_PAGE_TOKEN"),
        ("", b'{"alert_id": "a", "title": "t"}', b"NOTIFY_PAGE_TOKEN"),
        ("fake-token\r\nX-Injected: 1", b'{"alert_id": "a", "title": "t"}', b"NOTIFY_PAGE_TOKEN"),
        (TOKEN, b'{"title": "t"}', b"no alert_id"),
    ],
)
def test_the_page_handler_needs_one_token_and_an_alert_id(token, params, why):
    env = {"PATH": "/usr/bin:/bin", "NOTIFY_PAGE_URL": "https://notify.example.invalid/t"}
    if token is not None:
        env["NOTIFY_PAGE_TOKEN"] = token
    got = subprocess.run(["/bin/sh", str(HANDLER)], input=params, env=env, capture_output=True)
    assert got.returncode == 1 and why in got.stderr
