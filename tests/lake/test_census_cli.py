# SPDX-License-Identifier: Apache-2.0
"""``hnx lake source-census``: the two criteria, the exit codes and the state-diffed page."""

from __future__ import annotations

import json
import os
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml

from homelabnext import cli as hnx
from homelabnext.lake import cli as lcli
from homelabnext.notify import FakeSender
from homelabnext.notify.core import SendError

NOW = datetime(2026, 7, 31, 22, 30, tzinfo=UTC)


def _iso(d):
    return d.isoformat().replace("+00:00", "Z")


def rows(source, decoder, hours_ago):
    return [
        {
            "source": source,
            "decoder": decoder,
            "time": _iso(NOW - timedelta(hours=h) + timedelta(minutes=1)),
        }
        for h in hours_ago
    ]


def write(tmp: Path, rs, settings=None) -> list[str]:
    fx = tmp / "fixture.json"
    fx.write_text(json.dumps({"rows": rs}))
    st = tmp / "settings.yml"
    st.write_text(yaml.safe_dump(settings or {"census": {"table": "raw_archive"}}))
    return [
        "lake",
        "source-census",
        "--fixture",
        str(fx),
        "--settings",
        str(st),
        "--now",
        _iso(NOW),
    ]


def run(capsys, args):
    code = hnx.main(args)
    out = capsys.readouterr()
    return code, out.out, out.err


HEALTHY = rows("auth.log", "sshd", range(1, 8 * 24))


def test_healthy_passes_both_criteria(tmp_path, capsys):
    code, out, _ = run(capsys, write(tmp_path, HEALTHY))
    assert code == 0
    assert (
        "pass  source-census/sources-flowing" in out
        and "pass  source-census/all-classes-dark" in out
    )


def test_a_stale_source_fails_with_exit_1(tmp_path, capsys):
    code, out, _ = run(capsys, write(tmp_path, rows("auth.log", "sshd", range(12, 8 * 24))))
    assert (
        code == 1
        and "FAIL  source-census/sources-flowing" in out
        and "[STALE] auth.log / sshd" in out
    )


def test_learning_passes_but_says_warn(tmp_path, capsys):
    code, out, _ = run(capsys, write(tmp_path, rows("new.log", "app", range(1, 40))))
    assert code == 0 and "WARN  source-census/sources-flowing" in out and "still learning" in out


def test_an_empty_lake_fails_all_classes_dark_even_while_learning(tmp_path, capsys):
    code, out, _ = run(capsys, write(tmp_path, []))
    assert code == 1
    assert (
        "FAIL  source-census/all-classes-dark" in out
        and "FAIL  source-census/sources-flowing" in out
    )


def test_one_criterion_can_be_asked_for(tmp_path, capsys):
    code, out, _ = run(capsys, [*write(tmp_path, []), "--criterion", "all-classes-dark"])
    assert code == 1 and "sources-flowing" not in out


def test_the_dark_tables_and_window_are_settings(tmp_path, capsys):
    st = {
        "census": {"table": "raw_archive"},
        "dark": {"tables": ["raw_archive", "detections"], "hours": 48},
    }
    rs = [*rows("a", "b", [30]), {**rows("a", "b", [5])[0], "table": "detections"}]
    code, out, _ = run(capsys, [*write(tmp_path, rs, st), "--criterion", "all-classes-dark"])
    assert code == 0 and "events in 2/2 table(s) in the last 48h" in out


def test_could_not_measure_is_exit_100_not_a_fail(tmp_path, capsys, monkeypatch):
    from homelabnext.lake import FakeLake

    # the engine answers, but the table is not there: neither a pass nor a fail
    monkeypatch.setattr(
        lcli,
        "_lake",
        lambda *a, **k: FakeLake([lcli.fixture_schema("other", ("source", "decoder"), "time")]),
    )
    code, out, err = run(capsys, write(tmp_path, HEALTHY))
    assert code == 100 and "could not measure" in err and "FAIL" not in out


@pytest.mark.parametrize(
    "settings, msg",
    [
        ({"census": {"window_days": 1}}, "window_days"),
        ({"census": {"nonsense": 1}}, "unknown census setting"),
        ({"census": {"table": "raw archive"}}, "not a plain"),
    ],
)
def test_bad_settings_are_usage_errors(tmp_path, capsys, settings, msg):
    code, _, err = run(capsys, write(tmp_path, HEALTHY, settings))
    assert code == 2 and msg in err


def test_a_live_lake_needs_its_settings_and_a_private_credential_file(tmp_path, capsys):
    st = tmp_path / "s.yml"
    st.write_text(yaml.safe_dump({"census": {}}))
    code, _, err = run(capsys, ["lake", "source-census", "--config", str(st), "--now", _iso(NOW)])
    assert code == 2 and "lake.domain is required" in err
    cred = tmp_path / "cred"
    cred.write_text("pw-for-test\n")
    cred.chmod(0o644)
    st.write_text(
        yaml.safe_dump(
            {
                "lake": {
                    "domain": "lab.example.internal",
                    "warehouse": "wh",
                    "catalog": "cat",
                    "credential_file": str(cred),
                }
            }
        )
    )
    code, _, err = run(capsys, ["lake", "source-census", "--config", str(st), "--now", _iso(NOW)])
    assert code == 2 and "readable by group or others" in err
    assert stat.S_IMODE(os.stat(cred).st_mode) == 0o644


# ------------------------------------------------------------------ paging
def _page(flagged, state, sender, summary="s"):
    return lcli.page(flagged, state, sender, summary=summary)


def test_a_newly_flagged_source_pages_once_and_a_standing_set_never_again(tmp_path):
    s, state = FakeSender(), tmp_path / "state.json"
    assert _page({"source:a": "[STALE] a"}, state, s) == "paged"
    assert [m.title for m in s.sent] == [lcli.TITLE_FLAGGED]
    for _ in range(3):
        assert _page({"source:a": "[STALE] a"}, state, s) == "standing"
    assert len(s.sent) == 1


def test_a_second_source_joining_a_standing_set_pages_again_marking_the_new_one(tmp_path):
    s, state = FakeSender(), tmp_path / "state.json"
    _page({"source:a": "[STALE] a"}, state, s)
    assert _page({"source:a": "[STALE] a", "source:b": "[STALE] b"}, state, s) == "paged"
    body = s.sent[-1].body
    assert "NEW [STALE] b" in body and "NEW [STALE] a" not in body


def test_recovery_pages_once_with_the_constant_clean_title(tmp_path):
    s, state = FakeSender(), tmp_path / "state.json"
    _page({"source:a": "x"}, state, s)
    assert _page({}, state, s) == "recovered"
    assert s.sent[-1].title == lcli.TITLE_CLEAN and "recovered" in s.sent[-1].tags
    assert _page({}, state, s) == "clear"
    assert len(s.sent) == 2


def test_a_partial_recovery_pages_nothing_and_is_recorded(tmp_path):
    s, state = FakeSender(), tmp_path / "state.json"
    _page({"source:a": "x", "source:b": "y"}, state, s)
    assert _page({"source:b": "y"}, state, s) == "standing"
    assert json.loads(state.read_text())["flagged"] == ["source:b"]
    assert _page({"source:b": "y", "source:a": "x"}, state, s) == "paged"  # a came back: new again


def test_a_failed_send_keeps_the_old_state_so_the_page_is_retried(tmp_path):
    s, state = FakeSender(), tmp_path / "state.json"
    s.fail_next = 1
    with pytest.raises(SendError):
        _page({"source:a": "x"}, state, s)
    assert not state.exists()
    assert _page({"source:a": "x"}, state, s) == "paged"


def test_titles_carry_no_counts():
    assert not any(c.isdigit() for c in lcli.TITLE_FLAGGED + lcli.TITLE_CLEAN)


def test_the_command_pages_through_the_sender_it_is_given(tmp_path, capsys, monkeypatch):
    sender = FakeSender()
    monkeypatch.setattr(lcli, "_sender", lambda notify, domain: sender)
    st = {
        "census": {"table": "raw_archive"},
        "notify": {"topic": "t"},
        "state": str(tmp_path / "state.json"),
    }
    args = write(tmp_path, rows("auth.log", "sshd", range(12, 8 * 24)), st)
    ns = lcli._parser().parse_args(args[1:])
    assert lcli._source_census(ns, sender_for=lambda n, d: sender) == 1
    assert lcli._source_census(ns, sender_for=lambda n, d: sender) == 1
    assert len(sender.sent) == 1  # the second run found the same standing set
    assert "[STALE] auth.log / sshd" in sender.sent[0].body
    out = capsys.readouterr().out
    assert "paging: paged" in out and "paging: standing" in out


def test_no_notify_evaluates_and_keeps_no_state(tmp_path, capsys):
    st = {
        "census": {"table": "raw_archive"},
        "notify": {"topic": "t"},
        "state": str(tmp_path / "state.json"),
    }
    code, _out, _ = run(capsys, [*write(tmp_path, [], st), "--no-notify"])
    assert code == 1 and not (tmp_path / "state.json").exists()


def test_paging_needs_its_settings(tmp_path):
    with pytest.raises(lcli._Usage, match=r"notify\.token_file"):
        lcli._sender({"topic": "t", "ceiling": "red"}, "lab.example.internal")


def test_the_live_engine_is_built_by_the_shared_client_factory_and_binds_values(
    tmp_path, monkeypatch
):
    from homelabnext.conform.adapters import lake as lake_adapters

    seen = {}

    class Engine:
        catalog = schema = None

        def execute(self, sql, args=()):
            seen.update(sql=sql, args=list(args))
            return type("R", (), {"rows": [{"x": 1}]})()

    def fake_clients(**kw):
        seen["clients"] = kw
        return Engine(), object()

    monkeypatch.setattr(lake_adapters, "make_clients", fake_clients)
    live = {
        "domain": "lab.example.internal",
        "warehouse": "wh",
        "catalog": "cat",
        "namespace": "soc",
    }
    eng = lcli._Engine(live, "pw-for-test")
    assert eng.sql_dialect == "struct"
    assert eng.query('SELECT 1 FROM "t" WHERE "time" >= :since', {"since": NOW}) == [{"x": 1}]
    assert seen["sql"].endswith(">= ?") and seen["args"] == [NOW]
    kw = seen["clients"]
    assert (kw["domain"], kw["warehouse"], kw["user"]) == (
        "lab.example.internal",
        "wh",
        "analyzer:source-census",
    )
    assert (
        kw["credential"] == lcli.CREDENTIAL_REF
    )  # a secret NAME; the value is in the environment only
    assert (eng._engine.catalog, eng._engine.schema) == ("cat", "soc")


def test_a_refused_endpoint_is_a_usage_error_not_a_pass(monkeypatch):
    from homelabnext.conform.adapters import lake as lake_adapters
    from homelabnext.lake.errors import LakeError

    def refuse(**kw):
        raise LakeError("lake-query endpoint: refusing plaintext http to another host")

    monkeypatch.setattr(lake_adapters, "make_clients", refuse)
    live = {"domain": "lab.example.internal", "warehouse": "wh", "catalog": "cat"}
    with pytest.raises(lcli._Usage, match="refusing plaintext"):
        lcli._Engine(live, "pw-for-test")


def test_the_commands_are_listed():
    assert "lake" in hnx.COMMANDS and "logbursts" in hnx.COMMANDS
