# SPDX-License-Identifier: Apache-2.0
"""``hnx status``: the menu, the catalog gate, views check, collect and a deterministic render.
Only file sources are collected (``--source``): http sources would resolve names, and the
network guard is on."""

from __future__ import annotations

import json

from status_helpers import REGISTRY, ROOT, VIEWS

from homelabnext import cli
from homelabnext.status.cli import main


def test_sources_lists_the_menu(capsys):
    assert main(["sources", "--registry", str(REGISTRY)]) == 0
    out = capsys.readouterr().out
    assert "metrics-alerts" in out and "invariants" in out and "status source(s)" in out
    assert main(["sources", "--registry", str(REGISTRY), "--json"]) == 0
    rows = json.loads(capsys.readouterr().out)["sources"]
    assert {r["kind"] for r in rows} >= {"poll-http-json", "poll-file", "push-event"}


def test_catalog_check_passes_on_the_repo_and_fails_when_stale(tmp_path, capsys):
    page = ROOT / "docs" / "status" / "sources.md"
    assert main(["catalog", "check", "--registry", str(REGISTRY), "--out", str(page)]) == 0
    stale = tmp_path / "sources.md"
    stale.write_text(page.read_text() + "hand edit\n")
    assert main(["catalog", "check", "--registry", str(REGISTRY), "--out", str(stale)]) == 1
    assert "stale" in capsys.readouterr().out
    assert main(["catalog", "generate", "--registry", str(REGISTRY), "--out", str(stale)]) == 0
    assert stale.read_text() == page.read_text()


def test_views_check(tmp_path, capsys):
    assert main(["views", "check", str(VIEWS), "--registry", str(REGISTRY)]) == 0
    bad = tmp_path / "v.yml"
    bad.write_text(VIEWS.read_text().replace("service: dashboards", "service: no-such-service"))
    assert main(["views", "check", str(bad), "--registry", str(REGISTRY)]) == 1
    assert "no-such-service" in capsys.readouterr().err


FILE_SOURCES = ["--source", "invariants", "--source", "proposals", "--source", "approvals"]


def test_collect_then_render_is_deterministic(tmp_path, capsys):
    state = tmp_path / "state.json"
    reg = str(REGISTRY)
    collect = ["collect", "--registry", reg, "--root", str(ROOT), "--state", str(state)]
    assert main([*collect, *FILE_SOURCES]) == 0
    assert "collected 3 source(s)" in capsys.readouterr().out
    args = ["--registry", reg, "--views", str(VIEWS), "--state", str(state)]
    now = ["--now", "2026-10-20T09:00:00Z"]
    assert main(["render", "--out", str(tmp_path / "a"), *args, *now]) == 0
    assert main(["render", "--out", str(tmp_path / "b"), *args, *now]) == 0
    for name in ("index.html", "status.json"):
        assert (tmp_path / "a" / name).read_bytes() == (tmp_path / "b" / name).read_bytes()
    doc = json.loads((tmp_path / "a" / "status.json").read_text())
    assert doc["generated_at"] == "2026-10-20T09:00:00Z"
    items = {(o["source"], o["item"]) for o in doc["observations"]}
    assert ("proposals", "inbox") in items and ("approvals", "pending-approvals") in items
    assert any(s == "invariants" for s, _ in items)


def test_render_refuses_invalid_views(tmp_path, capsys):
    bad = tmp_path / "v.yml"
    bad.write_text(
        "views_version: 1\nshell: {title: x, main: nope}\nmenu: [{id: a, title: A, panel: grid}]\n"
    )
    rc = main(["render", "--out", str(tmp_path / "o"), "--registry", str(REGISTRY),
               "--views", str(bad), "--state", str(tmp_path / "s.json")])  # fmt: skip
    assert rc == 2 and "not a panel view" in capsys.readouterr().err


def test_bad_registry_and_usage_are_exit_two(tmp_path, capsys):
    (tmp_path / "r.yml").write_text("registry_version: 2\n")
    assert main(["sources", "--registry", str(tmp_path / "r.yml")]) == 2
    assert main(["bogus"]) == 2
    assert main(["collect", "--registry", str(REGISTRY), "--source", "nope"]) == 2


def test_hnx_routes_status(capsys):
    assert cli.main(["status", "--help"]) == 0
    assert "usage: hnx status" in capsys.readouterr().out


def test_collect_records_the_notify_pairs_it_holds_for_the_census(tmp_path, capsys):
    from homelabnext.notify.core_pairs import STATUS_ITEM
    from homelabnext.notify.record import parse_record

    pairs = tmp_path / "pairs"
    pairs.mkdir()
    collect = ["collect", "--registry", str(REGISTRY), "--root", str(ROOT),
               "--state", str(tmp_path / "state.json"), "--notify-topic", "status",
               "--notify-pairs-dir", str(pairs), *FILE_SOURCES]  # fmt: skip
    assert main(collect) == 0
    # the file sources page nothing here, so no message leaves; the pairs are recorded anyway
    assert "notifications sent: 0" in capsys.readouterr().out
    held = parse_record((pairs / "status" / "pairs.json").read_text(), "status").pairs
    assert {"problem": STATUS_ITEM[0], "recovery": STATUS_ITEM[1]} in held
    assert not (pairs / "broker").exists()
