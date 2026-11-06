# SPDX-License-Identifier: Apache-2.0
"""``hnx novelty run`` and ``hnx novelty corroborate`` over a fixture lake."""

from __future__ import annotations

import json
import shlex
from datetime import datetime
from pathlib import Path

import pytest
from novelty_support import SITE, SPEC, rows

from homelabnext import cli

ROOT = Path(__file__).resolve().parents[2]


def _iso(v):
    return v.isoformat().replace("+00:00", "Z") if isinstance(v, datetime) else v


@pytest.fixture
def files(tmp_path):
    def finding(entity, source, profile):
        return {
            "uid": f"{source}-{entity}",
            "time": "2026-03-09T12:00:00Z",
            "as_of": "2026-03-09T12:00:00Z",
            "source": source,
            "source_kind": "heuristic",
            "profile": profile,
            "entity_kind": "ip",
            "entity": entity,
            "value": "x",
            "status": "finding",
            "tlp": "green",
        }

    lake = {
        "network_activity": [
            {k: _iso(v) if k != "src_endpoint" else v for k, v in r.items()} for r in rows()
        ],
        "novelty_finding": [
            finding("192.0.2.10", "host-kernel", "process-lineage"),
            finding("192.0.2.10", "lake-novelty", "host-dst-port"),
            finding("192.0.2.12", "lake-novelty", "host-dst-port"),
        ],
    }
    paths = {}
    for name, doc in (("spec", SPEC), ("site", SITE), ("lake", lake)):
        paths[name] = tmp_path / f"{name}.json"
        paths[name].write_text(json.dumps(doc))
    return paths


def _main(argv, capsys):
    rc = cli.main(argv)
    out = capsys.readouterr()
    return rc, (json.loads(out.out) if out.out else None), out.err


def test_run_prints_the_summary_and_the_findings(files, capsys):
    argv = ["novelty", "run", "--spec", str(files["spec"]), "--as-of", "2026-03-10T00:00:00Z"]
    argv += ["--site", str(files["site"]), "--fixture", str(files["lake"]), "--show-findings"]
    rc, doc, _ = _main(argv, capsys)
    assert rc == 0
    (p,) = doc["profiles"]
    assert p["status"] == "ok" and p["written"] == 2 and p["replayed"] is False
    assert {(f["entity"], f["value"], f["status"]) for f in doc["findings"]} == {
        ("192.0.2.10", "22", "finding"),
        ("192.0.2.11", "443", "unlearned"),
    }
    rc, dry, _ = _main([*argv, "--dry-run"], capsys)
    assert rc == 0 and dry["dry_run"] is True and "written" not in dry["profiles"][0]
    assert dry["findings"] == doc["findings"]  # the same lake, spec and as_of


def test_run_reports_a_warming_profile(files, capsys):
    argv = ["novelty", "run", "--spec", str(files["spec"]), "--as-of", "2026-03-08T00:00:00Z"]
    rc, doc, _ = _main([*argv, "--site", str(files["site"]), "--fixture", str(files["lake"])], capsys)  # fmt: skip
    assert rc == 0
    (p,) = doc["profiles"]
    assert (p["status"], p["history_days"], p["days_remaining"]) == ("warming", 2, 2)


def test_corroborate_prints_entities_with_two_sources(files, capsys):
    argv = ["novelty", "corroborate", "--since", "2026-03-09T00:00:00Z"]
    argv += ["--until", "2026-03-10T00:00:00Z", "--site", str(files["site"])]
    rc, doc, _ = _main([*argv, "--fixture", str(files["lake"])], capsys)
    assert rc == 0
    (c,) = doc["candidates"]
    assert c["entity"] == "192.0.2.10" and c["sources"] == ["host-kernel", "lake-novelty"]


@pytest.mark.parametrize(
    "extra, match",
    [
        (["--as-of", "2026-03-10T00:00:00"], "UTC offset"),
        (["--as-of", "yesterday"], "ISO 8601"),
    ],
)
def test_as_of_is_an_aware_time(files, capsys, extra, match):
    argv = ["novelty", "run", "--spec", str(files["spec"]), "--site", str(files["site"])]
    try:
        rc = cli.main([*argv, "--fixture", str(files["lake"]), *extra])
    except SystemExit as exc:
        rc = exc.code
    assert rc == 2 and match in capsys.readouterr().err


def test_a_site_without_the_reader_is_refused(files, tmp_path, capsys):
    site = tmp_path / "bare.json"
    site.write_text(json.dumps({"lake_catalog": "lake", "tlp_readers": []}))
    argv = ["novelty", "run", "--spec", str(files["spec"]), "--as-of", "2026-03-10T00:00:00Z"]
    rc, _, err = _main([*argv, "--site", str(site), "--fixture", str(files["lake"])], capsys)
    assert rc == 2 and "no declared TLP ceiling" in err


def test_a_bad_spec_is_a_usage_error(files, tmp_path, capsys):
    spec = tmp_path / "bad.json"
    spec.write_text(json.dumps({**SPEC, "profiles": [{**SPEC["profiles"][0], "table": "nope"}]}))
    argv = ["novelty", "run", "--spec", str(spec), "--as-of", "2026-03-10T00:00:00Z"]
    rc, _, err = _main([*argv, "--site", str(files["site"]), "--fixture", str(files["lake"])], capsys)  # fmt: skip
    assert rc == 2 and "unknown table" in err


def test_an_as_of_with_an_offset_is_the_same_instant(files, capsys):
    argv = ["novelty", "run", "--spec", str(files["spec"]), "--as-of", "2026-03-10T01:00:00+01:00"]
    argv += ["--site", str(files["site"]), "--fixture", str(files["lake"])]
    rc, doc, _ = _main(argv, capsys)
    assert rc == 0
    assert doc["profiles"][0]["score_window"] == ["2026-03-09T00:00:00Z", "2026-03-10T00:00:00Z"]


def _documented_command(path):
    """The ``hnx novelty ...`` command a file documents in its leading comments."""
    lines = [ln[2:].strip() for ln in path.read_text().splitlines() if ln.startswith("# ")]
    start = next(i for i, ln in enumerate(lines) if ln.startswith("hnx novelty run"))
    cmd = [lines[start]]
    while cmd[-1].endswith("\\"):
        cmd[-1] = cmd[-1][:-1]
        cmd.append(lines[start + len(cmd)])
    return shlex.split(" ".join(cmd))


def test_the_example_specs_documented_command_runs(capsys, monkeypatch):
    monkeypatch.chdir(ROOT)
    argv = _documented_command(ROOT / "examples/novelty/spec.yml")
    assert argv[:3] == ["hnx", "novelty", "run"] and "--dry-run" in argv
    rc, doc, _ = _main(argv[1:], capsys)
    assert rc == 0 and doc["tlp"] == "amber"
    assert [p["status"] for p in doc["profiles"]] == ["ok", "ok"]
    assert {(f["entity"], f["value"], f["status"]) for f in doc["findings"]} == {
        ("192.0.2.10", "4444", "finding"),
        ("192.0.2.11", "443", "unlearned"),
        ("alice", "203.0.113.7", "finding"),
    }


def test_writing_needs_the_analyzers_writes_grant(files, tmp_path, capsys):
    site = tmp_path / "read-only.json"
    reader = {"reader": "analyzer:novelty", "ceiling": "amber", "why": "reads only"}
    site.write_text(json.dumps({"lake_catalog": "lake", "tlp_readers": [reader]}))
    argv = ["novelty", "run", "--spec", str(files["spec"]), "--as-of", "2026-03-10T00:00:00Z"]
    argv += ["--site", str(site), "--fixture", str(files["lake"])]
    rc, _, err = _main(argv, capsys)
    assert rc == 2 and "no writes grant for novelty_finding" in err
    rc, doc, _ = _main([*argv, "--dry-run"], capsys)
    assert rc == 0 and doc["profiles"][0]["status"] == "ok"


@pytest.mark.parametrize(
    "site, needle",
    [
        (
            {"tlp_readers": [{"reader": "analyzer:novelty", "ceiling": "amber", "why": "w"}]},
            "lake_catalog",
        ),
        (
            {
                "lake_catalog": "lake",
                "tlp_readers": [{"reader": "analyzer:novelty", "ceiling": "TLP:AMBER", "why": "w"}],
            },
            "ceiling",
        ),
        (
            {
                "lake_catalog": "lake",
                "tlp_readers": [
                    {
                        "reader": "module:x",
                        "ceiling": "amber",
                        "writes": ["novelty_finding"],
                        "why": "w",
                    }
                ],
            },
            "analyzer",
        ),
    ],
)
def test_the_site_is_held_to_the_module_selection_rules(files, tmp_path, capsys, site, needle):
    path = tmp_path / "site.json"
    path.write_text(json.dumps(site))
    argv = ["novelty", "run", "--spec", str(files["spec"]), "--as-of", "2026-03-10T00:00:00Z"]
    rc, _, err = _main([*argv, "--site", str(path), "--fixture", str(files["lake"])], capsys)
    assert rc == 2 and needle in err


def test_an_unreachable_live_lake_is_a_usage_error(files, capsys, monkeypatch):
    monkeypatch.delenv("LAB_WAREHOUSE", raising=False)
    argv = ["novelty", "run", "--spec", str(files["spec"]), "--as-of", "2026-03-10T00:00:00Z"]
    argv += ["--site", str(files["site"]), "--domain", "example.internal", "--dry-run"]
    rc, _, err = _main([*argv, "--warehouse", ""], capsys)
    assert rc == 2 and err.startswith("hnx novelty:")


def test_a_lake_that_cannot_be_resolved_is_a_usage_error(files, capsys, monkeypatch):
    import homelabnext.conform.adapters.lake as adapter

    def unresolved(**kw):
        raise LookupError("lake-query: no endpoint for example.internal")

    monkeypatch.setattr(adapter, "make_lake", unresolved)
    argv = ["novelty", "run", "--spec", str(files["spec"]), "--as-of", "2026-03-10T00:00:00Z"]
    argv += ["--site", str(files["site"]), "--domain", "example.internal", "--warehouse", "lab"]
    rc, _, err = _main([*argv, "--dry-run"], capsys)
    assert rc == 2 and "no endpoint for example.internal" in err
