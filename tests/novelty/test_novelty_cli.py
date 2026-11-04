# SPDX-License-Identifier: Apache-2.0
"""``hnx novelty run`` and ``hnx novelty corroborate`` over a fixture lake."""

from __future__ import annotations

import json
from datetime import datetime

import pytest
from novelty_support import SITE, SPEC, rows

from homelabnext import cli


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
    site.write_text(json.dumps({"tlp_readers": []}))
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
