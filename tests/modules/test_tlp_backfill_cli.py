# SPDX-License-Identifier: Apache-2.0
"""``hnx modules tlp-backfill``: prints the backfill plan, exit 2 when it cannot be made."""

import json

from homelabnext.logpipeline import tlp_labels as tl
from homelabnext.modules.cli import main
from homelabnext.tlp import Label


def _sources(tmp_path):
    doc = tl.table_doc([("feeds/open", Label.GREEN, False), ("feeds/shared", Label.AMBER, True)])
    path = tmp_path / "tlp-sources.json"
    path.write_text(json.dumps(doc))
    return path


def test_prints_the_plan(tmp_path, capsys):
    mapping = tmp_path / "map.json"
    mapping.write_text(json.dumps({"sensor-a": "feeds/open"}))
    code = main(
        [
            "tlp-backfill",
            "--sources", str(_sources(tmp_path)),
            "--table", "authentication",
            "--qualified", "lake.ocsf.authentication",
            "--route", "feeds/open",
            "--route", "feeds/shared",
            "--map", str(mapping),
            "--source-column", "metadata.log_source",
        ]
    )  # fmt: skip
    out = capsys.readouterr().out.splitlines()
    assert code == 0
    assert out[0].startswith("-- the TLP backfill of lake.ocsf.authentication: run it only if")
    assert "feeds/open, feeds/shared" in out[0]
    assert out[1].startswith("ALTER TABLE lake.ocsf.authentication ADD COLUMN IF NOT EXISTS")
    assert "'green'" in out[2] and "'sensor-a'" in out[2]
    assert out[-3] == 'UPDATE lake.ocsf.authentication SET "tlp" = \'red\' WHERE "tlp" IS NULL;'


def test_an_unknown_route_or_table_is_exit_2(tmp_path, capsys):
    base = ["tlp-backfill", "--sources", str(_sources(tmp_path)), "--qualified", "t"]
    assert main([*base, "--table", "authentication", "--route", "feeds/nope"]) == 2
    assert "does not hold" in capsys.readouterr().err
    assert main([*base, "--table", "nope", "--route", "feeds/open"]) == 2
    assert "unknown table" in capsys.readouterr().err


def test_a_map_and_a_source_column_go_together_and_bad_input_is_exit_2(tmp_path, capsys):
    sources = str(_sources(tmp_path))
    base = ["tlp-backfill", "--sources", sources, "--table", "authentication", "--qualified", "t"]
    base += ["--route", "feeds/open"]
    assert main([*base, "--source-column", "metadata.log_source"]) == 2
    assert "go together" in capsys.readouterr().err
    bad = tmp_path / "bad.json"
    bad.write_text("[1, 2]")
    assert main([*base, "--map", str(bad), "--source-column", "metadata.log_source"]) == 2
    assert "JSON object" in capsys.readouterr().err
    broken = tmp_path / "broken.json"
    broken.write_text("{not json")
    assert main(["tlp-backfill", "--sources", str(broken), "--table", "authentication",
                 "--qualified", "t", "--route", "feeds/open"]) == 2  # fmt: skip
    assert "broken.json" in capsys.readouterr().err
