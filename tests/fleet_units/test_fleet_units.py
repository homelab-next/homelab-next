# SPDX-License-Identifier: Apache-2.0
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from homelabnext.generators import fleet_units as fu

HERE = Path(__file__).parent
SPEC = HERE / "specs" / "basic.yml"
GOLDEN = HERE / "golden"


def entry(**kw):
    e = {"name": "job", "exec": "/usr/local/bin/job", "on_calendar": "*-*-* 01:00:00 UTC"}
    e.update(kw)
    return e


def test_goldens_are_byte_identical():
    files = fu.render_file(SPEC)
    assert sorted(files) == sorted(p.name for p in GOLDEN.iterdir())
    for name, content in files.items():
        assert content.encode() == (GOLDEN / name).read_bytes(), name


def test_render_is_deterministic_and_order_independent():
    spec = yaml.safe_load(SPEC.read_text())
    assert fu.render(spec) == fu.render(list(reversed(spec)))
    assert list(fu.render(spec)) == sorted(fu.render(spec))


def test_cli_writes_identical_bytes(tmp_path):
    assert fu.main([str(SPEC), str(tmp_path)]) == 0
    for p in GOLDEN.iterdir():
        assert (tmp_path / p.name).read_bytes() == p.read_bytes()


def test_cli_refusal_exit_code(tmp_path, capsys):
    bad = tmp_path / "bad.yml"
    bad.write_text(yaml.safe_dump([entry(on_calendar="*-*-* 01:00:00 America/Los_Angeles")]))
    assert fu.main([str(bad), str(tmp_path / "out")]) == 1
    assert "only UTC" in capsys.readouterr().err
    assert not (tmp_path / "out").exists()
    assert fu.main([str(tmp_path / "missing.yml"), str(tmp_path / "out")]) == 2


def test_pages_directly_and_retired_semantics():
    files = fu.render(yaml.safe_load(SPEC.read_text()))
    assert "OnFailure=hnx-page@%n.service" in files["hnx-notify-digest.service"]
    assert "OnFailure" not in files["hnx-lake-compact.service"]
    assert "[Install]" not in files["hnx-legacy-sweep.timer"]
    assert "retired hnx-legacy-sweep.timer" in files["fleet-units.manifest"]


def test_timers_are_oncalendar_only():
    for name, content in fu.render(yaml.safe_load(SPEC.read_text())).items():
        if name.endswith(".timer"):
            assert "OnCalendar=" in content
            for banned in (
                "OnBootSec",
                "OnUnitActiveSec",
                "OnUnitInactiveSec",
                "OnActiveSec",
                "OnStartupSec",
            ):
                assert banned not in content


REFUSED = {
    "deadlock pair": (
        entry(on_boot_sec="2min", on_unit_active_sec="5min"),
        "OnBootSec + OnUnitActiveSec",
    ),
    "OnBootSec alone": (entry(on_boot_sec="2min"), "OnBootSec"),
    "OnUnitActiveSec alone": (entry(on_unit_active_sec="5min"), "OnUnitActiveSec"),
    "OnUnitInactiveSec": (entry(on_unit_inactive_sec="5min"), "OnUnitInactiveSec"),
    "OnCalendar plus monotonic": (entry(on_boot_sec="2min"), "OnCalendar-only"),
    "no timezone": (entry(on_calendar="*-*-* 01:00:00"), "no time zone"),
    "named zone": (entry(on_calendar="*-*-* 01:00:00 Europe/Berlin"), "only UTC"),
    "abbrev zone": (entry(on_calendar="*-*-* 01:00:00 EST"), "only UTC"),
    "lowercase utc": (entry(on_calendar="*-*-* 01:00:00 utc"), "only UTC"),
    "shorthand daily": (entry(on_calendar="daily"), "shorthand"),
    "shorthand hourly": (entry(on_calendar="hourly"), "shorthand"),
    "bare UTC": (entry(on_calendar="UTC"), "no time expression"),
    "one bad calendar in list": (
        entry(on_calendar=["*-*-* 01:00:00 UTC", "*-*-* 02:00:00 PST"]),
        "only UTC",
    ),
    "missing calendar": ({"name": "job", "exec": "/bin/x"}, "on_calendar is required"),
    "relative exec": (entry(exec="bin/job"), "absolute path"),
    "bad name": (entry(name="Bad_Name"), "name must match"),
    "unknown key": (entry(oncalendar="x"), "unknown key"),
    "non-bool persistent": (entry(persistent="yes"), "boolean"),
    "negative delay": (entry(randomized_delay_sec=-1), "non-negative"),
    "multiline description": (entry(description="a\nb"), "single-line"),
}


@pytest.mark.parametrize("case", sorted(REFUSED))
def test_refused(case):
    e, msg = REFUSED[case]
    with pytest.raises(fu.FleetUnitsError, match=msg.replace("+", r"\+")):
        fu.render([e])


def test_duplicate_and_empty_specs_refused():
    with pytest.raises(fu.FleetUnitsError, match="duplicate"):
        fu.render([entry(), entry()])
    for bad in ([], None, {"name": "x"}, ["str"]):
        with pytest.raises(fu.FleetUnitsError):
            fu.render(bad)


@pytest.mark.skipif(shutil.which("systemd-analyze") is None, reason="systemd-analyze not installed")
def test_calendar_expressions_parse_with_systemd_analyze():
    for e in yaml.safe_load(SPEC.read_text()):
        cals = e["on_calendar"] if isinstance(e["on_calendar"], list) else [e["on_calendar"]]
        for c in cals:
            r = subprocess.run(["systemd-analyze", "calendar", c], capture_output=True, text=True)
            if "Failed to parse" in r.stderr + r.stdout and "time zone" in r.stderr.lower():
                pytest.skip("systemd too old for explicit zones")
            assert r.returncode == 0, (c, r.stderr)
