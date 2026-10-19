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
    "multiline description": (entry(description="a\nb"), "single line"),
    # directive injection (security review): a newline adds directives, a trailing backslash
    # joins the next generated line (User=) onto ExecStart
    "exec adds ExecStartPost": (
        entry(exec="/bin/true\nExecStartPost=/bin/sh -c id"),
        "exec: control character",
    ),
    "replaced_by adds a section": (
        entry(replaced_by="y\n[Service]\nExecStart=/bin/evil"),
        "replaced_by: control character",
    ),
    "carriage return": (entry(description="a\rb"), "control character"),
    "exec trailing backslash": (entry(exec="/bin/job \\"), "trailing backslash"),
    "name trailing newline": (entry(name="job\n"), "name must match"),
    "user trailing newline": (entry(user="svc\n"), "control character"),
    "user with space": (entry(user="svc x"), "user must match"),
    "calendar newline": (entry(on_calendar="*-*-* 01:00:00 UTC\nOnBootSec=1"), "control character"),
    "root without opt-in": (entry(user="root"), "run_as_root: true"),
    "run_as_root without root": (entry(user="svc", run_as_root=True), "requires user: root"),
    "unknown hardening opt-out": (
        entry(hardening_opt_out=["ProtectEverything"]),
        "unknown directive",
    ),
    "relative read_write_path": (entry(read_write_paths=["var/lib"]), "absolute paths"),
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


def _service(**kw):
    return fu.render([entry(**kw)])["hnx-job.service"]


def test_review_payload_is_refused():
    spec = HERE / "specs" / "injection.yml"
    with pytest.raises(fu.FleetUnitsError, match="control character"):
        fu.render_file(spec)


def test_retired_unit_runs_nothing():
    text = _service(replaced_by="st2:pack.workflow")
    assert "ExecStart=/bin/false" in text
    assert "/usr/local/bin/job" not in text


def test_default_user_is_dynamic_never_root():
    text = _service()
    assert "DynamicUser=yes" in text and "\nUser=" not in text
    named = _service(user="svc-job")
    assert "User=svc-job" in named and "DynamicUser" not in named
    root = _service(user="root", run_as_root=True)
    assert "User=root" in root


def test_hardening_block_is_on_by_default_with_per_unit_opt_out():
    text = _service()
    for directive, value in fu.HARDENING:
        assert f"\n{directive}={value}\n" in text
    opted = _service(hardening_opt_out=["ProtectHome", "PrivateDevices"])
    assert "ProtectHome=" not in opted and "PrivateDevices=" not in opted
    assert "ProtectSystem=strict" in opted


def test_read_write_paths_open_protect_system_strict():
    text = _service(read_write_paths=["/var/lib/job", "/srv/out"])
    assert "ReadWritePaths=/var/lib/job /srv/out" in text


def test_every_line_is_one_directive():
    """No value can contribute a second directive: one '=' per Service line, known keys only."""
    files = fu.render(yaml.safe_load(SPEC.read_text()))
    for name, content in files.items():
        if not name.endswith(".service"):
            continue
        body = content.split("[Service]\n", 1)[1]
        keys = [ln.split("=", 1)[0] for ln in body.splitlines() if ln]
        allowed = {"Type", "ExecStart", "User", "DynamicUser", "TimeoutStartSec", "ReadWritePaths"}
        allowed |= {d for d, _ in fu.HARDENING}
        assert set(keys) <= allowed, name
        assert keys.count("ExecStart") == 1, name
