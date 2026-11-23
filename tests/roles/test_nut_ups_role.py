# SPDX-License-Identifier: Apache-2.0
"""The role ``nut_ups`` (control ups-protection): ``config`` renders NUT's files with a MONITOR line
and loopback-only upsd, against fake systemctl/upsc/upsmon; the checker script (rendered, run as a
subprocess) writes the textfile metrics and forces a shutdown only on battery under the charge floor;
``validate`` refuses values that could add a config line.  Nothing here shuts anything down."""

from __future__ import annotations

import grp
import json
import os
import pwd
import subprocess
import sys
from pathlib import Path

import pytest
from rolerun import calls, fake, last_run_vars, logging_fake, run_cases, run_role

jinja2 = pytest.importorskip("jinja2")
pytestmark = pytest.mark.requires_tool("ansible-playbook")

ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = ROOT / "ansible/roles/nut_ups/templates/nut-ups-check.py.j2"
GROUP = grp.getgrgid(os.getgid()).gr_name


def _vars(tmp_path, **kw):
    d = {
        **last_run_vars(tmp_path, "nut_ups"),
        "nut_ups_name": "pm-ups",
        "nut_ups_vendorid": "075d",
        "nut_ups_productid": "0300",
        "nut_ups_conf_dir": str(tmp_path / "nut"),
        "nut_ups_conf_owner": pwd.getpwuid(os.getuid()).pw_name,
        "nut_ups_conf_group": GROUP,
        "nut_ups_state_dir": str(tmp_path / "state"),
        "nut_ups_libexec_dir": str(tmp_path / "libexec"),
        "nut_ups_systemd_dir": str(tmp_path / "systemd"),
        "nut_ups_textfile_dir": str(tmp_path / "textfile"),
        "nut_ups_systemctl_cli": logging_fake(tmp_path, "systemctl", "active\n"),
        "nut_ups_upsc_cli": fake(
            tmp_path / "upsc", "print('ups.status: OL')\nprint('battery.charge: 100')\n"
        ),
    }
    d.update(kw)
    (tmp_path / "nut").mkdir(exist_ok=True)
    (tmp_path / "systemd").mkdir(exist_ok=True)
    return d


def test_config_renders_a_monitor_line_loopback_upsd_and_is_idempotent(tmp_path):
    v = _vars(tmp_path)
    r = run_role(tmp_path, "nut_ups", "config", v)
    assert r.returncode == 0, r.stdout + r.stderr
    mon = (tmp_path / "nut/upsmon.conf").read_text()
    pw = (tmp_path / "state/upsmon-password").read_text().strip()
    assert len(pw) >= 20
    assert f"MONITOR pm-ups@localhost 1 upsmon {pw} primary" in mon
    assert "MINSUPPLIES 1" in mon and 'SHUTDOWNCMD "/sbin/shutdown -h +0' in mon
    assert "upsmon primary" in (tmp_path / "nut/upsd.users").read_text()
    upsd = (tmp_path / "nut/upsd.conf").read_text()
    assert "LISTEN localhost 3493" in upsd and "0.0.0.0" not in upsd
    ups = (tmp_path / "nut/ups.conf").read_text()
    assert "driver = usbhid-ups" in ups and "vendorid = 075d" in ups and "productid = 0300" in ups
    assert oct((tmp_path / "state/upsmon-password").stat().st_mode & 0o777) == "0o600"
    assert (tmp_path / "textfile/nut_ups.prom").exists()  # the checker ran once
    n = [c for c in calls(tmp_path) if "is-active" not in c]
    assert n == [
        "systemctl daemon-reload",
        "systemctl restart nut-driver.target nut-server.service",
        "systemctl restart nut-monitor.service",
    ]
    r2 = run_role(tmp_path, "nut_ups", "config", v)
    assert r2.returncode == 0, r2.stdout + r2.stderr
    assert (tmp_path / "state/upsmon-password").read_text().strip() == pw  # login kept
    assert [
        c for c in calls(tmp_path) if "is-active" not in c
    ] == n  # unchanged: no restart, no daemon-reload


def _render(tmp_path, **kw):
    v = {
        "nut_ups_name": "pm-ups",
        "nut_ups_upsc_cli": str(tmp_path / "upsc"),
        "nut_ups_upsmon_cli": str(tmp_path / "upsmon"),
        "nut_ups_systemctl_cli": str(tmp_path / "systemctl"),
        "nut_ups_textfile_dir": str(tmp_path),
        "nut_ups_shutdown_charge_percent": 20,
    }
    v.update(kw)
    out = tmp_path / "check.py"
    env = jinja2.Environment(undefined=jinja2.StrictUndefined, keep_trailing_newline=True)
    env.filters["to_json"] = json.dumps
    out.write_text(env.from_string(TEMPLATE.read_text()).render(**v))
    return out


def _run_check(tmp_path, status, charge, monitor="active\n", **kw):
    fake(tmp_path / "upsc", f"print('ups.status: {status}')\nprint('battery.charge: {charge}')\n")
    logging_fake(tmp_path, "upsmon")
    logging_fake(tmp_path, "systemctl", monitor)
    script = _render(tmp_path, **kw)
    r = subprocess.run([sys.executable, str(script)], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    return (tmp_path / "nut_ups.prom").read_text()


def test_checker_on_mains_writes_metrics_and_never_forces_shutdown(tmp_path):
    prom = _run_check(tmp_path, "OL", 100)
    assert 'nut_ups_up{ups="pm-ups"} 1' in prom and 'nut_ups_on_battery{ups="pm-ups"} 0' in prom
    assert (
        'nut_ups_battery_charge_percent{ups="pm-ups"} 100' in prom
        and "nut_monitor_active 1" in prom
    )
    assert calls(tmp_path) == ["systemctl is-active nut-monitor.service"]


def test_checker_reports_a_failed_monitor_as_zero(tmp_path):
    (tmp_path / "systemctl.fails").touch()
    prom = _run_check(tmp_path, "OL", 100, monitor="failed\n")
    assert "nut_monitor_active 0" in prom


def test_checker_on_battery_above_the_floor_only_reports(tmp_path):
    prom = _run_check(tmp_path, "OB DISCHRG", 60)
    assert 'nut_ups_on_battery{ups="pm-ups"} 1' in prom
    assert not any(c.startswith("upsmon") for c in calls(tmp_path))


def test_checker_on_battery_at_the_floor_asks_upsmon_for_a_forced_shutdown(tmp_path):
    prom = _run_check(tmp_path, "OB DISCHRG", 20)
    assert 'nut_ups_on_battery{ups="pm-ups"} 1' in prom
    assert "upsmon -c fsd" in calls(tmp_path)


def test_checker_low_battery_flag_is_exported(tmp_path):
    prom = _run_check(tmp_path, "OB LB", 50)
    assert 'nut_ups_low_battery{ups="pm-ups"} 1' in prom


def test_checker_fallback_off_never_forces(tmp_path):
    _run_check(tmp_path, "OB DISCHRG", 5, nut_ups_shutdown_charge_percent=0)
    assert not any(c.startswith("upsmon") for c in calls(tmp_path))


def test_checker_with_an_unreadable_ups_reports_down_and_no_charge(tmp_path):
    fake(tmp_path / "upsc", "import sys\nsys.exit(1)\n")
    logging_fake(tmp_path, "upsmon")
    logging_fake(tmp_path, "systemctl", "active\n")
    subprocess.run([sys.executable, str(_render(tmp_path))], check=True)
    prom = (tmp_path / "nut_ups.prom").read_text()
    assert 'nut_ups_up{ups="pm-ups"} 0' in prom and "battery_charge_percent" not in prom
    assert not any(c.startswith("upsmon") for c in calls(tmp_path))


def test_validate_refuses_values_that_could_add_a_config_line(tmp_path):
    base = _vars(tmp_path)
    over = {
        "ok": {},
        "newline-name": {"nut_ups_name": "a\nb"},
        "bad-vendor": {"nut_ups_vendorid": "xyz1"},
        "bad-cmd": {"nut_ups_shutdown_cmd": "x; reboot"},
        "charge-high": {"nut_ups_shutdown_charge_percent": 95},
        "rel-path": {"nut_ups_conf_dir": "relative/nut"},
    }
    res = run_cases(tmp_path, "nut_ups", "readiness", base, list(over.values()))
    failed = [r[0] for r in res]
    assert failed[0] is False and all(failed[1:]), res
