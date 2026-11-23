# SPDX-License-Identifier: Apache-2.0
"""The signature-based network-sensor role (found by slot, see network_sensor_module), run on localhost against fake commands (CI
is unprivileged): main renders the sensor configuration, hands the guests to the HOME_NET role,
tests the live configuration before anything restarts and restores the previous one when the test
fails, adds the alert-only log to the SIEM agent when it is installed, and a second run is
``changed=0``; bad inputs are refused first; health fails a stopped capture, drops over the bound,
no packets and an eve log that stopped growing; readiness refuses an address on a capture NIC."""

from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path

import pytest
import yaml
from rolerun import fake, first_run, run_role

from tests.modules.network_sensor_module import MID, ROLE_DIR, P

ROOT = Path(__file__).resolve().parents[2]
ROLE = str(ROLE_DIR)

_REG = yaml.safe_load((ROOT / "examples" / "services.yml").read_text())["hosts"]
_A = ipaddress.ip_address(_REG["edge-core"]["address"])
_B = ipaddress.ip_address(_REG["lake-core"]["address"])
_EXTRA4 = str(_A + 30)
_EXTRA6 = str(ipaddress.IPv6Address((0xFD << 120) | 5))
GUESTS = [
    {"id": "guest:app-1", "name": "app-1", "fqdn": "app-1.example.internal", "ip": str(_A),
     "zone": "services", "extra_addresses": [_EXTRA4, _EXTRA6]},
    {"id": "guest:db-1", "name": "db-1", "fqdn": "db-1.example.internal", "ip": str(_B), "zone": "data"},
]  # fmt: skip

UPDATE = r"""
import os, sys
state = os.environ["FAKE_SC_STATE"]
rules = os.environ["FAKE_RULES"]
a = sys.argv[1:]
if a[:1] == ["list-enabled-sources"]:
    sys.stdout.write(open(state).read() if os.path.exists(state) else "")
elif a[:1] == ["enable-source"]:
    open(state, "a").write("  - " + a[1] + "\n")
else:
    open(rules, "w").write("alert ip any any -> any any (msg:\"t\"; sid:1;)\n")
"""

ENGINE = r"""
import os, sys
open(os.environ["FAKE_LOG"], "a").write("main " + " ".join(sys.argv[1:]) + "\n")
sys.exit(1 if os.path.exists(os.environ["FAKE_ENGINE_FAILS"]) else 0)
"""


def setup_fakes(tmp: Path, counters: dict | None = None, active: bool = True) -> dict:
    bindir = tmp / "bin"
    bindir.mkdir(exist_ok=True)
    fake(bindir / MID, ENGINE)
    fake(bindir / f"{MID}-update", UPDATE)
    fake(bindir / f"{MID}sc",
         "import os, sys\nopen(os.environ['FAKE_LOG'], 'a').write('sc ' + ' '.join(sys.argv[1:]) + '\\n')\n"
         "if 'dump-counters' in sys.argv:\n"
         f"    sys.stdout.write({json.dumps(json.dumps({'return': 'OK', 'message': {'capture': counters or {'kernel_packets': 1000, 'kernel_drops': 1}}}))})\n")  # fmt: skip
    fake(bindir / "systemctl",
         "import os, sys\nopen(os.environ['FAKE_LOG'], 'a').write('systemctl ' + ' '.join(sys.argv[1:]) + '\\n')\n"
         f"sys.exit({0 if active else 3} if 'is-active' in sys.argv else 0)\n")  # fmt: skip
    fake(
        bindir / "ip",
        'import sys\nsys.stdout.write(\'[{"ifname":"x","addr_info":[{"family":"inet6"}]}]\')\n',
    )
    return {
        "PATH": f"{bindir}:{os.environ['PATH']}",
        "FAKE_LOG": str(tmp / "calls.log"),
        "FAKE_ENGINE_FAILS": str(tmp / "engine.fails"),
        "FAKE_SC_STATE": str(tmp / "enabled-sources"),
        "FAKE_RULES": str(tmp / "lib" / "rules" / f"{MID}.rules"),
    }


def sv(tmp: Path, **kw) -> dict:
    v = {
        "logical_id": "sensor",
        "capture_interfaces": ["mirror0", "gre-guests"],
        "guests": GUESTS,
        "config_dir": str(tmp / "etc"),
        "log_dir": str(tmp / "log"),
        "lib_dir": str(tmp / "lib"),
        "logrotate_dir": str(tmp / "logrotate"),
        "siem_agent_conf": str(tmp / "ossec" / "ossec.conf"),
        "install_packages": False,
        "service_manage": False,
    }
    v.update(kw)
    return {P + k: x for k, x in v.items()}


def prepare(tmp: Path) -> None:
    for d in ("etc", "log", "lib/rules", "units", "logrotate"):
        (tmp / d).mkdir(parents=True, exist_ok=True)


def case(tmp: Path, hook: str = "main", **kw) -> dict:
    prepare(tmp)
    return {"role": ROLE, "tasks_from": hook, "extra_vars": sv(tmp, **kw), "env": setup_fakes(tmp)}


def _first_main_renders_the_sensor_and_a_second_run_changes_nothing(tmp_path):
    return case(tmp_path)


@first_run(_first_main_renders_the_sensor_and_a_second_run_changes_nothing)
def test_main_renders_the_sensor_and_a_second_run_changes_nothing(first):
    r, tmp = first
    assert r.returncode == 0, r.stdout + r.stderr
    conf = yaml.safe_load((tmp / "etc" / f"{MID}.yaml").read_text())
    assert [a["interface"] for a in conf["af-packet"]] == ["mirror0", "gre-guests"]
    assert len({a["cluster-id"] for a in conf["af-packet"]}) == 2
    assert conf["vars"]["address-groups"] == {"include": "hnx-address-groups.yaml"}
    eve = [o["eve-log"] for o in conf["outputs"]]
    assert [e["filename"] for e in eve] == ["eve.json", "eve-alert.json"]
    assert [next(iter(t)) if isinstance(t, dict) else t for t in eve[1]["types"]] == ["alert"]
    assert conf["stats"]["interval"] == 60
    # the generated HOME_NET carries every address, extra and IPv6 included
    groups = yaml.safe_load((tmp / "etc" / "hnx-address-groups.yaml").read_text())
    assert groups["HOME_NET"] == "[" + ",".join(sorted([str(_A), str(_B), _EXTRA4, _EXTRA6])) + "]"
    assert groups["HNX_ZONE_SERVICES"] == "[" + ",".join(sorted([str(_A), _EXTRA4, _EXTRA6])) + "]"
    # the ruleset source was enabled before the fetch and the whole configuration was gated
    log = (tmp / "calls.log").read_text()
    assert "main -T -c " + str(tmp / "etc" / f"{MID}.yaml") in log
    assert (tmp / "enabled-sources").read_text().strip() == "- et/open"
    assert (tmp / "lib" / "rules" / f"{MID}.rules").exists()
    again = run_role(tmp, ROLE, "main", sv(tmp), env=setup_fakes(tmp))
    assert again.returncode == 0 and "changed=0" in again.stdout, again.stdout


def _first_main_writes_the_rotation_rule_and_starts_nothing(tmp_path):
    return case(tmp_path, logrotate_max_size="1G")


@first_run(_first_main_writes_the_rotation_rule_and_starts_nothing)
def test_main_writes_the_rotation_rule_and_starts_nothing(first):
    r, tmp = first
    assert r.returncode == 0, r.stdout + r.stderr
    rot = (tmp / "logrotate" / f"hnx-{MID}").read_text()
    assert f"{tmp}/log/eve.json" in rot and f"{tmp}/log/eve-alert.json" in rot
    assert "maxsize 1G" in rot and "reopen-log-files" in rot
    assert not list((tmp / "units").iterdir())  # no unit of its own: nothing a timer must catalogue
    assert "systemctl" not in (tmp / "calls.log").read_text()  # service_manage is false


@pytest.mark.parametrize(
    "bad",
    [
        {"capture_interfaces": []},
        {"capture_interfaces": ["a", "a"]},
        {"capture_interfaces": ["a-name-that-is-longer-than-fifteen"]},
        {"capture_interfaces": ["bad name"]},
        {"eve_alert_file": "eve.json"},
        {"eve_types": ["alert", "nonsense"]},
        {"rule_sources": ["et open"]},
        {"max_drop_ratio": 0},
        {"eve_max_age_seconds": 30, "stats_interval": 60},
        {"package_version": "latest*"},
        {"log_dir": "relative/dir"},
    ],
)
def test_main_refuses_bad_inputs_before_anything_is_written(tmp_path, bad):
    r = run_role(tmp_path, ROLE, "main", sv(tmp_path, **bad), env=setup_fakes(tmp_path))
    assert r.returncode != 0 and f"{MID}:" in r.stdout
    assert not (tmp_path / "etc" / f"{MID}.yaml").exists()


def test_main_refuses_an_empty_guest_list(tmp_path):
    prepare(tmp_path)
    r = run_role(tmp_path, ROLE, "main", sv(tmp_path, guests=[]), env=setup_fakes(tmp_path))
    assert r.returncode != 0 and "HOME_NET" in r.stdout
    assert not (tmp_path / "etc" / f"{MID}.yaml").exists()


def test_a_failed_gate_restores_the_previous_configuration_and_restarts_nothing(tmp_path):
    ok = run_role(tmp_path, **case(tmp_path))
    assert ok.returncode == 0, ok.stdout + ok.stderr
    live = tmp_path / "etc" / f"{MID}.yaml"
    before = live.read_text()
    (tmp_path / "engine.fails").write_text("")
    r = run_role(tmp_path, ROLE, "main", sv(tmp_path, eve_types=["alert"],
                                            service_manage=True),
                 env=setup_fakes(tmp_path))  # fmt: skip
    assert r.returncode != 0 and "previous configuration was restored" in r.stdout
    assert live.read_text() == before
    assert "restart" not in (tmp_path / "calls.log").read_text()


@first_run(lambda tmp: {**case(tmp), "setup": {"ossec": tmp / "ossec" / "ossec.conf"}})
def test_the_alert_only_log_is_added_to_an_installed_agent_once(first):
    r, tmp = first
    assert r.returncode == 0, r.stdout + r.stderr
    assert "no SIEM agent reads it yet" in r.stdout and not first.setup["ossec"].exists()
    ossec = first.setup["ossec"]
    ossec.parent.mkdir()
    ossec.write_text("<ossec_config>\n  <client/>\n</ossec_config>\n")
    for _ in range(2):
        again = run_role(tmp, ROLE, "main", sv(tmp), env=setup_fakes(tmp))
        assert again.returncode == 0, again.stdout + again.stderr
    text = ossec.read_text()
    assert text.count("<location>" + str(tmp / "log" / "eve-alert.json") + "</location>") == 1
    assert text.count(f"hnx-{MID} alert log") == 2 and "<client/>" in text


# ----------------------------------------------------------------------------- health


def _health(tmp: Path, counters=None, active=True, eve_age=0, **kw):
    prepare(tmp)
    eve = tmp / "log" / "eve.json"
    eve.write_text("{}\n")
    t = eve.stat().st_mtime - eve_age
    os.utime(eve, (t, t))
    return run_role(tmp, ROLE, "health", sv(tmp, **kw), env=setup_fakes(tmp, counters, active))


def test_health_passes_with_a_running_capture_low_drops_and_a_fresh_eve_log(tmp_path):
    r = _health(tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr


def test_health_fails_a_stopped_capture(tmp_path):
    r = _health(tmp_path, active=False)
    assert r.returncode != 0 and "is-active" in r.stdout + r.stderr


def test_health_fails_when_nothing_was_captured(tmp_path):
    r = _health(tmp_path, counters={"kernel_packets": 0, "kernel_drops": 0})
    assert r.returncode != 0 and "capture is not healthy" in r.stdout


def test_health_fails_kernel_drops_over_the_bound(tmp_path):
    r = _health(tmp_path, counters={"kernel_packets": 1000, "kernel_drops": 400})
    assert r.returncode != 0 and "400 kernel drop" in r.stdout
    ok = _health(tmp_path, counters={"kernel_packets": 1000, "kernel_drops": 400},
                 max_drop_ratio=0.5)  # fmt: skip
    assert ok.returncode == 0, ok.stdout


def test_health_fails_an_eve_log_that_stopped_growing(tmp_path):
    r = _health(tmp_path, eve_age=3600)
    assert r.returncode != 0 and "was not written in the last 300 seconds" in r.stdout


# ----------------------------------------------------------------------------- readiness, upgrade


def test_readiness_refuses_an_ipv4_address_on_a_capture_interface(tmp_path):
    prepare(tmp_path)
    env = setup_fakes(tmp_path)
    fake(
        tmp_path / "bin" / "ip",
        'import sys\nsys.stdout.write(\'[{"ifname":"x","addr_info":[{"family":"inet"}]}]\')\n',
    )
    r = run_role(tmp_path, ROLE, "readiness", sv(tmp_path), env=env)
    assert r.returncode != 0 and "holds an IPv4 address" in r.stdout


def test_readiness_passes_with_addressless_capture_interfaces(tmp_path):
    prepare(tmp_path)
    r = run_role(tmp_path, ROLE, "readiness", sv(tmp_path), env=setup_fakes(tmp_path))
    assert r.returncode == 0, r.stdout + r.stderr


def test_upgrade_refuses_a_target_that_is_not_a_package_version(tmp_path):
    prepare(tmp_path)
    r = run_role(tmp_path, ROLE, "upgrade", sv(tmp_path, target_version="*"),
                 env=setup_fakes(tmp_path))  # fmt: skip
    assert r.returncode != 0 and "package version" in r.stdout
    ok = run_role(tmp_path, ROLE, "upgrade", sv(tmp_path, target_version="1:7.0.11-1"),
                  env=setup_fakes(tmp_path))  # fmt: skip
    assert ok.returncode == 0, ok.stdout + ok.stderr


def test_the_module_has_no_secret_and_renders_no_credential():
    files = [p for p in Path(ROLE).rglob("*") if p.is_file()]
    assert not any("hnx_secret" in p.read_text() for p in files)
