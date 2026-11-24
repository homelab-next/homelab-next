# SPDX-License-Identifier: Apache-2.0
"""The flow-monitor network-sensor role (found by slot, see network_monitor_module), run on localhost
against fake commands (CI is unprivileged): main builds the local image from the pinned base and
packages only when it is missing, writes one hardened capture unit per interface, restarts a capture
only when something changed, and a second run is ``changed=0``; a failed build stops before any unit is
written; bad inputs are refused first; health fails a stopped capture, a silent heartbeat, no packets
and drops over the bound; readiness refuses an address on a capture NIC."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
import yaml
from rolerun import fake, first_run, run_role

from tests.modules.network_monitor_module import MID, ROLE_DIR, P

ROLE = str(ROLE_DIR)
CAPTURES = [
    {"slug": "mirror", "interface": "mirror0"},
    {"slug": "guests", "interface": "gre-guests"},
]
DOCKER = r"""
import os, sys
a = sys.argv[1:]
open(os.environ["FAKE_LOG"], "a").write("engine " + " ".join(a) + "\n")
built = os.environ["FAKE_BUILT"]
if a[:2] == ["image", "inspect"]:
    sys.exit(0 if os.path.exists(built) else 1)
if a[:1] == ["build"]:
    if os.path.exists(os.environ["FAKE_BUILD_FAILS"]):
        sys.stderr.write("package did not install\n")
        sys.exit(1)
    open(built, "w").write("x")
"""


def setup_fakes(tmp: Path, active: bool = True) -> dict:
    bindir = tmp / "bin"
    bindir.mkdir(exist_ok=True)
    fake(bindir / "engine", DOCKER)
    fake(
        bindir / "systemctl",
        "import os, sys\nopen(os.environ['FAKE_LOG'], 'a').write('systemctl ' + ' '.join(sys.argv[1:]) + '\\n')\n"
        f"sys.exit({0 if active else 3} if 'is-active' in sys.argv else 0)\n",
    )
    fake(
        bindir / "ip",
        'import sys\nsys.stdout.write(\'[{"ifname":"x","addr_info":[{"family":"inet6"}]}]\')\n',
    )
    return {
        "PATH": f"{bindir}:{os.environ['PATH']}",
        "FAKE_LOG": str(tmp / "calls.log"),
        "FAKE_BUILT": str(tmp / "built"),
        "FAKE_BUILD_FAILS": str(tmp / "build.fails"),
    }


def sv(tmp: Path, **kw) -> dict:
    v = {
        "logical_id": "monitor",
        "capture_interfaces": CAPTURES,
        "build_dir": str(tmp / "build"),
        "log_root": str(tmp / "logs"),
        "unit_dir": str(tmp / "units"),
        "logrotate_dir": str(tmp / "logrotate"),
        "docker_cli": str(tmp / "bin" / "engine"),
        "systemctl_cli": str(tmp / "bin" / "systemctl"),
        "service_manage": False,
        "engine_check": False,
    }
    v.update(kw)
    return {P + k: x for k, x in v.items()}


def prepare(tmp: Path) -> None:
    for d in ("units", "logrotate"):
        (tmp / d).mkdir(parents=True, exist_ok=True)


def case(tmp: Path, hook: str = "main", **kw) -> dict:
    prepare(tmp)
    return {"role": ROLE, "tasks_from": hook, "extra_vars": sv(tmp, **kw), "env": setup_fakes(tmp)}


def defaults() -> dict:
    return yaml.safe_load((ROLE_DIR / "defaults" / "main.yml").read_text())


def _first_main_builds_once_writes_hardened_units_and_a_second_run_changes_nothing(tmp_path):
    return case(tmp_path)


@first_run(_first_main_builds_once_writes_hardened_units_and_a_second_run_changes_nothing)
def test_main_builds_once_writes_hardened_units_and_a_second_run_changes_nothing(first):
    r, tmp = first
    assert r.returncode == 0, r.stdout + r.stderr
    d = defaults()
    dockerfile = (tmp / "build" / "Dockerfile").read_text()
    assert f"FROM {d[P + 'base_image']}" in dockerfile
    for p in d[P + "script_packages"]:
        assert f"{p['name']} --version {p['version']}" in dockerfile
    assert (tmp / "build" / f"self-signed.{MID}").is_file()
    assert "Stats::report_interval = 60sec" in (tmp / "build" / f"hnx-local.{MID}").read_text()
    log = (tmp / "calls.log").read_text()
    assert log.count("engine build -t ") == 1
    for c in CAPTURES:
        unit = (tmp / "units" / f"hnx-{MID}-{c['slug']}.service").read_text()
        assert f"-i {c['interface']} -C local" in unit and "--network host" in unit
        assert "--cap-drop ALL --cap-add NET_RAW --cap-add NET_ADMIN" in unit
        assert "no-new-privileges:true" in unit and "--read-only" in unit and "--memory 2g" in unit
        assert f"{tmp}/logs/{c['slug']}:/" in unit
        assert unit.rstrip().count("ExecStart=") == 1 and "packages" in unit
        assert (tmp / "logs" / c["slug"]).is_dir()
    rot = (tmp / "logrotate" / f"hnx-{MID}").read_text()
    assert f"{tmp}/logs/*/*.log" in rot and "copytruncate" in rot and "maxsize 2G" in rot
    again = run_role(tmp, ROLE, "main", sv(tmp), env=setup_fakes(tmp))
    assert again.returncode == 0 and "changed=0" in again.stdout, again.stdout
    assert (tmp / "calls.log").read_text().count("engine build -t ") == 1  # not rebuilt


def test_the_image_tag_follows_its_inputs(tmp_path):
    prepare(tmp_path)
    one = run_role(tmp_path, ROLE, "main", sv(tmp_path), env=setup_fakes(tmp_path))
    assert one.returncode == 0, one.stdout
    tag1 = next(
        ln
        for ln in (tmp_path / "calls.log").read_text().splitlines()
        if ln.startswith("engine build")
    )
    pk = defaults()[P + "script_packages"]
    changed = [{**pk[0], "version": "v9.9.9"}, *pk[1:]]
    (tmp_path / "built").unlink()
    two = run_role(
        tmp_path, ROLE, "main", sv(tmp_path, script_packages=changed), env=setup_fakes(tmp_path)
    )
    assert two.returncode == 0, two.stdout
    tag2 = [
        ln
        for ln in (tmp_path / "calls.log").read_text().splitlines()
        if ln.startswith("engine build")
    ][-1]
    assert tag1 != tag2


def test_a_failed_build_stops_before_any_unit_is_written(tmp_path):
    prepare(tmp_path)
    (tmp_path / "build.fails").write_text("")
    r = run_role(tmp_path, ROLE, "main", sv(tmp_path), env=setup_fakes(tmp_path))
    assert r.returncode != 0
    assert not list((tmp_path / "units").iterdir())


def test_a_capture_restarts_only_when_a_unit_the_script_or_the_image_changed():
    # the systemd module needs a real systemd, so CI reads the task: the restart is conditioned on
    # exactly the four things that change what a capture runs, and nothing else
    tasks = yaml.safe_load((ROLE_DIR / "tasks" / "main.yml").read_text())
    restart = next(t for t in tasks if t.get("name", "").startswith("Restart the captures"))
    cond = " ".join(str(restart["when"]).split())
    for reg in ("units", "context", "script", "built"):
        assert f"{P}{reg} is changed" in cond
    assert f"{P}service_manage" in cond


@pytest.mark.parametrize(
    "bad",
    [
        {"capture_interfaces": []},
        {"capture_interfaces": [CAPTURES[0], {**CAPTURES[1], "slug": "mirror"}]},
        {"capture_interfaces": [{"slug": "a", "interface": "a-name-that-is-longer-than-fifteen"}]},
        {"capture_interfaces": [{"slug": "Bad Slug", "interface": "x0"}]},
        {"base_image": "docker.io/example/" + MID + ":8.0.8"},
        {
            "script_packages": [
                {"name": "owner/repo/pkg", "version": "master"},
                {"name": "x", "version": "v1"},
            ]
        },
        {"stats_interval": 5},
        {"stats_max_age_seconds": 30, "stats_interval": 60},
        {"max_drop_ratio": 0},
        {"container_memory": "lots"},
        {"log_root": "relative"},
    ],
)
def test_main_refuses_bad_inputs_before_anything_is_written(tmp_path, bad):
    prepare(tmp_path)
    r = run_role(tmp_path, ROLE, "main", sv(tmp_path, **bad), env=setup_fakes(tmp_path))
    assert r.returncode != 0 and f"{MID}:" in r.stdout
    assert not (tmp_path / "build").exists() and not list((tmp_path / "units").iterdir())


# ----------------------------------------------------------------------------- health


def _health(tmp: Path, rows=None, active=True, age=0, **kw):
    prepare(tmp)
    rows = rows if rows is not None else [{"pkts_proc": 100, "pkts_dropped": 1}] * 3
    for c in CAPTURES:
        d = tmp / "logs" / c["slug"]
        d.mkdir(parents=True, exist_ok=True)
        f = d / "stats.log"
        f.write_text("".join(json.dumps(r) + "\n" for r in rows))
        t = f.stat().st_mtime - age
        os.utime(f, (t, t))
    return run_role(tmp, ROLE, "health", sv(tmp, **kw), env=setup_fakes(tmp, active))


def test_health_passes_with_running_captures_a_fresh_heartbeat_and_low_drops(tmp_path):
    r = _health(tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr


def test_health_fails_a_stopped_capture(tmp_path):
    r = _health(tmp_path, active=False)
    assert r.returncode != 0 and "is-active" in r.stdout + r.stderr


def test_health_fails_a_silent_heartbeat(tmp_path):
    r = _health(tmp_path, age=3600)
    assert r.returncode != 0 and "stats.log was not written" in r.stdout


def test_health_fails_when_no_packets_were_processed(tmp_path):
    r = _health(tmp_path, rows=[{"pkts_proc": 0, "pkts_dropped": 0}] * 3)
    assert r.returncode != 0 and "0 packet(s) processed" in r.stdout


def test_health_fails_drops_over_the_bound(tmp_path):
    rows = [{"pkts_proc": 100, "pkts_dropped": 40}] * 3
    r = _health(tmp_path, rows=rows)
    assert r.returncode != 0 and "120 dropped" in r.stdout
    assert _health(tmp_path, rows=rows, max_drop_ratio=0.5).returncode == 0


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


def test_upgrade_refuses_another_repository_and_an_unpinned_target(tmp_path):
    prepare(tmp_path)
    repo = defaults()[P + "base_image"].split("@")[0].rsplit(":", 1)[0]
    for bad in (repo + ":9.0.0", "docker.io/other/x:1@sha256:" + "a" * 64):
        r = run_role(
            tmp_path, ROLE, "upgrade", sv(tmp_path, target_image=bad), env=setup_fakes(tmp_path)
        )
        assert r.returncode != 0 and "the target must be" in r.stdout
    ok = run_role(
        tmp_path,
        ROLE,
        "upgrade",
        sv(tmp_path, target_image=repo + ":9.0.0@sha256:" + "a" * 64),
        env=setup_fakes(tmp_path),
    )
    assert ok.returncode == 0, ok.stdout + ok.stderr
