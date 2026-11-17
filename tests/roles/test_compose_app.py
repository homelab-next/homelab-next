# SPDX-License-Identifier: Apache-2.0
"""The compose_app health hook against a fake ``docker compose ps`` (one ansible-playbook run)."""

import grp
import json
import os
import pwd

import pytest
from rolerun import fake, first_run, run_cases

pytestmark = pytest.mark.requires_tool("ansible-playbook")

SPEC = {"services": {"web": {}, "db": {}}}


def row(service, state="running", health=""):
    return {"Service": service, "State": state, "Health": health}


def ndjson(*rows):
    return "".join(json.dumps(r) + "\n" for r in rows)


GOOD = [row("web", health="healthy"), row("db", health="healthy")]
CASES = {
    "ndjson, all up": (ndjson(*GOOD), False, ""),
    "older compose, one array": (json.dumps(GOOD), False, ""),
    "empty output (no containers)": ("", True, "no container for"),
    "empty array": ("[]", True, "no container for"),
    "a service has no container": (ndjson(row("web")), True, "no container for db"),
    "running with no healthcheck": (
        ndjson(row("web", health="healthy"), row("db")),
        True,
        "items failed",
    ),
    "a container is down": (ndjson(row("web"), row("db", "exited")), True, "items failed"),
    "a container is unhealthy": (
        ndjson(row("web", health="unhealthy"), row("db")),
        True,
        "items failed",
    ),
}


def _first(tmp_path):
    # the fake reads <dir>/ps.out for the compose file it is given (-f <dir>/docker-compose.yml)
    bindir = tmp_path / "bin"
    bindir.mkdir()
    fake(
        bindir / "docker",
        "import sys\n"
        "from pathlib import Path\n"
        "sys.stdout.write((Path(sys.argv[sys.argv.index('-f') + 1]).parent / 'ps.out').read_text())\n",
    )
    overrides = []
    for i, (out, _, _) in enumerate(CASES.values()):
        d = tmp_path / f"case{i}"
        d.mkdir()
        (d / "ps.out").write_text(out)
        overrides.append({"compose_app_dir": str(d)})
    return {
        "runner": run_cases,
        "role": "compose_app",
        "tasks_from": "health",
        "base_vars": {"compose_app_name": "demo-app", "compose_app_spec": SPEC},
        "overrides": overrides,
        "env": {"PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}"},
    }


@first_run(_first)
def test_compose_app_health_needs_every_service_running_and_healthy(first):
    results, _ = first
    for (name, (_, fails, msg)), (failed, got) in zip(CASES.items(), results, strict=True):
        assert failed is fails, name
        assert msg in got, (name, got)


# ------------------------------------------------- the cgroup parent needs docker's systemd driver

DOCKER = """import os, sys
open(os.environ["DOCKER_LOG"], "a").write(" ".join(sys.argv[1:]) + "\\n")
if sys.argv[1:2] == ["info"]:
    print(os.environ["DOCKER_DRIVER"])
"""
SYSTEMCTL = """import os
if os.environ["SLICE_UNIT"] == "installed":
    print("LoadState=loaded\\nFragmentPath=/etc/systemd/system/hnx-web_app-server.slice")
else:  # what systemd says of a slice with no unit file
    print("LoadState=not-found\\nFragmentPath=")
"""
DIGEST = "sha256:" + "ab" * 32


def _driver(tmp, driver, unit):
    bindir = tmp / "bin"
    bindir.mkdir()
    fake(bindir / "docker", DOCKER)
    fake(bindir / "systemctl", SYSTEMCTL)
    spec = {"services": {"web": {
        "image": "registry.example.internal/demo/web", "tag": "1.2.3", "digest": DIGEST,
        "healthcheck": {"test": ["CMD", "true"]},
    }}}  # fmt: skip
    return {
        "role": "compose_app",
        "tasks_from": "main",
        "extra_vars": {
            "compose_app_name": "demo-app",
            "compose_app_spec": spec,
            "compose_app_dir": str(tmp / "app"),
            "compose_app_data_dir": str(tmp / "app" / "data"),
            "compose_app_owner": pwd.getpwuid(os.getuid()).pw_name,
            "compose_app_group": grp.getgrgid(os.getgid()).gr_name,
            "compose_app_validate_with_docker": False,
            "compose_app_start": True,
            "hnx_module_slice": "hnx-web_app-server.slice",
        },
        "env": {
            "PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}",
            "DOCKER_LOG": str(tmp / "docker.log"),
            "DOCKER_DRIVER": driver,
            "SLICE_UNIT": unit,
        },
    }


@pytest.mark.parametrize(
    "driver, unit", [("systemd", "installed"), ("cgroupfs", "installed"), ("systemd", "missing")]
)
@first_run(_driver)
def test_a_slice_starts_only_under_systemd_and_with_its_unit_installed(first, driver, unit):
    """With cgroupfs docker would read the slice name as a cgroup directory of its own, outside
    the slice systemd limits; and a slice with no unit file is created empty by systemd.  Either
    way the container would run unconfined while it looked confined, so the start is refused,
    naming the fix."""
    r, tmp = first
    calls = (tmp / "docker.log").read_text().splitlines()
    assert calls[0] == "info --format {{.CgroupDriver}}"
    if (driver, unit) == ("systemd", "installed"):
        assert r.returncode == 0, r.stdout + r.stderr
        assert calls[1].startswith("compose -f ") and calls[1].endswith(" up -d --remove-orphans")
        return
    assert r.returncode != 0
    assert len(calls) == 1  # never started
    if driver == "cgroupfs":
        assert "native.cgroupdriver=systemd" in r.stdout
    else:
        assert "has no unit file: install the module limits first" in r.stdout


# ------------------------------------------------- the boot unit (opt-in): a container that did not
# come back after a power cycle is started at boot (LL-571)

SC = """import os, sys
a = sys.argv[1:]
open(os.environ["SC_LOG"], "a").write(" ".join(a) + "\\n")
flag = os.environ["SC_STATE"]
if a[0] == "enable":
    open(flag, "w").close()
elif a[0] == "is-enabled":
    print("enabled" if os.path.exists(flag) else "disabled")
    sys.exit(0 if os.path.exists(flag) else 1)
"""


def _boot(tmp_path, **over):
    from rolerun import run_role

    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    fake(bindir / "docker", "import sys\n")
    systemctl = fake(bindir / "systemctl", SC)
    units = tmp_path / "units"
    units.mkdir(exist_ok=True)
    v = {
        "compose_app_name": "demo-app",
        "compose_app_spec": {
            "services": {
                "web": {
                    "image": "registry.example.internal/demo/web",
                    "tag": "1.2.3",
                    "digest": DIGEST,
                    "healthcheck": {"test": ["CMD", "true"]},
                }
            }
        },
        "compose_app_dir": str(tmp_path / "app"),
        "compose_app_data_dir": str(tmp_path / "app" / "data"),
        "compose_app_owner": pwd.getpwuid(os.getuid()).pw_name,
        "compose_app_group": grp.getgrgid(os.getgid()).gr_name,
        "compose_app_validate_with_docker": False,
        "compose_app_cgroup_parent": "",
        "compose_app_unit_dir": str(units),
        "compose_app_systemctl_cli": systemctl,
        **over,
    }
    env = {"SC_LOG": str(tmp_path / "sc.log"), "SC_STATE": str(tmp_path / "sc.enabled"),
           "PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}"}  # fmt: skip
    return run_role(tmp_path, str(ROLES / "compose_app"), "main", v, env=env), units


ROLES = __import__("pathlib").Path(__file__).resolve().parents[2] / "ansible" / "roles"


def test_the_boot_unit_is_off_by_default(tmp_path):
    r, units = _boot(tmp_path, compose_app_start=True)
    assert r.returncode == 0, r.stdout + r.stderr
    assert list(units.iterdir()) == []


def test_the_boot_unit_runs_up_d_after_docker_and_is_enabled_once(tmp_path):
    r, units = _boot(tmp_path, compose_app_start=True, compose_app_boot_unit=True)
    assert r.returncode == 0, r.stdout + r.stderr
    text = (units / "hnx-compose-demo-app.service").read_text()
    assert "After=docker.service" in text and "Requires=docker.service" in text
    assert f"ConditionPathExists={tmp_path}/app/docker-compose.yml" in text  # nothing once removed
    assert (
        f"ExecStart=/usr/bin/docker compose -f {tmp_path}/app/docker-compose.yml up -d --remove-orphans"
        in text
    )
    assert "WantedBy=multi-user.target" in text
    log = (tmp_path / "sc.log").read_text().splitlines()
    assert log.count("daemon-reload") == 1 and log.count("enable hnx-compose-demo-app.service") == 1
    r, _ = _boot(tmp_path, compose_app_start=True, compose_app_boot_unit=True)
    assert r.returncode == 0, r.stdout + r.stderr
    log = (tmp_path / "sc.log").read_text().splitlines()
    assert log.count("daemon-reload") == 1 and log.count("enable hnx-compose-demo-app.service") == 1


def test_no_boot_unit_when_nothing_is_started(tmp_path):
    r, units = _boot(tmp_path, compose_app_start=False, compose_app_boot_unit=True)
    assert r.returncode == 0, r.stdout + r.stderr
    assert list(units.iterdir()) == []
