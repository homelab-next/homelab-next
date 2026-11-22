# SPDX-License-Identifier: Apache-2.0
"""The endpoint-forensics server role against the REAL pinned image and a real container engine.

Marked ``live``: it needs docker and the image (pulled from the registry), so the default CI job
(``-m "not live"``) never runs it, and it only runs when ``HNX_LIVE_IMAGE=1``. It is what the
unit-level tests stand in for, run by hand before a change to the role or an image bump:

* the role converges on a real server (first start generates the configuration, the principal is
  made, the server restarted once) and ``health`` passes, which runs the host script's probes in
  the real container: both ports verified against the server's own authority, the principal's
  effective policy equal to the allow-list, ``execve`` and ``artifact_set`` refused;
* a container restart and a recreate keep the configuration's sha256 (the start guard, LL-087);
* the image's own entrypoint, run the way the guard prevents, DOES rotate it (the control).
"""

from __future__ import annotations

import grp
import hashlib
import json
import os
import pwd
import socket
import subprocess
import time
from pathlib import Path

import pytest
from rolerun import fake, run_role

from tests.modules.endpoint_forensics_module import MID, SERVER, SP, env_for, ref, server_defaults
from tests.modules.endpoint_forensics_script import catalog_doc

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        os.environ.get("HNX_LIVE_IMAGE") != "1",
        reason="the real image is not available (set HNX_LIVE_IMAGE=1 with docker)",
    ),
]

PASSWORD = "fake-pw-live-run"
USER = pwd.getpwuid(os.getuid()).pw_name
GROUP = grp.getgrgid(os.getgid()).gr_name


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def compose(app: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "compose", "-f", str(app / "docker-compose.yml"), *args],
        capture_output=True, text=True, check=False,
    )  # fmt: skip


def wait_healthy(app: Path, seconds: int = 120) -> None:
    for _ in range(seconds // 3):
        out = compose(app, "ps", "--all", "--format", "json").stdout
        if '"Health":"healthy"' in out.replace(" ", ""):
            return
        time.sleep(3)
    raise AssertionError("the container did not become healthy: " + out[-500:])


def test_the_role_converges_on_the_real_image_and_the_start_guard_keeps_the_authority(tmp_path):
    bind = socket.gethostbyname("localhost")
    (tmp_path / "bin").mkdir()
    sc = fake(
        tmp_path / "bin" / "systemctl",
        "import sys\nsys.exit(0 if sys.argv[1] != 'is-enabled' else 3)\n",
    )
    (tmp_path / "units").mkdir()
    v = {
        f"{SP}logical_id": "endpoint-forensics",
        f"{SP}frontend_hostname": "localhost",
        "ansible_host": bind,
        f"{SP}dir": str(tmp_path / "app"),
        f"{SP}data_root": str(tmp_path / "data"),
        f"{SP}owner": USER,
        f"{SP}group": GROUP,
        f"{SP}uid": os.getuid(),
        f"{SP}gid": os.getgid(),
        f"{SP}client_config_group": GROUP,
        f"{SP}results_group": GROUP,
        f"{SP}frontend_port": 18000,
        f"{SP}gui_port": 18889,
        f"{SP}unit_dir": str(tmp_path / "units"),
        f"{SP}systemctl_cli": sc,
        f"{SP}last_run_dir": str(tmp_path / "last-run"),
        f"{SP}last_run_group": GROUP,
        f"{SP}last_run_writer": str(tmp_path / "libexec" / "hnx-last-run"),
        f"{SP}script": str(tmp_path / "libexec" / "cycle"),
        f"{SP}check_script": str(tmp_path / "libexec" / "check"),
        f"{SP}config_dir": str(tmp_path / "etc"),
        f"{SP}config_file": str(tmp_path / "etc" / "config.json"),
        f"{SP}catalog_file": str(tmp_path / "etc" / "catalog.yml"),
    }
    env = {env_for(ref("admin-password")): PASSWORD}
    try:
        r = run_role(tmp_path, str(SERVER), "main", v, env=env)
        assert r.returncode == 0, r.stdout[-3000:] + r.stderr[-1000:]
        etc = tmp_path / "data" / "etc"
        before = sha(etc / "server.config.yaml")
        h = run_role(tmp_path, str(SERVER), "health", v, env=env)
        assert h.returncode == 0, h.stdout[-3000:] + h.stderr[-1000:]
        # the cycle, on the real server: the fleet is read, one hunt over the allow-list is started
        cycle = [
            str(tmp_path / "libexec" / "cycle"),
            "--config",
            str(tmp_path / "etc" / "config.json"),
            "cycle",
        ]
        done = subprocess.run(cycle, capture_output=True, text=True, check=False, timeout=300)
        assert done.returncode == 0, done.stderr
        status = json.loads((tmp_path / "data" / "status" / "fleet.json").read_text())
        assert (
            status["service_up"] is True
            and status["problems"] == []
            and status["clients_total"] == 0
        )
        (hunt,) = json.loads((tmp_path / "data" / "state" / "hunts.json").read_text())["hunts"]
        assert hunt["hunt_id"].startswith("H.") and hunt["collected"] is False
        assert (
            subprocess.run(
                cycle, capture_output=True, text=True, check=False, timeout=300
            ).returncode
            == 0
        )
        assert (
            len(json.loads((tmp_path / "data" / "state" / "hunts.json").read_text())["hunts"]) == 1
        )
        # the principal holds exactly the allow-list's permissions, in the real server
        want = {p.lower() for p in catalog_doc()["principal"]["permissions"]}
        out = compose(tmp_path / "app", "exec", "-T", MID, f"/bin/{MID}", "--config",
                      f"/etc/{MID}/server.config.yaml", "acl", "show", "hnx-hunt")  # fmt: skip
        assert {
            k for k, x in json.loads(out.stdout.strip().splitlines()[-1]).items() if x is True
        } == want
        # restart and recreate: the guard keeps the configuration and its authority
        assert compose(tmp_path / "app", "restart", MID).returncode == 0
        assert compose(tmp_path / "app", "up", "-d", "--force-recreate").returncode == 0
        wait_healthy(tmp_path / "app")
        again = run_role(tmp_path, str(SERVER), "health", v, env=env)
        assert again.returncode == 0, again.stdout[-3000:]
        assert sha(etc / "server.config.yaml") == before
        # the control: the image's own entrypoint on the same volume rotates the authority
        image = server_defaults()[f"{SP}image"]
        stock = subprocess.run(
            ["docker", "run", "--rm", "--user", f"{os.getuid()}:{os.getgid()}", "--cap-drop", "ALL",
             "-e", f"{MID.upper()}_NO_INITIALIZE=1", "-e", f"{MID.upper()}_HOSTNAME=localhost",
             "-v", f"{etc}:/etc/{MID}", "-v", f"{tmp_path / 'data' / 'datastore'}:/datastore",
             "--entrypoint", "/bin/sh", image, "-c",
             f"/bin/{MID} query -f /bin/init.vql >/dev/null 2>&1; echo done"],
            capture_output=True, text=True, check=False, timeout=120,
        )  # fmt: skip
        assert stock.returncode == 0
        assert (
            sha(etc / "server.config.yaml") != before
        )  # which is what the guard exists to prevent
    finally:
        compose(tmp_path / "app", "down", "-v")
