# SPDX-License-Identifier: Apache-2.0
"""The flow-monitor network-sensor provider module (one container per capture interface).

* The public tree loads clean; the module contributes only its one role, a provisional slot, no registry row (a host's SSH port is claimed once) and no credential.
* The only egress is the build-time image and package fetch (the internet, from its one host role).
* A fictional overlay that places it on a stand-in physical host checks clean (with the egress
  grant) and renders ``modules.yml`` on ``mod_<id>_sensor``;
  without the egress grant it is refused.
* The shared probe adapter reports an open port healthy and a closed one not.
* role_lint passes the role and the lifecycle playbooks.
"""

from __future__ import annotations

import shutil
import socket
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from homelabnext.conform.adapters.network_sensor import make
from homelabnext.modules import cli as mcli
from homelabnext.modules import loader as ld
from tests.modules.network_monitor_module import MID, MODULE, P
from tests.modules.play_vars import without_footprint

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parent / "fixtures"
GUEST = ld.load_yaml(ROOT / "examples" / "services.yml")["hosts"]["edge-core"]["address"]
SLOTS = ld.load_yaml(ROOT / "examples" / "modules" / "slots.yml")["slots"]
REQUIRED = sorted(s for s, d in SLOTS.items() if d.get("required_in_core"))


class _NoAliases(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


def _dump(doc) -> str:
    return yaml.dump(doc, Dumper=_NoAliases, sort_keys=False)


def overlay(tmp: Path, grant: bool = True) -> Path:
    lab = tmp / "lab"
    (lab / "guests").mkdir(parents=True)
    reg = ld.load_yaml(ROOT / "examples" / "services.yml")
    reg["hosts"]["sensor"] = {"address": GUEST, "zone": "mgmt", "role": "apps"}
    hosts = {"agent-runtime": "runtime-core", "backup": "secrets-core", "broker": "idp-core",
             "edge": "edge-core", "records": "lake-core"}  # fmt: skip
    for i, (slot, host) in enumerate(sorted(hosts.items())):
        reg["services"][f"{slot}-incumbent"] = {
            "capability": slot, "impl": "example", "host": host, "protocol": "tcp",
            "port": 7001 + i, "health": {"kind": "none"}, "owner": "platform-team",
            "version": "1.0", "tls": "none",
        }  # fmt: skip
    (lab / "services.yml").write_text(_dump(reg))
    shutil.copy(FIXTURES / "guests" / "_baselines.yml", lab / "guests" / "_baselines.yml")
    rows = {n: r["capability"] for n, r in reg["services"].items()}
    sel = {
        "profile": "sensor-pilot",
        "hosts": {"sensor": {"kind": "host", "addresses": [GUEST],
                             "capacity": {"cpu": 4, "memory_mb": 8192, "disk_gb": 200}}},
        "slots": {"network-sensor": [{"provider": MID, "instance": "sensor",
                                      "placement": {"sensor": "sensor"}}]},
        "incumbents": {
            slot: {"service": next(n for n, c in rows.items() if c == slot), "why": "fictional"}
            for slot in REQUIRED
        },
    }  # fmt: skip
    if grant:
        sel["grants"] = {"egress": {MID: {"sensor": ["internet"]}}}
    (lab / "modules.yml").write_text(_dump(sel))
    return tmp


def _args(ov: Path) -> list[str]:
    return ["--root", str(ROOT), "--overlay", str(ov),
            "--keyring", str(ROOT / "examples" / "keyring" / "keyring.json"),
            "--mcp-catalog", str(ROOT / "examples" / "mcp")]  # fmt: skip


def _check(ov: Path, capsys) -> tuple[int, str]:
    code = mcli.main(["check", *_args(ov)])
    return code, capsys.readouterr().out


# ----------------------------------------------------------------------------- the public tree


@pytest.mark.static
def test_the_public_tree_loads_clean(capsys):
    code = mcli.main(["check", "--root", str(ROOT)])
    out = capsys.readouterr().out
    assert code == 0, out
    public = sum(1 for p in (ROOT / "modules").iterdir() if (p / "module.yml").is_file())
    assert out.rstrip().endswith(f"{public} module(s), 0 problem(s)")


@pytest.mark.static
def test_the_module_contributes_one_role_and_no_credential():
    manifest = ld.load_yaml(MODULE / "module.yml")
    assert sorted(p.name for p in (MODULE / "roles").iterdir()) == [MID]
    assert not any(p.is_symlink() for p in MODULE.rglob("*"))
    assert [c["file"] for c in manifest["contributes"]["roles"]] == [f"roles/{MID}"]
    assert manifest["credentials"] == []
    assert list(manifest["provides"]["slots"]) == ["network-sensor"]
    assert manifest["provides"]["slots"]["network-sensor"]["provisional"] is True
    assert "network-sensor" in SLOTS and SLOTS["network-sensor"]["contract"] is None
    assert [h["role"] for h in manifest["requires"]["hosts"]] == ["sensor"]


def test_the_only_egress_is_the_build_fetch_and_no_registry_row_is_contributed():
    manifest = ld.load_yaml(MODULE / "module.yml")
    assert [(e["host"], e["to"]) for e in manifest["egress"]] == [("sensor", ["internet"])]
    # a host's one SSH port is claimed once, by the other sensor's row; this monitor is judged by its
    # role's health hook and contributes no row
    assert "services" not in manifest["contributes"]
    assert not (MODULE / "registry").exists()


def test_the_base_image_is_the_product_version_pinned_by_digest_and_every_package_is_pinned():
    defaults = ld.load_yaml(MODULE / "roles" / MID / "defaults" / "main.yml")
    version = ld.load_yaml(MODULE / "module.yml")["product"]["version"]
    image = defaults[P + "base_image"]
    assert image.split("@")[0].endswith(":" + version)
    assert image.split("@")[1].startswith("sha256:") and len(image.split("@")[1]) == 71
    pkgs = defaults[P + "script_packages"]
    assert pkgs and all(p["version"] not in ("master", "main", "latest") for p in pkgs)


# ----------------------------------------------------------------------------- an overlay


def test_an_overlay_placing_the_sensor_on_a_host_checks_clean_and_renders(tmp_path, capsys):
    ov = overlay(tmp_path / "ov")
    code, out = _check(ov, capsys)
    assert code == 0, out
    dest = tmp_path / "out"
    code = mcli.main(["render", *_args(ov), "--out", str(dest)])
    out = capsys.readouterr().out
    assert code == 0, out
    books = yaml.safe_load((dest / "modules.yml").read_text())
    plays = [p for p in books if p["hosts"] == f"mod_{MID}_sensor"]
    assert len(plays) == 1 and plays[0]["become"] is True
    assert plays[0]["roles"][0]["role"].endswith(f"modules/{MID}/roles/{MID}")
    assert plays[0]["pre_tasks"][0]["ansible.builtin.include_role"]["tasks_from"] == "readiness"
    assert without_footprint(plays[0]["vars"]) == {"hnx_module_slice": f"hnx-{MID}-sensor.slice"}


def test_internet_egress_needs_the_overlays_grant(tmp_path, capsys):
    code, out = _check(overlay(tmp_path, grant=False), capsys)
    assert code == 1 and "internet" in out, out


# ----------------------------------------------------------------------------- the probe


def test_the_probe_is_healthy_on_an_open_port_and_not_on_a_closed_one(monkeypatch):
    srv = socket.socket()
    srv.bind(("localhost", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    monkeypatch.setenv("HNX_ENDPOINT_NETWORK_SENSOR", f"tcp://localhost:{port}")
    try:
        assert make().health() is True
    finally:
        srv.close()
    assert make({"timeout": 1.0}).health() is False


# ----------------------------------------------------------------------------- lint


def test_role_lint_passes_the_role_and_the_lifecycle_playbooks():
    lint = [sys.executable, str(ROOT / "tools" / "role_lint.py")]
    r = subprocess.run([*lint, str(MODULE / "roles" / MID)], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    books = sorted(str(p) for p in (MODULE / "playbooks").glob("*.yml"))
    inv = str(ROOT / "ansible" / "inventory" / "example" / "hosts.yml")
    r = subprocess.run([*lint, "--playbook", *books, "--inventory", inv],
                       capture_output=True, text=True)  # fmt: skip
    assert r.returncode == 0, r.stdout + r.stderr


@pytest.mark.static
def test_the_siem_agent_reads_each_captures_event_streams_and_only_those():
    """The monitor adds one marked localfile block for each capture's event streams to an installed
    SIEM agent (the IDS module's contract), so a re-converge keeps the agent reading the logs."""
    import jinja2

    root = Path(__file__).resolve().parents[2]
    role = next(
        p.parents[1]
        for p in sorted(root.glob("modules/*/roles/*/templates/siem-localfile.xml.j2"))
        if (p.parents[1] / "tasks/siem.yml").read_text().count("_capture_interfaces") == 0
        and "streams" in (p.parents[1] / "defaults/main.yml").read_text()
    )
    pfx = role.name
    defaults = yaml.safe_load((role / "defaults/main.yml").read_text())
    env = jinja2.Environment(
        autoescape=True
    )  # the block is XML: escaping is what the agent should get
    out = env.from_string((role / "templates/siem-localfile.xml.j2").read_text()).render(
        {
            f"{pfx}_capture_interfaces": [{"slug": "mirror"}, {"slug": "guests"}],
            f"{pfx}_siem_streams": defaults[f"{pfx}_siem_streams"],
            f"{pfx}_log_root": defaults[f"{pfx}_log_root"],
        }
    )
    locs = [line.strip()[10:-11] for line in out.splitlines() if "<location>" in line]
    assert locs[0] == f"{defaults[pfx + '_log_root']}/mirror/conn.log" and len(locs) == 18
    assert not any(n in loc for loc in locs for n in ("stats", "loaded_scripts", "packet_filter"))
    tasks = yaml.safe_load((role / "tasks/siem.yml").read_text())
    block, retired = [t for t in tasks if "ansible.builtin.blockinfile" in t]
    assert (
        block["when"] == f"{pfx}_siem_conf.stat.exists"
    )  # never creates the agent's configuration
    # the predecessor's blocks are only ever removed, and only from an existing configuration
    assert retired["ansible.builtin.blockinfile"]["state"] == "absent"
    assert retired["when"].startswith(f"{pfx}_siem_conf.stat.exists")


def _retire_play(tmp_path, check: bool) -> tuple[subprocess.CompletedProcess, list[str]]:
    """retire.yml for real, with stand-in service-manager and container CLIs that report a live,
    restartable predecessor and record every call."""
    import stat

    log = tmp_path / "calls.txt"
    clis = {}
    for name, body in (
        ("svc", "a=sys.argv[1]\nprint('enabled' if a == 'is-enabled' else 'active')"),
        ("ctr", "print('true always') if sys.argv[1] == 'inspect' else None"),
    ):
        f = tmp_path / name
        f.write_text(
            "#!/usr/bin/env python3\nimport sys\n"
            f"open({str(log)!r}, 'a').write(' '.join(sys.argv[1:]) + '\\n')\n" + body + "\n"
        )
        f.chmod(f.stat().st_mode | stat.S_IXUSR)
        clis[name] = str(f)
    tasks = yaml.safe_load((MODULE / "roles" / MID / "tasks" / "retire.yml").read_text())
    play = [{
        "hosts": "localhost", "connection": "local", "gather_facts": False,
        "vars": {P + "systemctl_cli": clis["svc"], P + "docker_cli": clis["ctr"],
                 P + "retired_units": ["old-watchdog.timer"], P + "retired_containers": ["old-a", "old-b"]},
        "tasks": tasks,
    }]  # fmt: skip
    (tmp_path / "p.yml").write_text(yaml.safe_dump(play))
    argv = ["ansible-playbook", "-i", "localhost,", str(tmp_path / "p.yml")]
    r = subprocess.run(
        argv + (["--check"] if check else []), capture_output=True, text=True, cwd=tmp_path
    )
    return r, (log.read_text().splitlines() if log.exists() else [])


@pytest.mark.requires_tool("ansible-playbook")
def test_retiring_the_predecessor_probes_it_in_check_mode_too(tmp_path):
    """The read-only probes run under --check, so a dry run reads the real state instead of failing
    on an empty probe result (the 2026-11-24 redeploy's --check failed on every container)."""
    r, calls = _retire_play(tmp_path, check=True)
    assert r.returncode == 0, r.stdout + r.stderr
    assert sorted(c.split()[0] for c in calls) == ["inspect", "inspect", "is-active", "is-enabled"]
    (tmp_path / "live").mkdir()
    r, calls = _retire_play(tmp_path / "live", check=False)
    assert r.returncode == 0, r.stdout + r.stderr
    assert {"disable --now old-watchdog.timer", "update --restart=no old-a", "stop old-b"} <= set(
        calls
    )
