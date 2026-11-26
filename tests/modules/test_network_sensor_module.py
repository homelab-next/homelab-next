# SPDX-License-Identifier: Apache-2.0
"""The signature-based network-sensor provider module (an IDS on a capture host).

* The public tree loads clean; the module contributes only its one role, a provisional slot, one
  registry row (the host's SSH: a passive sensor listens on nothing) and no credential.
* The only egress is the rule feed (the internet, from its one host role).
* A fictional overlay that places it on a stand-in physical host checks clean (with the egress
  grant) and renders ``modules.yml`` on ``mod_<id>_sensor``; a registry row that differs is
  refused; without the egress grant it is refused.
* The shared probe adapter reports an open port healthy and a closed one not.
* role_lint passes the role and the lifecycle playbooks.
"""

from __future__ import annotations

import copy
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
from tests.modules.network_sensor_module import MID, MODULE
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


def bound_row() -> dict:
    row = ld.load_yaml(MODULE / "registry" / "services.yml")["services"]["network-sensor"]
    version = str(ld.load_yaml(MODULE / "module.yml")["product"]["version"])
    return {**copy.deepcopy(row), "host": "sensor", "version": version}


def overlay(tmp: Path, grant: bool = True) -> Path:
    lab = tmp / "lab"
    (lab / "guests").mkdir(parents=True)
    reg = ld.load_yaml(ROOT / "examples" / "services.yml")
    reg["hosts"]["sensor"] = {"address": GUEST, "zone": "mgmt", "role": "apps"}
    reg["services"]["sensor"] = bound_row()
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
def test_the_module_contributes_one_role_one_row_and_no_credential():
    manifest = ld.load_yaml(MODULE / "module.yml")
    assert sorted(p.name for p in (MODULE / "roles").iterdir()) == [MID]
    assert not any(p.is_symlink() for p in MODULE.rglob("*"))
    assert [c["file"] for c in manifest["contributes"]["roles"]] == [f"roles/{MID}"]
    assert manifest["credentials"] == []
    assert list(manifest["provides"]["slots"]) == ["network-sensor"]
    assert manifest["provides"]["slots"]["network-sensor"]["provisional"] is True
    assert "network-sensor" in SLOTS and SLOTS["network-sensor"]["contract"] is None
    assert [h["role"] for h in manifest["requires"]["hosts"]] == ["sensor"]


def test_the_only_egress_is_the_rule_feed_and_the_row_names_no_public_route():
    manifest = ld.load_yaml(MODULE / "module.yml")
    assert [(e["host"], e["to"]) for e in manifest["egress"]] == [("sensor", ["internet"])]
    row = ld.load_yaml(MODULE / "registry" / "services.yml")["services"]["network-sensor"]
    assert row["capability"] == "network-sensor"
    assert row["impl"] == manifest["product"]["name"]
    assert (row["protocol"], row["port"], row["health"]) == ("ssh", 22, {"kind": "tcp"})
    assert not {"public_hostname", "version", "upstreams"} & set(row)


def test_the_package_pin_is_an_exact_version_not_a_range():
    defaults = ld.load_yaml(MODULE / "roles" / MID / "defaults" / "main.yml")
    version = ld.load_yaml(MODULE / "module.yml")["product"]["version"]
    pin = defaults[f"{MID}_package_version"]
    assert pin.split(":")[-1].startswith(version + "-")
    assert not any(c in pin for c in "*<>=")


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


def test_a_registry_row_that_differs_is_named(tmp_path, capsys):
    ov = overlay(tmp_path)
    reg = ld.load_yaml(ov / "lab" / "services.yml")
    reg["services"]["sensor"]["port"] = 2222
    (ov / "lab" / "services.yml").write_text(_dump(reg))
    code, out = _check(ov, capsys)
    assert code == 1
    assert (
        f"registry: services.sensor.port: {MID} (instance sensor) contributes 22 (its row network-sensor)"
        in out
    )


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
