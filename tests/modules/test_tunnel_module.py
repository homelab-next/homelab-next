# SPDX-License-Identifier: Apache-2.0
"""The module ``modules/tunnel`` (the tunnel provider, a connector of a remotely managed tunnel).

* The public tree loads clean; the module contributes only its one role, a provisional slot, one
  registry row (the metrics and readiness listener) and the token as its only credential, under
  its own secret namespace.
* The connector is outbound only: egress is the internet from its one host role, and the row has
  no public route.
* A fictional overlay that places it on a guest checks clean (with the egress grant) and renders
  ``modules.yml`` on ``mod_tunnel_server``; a registry row that differs is refused; without the
  egress grant it is refused.
* role_lint passes the role and the lifecycle playbooks.
"""

from __future__ import annotations

import copy
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from homelabnext.modules import cli as mcli
from homelabnext.modules import loader as ld
from tests.modules.play_vars import without_footprint

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "modules" / "tunnel"
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
    row = ld.load_yaml(MODULE / "registry" / "services.yml")["services"]["tunnel"]
    version = str(ld.load_yaml(MODULE / "module.yml")["product"]["version"])
    return {**copy.deepcopy(row), "host": "edge-1", "version": version}


def overlay(tmp: Path, grant: bool = True) -> Path:
    lab = tmp / "lab"
    (lab / "guests").mkdir(parents=True)
    reg = ld.load_yaml(ROOT / "examples" / "services.yml")
    reg["hosts"]["edge-1"] = {"address": GUEST, "zone": "mgmt", "role": "apps"}
    reg["services"]["edge-tunnel"] = bound_row()
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
    (lab / "guests" / "edge-1.yml").write_text(
        "# SPDX-License-Identifier: Apache-2.0\n"
        "id: guest:edge-1\nkind: vm\nprovisioning: terraform\nstatus: planned\n"
        "placement: {node: hv-01, vmid: 241, vmid_scheme: freeform}\n"
        "resources:\n  cpu: {cores: 2}\n  memory: {size_mb: 4096}\n"
        "  disks: [{name: rootfs, size_gb: 32, pool: fast}]\n"
        "image: {logical: debian-13-cloudinit, kind: template-clone, os_type: linux-6}\n"
        "cloudinit: {user: ansible, ssh_authorized_keys: [operator]}\n"
        f"network: {{zone: mgmt, ip: {GUEST}}}\n"
        "capability: cap:tunnel\nbackup: {policy: none}\n"
        "owners: {primary: platform-team}\nbaseline: {names: [base]}\n"
    )
    rows = {n: r["capability"] for n, r in reg["services"].items()}
    sel = {
        "profile": "tunnel-pilot",
        "hosts": {"edge": {"guest": "guest:edge-1"}},
        "slots": {"tunnel": [{"provider": "tunnel", "instance": "edge-tunnel",
                              "placement": {"server": "edge"}}]},
        "incumbents": {
            slot: {"service": next(n for n, c in rows.items() if c == slot), "why": "fictional"}
            for slot in REQUIRED
        },
    }  # fmt: skip
    if grant:
        sel["grants"] = {"egress": {"tunnel": {"server": ["internet"]}}}
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
def test_the_module_contributes_one_role_one_row_and_one_credential():
    manifest = ld.load_yaml(MODULE / "module.yml")
    assert sorted(p.name for p in (MODULE / "roles").iterdir()) == ["tunnel"]
    assert not any(p.is_symlink() for p in MODULE.rglob("*"))
    assert [c["file"] for c in manifest["contributes"]["roles"]] == ["roles/tunnel"]
    assert [c["secret"] for c in manifest["credentials"]] == ["secret:tunnel/token"]
    assert list(manifest["provides"]["slots"]) == ["tunnel"]
    assert manifest["provides"]["slots"]["tunnel"]["provisional"] is True
    assert "tunnel" in SLOTS and SLOTS["tunnel"]["contract"] is None


def test_the_connector_is_outbound_only_and_its_row_is_the_readiness_listener():
    manifest = ld.load_yaml(MODULE / "module.yml")
    assert [(e["host"], e["to"]) for e in manifest["egress"]] == [("server", ["internet"])]
    row = ld.load_yaml(MODULE / "registry" / "services.yml")["services"]["tunnel"]
    assert (
        row["capability"] == "tunnel"
        and row["impl"] == ld.load_yaml(MODULE / "module.yml")["product"]["name"]
    )
    assert row["port"] == 20241 and row["protocol"] == "http"
    assert row["health"] == {"kind": "http", "path": "/ready", "expect_status": 200}
    assert "public_hostname" not in row and "version" not in row and "upstreams" not in row


def test_the_image_pin_is_the_product_version_and_a_digest():
    defaults = ld.load_yaml(MODULE / "roles" / "tunnel" / "defaults" / "main.yml")
    version = ld.load_yaml(MODULE / "module.yml")["product"]["version"]
    image = defaults["tunnel_image"]
    assert image.split("@")[0].endswith(":" + version)
    assert image.split("@")[1].startswith("sha256:") and len(image.split("@")[1]) == 71


@pytest.mark.static
def test_no_ingress_configuration_ships_with_the_module():
    files = [p for p in MODULE.rglob("*") if p.is_file() and "roles" in p.parts]
    assert not [p for p in files if p.suffix == ".j2" or p.name.startswith("config")]
    assert not any("ingress:" in p.read_text() for p in files)


# ----------------------------------------------------------------------------- an overlay


def test_an_overlay_placing_the_tunnel_on_a_guest_checks_clean_and_renders(tmp_path, capsys):
    ov = overlay(tmp_path / "ov")
    code, out = _check(ov, capsys)
    assert code == 0, out
    dest = tmp_path / "out"
    code = mcli.main(["render", *_args(ov), "--out", str(dest)])
    out = capsys.readouterr().out
    assert code == 0, out
    books = yaml.safe_load((dest / "modules.yml").read_text())
    plays = [p for p in books if p["hosts"] == "mod_tunnel_server"]
    assert len(plays) == 1 and plays[0]["become"] is True
    assert plays[0]["roles"][0]["role"].endswith("modules/tunnel/roles/tunnel")
    assert plays[0]["pre_tasks"][0]["ansible.builtin.include_role"]["tasks_from"] == "readiness"
    assert without_footprint(plays[0]["vars"]) == {"hnx_module_slice": "hnx-tunnel-server.slice"}


def test_internet_egress_needs_the_overlays_grant(tmp_path, capsys):
    ov = overlay(tmp_path, grant=False)
    code, out = _check(ov, capsys)
    assert code == 1 and "internet" in out, out


def test_a_registry_row_that_differs_is_named(tmp_path, capsys):
    ov = overlay(tmp_path)
    reg = ld.load_yaml(ov / "lab" / "services.yml")
    reg["services"]["edge-tunnel"]["port"] = 9000
    (ov / "lab" / "services.yml").write_text(_dump(reg))
    code, out = _check(ov, capsys)
    assert code == 1
    assert (
        "registry: services.edge-tunnel.port: tunnel (instance edge-tunnel) contributes 20241"
        in out
    )


# ----------------------------------------------------------------------------- lint


def test_role_lint_passes_the_role_and_the_lifecycle_playbooks():
    lint = [sys.executable, str(ROOT / "tools" / "role_lint.py")]
    r = subprocess.run([*lint, str(MODULE / "roles" / "tunnel")], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    books = sorted(str(p) for p in (MODULE / "playbooks").glob("*.yml"))
    inv = str(ROOT / "ansible" / "inventory" / "example" / "hosts.yml")
    r = subprocess.run([*lint, "--playbook", *books, "--inventory", inv],
                       capture_output=True, text=True)  # fmt: skip
    assert r.returncode == 0, r.stdout + r.stderr
