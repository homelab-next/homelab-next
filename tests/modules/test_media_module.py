# SPDX-License-Identifier: Apache-2.0
"""The media provider module, ``modules/media`` (modules/media/README.md).

* The public tree loads clean and the module's ``roles/`` holds only its one contributed role.
* The manifest says what the README says: local accounts and no secrets, internet egress that the
  site must grant, a pinned image whose version is the product's, a read-only library at a
  configurable path, CPU transcoding.
* A fictional overlay that places it on a guest (and grants its egress and public route) passes
  ``hnx modules check --overlay`` and renders ``modules.yml`` on ``mod_media_server``; a registry
  row that differs, an ungranted egress and a guest without the ``base`` baseline are refused.
* The module's own probe reads the three anonymous endpoints from the resolved endpoint only.
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

from homelabnext.conform.adapters._env import AdapterConfigError
from homelabnext.modules import cli as mcli
from homelabnext.modules import loader as ld
from tests.modules.media_front import Server

ROOT = Path(__file__).resolve().parents[2]

FIXTURES = Path(__file__).resolve().parent / "fixtures"
MODULE = ROOT / "modules" / "media"
GUEST = ld.load_yaml(ROOT / "examples" / "services.yml")["hosts"]["dns-core"]["address"]
REQUIRED = sorted(
    s
    for s, d in ld.load_yaml(ROOT / "examples" / "modules" / "slots.yml")["slots"].items()
    if d.get("required_in_core")
)


class _NoAliases(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


def _dump(doc) -> str:
    return yaml.dump(doc, Dumper=_NoAliases, sort_keys=False)


def _args(ov: Path) -> list[str]:
    return [
        "--root", str(ROOT), "--overlay", str(ov),
        "--keyring", str(ROOT / "examples" / "keyring" / "keyring.json"),
        "--mcp-catalog", str(ROOT / "examples" / "mcp"),
    ]  # fmt: skip


def bound_row() -> dict:
    row = ld.load_yaml(MODULE / "registry" / "services.yml")["services"]["media"]
    version = str(ld.load_yaml(MODULE / "module.yml")["product"]["version"])
    return {
        **copy.deepcopy(row),
        "host": "media-1",
        "version": version,
        "public_hostname": "media.lab.example.internal",
    }


def overlay(tmp: Path) -> Path:
    lab = tmp / "lab"
    (lab / "guests").mkdir(parents=True)
    reg = ld.load_yaml(ROOT / "examples" / "services.yml")
    reg["hosts"]["media-1"] = {"address": GUEST, "zone": "mgmt", "role": "media"}
    reg["services"]["media-server"] = bound_row()
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
    (lab / "guests" / "media-1.yml").write_text(
        "# SPDX-License-Identifier: Apache-2.0\n"
        "id: guest:media-1\nkind: vm\nprovisioning: terraform\nstatus: planned\n"
        "placement: {node: hv-01, vmid: 241, vmid_scheme: freeform}\n"
        "resources:\n  cpu: {cores: 4}\n  memory: {size_mb: 16384}\n"
        "  disks: [{name: rootfs, size_gb: 40, pool: fast}]\n"
        "image: {logical: debian-13-cloudinit, kind: template-clone, os_type: linux-6}\n"
        "cloudinit: {user: ansible, ssh_authorized_keys: [operator]}\n"
        f"network: {{zone: mgmt, ip: {GUEST}}}\n"
        "capability: cap:media\nbackup: {policy: none}\n"
        "owners: {primary: platform-team}\nbaseline: {names: [base]}\n"
    )
    rows = {n: r["capability"] for n, r in reg["services"].items()}
    incumbents = {
        slot: {"service": next(n for n, c in rows.items() if c == slot), "why": "fictional"}
        for slot in REQUIRED
    }
    sel = {
        "profile": "media-pilot",
        "hosts": {"media": {"guest": "guest:media-1"}},
        "slots": {"media": [{"provider": "media", "instance": "media-server", "placement": {"server": "media"}}]},
        "incumbents": incumbents,
        "grants": {"egress": {"media": {"server": ["internet"]}}, "public_routes": {"media": ["media"]}},
    }  # fmt: skip
    (lab / "modules.yml").write_text(_dump(sel))
    return tmp


def _check(ov: Path, capsys) -> tuple[int, str]:
    code = mcli.main(["check", *_args(ov)])
    return code, capsys.readouterr().out


# ----------------------------------------------------------------------------- the public tree


def test_the_public_tree_loads_clean(capsys):
    code = mcli.main(["check", "--root", str(ROOT)])
    out = capsys.readouterr().out
    assert code == 0, out
    public = sum(1 for p in (ROOT / "modules").iterdir() if (p / "module.yml").is_file())
    assert out.rstrip().endswith(f"{public} module(s), 0 problem(s)")


def test_roles_holds_only_the_contributed_role():
    assert sorted(p.name for p in (MODULE / "roles").iterdir()) == ["media"]
    assert not any(p.is_symlink() for p in MODULE.rglob("*"))
    manifest = ld.load_yaml(MODULE / "module.yml")
    assert [c["file"] for c in manifest["contributes"]["roles"]] == ["roles/media"]


def test_the_manifest_keeps_local_accounts_and_declares_its_egress():
    manifest = ld.load_yaml(MODULE / "module.yml")
    assert manifest["credentials"] == []  # the accounts are the server's own: nothing in the store
    assert manifest["egress"][0]["to"] == ["internet"]
    row = ld.load_yaml(MODULE / "registry" / "services.yml")["services"]["media"]
    assert row["auth"] == "own" and row["port"] == 8096 and row["health"]["path"] == "/health"
    assert "version" not in row  # a provider's row takes product.version
    assert "forward" not in str(row).lower()  # no SSO in front of the TV clients


def test_the_image_pin_is_the_product_version_and_a_digest():
    defaults = ld.load_yaml(MODULE / "roles" / "media" / "defaults" / "main.yml")
    version = ld.load_yaml(MODULE / "module.yml")["product"]["version"]
    image = defaults["media_image"]
    assert image.split("@")[0].endswith(":" + version)
    assert image.split("@")[1].startswith("sha256:") and len(image.split("@")[1]) == 71


def test_the_defaults_are_a_configurable_read_only_library_cpu_transcoding_and_quick_connect():
    d = ld.load_yaml(MODULE / "roles" / "media" / "defaults" / "main.yml")
    assert d["media_library_path"] == "/srv/media"
    assert d["media_hwaccel"] == "none" and d["media_quick_connect"] is True
    task = (MODULE / "roles" / "media" / "tasks" / "app.yml").read_text()
    assert "{{ media_library_path }}:{{ media_library_path }}:ro" in task


# ----------------------------------------------------------------------------- an overlay


def test_an_overlay_placing_the_module_on_a_guest_checks_clean_and_renders(tmp_path, capsys):
    ov = overlay(tmp_path / "ov")
    code, out = _check(ov, capsys)
    assert code == 0, out
    dest = tmp_path / "out"
    code = mcli.main(["render", *_args(ov), "--out", str(dest)])
    out = capsys.readouterr().out
    assert code == 0, out
    books = yaml.safe_load((dest / "modules.yml").read_text())
    plays = [p for p in books if p["hosts"] == "mod_media_server"]
    assert len(plays) == 1 and plays[0]["become"] is True
    assert plays[0]["roles"][0]["role"].endswith("modules/media/roles/media")
    assert plays[0]["vars"] == {"hnx_module_slice": "hnx-media-server.slice"}


def test_a_registry_row_that_differs_is_named(tmp_path, capsys):
    ov = overlay(tmp_path)
    reg = ld.load_yaml(ov / "lab" / "services.yml")
    reg["services"]["media-server"]["auth"] = "idp"
    (ov / "lab" / "services.yml").write_text(_dump(reg))
    code, out = _check(ov, capsys)
    assert code == 1 and "registry: services.media-server.auth" in out, out


def test_an_ungranted_egress_is_refused(tmp_path, capsys):
    ov = overlay(tmp_path)
    sel = ld.load_yaml(ov / "lab" / "modules.yml")
    del sel["grants"]["egress"]
    (ov / "lab" / "modules.yml").write_text(_dump(sel))
    code, out = _check(ov, capsys)
    assert code == 1 and "internet" in out, out


def test_a_guest_without_the_base_baseline_is_refused(tmp_path, capsys):
    ov = overlay(tmp_path)
    g = ov / "lab" / "guests" / "media-1.yml"
    g.write_text(g.read_text().replace("names: [base]", "names: []"))
    code, out = _check(ov, capsys)
    assert code == 1 and "base" in out, out


# ----------------------------------------------------------------------------- the probe


def test_the_probe_reads_the_three_endpoints_from_the_resolved_endpoint(monkeypatch):
    from homelabnext.conform.adapters.media import make

    monkeypatch.delenv("HNX_ENDPOINT_MEDIA", raising=False)
    with pytest.raises(AdapterConfigError, match="HNX_ENDPOINT_MEDIA"):
        make()  # no default endpoint
    with Server() as srv:
        monkeypatch.setenv("HNX_ENDPOINT_MEDIA", "http://{}:{}".format(*srv.addr))
        probe = make()
        assert probe.health() and probe.quick_connect_enabled()
        assert probe.info()["ProductName"] == "Media Server"
        assert srv.paths == ["/health", "/QuickConnect/Enabled", "/System/Info/Public"]
    probe.close()


# ----------------------------------------------------------------------------- lint


def test_role_lint_passes_the_role_and_the_lifecycle_playbooks():
    lint = [sys.executable, str(ROOT / "tools" / "role_lint.py")]
    r = subprocess.run([*lint, str(MODULE / "roles" / "media")], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    books = sorted(str(p) for p in (MODULE / "playbooks").glob("*.yml"))
    inv = str(ROOT / "ansible" / "inventory" / "example" / "hosts.yml")
    r = subprocess.run(
        [*lint, "--playbook", *books, "--inventory", inv], capture_output=True, text=True
    )
    assert r.returncode == 0, r.stdout + r.stderr
