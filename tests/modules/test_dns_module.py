# SPDX-License-Identifier: Apache-2.0
"""The dns provider module (its README beside its manifest; the tests name the slot).

* The public tree loads clean, and the module's ``roles/`` holds only its one contributed role.
* A fictional overlay that places it on a guest (every other required core slot an incumbent)
  passes ``hnx modules check --overlay`` and renders ``modules.yml`` and ``checks/<id>.yml``
  on ``mod_" + MID + "_server``; a registry row that differs from the module's, a guest without
  the ``base`` baseline and a dns slot answered by both the module and an incumbent are refused.
* The conformance target binds the adapter with ``password_env``, and the dns suite runs through
  it against the loopback stand-in; a wrong password fails when the target is built.
* role_lint passes the role and the lifecycle playbooks.
"""

from __future__ import annotations

import copy
import ipaddress
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from conformance.suites import dns as dns_suite
from homelabnext.conform.adapters import dns_zone as adapter
from homelabnext.conform.adapters._env import AdapterConfigError
from homelabnext.conform.core import run_checks
from homelabnext.conform.target import load_target, make_factory
from homelabnext.modules import cli as mcli
from homelabnext.modules import loader as ld
from tests.modules.dns_front import FakeDnsAdmin
from tests.modules.dns_module import MID, MODULE, P, ref
from tests.modules.play_vars import without_footprint

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parent / "fixtures"
#: the example registry's edge address (a documentation-range address, never connected to)
GUEST = ld.load_yaml(ROOT / "examples" / "services.yml")["hosts"]["edge-core"]["address"]
PASSWORD = "admin-password-fake"
HOST_ADDR = str(ipaddress.IPv4Address(GUEST) + 9)
REQUIRED = sorted(
    s for s, d in ld.load_yaml(ROOT / "examples" / "modules" / "slots.yml")["slots"].items()
    if d.get("required_in_core")
)  # fmt: skip


class _NoAliases(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


def _dump(doc) -> str:
    return yaml.dump(doc, Dumper=_NoAliases, sort_keys=False)


def bound_row() -> dict:
    """The module's row as the overlay copies it: the instance's name, the guest as host and the
    product's version."""
    row = ld.load_yaml(MODULE / "registry" / "services.yml")["services"]["dns"]
    version = str(ld.load_yaml(MODULE / "module.yml")["product"]["version"])
    return {**copy.deepcopy(row), "host": "apps-1", "version": version}


def overlay(tmp: Path) -> Path:
    """A fictional overlay adopting the module: the example registry with the bound row (and one
    row for each required core slot it has none for), one guest, and a selection placing the
    module on it with every other required core slot an incumbent."""
    lab = tmp / "lab"
    (lab / "guests").mkdir(parents=True)
    reg = ld.load_yaml(ROOT / "examples" / "services.yml")
    reg["hosts"]["apps-1"] = {"address": GUEST, "zone": "mgmt", "role": "apps"}
    reg["services"]["dns"] = bound_row()
    have = {r["capability"] for n, r in reg["services"].items() if n != "dns"}
    for i, slot in enumerate(s for s in REQUIRED if s != "dns" and s not in have):
        reg["services"][f"{slot}-incumbent"] = {
            "capability": slot, "impl": "example", "host": "runtime-core", "protocol": "tcp",
            "port": 7001 + i, "health": {"kind": "none"}, "owner": "platform-team",
            "version": "1.0", "tls": "none",
        }  # fmt: skip
    (lab / "services.yml").write_text(_dump(reg))
    shutil.copy(FIXTURES / "guests" / "_baselines.yml", lab / "guests" / "_baselines.yml")
    (lab / "guests" / "apps-1.yml").write_text(
        "# SPDX-License-Identifier: Apache-2.0\n"
        "id: guest:apps-1\nkind: vm\nprovisioning: terraform\nstatus: planned\n"
        "placement: {node: hv-01, vmid: 240, vmid_scheme: freeform}\n"
        "resources:\n  cpu: {cores: 2}\n  memory: {size_mb: 4096}\n"
        "  disks: [{name: rootfs, size_gb: 32, pool: fast}]\n"
        "image: {logical: debian-13-cloudinit, kind: template-clone, os_type: linux-6}\n"
        "cloudinit: {user: ansible, ssh_authorized_keys: [operator]}\n"
        f"network: {{zone: mgmt, ip: {GUEST}}}\n"
        "capability: cap:dns\nbackup: {policy: none}\n"
        "owners: {primary: platform-team}\nbaseline: {names: [base]}\n"
    )
    rows = {n: r["capability"] for n, r in reg["services"].items()}
    incumbents = {
        slot: {"service": next(n for n, c in rows.items() if c == slot), "why": "fictional"}
        for slot in REQUIRED
        if slot != "dns"
    }
    sel = {
        "profile": "dns-pilot",
        "hosts": {"apps": {"guest": "guest:apps-1"}},
        "slots": {"dns": [{"provider": MID, "instance": "dns",
                           "placement": {"server": "apps"}}]},
        "incumbents": incumbents,
        "grants": {"egress": {MID: {"server": ["internet"]}}},
    }  # fmt: skip
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


def test_the_public_tree_loads_clean(capsys):
    code = mcli.main(["check", "--root", str(ROOT)])
    out = capsys.readouterr().out
    assert code == 0, out
    public = sum(1 for p in (ROOT / "modules").iterdir() if (p / "module.yml").is_file())
    assert out.rstrip().endswith(f"{public} module(s), 0 problem(s)")


def test_roles_holds_only_the_contributed_role():
    assert sorted(p.name for p in (MODULE / "roles").iterdir()) == [MID]
    assert not any(p.is_symlink() for p in MODULE.rglob("*"))
    manifest = ld.load_yaml(MODULE / "module.yml")
    assert [c["file"] for c in manifest["contributes"]["roles"]] == ["roles/" + MID]


def test_the_manifest_declares_internet_egress_and_no_public_row():
    manifest = ld.load_yaml(MODULE / "module.yml")
    assert manifest["egress"] == [
        {"host": "server", "to": ["internet"], "purpose": manifest["egress"][0]["purpose"]}
    ]
    row = ld.load_yaml(MODULE / "registry" / "services.yml")["services"]["dns"]
    assert "public_hostname" not in row and row["port"] == 53 and row["protocol"] == "dns"
    assert "version" not in row  # a provider's row takes product.version


def test_the_image_pin_is_the_product_version():
    defaults = ld.load_yaml(MODULE / "roles" / MID / "defaults" / "main.yml")
    version = ld.load_yaml(MODULE / "module.yml")["product"]["version"]
    image = defaults[P + "image"]
    assert image.split("@")[0].endswith(":" + version)
    assert image.split("@")[1].startswith("sha256:") and len(image.split("@")[1]) == 71


def test_the_only_secret_is_the_admin_password_by_reference():
    manifest = ld.load_yaml(MODULE / "module.yml")
    assert [c["secret"] for c in manifest["credentials"]] == [ref("admin-password")]
    defaults = ld.load_yaml(MODULE / "roles" / MID / "defaults" / "main.yml")
    assert defaults[P + "admin_login_ref"] == ref("admin-password")
    assert not any("password" in k and not k.endswith("_ref") for k in defaults)


# ----------------------------------------------------------------------------- an overlay


def test_an_overlay_placing_the_module_on_a_guest_checks_clean_and_renders(tmp_path, capsys):
    ov = overlay(tmp_path / "ov")
    code, out = _check(ov, capsys)
    assert code == 0, out
    assert "0 problem(s)" in out.rstrip().splitlines()[-1]
    # recursion and block list fetches leave the guest: the module declares internet egress, the
    # site grants it, and check says the bridge network cannot enforce it
    assert "warning: " + MID + "/server on apps: egress to internet is NOT enforced" in out
    dest = tmp_path / "out"
    code = mcli.main(["render", *_args(ov), "--out", str(dest)])
    out = capsys.readouterr().out
    assert code == 0, out
    books = yaml.safe_load((dest / "modules.yml").read_text())
    plays = [p for p in books if p["hosts"] == "mod_" + MID + "_server"]
    assert len(plays) == 1 and plays[0]["become"] is True
    assert plays[0]["roles"][0]["role"].endswith("modules/" + MID + "/roles/" + MID)
    assert plays[0]["pre_tasks"][0]["ansible.builtin.include_role"]["tasks_from"] == "readiness"
    assert (dest / "checks" / (MID + ".yml")).is_file()
    assert without_footprint(plays[0]["vars"]) == {"hnx_module_slice": f"hnx-{MID}-server.slice"}


def test_a_registry_row_that_differs_is_named(tmp_path, capsys):
    ov = overlay(tmp_path)
    reg = ld.load_yaml(ov / "lab" / "services.yml")
    reg["services"]["dns"]["port"] = 5353
    (ov / "lab" / "services.yml").write_text(_dump(reg))
    code, out = _check(ov, capsys)
    assert code == 1
    assert "registry: services.dns.port: " + MID + " (instance dns) contributes 53" in out


def test_a_guest_without_the_base_baseline_is_refused(tmp_path, capsys):
    ov = overlay(tmp_path)
    g = ov / "lab" / "guests" / "apps-1.yml"
    g.write_text(g.read_text().replace("names: [base]", "names: []"))
    code, out = _check(ov, capsys)
    assert code == 1 and "base" in out, out


def test_internet_egress_without_a_grant_is_refused(tmp_path, capsys):
    ov = overlay(tmp_path)
    sel = ld.load_yaml(ov / "lab" / "modules.yml")
    del sel["grants"]
    (ov / "lab" / "modules.yml").write_text(_dump(sel))
    code, out = _check(ov, capsys)
    assert code == 1 and "host server egresses to internet without a grant" in out, out


def test_dns_cannot_be_both_the_module_and_an_incumbent(tmp_path, capsys):
    ov = overlay(tmp_path)
    sel = ld.load_yaml(ov / "lab" / "modules.yml")
    sel["incumbents"]["dns"] = {"service": "dns", "why": "both"}
    (ov / "lab" / "modules.yml").write_text(_dump(sel))
    code, out = _check(ov, capsys)
    assert code == 1 and "incumbents.dns: the slot is also selected under slots" in out, out


# ----------------------------------------------------------------------------- conformance


def _target_factory():
    target = load_target(str(MODULE / "conformance" / "target.yml"), root=ROOT)
    binding = target.binding("dns")
    assert binding.adapter == "homelabnext.conform.adapters.dns_zone:make"
    assert binding.config == {"password_env": "HNX_DNS_PASSWORD"}
    return make_factory(binding, root=ROOT)


def test_the_dns_suite_passes_through_the_target(monkeypatch):
    with FakeDnsAdmin(password=PASSWORD) as srv:
        monkeypatch.setenv("HNX_ENDPOINT_DNS", srv.url)
        monkeypatch.setenv("HNX_DNS_PASSWORD", PASSWORD)
        factory = _target_factory()
        # the lab reaches the API over http: a copy of the target sets allow_plaintext (loopback
        # here, which the adapter accepts as it is)
        results = run_checks(dns_suite.SUITE, factory)
        left = sorted(srv.zones)
        signed_in = srv.logins
    assert sorted(r.check for r in results if r.status != "pass") == []
    assert len(results) == 10 and signed_in >= len(results)
    assert left == []  # the scratch zone the target created is removed again at close


def test_a_zone_that_was_already_there_is_not_removed_at_close(monkeypatch):
    with FakeDnsAdmin(password=PASSWORD) as srv:
        srv.add_zone("svc.example.internal", {"keep": HOST_ADDR})
        monkeypatch.setenv("HNX_ENDPOINT_DNS", srv.url)
        monkeypatch.setenv("HNX_DNS_PASSWORD", PASSWORD)
        results = run_checks(dns_suite.SUITE, _target_factory())
        assert all(r.status == "pass" for r in results)
        assert "svc.example.internal" in srv.zones


def test_a_wrong_password_fails_when_the_target_is_built(monkeypatch):
    with FakeDnsAdmin(password=PASSWORD) as srv:
        monkeypatch.setenv("HNX_ENDPOINT_DNS", srv.url)
        monkeypatch.setenv("HNX_DNS_PASSWORD", "not-the-admin-password")
        with pytest.raises(adapter.ApiError, match="sign-in refused"):
            _target_factory()()


def test_a_missing_password_variable_fails_when_the_target_is_built(monkeypatch):
    with FakeDnsAdmin(password=PASSWORD) as srv:
        monkeypatch.setenv("HNX_ENDPOINT_DNS", srv.url)
        monkeypatch.delenv("HNX_DNS_PASSWORD", raising=False)
        with pytest.raises(AdapterConfigError, match="HNX_DNS_PASSWORD"):
            _target_factory()()


def test_the_adapter_never_puts_the_password_or_token_in_a_url(monkeypatch):
    seen = []
    real = adapter.safe_urlopen

    def spy(req, timeout=None):
        seen.append(req.full_url)
        return real(req, timeout=timeout)

    monkeypatch.setattr(adapter, "safe_urlopen", spy)
    with FakeDnsAdmin(password=PASSWORD) as srv:
        monkeypatch.setenv("HNX_ENDPOINT_DNS", srv.url)
        monkeypatch.setenv("HNX_DNS_PASSWORD", PASSWORD)
        _target_factory()().close()
    assert seen and not any("token=" in u or "pass=" in u or PASSWORD in u for u in seen)


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
