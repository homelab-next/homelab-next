# SPDX-License-Identifier: Apache-2.0
"""The first real module, ``modules/ntfy`` (the notify provider; modules/ntfy/README.md).

* The public tree loads clean, and the module's ``roles/`` holds only its one contributed role.
* A fictional overlay that places it on a guest (every other required core slot an incumbent)
  passes ``hnx modules check --overlay`` and renders ``modules.yml`` and ``checks/ntfy.yml`` on
  ``mod_ntfy_server``; a registry row that differs from the module's, a guest without the
  ``base`` baseline and a notify slot answered by both the module and an incumbent are refused.
* The conformance target binds the shared adapter with ``token_env``, and the notify suite runs
  through it against the loopback stand-in behind a deny-all front; without the token every
  check fails, so the front is real.
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

from conformance.suites import notify as notify_suite
from homelabnext.conform.adapters._env import AdapterConfigError
from homelabnext.conform.core import run_checks
from homelabnext.conform.target import load_target, make_factory
from homelabnext.modules import cli as mcli
from homelabnext.modules import loader as ld
from tests.modules.ntfy_front import DenyAllNtfy

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "modules" / "ntfy"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
GUEST = "192.0.2.40"  # no-raw-endpoint: allow a documentation-range guest address
TOKEN = "tk_fakefakefakefakefakefakefake0"
ADMIN = ("admin", "admin-password-fake")
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
    row = ld.load_yaml(MODULE / "registry" / "services.yml")["services"]["notify"]
    version = str(ld.load_yaml(MODULE / "module.yml")["product"]["version"])
    return {**copy.deepcopy(row), "host": "apps-1", "version": version}


def overlay(tmp: Path) -> Path:
    """A fictional overlay adopting the module: the example registry with the bound row (and one
    row for each required core slot it has none for), one guest, and a selection placing ntfy on
    it with every other required core slot an incumbent."""
    lab = tmp / "lab"
    (lab / "guests").mkdir(parents=True)
    reg = ld.load_yaml(ROOT / "examples" / "services.yml")
    reg["hosts"]["apps-1"] = {
        "address": GUEST,
        "zone": "mgmt",
        "role": "apps",
    }
    reg["services"]["notify"] = bound_row()
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
    (lab / "guests" / "apps-1.yml").write_text(
        "# SPDX-License-Identifier: Apache-2.0\n"
        "id: guest:apps-1\nkind: vm\nprovisioning: terraform\nstatus: planned\n"
        "placement: {node: hv-01, vmid: 240, vmid_scheme: freeform}\n"
        "resources:\n  cpu: {cores: 2}\n  memory: {size_mb: 4096}\n"
        "  disks: [{name: rootfs, size_gb: 32, pool: fast}]\n"
        "image: {logical: debian-13-cloudinit, kind: template-clone, os_type: linux-6}\n"
        "cloudinit: {user: ansible, ssh_authorized_keys: [operator]}\n"
        f"network: {{zone: mgmt, ip: {GUEST}}}\n"
        "capability: cap:notify\nbackup: {policy: none}\n"
        "owners: {primary: platform-team}\nbaseline: {names: [base]}\n"
    )
    rows = {n: r["capability"] for n, r in reg["services"].items()}
    incumbents = {
        slot: {"service": next(n for n, c in rows.items() if c == slot), "why": "fictional"}
        for slot in REQUIRED
        if slot != "notify"
    }
    sel = {
        "profile": "ntfy-pilot",
        "hosts": {"apps": {"guest": "guest:apps-1"}},
        "slots": {"notify": [{"provider": "ntfy", "instance": "notify",
                              "placement": {"server": "apps"}}]},
        "incumbents": incumbents,
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
    assert out.rstrip().endswith("2 module(s), 0 problem(s)")


def test_roles_holds_only_the_contributed_role():
    assert sorted(p.name for p in (MODULE / "roles").iterdir()) == ["ntfy"]
    assert not any(p.is_symlink() for p in MODULE.rglob("*"))
    manifest = ld.load_yaml(MODULE / "module.yml")
    assert [c["file"] for c in manifest["contributes"]["roles"]] == ["roles/ntfy"]


def test_the_manifest_has_no_egress_and_no_public_row():
    manifest = ld.load_yaml(MODULE / "module.yml")
    assert manifest["egress"] == "none"
    row = ld.load_yaml(MODULE / "registry" / "services.yml")["services"]["notify"]
    assert "public_hostname" not in row and row["auth"] == "own"
    assert "version" not in row  # a provider's row takes product.version


def test_the_image_pin_is_the_product_version():
    defaults = ld.load_yaml(MODULE / "roles" / "ntfy" / "defaults" / "main.yml")
    version = ld.load_yaml(MODULE / "module.yml")["product"]["version"]
    image = defaults["ntfy_image"]
    assert image.split("@")[0].endswith(":v" + version)
    assert image.split("@")[1].startswith("sha256:") and len(image.split("@")[1]) == 71


# ----------------------------------------------------------------------------- an overlay


def test_an_overlay_placing_ntfy_on_a_guest_checks_clean_and_renders(tmp_path, capsys):
    ov = overlay(tmp_path / "ov")
    code, out = _check(ov, capsys)
    assert code == 0, out
    assert out.rstrip().endswith("0 problem(s), 1 warning(s)")
    # its container is on a bridge network: egress: none cannot be enforced, and check says so
    assert (
        "warning: ntfy/server on apps: egress: none is NOT enforced: the role runs containers"
        in out
    )
    dest = tmp_path / "out"
    code = mcli.main(["render", *_args(ov), "--out", str(dest)])
    out = capsys.readouterr().out
    assert code == 0, out
    books = yaml.safe_load((dest / "modules.yml").read_text())
    plays = [p for p in books if p["hosts"] == "mod_ntfy_server"]
    assert len(plays) == 1 and plays[0]["become"] is True
    assert plays[0]["roles"][0]["role"].endswith("modules/ntfy/roles/ntfy")
    assert plays[0]["pre_tasks"][0]["ansible.builtin.include_role"]["tasks_from"] == "readiness"
    assert (dest / "checks" / "ntfy.yml").is_file()
    # its container joins the role's slice (compose_app reads the play variable) ...
    assert plays[0]["vars"] == {"hnx_module_slice": "hnx-ntfy-server.slice"}
    assert (dest / "limits" / "apps" / "hnx-ntfy-server.slice").is_file()
    # ... and on a vm its data root is capped by the guest's disk, never by an image over its data
    quota = (dest / "limits" / "apps" / "hnx-module-quota.sh").read_text()
    assert "\nrun guest_disk ntfy 4 vm 4\n" in quota and "\nrun cap " not in quota


def test_a_registry_row_that_differs_is_named(tmp_path, capsys):
    ov = overlay(tmp_path)
    reg = ld.load_yaml(ov / "lab" / "services.yml")
    reg["services"]["notify"]["port"] = 8080
    (ov / "lab" / "services.yml").write_text(_dump(reg))
    code, out = _check(ov, capsys)
    assert code == 1
    assert "registry: services.notify.port: ntfy (instance notify) contributes 80" in out


def test_a_guest_without_the_base_baseline_is_refused(tmp_path, capsys):
    ov = overlay(tmp_path)
    g = ov / "lab" / "guests" / "apps-1.yml"
    g.write_text(g.read_text().replace("names: [base]", "names: []"))
    code, out = _check(ov, capsys)
    assert code == 1 and "base" in out, out


def test_notify_cannot_be_both_the_module_and_an_incumbent(tmp_path, capsys):
    ov = overlay(tmp_path)
    sel = ld.load_yaml(ov / "lab" / "modules.yml")
    sel["incumbents"]["notify"] = {"service": "notify", "why": "both"}
    (ov / "lab" / "modules.yml").write_text(_dump(sel))
    code, out = _check(ov, capsys)
    assert code == 1 and "incumbents.notify: the slot is also selected under slots" in out, out


# ----------------------------------------------------------------------------- conformance


def _target_factory():
    target = load_target(str(MODULE / "conformance" / "target.yml"), root=ROOT)
    binding = target.binding("notify")
    assert binding.adapter == "homelabnext.conform.adapters.ntfy:make"
    assert binding.config == {"token_env": "HNX_NOTIFY_TOKEN"}
    return make_factory(binding, root=ROOT)


def test_the_notify_suite_passes_through_the_target_behind_deny_all(monkeypatch):
    with DenyAllNtfy(token=TOKEN, admin=ADMIN) as srv:
        monkeypatch.setenv("HNX_ENDPOINT_NOTIFY", srv.url)
        monkeypatch.setenv("HNX_NOTIFY_TOKEN", TOKEN)
        results = run_checks(notify_suite.SUITE, _target_factory())
        refused = srv.refused
    assert sorted(r.check for r in results if r.status != "pass") == []
    assert refused == 0  # every request carried the token


def test_without_the_token_the_deny_all_front_refuses_every_check(monkeypatch):
    with DenyAllNtfy(token=TOKEN, admin=ADMIN) as srv:
        monkeypatch.setenv("HNX_ENDPOINT_NOTIFY", srv.url)
        monkeypatch.setenv("HNX_NOTIFY_TOKEN", "tk_wrongwrongwrongwrongwrongwron")
        results = run_checks(notify_suite.SUITE, _target_factory())
        assert srv.refused > 0
    assert all(r.status != "pass" for r in results if "deliver" in r.check), results


def test_a_missing_token_variable_fails_when_the_target_is_built(monkeypatch):
    with DenyAllNtfy(token=TOKEN, admin=ADMIN) as srv:
        monkeypatch.setenv("HNX_ENDPOINT_NOTIFY", srv.url)
        monkeypatch.delenv("HNX_NOTIFY_TOKEN", raising=False)
        with pytest.raises(AdapterConfigError, match="HNX_NOTIFY_TOKEN"):
            _target_factory()()


# ----------------------------------------------------------------------------- lint


def test_role_lint_passes_the_role_and_the_lifecycle_playbooks():
    lint = [sys.executable, str(ROOT / "tools" / "role_lint.py")]
    r = subprocess.run([*lint, str(MODULE / "roles" / "ntfy")], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    books = sorted(str(p) for p in (MODULE / "playbooks").glob("*.yml"))
    inv = str(ROOT / "ansible" / "inventory" / "example" / "hosts.yml")
    r = subprocess.run([*lint, "--playbook", *books, "--inventory", inv],
                       capture_output=True, text=True)  # fmt: skip
    assert r.returncode == 0, r.stdout + r.stderr
