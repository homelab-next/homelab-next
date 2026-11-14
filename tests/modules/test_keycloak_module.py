# SPDX-License-Identifier: Apache-2.0
"""The idp provider module, ``modules/keycloak`` (modules/keycloak/README.md).

* The public tree loads clean; the module's ``roles/`` holds only its one contributed role; its
  images are pinned by tag and digest, the IdP's tag being the product's version.
* A fictional overlay that places it on a guest (every other required core slot an incumbent)
  passes ``hnx modules check --overlay`` and renders ``modules.yml`` and ``checks/keycloak.yml``
  on ``mod_keycloak_server``; a registry row without the site's ``public_hostname``, or a selection
  without ``grants.public_routes`` for it, is refused.
* The conformance target binds the Keycloak adapter, and the idp suite runs through it against
  the HTTPS stand-in; a wrong admin password fails the target when it is built.
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

from conformance.suites import idp as idp_suite
from homelabnext.conform.adapters._env import AdapterConfigError
from homelabnext.conform.adapters.keycloak import KeycloakError
from homelabnext.conform.core import run_checks
from homelabnext.conform.target import load_target, make_factory
from homelabnext.modules import cli as mcli
from homelabnext.modules import loader as ld
from tests.modules.keycloak_stand_in import LOOPBACK, SERVER_NAME, StandIn

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "modules" / "keycloak"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
GUEST = "192.0.2.41"  # no-raw-endpoint: allow a documentation-range guest address
ADMIN = ("hnx-admin", "admin-password-fake-0123456789")
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
    """The module's row as the overlay binds it: the guest as host, the product's version, and
    the site's own public name and CA secret in the two fields whose value is the site's."""
    row = ld.load_yaml(MODULE / "registry" / "services.yml")["services"]["idp"]
    version = str(ld.load_yaml(MODULE / "module.yml")["product"]["version"])
    return {
        **copy.deepcopy(row),
        "host": "idp-1",
        "version": version,
        "public_hostname": "sso.lab.example",
        "edge_tls": {"ca": "secret:pki/lab-ca", "server_name": "idp.svc.example.internal"},
    }


def overlay(tmp: Path, *, grant: bool = True) -> Path:
    lab = tmp / "lab"
    (lab / "guests").mkdir(parents=True)
    reg = ld.load_yaml(ROOT / "examples" / "services.yml")
    reg["hosts"]["idp-1"] = {"address": GUEST, "zone": "mgmt", "role": "identity"}
    reg["services"]["idp"] = bound_row()
    (lab / "services.yml").write_text(_dump(reg))
    shutil.copy(FIXTURES / "guests" / "_baselines.yml", lab / "guests" / "_baselines.yml")
    (lab / "guests" / "idp-1.yml").write_text(
        "# SPDX-License-Identifier: Apache-2.0\n"
        "id: guest:idp-1\nkind: vm\nprovisioning: terraform\nstatus: planned\n"
        "placement: {node: hv-01, vmid: 241, vmid_scheme: freeform}\n"
        "resources:\n  cpu: {cores: 2}\n  memory: {size_mb: 4096}\n"
        "  disks: [{name: rootfs, size_gb: 32, pool: fast}]\n"
        "image: {logical: debian-13-cloudinit, kind: template-clone, os_type: linux-6}\n"
        "cloudinit: {user: ansible, ssh_authorized_keys: [operator]}\n"
        f"network: {{zone: mgmt, ip: {GUEST}}}\n"
        "capability: cap:idp\nbackup: {policy: none}\n"
        "owners: {primary: platform-team}\nbaseline: {names: [base]}\n"
    )
    rows = {n: r["capability"] for n, r in reg["services"].items()}
    hosts = {"agent-runtime": "runtime-core", "backup": "secrets-core", "broker": "idp-core",
             "edge": "edge-core", "records": "lake-core"}  # fmt: skip
    for i, (slot, host) in enumerate(sorted(hosts.items())):
        if slot not in rows.values():
            reg["services"][f"{slot}-incumbent"] = {
                "capability": slot, "impl": "example", "host": host, "protocol": "tcp",
                "port": 7001 + i, "health": {"kind": "none"}, "owner": "platform-team",
                "version": "1.0", "tls": "none",
            }  # fmt: skip
    (lab / "services.yml").write_text(_dump(reg))
    rows = {n: r["capability"] for n, r in reg["services"].items()}
    incumbents = {
        slot: {"service": next(n for n, c in rows.items() if c == slot), "why": "fictional"}
        for slot in REQUIRED
        if slot != "idp"
    }
    sel = {
        "profile": "keycloak-pilot",
        "hosts": {"identity": {"guest": "guest:idp-1"}},
        "slots": {"idp": [{"provider": "keycloak", "instance": "idp",
                           "placement": {"server": "identity"}}]},
        "incumbents": incumbents,
    }  # fmt: skip
    if grant:
        sel["grants"] = {"public_routes": {"keycloak": ["idp"]}}
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


def test_roles_holds_only_the_contributed_role():
    assert sorted(p.name for p in (MODULE / "roles").iterdir()) == ["keycloak"]
    assert not any(p.is_symlink() for p in MODULE.rglob("*"))
    manifest = ld.load_yaml(MODULE / "module.yml")
    assert [c["file"] for c in manifest["contributes"]["roles"]] == ["roles/keycloak"]


def test_the_manifest_has_no_egress_and_a_public_row_only_through_the_edge():
    manifest = ld.load_yaml(MODULE / "module.yml")
    assert manifest["egress"] == "none"
    assert set(manifest["provides"]["slots"]) == {"idp"}
    assert manifest["provides"]["slots"]["idp"]["migration"]["formats"] == ["json"]
    row = ld.load_yaml(MODULE / "registry" / "services.yml")["services"]["idp"]
    # the sign-in pages are public through the edge, on the IdP's own login, over TLS from the
    # lab CA; the public name and the CA's secret name are the site's (example values here)
    assert row["auth"] == "own" and row["tls"] == "internal" and row["protocol"] == "https"
    assert row["public_hostname"].endswith(".example.internal")
    assert row["edge_tls"] == {"ca": "secret:keycloak/ca"}
    assert "version" not in row and "clients" not in row
    for c in manifest["credentials"]:
        assert c["secret"].split("/")[0] == "secret:keycloak" and c["holder"] == "provider"


def test_the_images_are_pinned_and_the_idps_tag_is_the_product_version():
    defaults = ld.load_yaml(MODULE / "roles" / "keycloak" / "defaults" / "main.yml")
    version = ld.load_yaml(MODULE / "module.yml")["product"]["version"]
    for key in ("keycloak_image", "keycloak_postgres_image"):
        _ref, digest = defaults[key].split("@")
        assert digest.startswith("sha256:") and len(digest) == 71, key
    assert defaults["keycloak_image"].split("@")[0] == f"quay.io/keycloak/keycloak:{version}"
    assert defaults["keycloak_postgres_image"].startswith("docker.io/library/postgres:17.")


def test_pin_freshness_watches_both_images():
    sys.path.insert(0, str(ROOT / "tools"))
    try:
        import pin_freshness as pf
    finally:
        sys.path.pop(0)
    ids = {p.id for p in pf.inventory(ROOT)}
    assert {"role:keycloak/keycloak_image", "role:keycloak/keycloak_postgres_image"} <= ids
    assert pf.check_inventory(pf.inventory(ROOT)) == []


# ----------------------------------------------------------------------------- an overlay


def test_an_overlay_placing_keycloak_on_a_guest_checks_clean_and_renders(tmp_path, capsys):
    ov = overlay(tmp_path / "ov")
    code, out = _check(ov, capsys)
    assert code == 0, out
    assert "warning: keycloak/server on identity: egress: none is NOT enforced" in out
    dest = tmp_path / "out"
    code = mcli.main(["render", *_args(ov), "--out", str(dest)])
    out = capsys.readouterr().out
    assert code == 0, out
    books = yaml.safe_load((dest / "modules.yml").read_text())
    plays = [p for p in books if p["hosts"] == "mod_keycloak_server"]
    assert len(plays) == 1 and plays[0]["become"] is True
    assert plays[0]["roles"][0]["role"].endswith("modules/keycloak/roles/keycloak")
    assert plays[0]["pre_tasks"][0]["ansible.builtin.include_role"]["tasks_from"] == "readiness"
    assert plays[0]["vars"] == {"hnx_module_slice": "hnx-keycloak-server.slice"}
    assert (dest / "checks" / "keycloak.yml").is_file()


def test_a_registry_row_without_the_sites_public_name_is_named(tmp_path, capsys):
    ov = overlay(tmp_path)
    reg = ld.load_yaml(ov / "lab" / "services.yml")
    del reg["services"]["idp"]["public_hostname"]
    (ov / "lab" / "services.yml").write_text(_dump(reg))
    code, out = _check(ov, capsys)
    assert code == 1
    assert "registry: services.idp.public_hostname: keycloak (instance idp) declares one" in out


def test_the_public_row_needs_a_public_routes_grant(tmp_path, capsys):
    ov = overlay(tmp_path, grant=False)
    code, out = _check(ov, capsys)
    assert code == 1
    assert "keycloak: service idp is public without grants.public_routes" in out


# ----------------------------------------------------------------------------- conformance

pytestmark_tls = pytest.mark.requires_tool("openssl")


def _target_factory():
    target = load_target(str(MODULE / "conformance" / "target.yml"), root=ROOT)
    binding = target.binding("idp")
    assert binding.adapter == "homelabnext.conform.adapters.keycloak:make"
    return make_factory(binding, root=ROOT)


def _env(monkeypatch, kc: StandIn, password: str = ADMIN[1]) -> None:
    # the endpoint is the certificate's name; the test resolves it to loopback by the URL's
    # address instead (the stand-in's certificate also carries the loopback address)
    monkeypatch.setenv("HNX_ENDPOINT_IDP", f"https://{LOOPBACK}:{kc.port}")
    monkeypatch.setenv("HNX_IDP_CA_FILE", str(kc.pki["ca"]))
    monkeypatch.setenv("HNX_IDP_ADMIN_USER", ADMIN[0])
    monkeypatch.setenv("HNX_IDP_ADMIN_PASSWORD", password)


@pytestmark_tls
def test_the_idp_suite_passes_through_the_target_against_the_stand_in(tmp_path, monkeypatch):
    with StandIn(tmp_path, ADMIN) as kc:
        _env(monkeypatch, kc)
        results = run_checks(idp_suite.SUITE, _target_factory())
        left = sorted(kc.realms)
    assert sorted((r.check, r.status) for r in results if r.status != "pass") == []
    # every scratch realm was deleted when its target closed; nothing else was ever created
    assert left == []


@pytestmark_tls
def test_a_wrong_admin_password_fails_the_target_when_it_is_built(tmp_path, monkeypatch):
    with StandIn(tmp_path, ADMIN) as kc:
        _env(monkeypatch, kc, password="not-the-admin-password")
        with pytest.raises(KeycloakError, match="HTTP 401"):
            _target_factory()()


@pytestmark_tls
def test_a_server_outside_the_ca_is_refused(tmp_path, monkeypatch):
    other = tmp_path / "other"
    other.mkdir()
    with StandIn(tmp_path, ADMIN) as kc:
        _env(monkeypatch, kc)
        from tests.modules.keycloak_stand_in import make_pki

        monkeypatch.setenv("HNX_IDP_CA_FILE", str(make_pki(other)["ca"]))
        with pytest.raises(KeycloakError, match="URLError"):
            _target_factory()()
        assert kc.realms == {}


def test_a_missing_admin_variable_fails_when_the_target_is_built(monkeypatch):
    monkeypatch.setenv("HNX_ENDPOINT_IDP", f"https://{SERVER_NAME}:8443")
    monkeypatch.delenv("HNX_IDP_ADMIN_PASSWORD", raising=False)
    monkeypatch.setenv("HNX_IDP_ADMIN_USER", ADMIN[0])
    with pytest.raises(AdapterConfigError, match="HNX_IDP_ADMIN_PASSWORD"):
        _target_factory()()


def test_the_adapter_refuses_plain_http(tmp_path, monkeypatch):
    ca = tmp_path / "ca.pem"
    ca.write_text("not read before the scheme is checked\n")
    monkeypatch.setenv("HNX_IDP_CA_FILE", str(ca))
    monkeypatch.setenv("HNX_ENDPOINT_IDP", f"http://{SERVER_NAME}:8080")
    monkeypatch.setenv("HNX_IDP_ADMIN_USER", ADMIN[0])
    monkeypatch.setenv("HNX_IDP_ADMIN_PASSWORD", ADMIN[1])
    with pytest.raises(AdapterConfigError, match="https"):
        _target_factory()()


def test_rs256_check_rejects_a_short_or_padded_signature():
    from homelabnext.conform.adapters.keycloak import rs256_valid

    n = (1 << 2047) + 12345  # a 2048-bit odd number (not a key: only the length rules matter)
    assert not rs256_valid(n, 65537, b"x", b"\x00" * 255)
    assert not rs256_valid(n, 65537, b"x", b"\xff" * 256)  # >= n
    assert not rs256_valid((1 << 1023) + 1, 65537, b"x", b"\x01" * 128)  # a 1024-bit key
    assert SERVER_NAME.endswith(".example.internal")


# ----------------------------------------------------------------------------- lint


def test_role_lint_passes_the_role_and_the_lifecycle_playbooks():
    lint = [sys.executable, str(ROOT / "tools" / "role_lint.py")]
    r = subprocess.run([*lint, str(MODULE / "roles" / "keycloak")], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    books = sorted(str(p) for p in (MODULE / "playbooks").glob("*.yml"))
    inv = str(ROOT / "ansible" / "inventory" / "example" / "hosts.yml")
    r = subprocess.run([*lint, "--playbook", *books, "--inventory", inv],
                       capture_output=True, text=True)  # fmt: skip
    assert r.returncode == 0, r.stdout + r.stderr


def test_the_adapter_needs_the_lab_ca_and_works_only_in_a_scratch_realm(tmp_path, monkeypatch):
    from homelabnext.conform.adapters.keycloak import KeycloakIdP

    monkeypatch.setenv("HNX_ENDPOINT_IDP", f"https://{SERVER_NAME}:8443")
    monkeypatch.setenv("HNX_IDP_ADMIN_USER", ADMIN[0])
    monkeypatch.setenv("HNX_IDP_ADMIN_PASSWORD", ADMIN[1])
    monkeypatch.delenv("HNX_IDP_CA_FILE", raising=False)
    with pytest.raises(AdapterConfigError, match="HNX_IDP_CA_FILE"):
        _target_factory()()
    with pytest.raises(ValueError, match="scratch realm"):
        KeycloakIdP(f"https://{SERVER_NAME}:8443", lambda: ADMIN, realm="northwind")


@pytestmark_tls
def test_a_failed_set_up_leaves_no_scratch_realm(tmp_path, monkeypatch):
    from homelabnext.conform.adapters import keycloak as kca

    with StandIn(tmp_path, ADMIN) as kc:
        _env(monkeypatch, kc)
        monkeypatch.setattr(kca.KeycloakIdP, "_discover", lambda self: (_ for _ in ()).throw(
            KeycloakError("boom")))  # fmt: skip
        with pytest.raises(KeycloakError, match="boom"):
            _target_factory()()
        assert kc.realms == {}
