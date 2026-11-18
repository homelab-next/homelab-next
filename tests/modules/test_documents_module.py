# SPDX-License-Identifier: Apache-2.0
"""The documents provider module, ``modules/documents`` (modules/documents/README.md).

* The public tree loads clean and the module's ``roles/`` holds only its one contributed role.
* The manifest says what the README says: three secrets by reference (signing key, admin password,
  API token), no egress, no public route, local accounts, a pinned application image whose version
  is the product's and a pinned broker.
* A fictional overlay that places it on a guest (no egress grant, no public route) passes
  ``hnx modules check --overlay`` and renders ``modules.yml`` on ``mod_documents_server``; a
  registry row that differs and a guest without the ``base`` baseline are refused.
* The module's own probe reads the sign-in page and the refused anonymous list from the resolved
  endpoint only.
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
from tests.modules.documents_front import Server
from tests.modules.play_vars import without_footprint

ROOT = Path(__file__).resolve().parents[2]

FIXTURES = Path(__file__).resolve().parent / "fixtures"
MODULE = ROOT / "modules" / "documents"
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
    row = ld.load_yaml(MODULE / "registry" / "services.yml")["services"]["documents"]
    version = str(ld.load_yaml(MODULE / "module.yml")["product"]["version"])
    return {**copy.deepcopy(row), "host": "documents-1", "version": version}


def overlay(tmp: Path) -> Path:
    lab = tmp / "lab"
    (lab / "guests").mkdir(parents=True)
    reg = ld.load_yaml(ROOT / "examples" / "services.yml")
    reg["hosts"]["documents-1"] = {"address": GUEST, "zone": "mgmt", "role": "documents"}
    reg["services"]["docs-library"] = bound_row()
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
    (lab / "guests" / "documents-1.yml").write_text(
        "# SPDX-License-Identifier: Apache-2.0\n"
        "id: guest:documents-1\nkind: vm\nprovisioning: terraform\nstatus: planned\n"
        "placement: {node: hv-01, vmid: 242, vmid_scheme: freeform}\n"
        "resources:\n  cpu: {cores: 2}\n  memory: {size_mb: 3072}\n"
        "  disks: [{name: rootfs, size_gb: 20, pool: fast}]\n"
        "image: {logical: debian-13-cloudinit, kind: template-clone, os_type: linux-6}\n"
        "cloudinit: {user: ansible, ssh_authorized_keys: [operator]}\n"
        f"network: {{zone: mgmt, ip: {GUEST}}}\n"
        "capability: cap:documents\nbackup: {policy: none}\n"
        "owners: {primary: platform-team}\nbaseline: {names: [base]}\n"
    )
    rows = {n: r["capability"] for n, r in reg["services"].items()}
    incumbents = {
        slot: {"service": next(n for n, c in rows.items() if c == slot), "why": "fictional"}
        for slot in REQUIRED
    }
    sel = {
        "profile": "documents-pilot",
        "hosts": {"documents": {"guest": "guest:documents-1"}},
        "slots": {"documents": [{"provider": "documents", "instance": "docs-library", "placement": {"server": "documents"}}]},
        "incumbents": incumbents,
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
    assert sorted(p.name for p in (MODULE / "roles").iterdir()) == ["documents"]
    assert not any(p.is_symlink() for p in MODULE.rglob("*"))
    manifest = ld.load_yaml(MODULE / "module.yml")
    assert [c["file"] for c in manifest["contributes"]["roles"]] == ["roles/documents"]


def test_the_manifest_names_its_four_secrets_and_no_egress_and_no_public_route():
    manifest = ld.load_yaml(MODULE / "module.yml")
    assert [c["secret"] for c in manifest["credentials"]] == [
        "secret:documents/secret-key",
        "secret:documents/admin-password",
        "secret:documents/api-token",
        "secret:documents/agent-token",
    ]
    assert manifest["egress"] == "none"
    row = ld.load_yaml(MODULE / "registry" / "services.yml")["services"]["documents"]
    assert row["auth"] == "own" and row["port"] == 8000
    assert row["health"]["path"] == "/accounts/login/"
    assert "public_hostname" not in row  # private by default: the site adds a route if it wants one
    assert "version" not in row  # a provider's row takes product.version


def test_the_role_defaults_carry_the_same_four_references():
    d = ld.load_yaml(MODULE / "roles" / "documents" / "defaults" / "main.yml")
    refs = {
        d["documents_signing_ref"],
        d["documents_admin_login_ref"],
        d["documents_api_login_ref"],
        d["documents_agent_login_ref"],
    }
    manifest = ld.load_yaml(MODULE / "module.yml")
    assert refs == {c["secret"] for c in manifest["credentials"]}


def test_the_image_pins_are_the_product_version_and_digests():
    defaults = ld.load_yaml(MODULE / "roles" / "documents" / "defaults" / "main.yml")
    version = ld.load_yaml(MODULE / "module.yml")["product"]["version"]
    for key in ("documents_image", "documents_broker_image"):
        image = defaults[key]
        assert image.split("@")[1].startswith("sha256:") and len(image.split("@")[1]) == 71, key
    assert defaults["documents_image"].split("@")[0].endswith(":" + version)


def test_the_defaults_are_sqlite_a_private_inbox_and_languages_as_data():
    d = ld.load_yaml(MODULE / "roles" / "documents" / "defaults" / "main.yml")
    assert d["documents_ocr_languages"] == ["eng"]
    assert d["documents_admin_bootstrap"] is True and d["documents_port"] == 8000
    text = (MODULE / "roles" / "documents" / "tasks" / "app.yml").read_text()
    assert (
        "PAPERLESS_DBHOST" not in text and "PAPERLESS_DBENGINE" not in text
    )  # the one database file
    assert "consume" in text


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
    plays = [p for p in books if p["hosts"] == "mod_documents_server"]
    assert len(plays) == 1 and plays[0]["become"] is True
    assert plays[0]["roles"][0]["role"].endswith("modules/documents/roles/documents")
    assert without_footprint(plays[0]["vars"]) == {"hnx_module_slice": "hnx-documents-server.slice"}


def test_a_registry_row_that_differs_is_named(tmp_path, capsys):
    ov = overlay(tmp_path)
    reg = ld.load_yaml(ov / "lab" / "services.yml")
    reg["services"]["docs-library"]["auth"] = "idp"
    (ov / "lab" / "services.yml").write_text(_dump(reg))
    code, out = _check(ov, capsys)
    assert code == 1 and "registry: services.docs-library.auth" in out, out


def test_a_guest_without_the_base_baseline_is_refused(tmp_path, capsys):
    ov = overlay(tmp_path)
    g = ov / "lab" / "guests" / "documents-1.yml"
    g.write_text(g.read_text().replace("names: [base]", "names: []"))
    code, out = _check(ov, capsys)
    assert code == 1 and "base" in out, out


# ----------------------------------------------------------------------------- the probe


def test_the_probe_reads_the_sign_in_page_and_the_refused_list_from_the_resolved_endpoint(
    monkeypatch,
):
    from homelabnext.conform.adapters.documents import make

    monkeypatch.delenv("HNX_ENDPOINT_DOCUMENTS", raising=False)
    with pytest.raises(AdapterConfigError, match="HNX_ENDPOINT_DOCUMENTS"):
        make()  # no default endpoint
    with Server() as srv:
        monkeypatch.setenv("HNX_ENDPOINT_DOCUMENTS", "http://{}:{}".format(*srv.addr))
        probe = make()
        assert probe.health() and probe.library_is_private()
        assert srv.paths == ["/accounts/login/", "/api/documents/?page_size=1"]
        assert srv.tokens == []  # no credential is ever sent
    probe.close()


def test_the_probe_says_so_when_the_library_is_open_to_anonymous_readers(monkeypatch):
    from homelabnext.conform.adapters.documents import make

    with Server(anonymous=200) as srv:
        monkeypatch.setenv("HNX_ENDPOINT_DOCUMENTS", "http://{}:{}".format(*srv.addr))
        assert make().library_is_private() is False


# ----------------------------------------------------------------------------- lint


def test_role_lint_passes_the_role_and_the_lifecycle_playbooks():
    lint = [sys.executable, str(ROOT / "tools" / "role_lint.py")]
    r = subprocess.run([*lint, str(MODULE / "roles" / "documents")], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    books = sorted(str(p) for p in (MODULE / "playbooks").glob("*.yml"))
    inv = str(ROOT / "ansible" / "inventory" / "example" / "hosts.yml")
    r = subprocess.run(
        [*lint, "--playbook", *books, "--inventory", inv], capture_output=True, text=True
    )
    assert r.returncode == 0, r.stdout + r.stderr
