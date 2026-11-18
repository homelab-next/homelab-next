# SPDX-License-Identifier: Apache-2.0
"""The projects provider module (module id and role ``openproject``: the id is the product's, as
keycloak's and ntfy's are; ``projects`` is the slot and the instance), ``modules/openproject`` (modules/openproject/README.md).

* The public tree loads clean; the module's ``roles/`` holds only its one contributed role; its
  three images are pinned by tag and digest, the app's tag being the product's version.
* A fictional overlay that places it on a guest (every other required core slot an incumbent)
  passes ``hnx modules check --overlay`` and renders ``modules.yml`` and ``checks/openproject.yml``
  on ``mod_openproject_server``; the row is public with the app's own accounts (``auth: own``), a
  registry row without the site's ``public_hostname``, or a selection without
  ``grants.public_routes`` for it, is refused.
* The conformance target binds the shared adapter of the slot.
* role_lint passes the role and the lifecycle playbooks.
* The secrets the manifest declares are exactly the three the role reads, under the module's name.
"""

from __future__ import annotations

import copy
import re
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

from homelabnext.modules import cli as mcli
from homelabnext.modules import loader as ld
from tests.modules.play_vars import without_footprint

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "modules" / "openproject"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
#: a documentation-range address from the example registry (never connected to)
GUEST = ld.load_yaml(ROOT / "examples" / "services.yml")["hosts"]["lake-core"]["address"]
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
    the site's own public name in the one field whose value is the site's."""
    row = ld.load_yaml(MODULE / "registry" / "services.yml")["services"]["projects"]
    version = str(ld.load_yaml(MODULE / "module.yml")["product"]["version"])
    return {**copy.deepcopy(row), "host": "projects-1", "version": version,
            "public_hostname": "projects.lab.example"}  # fmt: skip


def overlay(tmp: Path, *, grant: bool = True) -> Path:
    lab = tmp / "lab"
    (lab / "guests").mkdir(parents=True)
    reg = ld.load_yaml(ROOT / "examples" / "services.yml")
    reg["hosts"]["projects-1"] = {"address": GUEST, "zone": "mgmt", "role": "work"}
    reg["services"]["projects"] = bound_row()
    shutil.copy(FIXTURES / "guests" / "_baselines.yml", lab / "guests" / "_baselines.yml")
    (lab / "guests" / "projects-1.yml").write_text(
        "# SPDX-License-Identifier: Apache-2.0\n"
        "id: guest:projects-1\nkind: vm\nprovisioning: terraform\nstatus: planned\n"
        "placement: {node: hv-01, vmid: 242, vmid_scheme: freeform}\n"
        "resources:\n  cpu: {cores: 4}\n  memory: {size_mb: 8192}\n"
        "  disks: [{name: rootfs, size_gb: 40, pool: fast}]\n"
        "image: {logical: debian-13-cloudinit, kind: template-clone, os_type: linux-6}\n"
        "cloudinit: {user: ansible, ssh_authorized_keys: [operator]}\n"
        f"network: {{zone: mgmt, ip: {GUEST}}}\n"
        "capability: cap:projects\nbackup: {policy: none}\n"
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
    }
    sel = {
        "profile": "projects-pilot",
        "hosts": {"work": {"guest": "guest:projects-1"}},
        "slots": {"projects": [{"provider": "openproject", "instance": "projects",
                                "placement": {"server": "work"}}]},
        "incumbents": incumbents,
    }  # fmt: skip
    if grant:
        sel["grants"] = {"public_routes": {"openproject": ["projects"]}}
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
    assert sorted(p.name for p in (MODULE / "roles").iterdir()) == ["openproject"]
    assert not any(p.is_symlink() for p in MODULE.rglob("*"))
    manifest = ld.load_yaml(MODULE / "module.yml")
    assert [c["file"] for c in manifest["contributes"]["roles"]] == ["roles/openproject"]


def test_the_row_is_public_through_the_edge_on_the_apps_own_accounts():
    manifest = ld.load_yaml(MODULE / "module.yml")
    assert manifest["egress"] == "none"
    assert set(manifest["provides"]["slots"]) == {"projects"}
    assert manifest["provides"]["slots"]["projects"]["migration"]["formats"] == ["object-tree"]
    row = ld.load_yaml(MODULE / "registry" / "services.yml")["services"]["projects"]
    # people sign in with their own accounts here: not behind the edge's single sign-on
    assert row["auth"] == "own" and row["auth"] != "idp"
    assert row["protocol"] == "http" and row["port"] == 8080 and row["tls"] == "none"
    assert row["health"] == {"kind": "http", "path": "/health_checks/default", "expect_status": 200}
    assert row["public_hostname"].endswith(".example.internal")
    assert "version" not in row and "clients" not in row and "roles" not in row


def test_the_secrets_are_the_three_the_role_reads_and_nothing_else():
    manifest = ld.load_yaml(MODULE / "module.yml")
    declared = sorted(c["secret"] for c in manifest["credentials"])
    assert declared == ["secret:openproject/admin-password", "secret:openproject/db-password",
                        "secret:openproject/secret-key-base"]  # fmt: skip
    assert all(c["holder"] == "provider" for c in manifest["credentials"])
    defaults = ld.load_yaml(MODULE / "roles" / "openproject" / "defaults" / "main.yml")
    refs = sorted(v for k, v in defaults.items() if k.endswith("_ref"))
    assert refs == declared
    text = "".join(p.read_text() for p in MODULE.rglob("*.yml"))
    assert sorted(set(re.findall(r"secret:[a-z0-9/_.-]+", text))) == declared


def test_the_images_are_pinned_and_the_apps_tag_carries_the_product_version():
    defaults = ld.load_yaml(MODULE / "roles" / "openproject" / "defaults" / "main.yml")
    version = ld.load_yaml(MODULE / "module.yml")["product"]["version"]
    for key in ("openproject_image", "openproject_postgres_image", "openproject_cache_image"):
        _ref, digest = defaults[key].split("@")
        assert digest.startswith("sha256:") and len(digest) == 71, key
    assert defaults["openproject_image"].split("@")[0].endswith(f":{version}-slim")
    assert defaults["openproject_postgres_image"].startswith("docker.io/library/postgres:17.")


def test_pin_freshness_watches_the_three_images():
    sys.path.insert(0, str(ROOT / "tools"))
    try:
        import pin_freshness as pf
    finally:
        sys.path.pop(0)
    ids = {p.id for p in pf.inventory(ROOT)}
    assert {
        f"role:openproject/openproject_{k}" for k in ("image", "postgres_image", "cache_image")
    } <= ids
    assert pf.check_inventory(pf.inventory(ROOT)) == []


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
    plays = [p for p in books if p["hosts"] == "mod_openproject_server"]
    assert len(plays) == 1 and plays[0]["become"] is True
    assert plays[0]["roles"][0]["role"].endswith("modules/openproject/roles/openproject")
    assert plays[0]["pre_tasks"][0]["ansible.builtin.include_role"]["tasks_from"] == "readiness"
    assert without_footprint(plays[0]["vars"]) == {
        "hnx_module_slice": "hnx-openproject-server.slice"
    }
    assert (dest / "checks" / "openproject.yml").is_file()


def test_a_registry_row_without_the_sites_public_name_is_named(tmp_path, capsys):
    ov = overlay(tmp_path)
    reg = ld.load_yaml(ov / "lab" / "services.yml")
    del reg["services"]["projects"]["public_hostname"]
    (ov / "lab" / "services.yml").write_text(_dump(reg))
    code, out = _check(ov, capsys)
    assert code == 1
    assert (
        "registry: services.projects.public_hostname: openproject (instance projects) declares one"
        in out
    )


def test_the_public_row_needs_a_public_routes_grant(tmp_path, capsys):
    ov = overlay(tmp_path, grant=False)
    code, out = _check(ov, capsys)
    assert code == 1
    assert "openproject: service projects is public without grants.public_routes" in out


# ----------------------------------------------------------------------------- conformance, lint


def test_the_conformance_target_binds_the_slots_shared_adapter():
    from homelabnext.conform.target import load_target

    target = load_target(str(MODULE / "conformance" / "target.yml"), root=ROOT)
    binding = target.binding("projects")
    assert binding.adapter == "homelabnext.conform.adapters.openproject:make"
    assert binding.config == {"config": "openproject.yml"}


def test_role_lint_passes_the_role_and_the_lifecycle_playbooks():
    lint = [sys.executable, str(ROOT / "tools" / "role_lint.py")]
    r = subprocess.run(
        [*lint, str(MODULE / "roles" / "openproject")], capture_output=True, text=True
    )
    assert r.returncode == 0, r.stdout + r.stderr
    books = sorted(str(p) for p in (MODULE / "playbooks").glob("*.yml"))
    inv = str(ROOT / "ansible" / "inventory" / "example" / "hosts.yml")
    r = subprocess.run([*lint, "--playbook", *books, "--inventory", inv],
                       capture_output=True, text=True)  # fmt: skip
    assert r.returncode == 0, r.stdout + r.stderr
