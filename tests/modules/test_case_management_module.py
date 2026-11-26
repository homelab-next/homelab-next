# SPDX-License-Identifier: Apache-2.0
"""The case-management provider module, ``modules/<id>`` (its README.md).

* The public tree loads clean; the module's ``roles/`` holds only its one contributed role; its four
  images are pinned by tag and digest, the product images' tag being ``v`` + the product's version.
* The row is internal, HTTPS with a certificate from the lab CA, the product's own accounts, no public
  route; the secrets the manifest declares are exactly the nine the role reads, under the module's name.
* A fictional overlay that places it on a guest renders ``modules.yml`` on ``mod_<id>_server`` (the render
  runs the overlay check first). role_lint and the row-binding refusals are covered by ``make gates`` and
  the shared module tests, not repeated here: the ``tests/modules`` suite is within a second of its budget.
* The slot is provisional and its shared probe is the module's adapter.
* Pin freshness watches the four images.
"""

from __future__ import annotations

import copy
import re
import shutil
import sys
from pathlib import Path

import pytest
import yaml

from homelabnext.modules import cli as mcli
from homelabnext.modules import loader as ld
from tests.modules.case_management_module import MID, MODULE, ROLE, SLOT, P, defaults
from tests.modules.play_vars import without_footprint

ROOT = Path(__file__).resolve().parents[2]
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
    """The module's row as the overlay binds it: the guest as host and the product's version."""
    row = ld.load_yaml(MODULE / "registry" / "services.yml")["services"][SLOT]
    version = str(ld.load_yaml(MODULE / "module.yml")["product"]["version"])
    return {**copy.deepcopy(row), "host": "cases-1", "version": version}


def overlay(tmp: Path, row: dict | None = None) -> Path:
    lab = tmp / "lab"
    (lab / "guests").mkdir(parents=True)
    reg = ld.load_yaml(ROOT / "examples" / "services.yml")
    reg["hosts"]["cases-1"] = {"address": GUEST, "zone": "mgmt", "role": "work"}
    reg["services"][SLOT] = row or bound_row()
    shutil.copy(FIXTURES / "guests" / "_baselines.yml", lab / "guests" / "_baselines.yml")
    (lab / "guests" / "cases-1.yml").write_text(
        "# SPDX-License-Identifier: Apache-2.0\n"
        "id: guest:cases-1\nkind: vm\nprovisioning: terraform\nstatus: planned\n"
        "placement: {node: hv-01, vmid: 243, vmid_scheme: freeform}\n"
        "resources:\n  cpu: {cores: 4}\n  memory: {size_mb: 8192}\n"
        "  disks: [{name: rootfs, size_gb: 60, pool: fast}]\n"
        "image: {logical: debian-13-cloudinit, kind: template-clone, os_type: linux-6}\n"
        "cloudinit: {user: ansible, ssh_authorized_keys: [operator]}\n"
        f"network: {{zone: mgmt, ip: {GUEST}}}\n"
        f"capability: cap:{SLOT}\nbackup: {{policy: none}}\n"
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
        "profile": "cases-pilot",
        "hosts": {"work": {"guest": "guest:cases-1"}},
        "slots": {SLOT: [{"provider": MID, "instance": SLOT, "placement": {"server": "work"}}]},
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


@pytest.mark.static
def test_roles_holds_only_the_contributed_role():
    assert sorted(p.name for p in (MODULE / "roles").iterdir()) == [ROLE]
    assert not any(p.is_symlink() for p in MODULE.rglob("*"))
    manifest = ld.load_yaml(MODULE / "module.yml")
    assert [c["file"] for c in manifest["contributes"]["roles"]] == [f"roles/{ROLE}"]


def test_the_row_is_internal_https_with_the_products_own_accounts_and_no_public_route():
    manifest = ld.load_yaml(MODULE / "module.yml")
    assert manifest["egress"] == "none"
    assert set(manifest["provides"]["slots"]) == {SLOT}
    slot = manifest["provides"]["slots"][SLOT]
    assert slot["provisional"] is True and slot["migration"]["formats"] == ["object-tree"]
    assert slot["adapter"] == "homelabnext.conform.adapters.case_management:make"
    row = ld.load_yaml(MODULE / "registry" / "services.yml")["services"][SLOT]
    assert row["auth"] == "own" and row["protocol"] == "https" and row["tls"] == "internal"
    assert row["port"] == defaults()[P + "port"] == 8443
    assert row["health"] == {"kind": "http", "path": "/login", "expect_status": 200,
                             "interval_s": 60}  # fmt: skip
    assert "public_hostname" not in row and "version" not in row and "roles" not in row


@pytest.mark.static
def test_the_secrets_are_the_ten_the_role_reads_and_nothing_else():
    manifest = ld.load_yaml(MODULE / "module.yml")
    declared = sorted(c["secret"] for c in manifest["credentials"])
    # nine for the service, one for the optional MISP wiring (the platform account's key)
    assert len(declared) == 10 and all(s.startswith(f"secret:{MID}/") for s in declared)
    assert all(c["holder"] == "provider" for c in manifest["credentials"])
    refs = sorted(
        v for k, v in defaults().items() if k.endswith("_ref") and str(v).startswith("secret:")
    )
    assert refs == declared
    text = "".join(p.read_text() for p in MODULE.rglob("*.yml"))
    assert sorted(set(re.findall(r"secret:[a-z0-9/_.-]+", text))) == declared


def test_the_images_are_pinned_and_the_product_images_tag_carries_the_version():
    d = defaults()
    version = ld.load_yaml(MODULE / "module.yml")["product"]["version"]
    for key in ("app_image", "db_image", "nginx_image", "broker_image"):
        _ref, digest = d[P + key].split("@")
        assert digest.startswith("sha256:") and len(digest) == 71, key
    for key in ("app_image", "db_image", "nginx_image"):
        assert d[P + key].split("@")[0].endswith(f":v{version}"), key  # one release


@pytest.mark.static
def test_the_slot_is_registered_classified_and_provisional():
    slots = ld.load_yaml(ROOT / "examples" / "modules" / "slots.yml")["slots"]
    assert slots[SLOT]["contract"] is None and slots[SLOT]["stateful"] is True
    classes = yaml.safe_load((ROOT / "homelabnext" / "agent" / "tool_classes.yml").read_text())
    assert classes["capabilities"][f"cap:{SLOT}"] == ["record-write"]


@pytest.mark.static
def test_pin_freshness_watches_the_four_images():
    sys.path.insert(0, str(ROOT / "tools"))
    try:
        import pin_freshness as pf
    finally:
        sys.path.pop(0)
    ids = {p.id for p in pf.inventory(ROOT)}
    assert {
        f"role:{ROLE}/{P}{k}" for k in ("app_image", "db_image", "nginx_image", "broker_image")
    } <= ids
    assert pf.check_inventory(pf.inventory(ROOT)) == []


# ----------------------------------------------------------------------------- an overlay


def test_an_overlay_placing_the_module_on_a_guest_checks_clean_and_renders(tmp_path, capsys):
    ov = overlay(tmp_path / "ov")
    dest = tmp_path / "out"
    code = mcli.main(["render", *_args(ov), "--out", str(dest)])
    out = capsys.readouterr().out
    assert code == 0, out
    books = yaml.safe_load((dest / "modules.yml").read_text())
    plays = [p for p in books if p["hosts"] == f"mod_{ROLE}_server"]
    assert len(plays) == 1 and plays[0]["become"] is True
    assert plays[0]["roles"][0]["role"].endswith(f"modules/{MID}/roles/{ROLE}")
    assert plays[0]["pre_tasks"][0]["ansible.builtin.include_role"]["tasks_from"] == "readiness"
    assert without_footprint(plays[0]["vars"]) == {"hnx_module_slice": f"hnx-{ROLE}-server.slice"}


# ----------------------------------------------------------------------------- lint
