# SPDX-License-Identifier: Apache-2.0
"""The automation provider module (the module that fills the ``automation`` slot; its README).

* The public tree loads clean; ``roles/`` holds only the contributed role; the images are pinned by
  digest and the st2 release is the product's version; the slot is provisional (no contract yet)
  with a shared, product-free client.
* The row is internal (no public hostname, no edge site), carries its own sign-in, and its status
  source is a reader the status hub has, with only the mapping keys that reader takes.
* Everything the manifest asks of the site is named: the broker and bus it reaches, the egress the
  site must grant (the interpreter's download and the package index), a memory budget inside the
  footprint, and credentials by reference only.
* A fictional overlay that places it on a guest (and grants its egress) passes ``hnx modules check
  --overlay`` and renders a play on ``mod_<id>_server`` with the role, its readiness preflight and
  its slice; a row that differs, an ungranted egress, a public route and a guest without the
  ``base`` baseline are refused.
* The status fixture the hub already parses keeps parsing.

The module is found by the slot it fills; nothing here names the product.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

from homelabnext.modules import cli as mcli
from homelabnext.modules import loader as ld
from homelabnext.status import products as status_products
from tests.modules.play_vars import without_footprint

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _module_dir() -> Path:
    for manifest in sorted((ROOT / "modules").glob("*/module.yml")):
        if "automation" in (ld.load_yaml(manifest).get("provides") or {}).get("slots", {}):
            return manifest.parent
    raise AssertionError("no module fills the automation slot")


MODULE = _module_dir()
ID = MODULE.name
MANIFEST = ld.load_yaml(MODULE / "module.yml")
DEFAULTS = ld.load_yaml(MODULE / "roles" / ID / "defaults" / "main.yml")
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


def bound_row() -> dict:
    """The module's row as the overlay copies it: the instance's name, the guest as host and the
    product's version."""
    row = ld.load_yaml(MODULE / "registry" / "services.yml")["services"]["automation"]
    return {**copy.deepcopy(row), "host": "auto-1", "version": str(MANIFEST["product"]["version"])}


def overlay(tmp: Path) -> Path:
    lab = tmp / "lab"
    (lab / "guests").mkdir(parents=True)
    reg = ld.load_yaml(ROOT / "examples" / "services.yml")
    guest = str(ipaddress.ip_address(reg["hosts"]["mon-core"]["address"]) + 100)
    reg["hosts"]["auto-1"] = {"address": guest, "zone": "mgmt", "role": "automation"}
    reg["services"].pop("automation", None)  # the example registry's own automation row
    reg["services"]["automation-1"] = bound_row()
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
    (lab / "guests" / "auto-1.yml").write_text(
        "# SPDX-License-Identifier: Apache-2.0\n"
        "id: guest:auto-1\nkind: vm\nprovisioning: terraform\nstatus: planned\n"
        "placement: {node: hv-01, vmid: 243, vmid_scheme: freeform}\n"
        "resources:\n  cpu: {cores: 4}\n  memory: {size_mb: 8192}\n"
        "  disks: [{name: rootfs, size_gb: 64, pool: fast}]\n"
        "image: {logical: debian-13-cloudinit, kind: template-clone, os_type: linux-6}\n"
        "cloudinit: {user: ansible, ssh_authorized_keys: [operator]}\n"
        f"network: {{zone: mgmt, ip: {guest}}}\n"
        "capability: cap:automation\nbackup: {policy: none}\n"
        "owners: {primary: platform-team}\nbaseline: {names: [base]}\n"
    )
    rows = {n: r["capability"] for n, r in reg["services"].items()}
    incumbents = {
        slot: {"service": next(n for n, c in rows.items() if c == slot), "why": "fictional"}
        for slot in REQUIRED
    }
    sel = {
        "profile": "automation-pilot",
        "hosts": {"auto": {"guest": "guest:auto-1"}},
        "slots": {"automation": [{"provider": ID, "instance": "automation-1", "placement": {"server": "auto"}}]},
        "incumbents": incumbents,
        "grants": {"egress": {ID: {"server": ["internet"]}}},
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
    assert sorted(p.name for p in (MODULE / "roles").iterdir()) == [ID]
    assert not any(p.is_symlink() for p in MODULE.rglob("*"))
    assert [c["file"] for c in MANIFEST["contributes"]["roles"]] == [f"roles/{ID}"]


def test_the_slot_is_provisional_and_the_client_is_a_shared_one_that_names_no_product():
    slot = MANIFEST["provides"]["slots"]["automation"]
    assert (
        slot["provisional"] is True
        and slot["adapter"] == "homelabnext.conform.adapters.automation:make"
    )
    registry = ld.load_yaml(ROOT / "examples" / "modules" / "slots.yml")["slots"]
    assert registry["automation"]["contract"] is None and not registry["automation"].get(
        "required_in_core"
    )
    assert (
        not list((MODULE / "conformance").glob("*")) if (MODULE / "conformance").exists() else True
    )


def test_the_row_is_internal_has_its_own_sign_in_and_a_status_source_the_hub_reads():
    row = ld.load_yaml(MODULE / "registry" / "services.yml")["services"]["automation"]
    assert "public_hostname" not in row and "edge_tls" not in row
    assert row["auth"] == "own" and row["tls"] == "none" and "version" not in row
    assert row["host"] == "server" and row["port"] == 9101
    source, shadow = row["status_sources"]
    for src in (source, shadow):
        assert src["kind"] in status_products.PRODUCT_COLLECTORS
        assert (
            src["target"]["path"] == "/api/v1/executions"
        )  # the front's path: the API itself has no /api prefix
        assert src["auth"]["secret"] in {c["secret"] for c in MANIFEST["credentials"]}
    assert set(source["mapping"]) <= status_products._KIND_KEYS[source["kind"]]
    # the second reads the shadow evidence per rule (a promotion review's input), same key
    assert shadow["kind"] == source["kind"] and shadow["auth"] == source["auth"]
    assert shadow["mapping"]["builtin"] == status_products.AUTOMATION_SHADOW
    assert status_products.source_problems(shadow, "automation") == []


def test_the_status_fixture_the_hub_already_parses_still_parses():
    kind = ld.load_yaml(MODULE / "registry" / "services.yml")["services"]["automation"][
        "status_sources"
    ][0]["kind"]
    fixture = (
        ROOT / "tests" / "status" / "fixtures" / (kind.removeprefix("poll-") + "-executions.json")
    )
    doc = json.loads(fixture.read_text())
    assert isinstance(doc, list) and doc and all("status" in e and "action" in e for e in doc)


def test_every_image_is_pinned_by_digest_and_the_release_is_the_products_version():
    release_digests = DEFAULTS[f"{ID}_release_digests"]
    assert len(release_digests) == 10 and all(
        d.startswith("sha256:") and len(d) == 71 for d in release_digests.values()
    )
    assert DEFAULTS[f"{ID}_release_tag"] == MANIFEST["product"]["version"]
    for name in ("mongo", "rabbitmq", "redis", "python_provisioner"):
        image = DEFAULTS[f"{ID}_{name}_image"]
        ref, digest = image.split("@")
        assert digest.startswith("sha256:") and len(digest) == 71
        assert not ref.endswith(":latest") and ":" in ref.rsplit("/", 1)[1], name


def test_the_manifest_declares_what_it_reaches_and_holds_no_literal_secret():
    assert MANIFEST["egress"] == [
        {"host": "server", "to": ["internet"], "purpose": MANIFEST["egress"][0]["purpose"]}
    ]
    caps = {c["cap"] for c in MANIFEST["requires"]["capabilities"]}
    assert {"cap:secrets", "cap:broker", "cap:events"} <= caps
    refs = {c["secret"] for c in MANIFEST["credentials"]}
    assert all(r.startswith(f"secret:{ID}/") for r in refs) and len(refs) == len(
        MANIFEST["credentials"]
    )
    for key, val in DEFAULTS.items():  # every reference the role takes is one the manifest declares
        if key.endswith("_ref"):
            assert val in refs, key
    # the role's budget is the placed footprint's memory, the manifest's as its fallback
    mem = DEFAULTS[f"{ID}_footprint_memory_mb"]
    assert "hnx_module_footprint" in mem
    assert mem.endswith(
        f"default({MANIFEST['requires']['hosts'][0]['footprint']['memory_mb']}) }}}}"
    )
    assert (MODULE / "roles" / ID / "files" / "runtime-compat.txt").is_file()


def test_the_lifecycle_playbooks_target_the_module_group_and_export_before_removing():
    for name in ("install", "upgrade", "remove"):
        plays = yaml.safe_load((MODULE / "playbooks" / f"{name}.yml").read_text())
        assert [p["hosts"] for p in plays] == [f"mod_{ID}_server"]
    assert MANIFEST["lifecycle"]["remove"]["export_first"] is True
    remove = (MODULE / "playbooks" / "remove.yml").read_text()
    assert remove.index("tasks_from: export") < remove.index("down")


# ----------------------------------------------------------------------------- an overlay


def test_an_overlay_placing_the_module_on_a_guest_checks_clean_and_renders(tmp_path, capsys):
    ov = overlay(tmp_path / "ov")
    code, out = _check(ov, capsys)
    assert code == 0, out
    assert " 0 problem(s)" in out.rstrip().splitlines()[-1]
    dest = tmp_path / "out"
    code = mcli.main(["render", *_args(ov), "--out", str(dest)])
    out = capsys.readouterr().out
    assert code == 0, out
    books = yaml.safe_load((dest / "modules.yml").read_text())
    plays = [p for p in books if p["hosts"] == f"mod_{ID}_server"]
    assert len(plays) == 1 and plays[0]["become"] is True
    assert plays[0]["roles"][0]["role"].endswith(f"modules/{ID}/roles/{ID}")
    assert plays[0]["pre_tasks"][0]["ansible.builtin.include_role"]["tasks_from"] == "readiness"
    assert without_footprint(plays[0]["vars"]) == {"hnx_module_slice": f"hnx-{ID}-server.slice"}
    assert (dest / "limits" / "auto" / f"hnx-{ID}-server.slice").is_file()


def test_a_registry_row_that_differs_is_named(tmp_path, capsys):
    ov = overlay(tmp_path)
    reg = ld.load_yaml(ov / "lab" / "services.yml")
    reg["services"]["automation-1"]["port"] = 8080
    (ov / "lab" / "services.yml").write_text(_dump(reg))
    code, out = _check(ov, capsys)
    assert code == 1 and "services.automation-1.port" in out and "9101" in out, out


def test_a_row_that_gains_a_public_route_is_refused(tmp_path, capsys):
    ov = overlay(tmp_path)
    reg = ld.load_yaml(ov / "lab" / "services.yml")
    reg["services"]["automation-1"]["public_hostname"] = "automation.example.internal"
    (ov / "lab" / "services.yml").write_text(_dump(reg))
    code, out = _check(ov, capsys)
    assert code == 1 and "public_hostname" in out, out


def test_an_ungranted_egress_is_refused(tmp_path, capsys):
    ov = overlay(tmp_path)
    sel = ld.load_yaml(ov / "lab" / "modules.yml")
    del sel["grants"]["egress"]
    (ov / "lab" / "modules.yml").write_text(_dump(sel))
    code, out = _check(ov, capsys)
    assert code == 1 and "internet" in out, out


def test_a_guest_without_the_base_baseline_is_refused(tmp_path, capsys):
    ov = overlay(tmp_path)
    g = ov / "lab" / "guests" / "auto-1.yml"
    g.write_text(g.read_text().replace("names: [base]", "names: []"))
    code, out = _check(ov, capsys)
    assert code == 1 and "base" in out, out


def test_the_slot_cannot_be_both_the_module_and_an_incumbent(tmp_path, capsys):
    ov = overlay(tmp_path)
    sel = ld.load_yaml(ov / "lab" / "modules.yml")
    sel["incumbents"]["automation"] = {"service": "automation-1", "why": "both"}
    (ov / "lab" / "modules.yml").write_text(_dump(sel))
    code, out = _check(ov, capsys)
    assert code == 1 and "incumbents.automation: the slot is also selected under slots" in out, out


# ----------------------------------------------------------------------------- lint


def test_role_lint_passes_the_role_and_the_lifecycle_playbooks():
    lint = [sys.executable, str(ROOT / "tools" / "role_lint.py")]
    r = subprocess.run([*lint, str(MODULE / "roles" / ID)], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    books = sorted(str(p) for p in (MODULE / "playbooks").glob("*.yml"))
    inv = str(ROOT / "ansible" / "inventory" / "example" / "hosts.yml")
    r = subprocess.run(
        [*lint, "--playbook", *books, "--inventory", inv], capture_output=True, text=True
    )
    assert r.returncode == 0, r.stdout + r.stderr
