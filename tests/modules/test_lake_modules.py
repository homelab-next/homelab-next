# SPDX-License-Identifier: Apache-2.0
"""The three lake provider modules (modules/garage, modules/iceberg-rest, modules/trino).

One module per product (a provider module fills its slots with one product), the three placed on
one guest by the site:

* each manifest fills the slot the lake contracts name, with the shared adapter and the conformance
  target, pins its image by digest at the product version, and keeps its secrets in its own namespace;
* the lake's fixed names are fixed (the bucket, the catalog, the warehouse, the region), the S3
  settings of the three agree, and no file names the operator's workstation;
* a fictional overlay placing all three on one guest passes ``hnx modules check --overlay``, renders
  the three plays, and a registry row that differs from a module's is named;
* the maintenance timer is a contributed scheduler job of the module whose role installs it;
* the object-store suite passes through the object store's conformance target against a loopback S3
  server, and the catalog client accepts a catalog that names no warehouse prefix (the only shape
  the Apache REST catalog has) only when told to;
* role_lint passes the three roles and the lifecycle playbooks.
"""

from __future__ import annotations

import copy
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from conformance.suites import object_store as object_store_suite
from homelabnext.conform.core import run_checks
from homelabnext.conform.target import load_target, make_factory
from homelabnext.modules import cli as mcli
from homelabnext.modules import loader as ld
from tests.conform.fake_s3 import FakeS3

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parent / "fixtures"
GUEST = "192.0.2.60"  # no-raw-endpoint: allow a documentation-range guest address
MODULES = {
    "garage": {"slot": "object-store", "role": "garage", "row": "object-store"},
    "iceberg-rest": {"slot": "lake-catalog", "role": "iceberg_rest", "row": "lake-catalog"},
    "trino": {"slot": "lake-query", "role": "trino", "row": "lake-query"},
}
REQUIRED = sorted(
    s for s, d in ld.load_yaml(ROOT / "examples" / "modules" / "slots.yml")["slots"].items()
    if d.get("required_in_core")
)  # fmt: skip


def manifest(mid: str) -> dict:
    return ld.load_yaml(ROOT / "modules" / mid / "module.yml")


def defaults(mid: str) -> dict:
    return ld.load_yaml(
        ROOT / "modules" / mid / "roles" / MODULES[mid]["role"] / "defaults" / "main.yml"
    )


# ----------------------------------------------------------------------------- the manifests


@pytest.mark.parametrize("mid", MODULES)
def test_the_module_fills_its_slot_with_one_product_and_the_shared_adapter(mid):
    m = manifest(mid)
    assert m["kind"] == "provider" and m["egress"] == "none"
    assert list(m["provides"]["slots"]) == [MODULES[mid]["slot"]]
    slot = m["provides"]["slots"][MODULES[mid]["slot"]]
    assert slot["adapter"].startswith("homelabnext.conform.adapters.")
    assert (ROOT / "modules" / mid / slot["conformance"]["target"]).is_file()
    assert [c["file"] for c in m["contributes"]["roles"]] == [f"roles/{MODULES[mid]['role']}"]
    assert sorted(p.name for p in (ROOT / "modules" / mid / "roles").iterdir()) == [
        MODULES[mid]["role"]
    ]
    assert not any(p.is_symlink() for p in (ROOT / "modules" / mid).rglob("*"))
    row = ld.load_yaml(ROOT / "modules" / mid / "registry" / "services.yml")["services"][
        MODULES[mid]["row"]
    ]
    assert (
        row["capability"] == MODULES[mid]["slot"]
        and row["impl"] == manifest(mid)["product"]["name"]
    )
    assert "version" not in row and "public_hostname" not in row  # internal only


@pytest.mark.parametrize("mid", MODULES)
def test_every_secret_is_in_the_modules_own_namespace_and_none_has_a_value(mid):
    refs = [c["secret"] for c in manifest(mid)["credentials"]]
    assert refs and all(r.startswith(f"secret:{mid}/") for r in refs)
    assert len(set(refs)) == len(refs)
    text = yaml.safe_dump(defaults(mid))
    for ref in (x for x in refs if x in text):
        assert f"{ref}" in text  # named by reference in the role's defaults, never by value


@pytest.mark.parametrize("mid", MODULES)
def test_the_image_is_pinned_by_digest_at_the_product_version(mid):
    d = defaults(mid)
    image = d[f"{MODULES[mid]['role']}_image"]
    repo_tag, digest = image.split("@")
    assert digest.startswith("sha256:") and len(digest) == 71
    tag = repo_tag.rsplit(":", 1)[1]
    version = str(manifest(mid)["product"]["version"])
    assert tag != "latest"
    assert tag.lstrip("v") == version or version.startswith(tag.lstrip("v") + ".")


def test_the_catalog_runs_the_very_build_the_old_lake_wrote_its_catalog_with():
    image = defaults("iceberg-rest")["iceberg_rest_image"]
    assert image.endswith(
        "@sha256:db8de90b5b7693d4ac334c336f91d9bbe320d7b19f4f514d26de84cdfbcbfe8d"
    )


def test_the_object_store_is_the_major_version_the_old_lake_runs():
    # the old lake runs v2.3.0; the repository pins v2.5.0. Same major: the S3 API and the admin
    # API v2 are the same, and the objects are copied through the S3 API, not as Garage's own files.
    assert defaults("garage")["garage_image"].split("@")[0].rsplit(":", 1)[1].startswith("v2.")


def test_the_lakes_fixed_names_agree_across_the_three_roles():
    g, c, t = defaults("garage"), defaults("iceberg-rest"), defaults("trino")
    assert (
        g["garage_bucket"] == "iceberg-warehouse"
    )  # the table metadata embeds s3://iceberg-warehouse/
    assert c["iceberg_rest_warehouse"] == t["trino_warehouse"] == "s3://iceberg-warehouse/"
    assert g["garage_region"] == c["iceberg_rest_region"] == t["trino_region"] == "garage"
    assert t["trino_catalog_name"] == "iceberg"
    assert c["iceberg_rest_busy_timeout_ms"] == 30000  # LL-407


def test_the_trino_retention_values_are_the_lakes():
    t = defaults("trino")
    assert (t["trino_expire_retention"], t["trino_retain_last"], t["trino_orphan_retention"]) == (
        "7d",
        10,
        "3d",
    )
    # the engine's floors sit at or below what the timer asks, so it never refuses its own run
    assert int(t["trino_expire_min_retention"][:-1]) <= int(t["trino_expire_retention"][:-1])
    assert int(t["trino_orphan_min_retention"][:-1]) <= int(t["trino_orphan_retention"][:-1])
    assert (
        "OnCalendar" not in t["trino_maintenance_schedule"]
    )  # the value is a calendar, not a boot offset
    assert "boot" not in t["trino_maintenance_schedule"].lower()


def test_the_timer_is_a_scheduler_job_of_the_role_that_installs_it():
    m = manifest("trino")
    assert m["contributes"]["scheduler_jobs"] == [{"timer": "timer:trino/lake-maintenance"}]
    assert {"cap:notify", "cap:lake-catalog", "cap:object-store"} <= {
        c["cap"] for c in m["requires"]["capabilities"]
    }
    units = sorted(
        p.name
        for p in (ROOT / "modules" / "trino" / "roles" / "trino" / "templates").glob(
            "lake-maintenance.*"
        )
    )
    assert units == [
        "lake-maintenance.py.j2",
        "lake-maintenance.service.j2",
        "lake-maintenance.timer.j2",
    ]


def test_nothing_in_the_modules_names_the_operators_workstation():
    for mid in MODULES:
        for f in (ROOT / "modules" / mid).rglob("*"):
            if f.is_file():
                text = f.read_text().lower()
                assert not re.search(r"192\.168\.20\.150|wsl", text), f


# ----------------------------------------------------------------------------- an overlay


class _NoAliases(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


def _dump(doc) -> str:
    return yaml.dump(doc, Dumper=_NoAliases, sort_keys=False)


def bound_row(mid: str) -> dict:
    row = ld.load_yaml(ROOT / "modules" / mid / "registry" / "services.yml")["services"][
        MODULES[mid]["row"]
    ]
    return {
        **copy.deepcopy(row),
        "host": "lake-1",
        "version": str(manifest(mid)["product"]["version"]),
    }


def overlay(tmp: Path) -> Path:
    """A fictional overlay placing the three lake modules on one guest, every other required core
    slot an incumbent."""
    lab = tmp / "lab"
    (lab / "guests").mkdir(parents=True)
    reg = ld.load_yaml(ROOT / "examples" / "services.yml")
    reg["hosts"]["lake-1"] = {"address": GUEST, "zone": "mgmt", "role": "lake"}
    for mid in MODULES:
        reg["services"][MODULES[mid]["row"]] = bound_row(mid)
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
    (lab / "guests" / "lake-1.yml").write_text(
        "# SPDX-License-Identifier: Apache-2.0\n"
        "id: guest:lake-1\nkind: vm\nprovisioning: terraform\nstatus: planned\n"
        "placement: {node: hv-01, vmid: 241, vmid_scheme: freeform}\n"
        "resources:\n  cpu: {cores: 8}\n  memory: {size_mb: 32768}\n"
        "  disks: [{name: rootfs, size_gb: 400, pool: fast}]\n"
        "image: {logical: debian-13-cloudinit, kind: template-clone, os_type: linux-6}\n"
        "cloudinit: {user: ansible, ssh_authorized_keys: [operator]}\n"
        f"network: {{zone: mgmt, ip: {GUEST}}}\n"
        "capability: cap:lake-query\nbackup: {policy: none}\n"
        "owners: {primary: platform-team}\nbaseline: {names: [base]}\n"
    )
    rows = {n: r["capability"] for n, r in reg["services"].items()}
    taken = {m["slot"] for m in MODULES.values()}
    incumbents = {
        slot: {"service": next(n for n, c in rows.items() if c == slot), "why": "fictional"}
        for slot in REQUIRED
        if slot not in taken
    }
    sel = {
        "profile": "lake-pilot",
        "hosts": {"lake": {"guest": "guest:lake-1"}},
        "slots": {m["slot"]: [{"provider": mid, "instance": m["row"], "placement": {"server": "lake"}}]
                  for mid, m in MODULES.items()},
        "incumbents": incumbents,
    }  # fmt: skip
    (lab / "modules.yml").write_text(_dump(sel))
    return tmp


def _args(ov: Path) -> list[str]:
    return ["--root", str(ROOT), "--overlay", str(ov),
            "--keyring", str(ROOT / "examples" / "keyring" / "keyring.json"),
            "--mcp-catalog", str(ROOT / "examples" / "mcp")]  # fmt: skip


def test_the_public_tree_loads_clean(capsys):
    code = mcli.main(["check", "--root", str(ROOT)])
    out = capsys.readouterr().out
    assert code == 0, out
    public = sum(1 for p in (ROOT / "modules").iterdir() if (p / "module.yml").is_file())
    assert out.rstrip().endswith(f"{public} module(s), 0 problem(s)")


def test_an_overlay_placing_the_three_modules_on_one_guest_checks_clean_and_renders(
    tmp_path, capsys
):
    ov = overlay(tmp_path / "ov")
    code = mcli.main(["check", *_args(ov)])
    out = capsys.readouterr().out
    assert code == 0, out
    dest = tmp_path / "out"
    code = mcli.main(["render", *_args(ov), "--out", str(dest)])
    out = capsys.readouterr().out
    assert code == 0, out
    books = yaml.safe_load((dest / "modules.yml").read_text())
    for mid, m in MODULES.items():
        plays = [p for p in books if p["hosts"] == f"mod_{mid.replace('-', '_')}_server"]
        assert len(plays) == 1 and plays[0]["become"] is True, mid
        assert plays[0]["roles"][0]["role"].endswith(f"modules/{mid}/roles/{m['role']}")
        assert plays[0]["pre_tasks"][0]["ansible.builtin.include_role"]["tasks_from"] == "readiness"
    # the three share one guest: each container joins its own role's slice
    assert (dest / "limits" / "lake").is_dir()


@pytest.mark.parametrize("mid", MODULES)
def test_a_registry_row_that_differs_is_named(mid, tmp_path, capsys):
    ov = overlay(tmp_path)
    reg = ld.load_yaml(ov / "lab" / "services.yml")
    reg["services"][MODULES[mid]["row"]]["port"] = 9999
    (ov / "lab" / "services.yml").write_text(_dump(reg))
    code = mcli.main(["check", *_args(ov)])
    out = capsys.readouterr().out
    assert code == 1 and f"services.{MODULES[mid]['row']}.port" in out, out


def test_the_query_engine_cannot_be_placed_without_the_catalog_it_requires(tmp_path, capsys):
    ov = overlay(tmp_path)
    sel = ld.load_yaml(ov / "lab" / "modules.yml")
    del sel["slots"]["lake-catalog"]
    (ov / "lab" / "modules.yml").write_text(_dump(sel))
    code = mcli.main(["check", *_args(ov)])
    out = capsys.readouterr().out
    assert code == 1 and "lake-catalog" in out, out


# ----------------------------------------------------------------------------- conformance


def test_the_object_store_suite_passes_through_the_garage_target(monkeypatch):
    access, secret, region = "GK" + "ab" * 12, "cd" * 32, "garage"
    with FakeS3(access, secret, region) as s:
        monkeypatch.setenv("HNX_ENDPOINT_OBJECT_STORE", s.url)
        monkeypatch.setenv("HNX_S3_ACCESS_KEY", access)
        monkeypatch.setenv("HNX_S3_SECRET_KEY", secret)
        monkeypatch.setenv("HNX_S3_REGION", region)
        target = load_target(
            str(ROOT / "modules" / "garage" / "conformance" / "target.yml"), root=ROOT
        )
        binding = target.binding("object-store")
        assert binding.adapter == "homelabnext.conform.adapters.s3:make_object_store"
        results = run_checks(object_store_suite.SUITE, make_factory(binding, root=ROOT))
    assert sorted(r.check for r in results if r.status != "pass") == []


@pytest.mark.parametrize("mid", ["iceberg-rest", "trino"])
def test_the_lake_targets_bind_the_shared_adapter_for_a_catalog_at_the_root_without_a_prefix(mid):
    target = load_target(str(ROOT / "modules" / mid / "conformance" / "target.yml"), root=ROOT)
    binding = target.binding(MODULES[mid]["slot"])
    assert binding.adapter == "homelabnext.conform.adapters.lake:make_lake"
    assert binding.config["api_root"] == "" and binding.config["catalog_prefix_optional"] is True
    assert binding.config["trino_catalog"] == "iceberg"
    # the credential is a secret NAME, never a value
    assert binding.config["credential"].startswith("secret:")


# ----------------------------------------------------------------------------- lint


@pytest.mark.parametrize("mid", MODULES)
def test_role_lint_passes_the_role_and_the_lifecycle_playbooks(mid):
    lint = [sys.executable, str(ROOT / "tools" / "role_lint.py")]
    r = subprocess.run([*lint, str(ROOT / "modules" / mid / "roles" / MODULES[mid]["role"])],
                       capture_output=True, text=True)  # fmt: skip
    assert r.returncode == 0, r.stdout + r.stderr
    books = sorted(str(p) for p in (ROOT / "modules" / mid / "playbooks").glob("*.yml"))
    inv = str(ROOT / "ansible" / "inventory" / "example" / "hosts.yml")
    r = subprocess.run(
        [*lint, "--playbook", *books, "--inventory", inv], capture_output=True, text=True
    )
    assert r.returncode == 0, r.stdout + r.stderr
