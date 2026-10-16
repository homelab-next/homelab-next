# SPDX-License-Identifier: Apache-2.0
"""Guest model: loading, semantic validation, goldens for every target, plan, CLI, registry."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest
import yaml

from homelabnext import cli as hnx
from homelabnext.compute import (
    TARGETS,
    ComputeError,
    MappingZones,
    SiteAdapter,
    ZoneInfo,
    ZoneLookup,
    load_fleet,
    load_guests,
    load_zones_file,
    plan,
    render,
    validate,
)
from homelabnext.compute.gen import registry_hosts
from homelabnext.compute.plan import read_tree

HERE = Path(__file__).resolve().parent
FLEET = HERE / "fleet"
SITE = HERE / "site.yml"
KEYS = HERE / "keys.yml"
GOLDEN = HERE / "golden"

# A stub site model: the compute model never needs W13's real one.
STUB = MappingZones(
    [
        ZoneInfo("mgmt", "192.0.2.0/24", "192.0.2.1", None, 10),
        ZoneInfo(
            "data", "198.51.100.0/25", "198.51.100.1", ("198.51.100.100", "198.51.100.126"), 20
        ),
        ZoneInfo("compute", "198.51.100.128/25", "198.51.100.129", None, 30),
        ZoneInfo("edge", "203.0.113.0/24", "203.0.113.1", None, 40),
    ]
)


@pytest.fixture(scope="module")
def good():
    return load_fleet(FLEET, STUB, keys_path=KEYS)


def mutate(tmp_path: Path, name: str, edit) -> Path:
    d = tmp_path / "fleet"
    shutil.copytree(FLEET, d)
    p = d / f"{name}.yml"
    doc = yaml.safe_load(p.read_text())
    edit(doc)
    p.write_text(yaml.safe_dump(doc, sort_keys=False))
    return d


def problems_of(d: Path) -> str:
    with pytest.raises(ComputeError) as ei:
        load_fleet(d, STUB)
    return str(ei.value)


# ---------------------------------------------------------------- loading
def test_stub_satisfies_protocol():
    assert isinstance(STUB, ZoneLookup)


def test_example_fleet_loads_and_validates(good):
    assert len(good.guests) == 7
    assert validate(good) == []
    assert [g.name for g in good.manual()] == ["secrets-core"]
    assert "hv-a" not in [g.name for g in good.iac()]


def test_support_files_are_not_guests():
    guests, problems = load_guests(FLEET)
    assert problems == [] and len(guests) == 7


def test_site_file_reader_matches_stub():
    zones, domain = load_zones_file(SITE)
    assert domain == "example.internal"
    assert zones.zone("data") == STUB.zone("data")
    assert zones.zone("nope") is None


def test_site_adapter_duck_types_objects():
    from types import SimpleNamespace as NS

    z = NS(
        id="data",
        subnet="198.51.100.0/25",
        gateway="198.51.100.1",
        dhcp={"range": ["198.51.100.100", "198.51.100.126"]},
        vlan_id=20,
    )
    assert SiteAdapter(NS(zones=[z])).zone("data") == STUB.zone("data")
    assert SiteAdapter(NS(zones={"data": z})).zone("data") == STUB.zone("data")
    assert SiteAdapter(NS(zones=[z])).zone("none") is None


def test_file_name_must_match_id(tmp_path):
    d = tmp_path / "f"
    shutil.copytree(FLEET, d)
    (d / "lake-core.yml").rename(d / "other.yml")
    assert "must be lake-core.yml" in problems_of(d)


def test_duplicate_yaml_key_rejected(tmp_path):
    d = tmp_path / "f"
    shutil.copytree(FLEET, d)
    with (d / "edge-core.yml").open("a") as fh:
        fh.write("capability: cap:idp\n")
    assert "duplicate key" in problems_of(d)


def test_schema_negative_surfaces_as_problem(tmp_path):
    d = mutate(tmp_path, "edge-core", lambda x: x["network"].update(firewall=True))
    assert "network/firewall" in problems_of(d)


# ---------------------------------------------------------------- semantics
CASES = [
    ("unknown-zone", "lake-core", lambda d: d["network"].update(zone="nowhere"), "does not exist"),
    (
        "ip-outside-subnet",
        "lake-core",
        lambda d: d["network"].update(ip="203.0.113.40"),
        "outside zone",
    ),
    (
        "ip-in-dhcp-pool",
        "lake-core",
        lambda d: d["network"].update(ip="198.51.100.101"),
        "DHCP pool",
    ),
    (
        "ip-is-gateway",
        "lake-core",
        lambda d: d["network"].update(ip="198.51.100.1"),
        "zone gateway",
    ),
    (
        "octet-mismatch",
        "lake-core",
        lambda d: d["placement"].update(vmid=41, vmid_scheme="octet"),
        "last octet 40",
    ),
    ("duplicate-ip", "bus-core", lambda d: d["network"].update(ip="198.51.100.40"), "already used"),
    (
        "duplicate-vmid",
        "bus-core",
        lambda d: d["placement"].update(vmid=140, vmid_scheme="freeform"),
        "vmid 140",
    ),
    (
        "gpu-on-lxc",
        "idp-core",
        lambda d: d.update(gpu={"profile": "accel-a"}),
        "gpu requires kind vm",
    ),
    ("manual-without-steps", "secrets-core", lambda d: d.pop("lifecycle"), "requires_root_steps"),
    (
        "unknown-capability",
        "lake-core",
        lambda d: d.update(capability="cap:made-up"),
        "known capability",
    ),
    (
        "unknown-group",
        "lake-core",
        lambda d: d.update(capability_groups=["cap_nope"]),
        "inventory group",
    ),
    (
        "unknown-backup-policy",
        "lake-core",
        lambda d: d["backup"].update(policy="hourly"),
        "policy set",
    ),
    ("host-wrong-provisioning", "hv-a", lambda d: d.update(provisioning="terraform"), "host-only"),
    ("vm-without-vmid", "edge-core", lambda d: d["placement"].pop("vmid"), "vmid is required"),
    (
        "balloon-above-memory",
        "bus-core",
        lambda d: d["resources"]["memory"].update(balloon_min_mb=99999),
        "balloon",
    ),
]


@pytest.mark.parametrize(("label", "name", "edit", "expect"), CASES, ids=[c[0] for c in CASES])
def test_semantic_negative(tmp_path, label, name, edit, expect):
    d = mutate(tmp_path, name, edit)
    msg = problems_of(d)
    assert expect in msg, msg


def test_per_vlan_bridge_needs_vlan_id(tmp_path):
    d = mutate(tmp_path, "bus-core", lambda x: None)
    zones = MappingZones([ZoneInfo("data", "198.51.100.0/25", "198.51.100.1", None, None)])
    with pytest.raises(ComputeError, match="needs a zone with a vlan_id"):
        load_fleet(d, zones)


def test_inherit_gateway_needs_zone_gateway(tmp_path):
    zones = MappingZones(
        [
            ZoneInfo(z, STUB.zone(z).subnet, None, None, 1)
            for z in ("mgmt", "data", "compute", "edge")
        ]
    )
    with pytest.raises(ComputeError, match="declares none"):
        load_fleet(FLEET, zones)


def test_manual_guest_excluded_from_iac_but_listed(good):
    tf = render(good, "terraform-proxmox")
    assert not any("secrets-core" in k for k in tf if k.endswith(".tf"))
    assert "pct create 131 as a privileged container" in tf["MANUAL.md"]
    assert "secrets-core" in render(good, "inventory")["hosts.yml"]


# ---------------------------------------------------------------- goldens
def _golden_cases():
    return sorted(TARGETS)


@pytest.mark.parametrize("target", _golden_cases())
def test_target_matches_golden(good, target):
    out = render(good, target)
    assert out
    gdir = GOLDEN / target
    if os.environ.get("HNX_UPDATE_GOLDEN") == "1":
        shutil.rmtree(gdir, ignore_errors=True)
        for rel, text in out.items():
            (gdir / rel).parent.mkdir(parents=True, exist_ok=True)
            (gdir / rel).write_text(text, encoding="utf-8")
    want = read_tree(gdir)
    assert set(out) == set(want), f"file set differs: {set(out) ^ set(want)}"
    for rel in out:
        assert out[rel] == want[rel], f"{target}/{rel} differs from golden"


@pytest.mark.parametrize("target", _golden_cases())
def test_render_is_deterministic(good, target):
    assert render(good, target) == render(good, target)


def test_unresolved_key_renders_placeholder_never_material():
    f = load_fleet(FLEET, STUB)  # no keys supplied
    ud = render(f, "cloudinit")["lake-core/user-data"]
    assert "<ssh-key:operator>" in ud and "AAAA" not in ud


def test_terraform_shapes(good):
    tf = render(good, "terraform-proxmox")
    vm = tf["vm-infer-core.tf"]
    assert 'resource "proxmox_virtual_environment_vm" "infer_core"' in vm
    assert 'mapping = "gpu-a"' in vm and "bios" in vm
    ct = tf["ct-idp-core.tf"]
    assert 'resource "proxmox_virtual_environment_container" "idp_core"' in ct
    assert "mount_point" in ct and "read_only = true" in ct
    assert "ignore_changes = [clone, operating_system]" in tf["vm-bus-core.tf"]
    assert '"${var.default_bridge}v20"' in tf["vm-bus-core.tf"]
    assert "endpoint" in tf["providers.tf"] and "198." not in tf["providers.tf"]


def test_libvirt_skips_non_vm_and_manual(good):
    lv = render(good, "libvirt")
    assert "idp-core.sh" not in lv and "lake-core.sh" in lv
    assert "kind lxc" in lv["SKIPPED.txt"] and "secrets-core: not terraform" in lv["SKIPPED.txt"]
    assert "backing_store" in lv["lake-core.sh"]


def test_inventory_groups(good):
    inv = yaml.safe_load(render(good, "inventory")["hosts.yml"])
    ch = inv["all"]["children"]
    assert "lake-core.example.internal" in ch["cap_lake"]["hosts"]
    assert "lake-core.example.internal" in ch["cap_query"]["hosts"]
    assert set(ch["guests"]["hosts"]) >= {"hv-a.example.internal"}
    assert "tag_gpu" in ch


def test_backup_jobs_exclude_opt_outs(good):
    jobs = yaml.safe_load(render(good, "backup-jobs")["backup-jobs.yml"])["jobs"]
    members = {m["guest"] for j in jobs for m in j["members"]}
    assert "guest:bus-core" not in members and "guest:secrets-core" in members


def test_unknown_target(good):
    with pytest.raises(ComputeError, match="unknown target"):
        render(good, "nope")


# ---------------------------------------------------------------- registry feed
def test_registry_hosts_feed_existing_generators(good):
    from homelabnext.generators import generate
    from homelabnext.registry.model import build_registry

    frag = registry_hosts.fragment(good)
    doc = {
        "registry_version": 1,
        "lab": {"name": "northwind", "domain": "example.internal", "owner": "platform-team"},
        "services": {
            "lake-query": {
                "capability": "lake-query",
                "host": "lake-core",
                "protocol": "https",
                "port": 8443,
                "health": {"kind": "tcp"},
                "metrics": {"path": "/metrics"},
                "owner": "data-team",
                "version": "1.0",
                "tls": "internal",
                "clients": ["data", "compute"],
            }
        },
    }
    merged = registry_hosts.merge_into_registry(doc, frag)
    reg = build_registry(merged)
    out = generate(reg, ["dns_zone", "hosts_file", "prometheus"])
    blob = "\n".join(t for gen in out.values() for t in gen.values())
    assert "198.51.100.40" in blob


def test_registry_merge_conflict_is_an_error(good):
    frag = registry_hosts.fragment(good)
    doc = {
        "zones": {},
        "hosts": {"lake-core": {"address": "192.0.2.99", "zone": "mgmt", "role": "x"}},
    }
    with pytest.raises(ComputeError, match="differs"):
        registry_hosts.merge_into_registry(doc, frag)


# ---------------------------------------------------------------- plan
def test_plan_reports_add_change_remove(good):
    old = render(good, "terraform-proxmox")
    new = dict(old)
    new["vm-edge-core.tf"] = old["vm-edge-core.tf"].replace("cores = 2", "cores = 4")
    del new["vm-bus-core.tf"]
    new["vm-extra.tf"] = "x\n"
    p = plan(old, new)
    assert p.added == ("vm-extra.tf",) and p.removed == ("vm-bus-core.tf",)
    assert p.changed == ("vm-edge-core.tf",)
    assert "-    cores = 2" in p.diff and "+    cores = 4" in p.diff
    assert "/dev/null" in p.diff
    assert plan(old, old).empty


# ---------------------------------------------------------------- CLI
def run_cli(*args):
    return hnx.main(["guests", *args])


BASE = [str(FLEET), "--site", str(SITE)]


def test_cli_validate_ok(capsys):
    assert run_cli("validate", *BASE) == 0
    assert "ok: 7 guests (5 rendered, 1 manual)" in capsys.readouterr().out


def test_cli_validate_fails_on_bad_fleet(tmp_path, capsys):
    d = mutate(tmp_path, "lake-core", lambda x: x["network"].update(ip="198.51.100.101"))
    assert run_cli("validate", str(d), "--site", str(SITE)) == 1
    assert "DHCP pool" in capsys.readouterr().err


@pytest.mark.parametrize("target", sorted(TARGETS))
def test_cli_render_writes_tree(tmp_path, target, capsys):
    out = tmp_path / "o"
    assert run_cli("render", *BASE, "--keys", str(KEYS), "--target", target, "--out", str(out)) == 0
    assert read_tree(out) == read_tree(GOLDEN / target)


def test_cli_plan_against_previous_render(tmp_path, capsys):
    out = tmp_path / "prev"
    run_cli("render", *BASE, "--keys", str(KEYS), "--target", "inventory", "--out", str(out))
    assert (
        run_cli(
            "plan",
            *BASE,
            "--keys",
            str(KEYS),
            "--target",
            "inventory",
            "--against",
            str(out),
            "--exit-code",
        )
        == 0
    )
    (out / "hosts.yml").write_text("all: {}\n")
    capsys.readouterr()
    code = run_cli("plan", *BASE, "--target", "inventory", "--against", str(out), "--exit-code")
    text = capsys.readouterr().out
    assert code == 2 and "1 to change" in text and "host_vars/" not in text.split("\n")[0]


def test_cli_unknown_target_rejected():
    assert run_cli("render", *BASE, "--target", "bogus") == 2
