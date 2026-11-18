# SPDX-License-Identifier: Apache-2.0
"""A placement's footprint, raised by the site (docs/modules/slots.md, "Footprint and resources";
docs/modules/selection.md): a selection entry's ``footprint: {<host role>: {cpu, memory_mb,
disk_gb}}`` replaces those dimensions of the module's declared footprint for that one placement.
The module's own footprint is the floor (a value below it is refused, and never rendered below
it), the raised footprint is what every rule sums (the guest alone, then the host's sum over
every placement on it, so the other placements' footprints still count), and the slice takes it
as its limits.  A placement with no override renders byte for byte what it did before."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from homelabnext.modules import guest_hosts as gh
from homelabnext.modules import limits as ml
from homelabnext.modules import loader as ld
from homelabnext.modules import rules as mr

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "examples" / "modules"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
SMALL_LAB = EXAMPLES / "sites" / "small-lab.yml"
GUEST_SITE = FIXTURES / "selection.guest-hosts.yml"
GUESTS = FIXTURES / "guests"
SLOTS = ld.load_yaml(EXAMPLES / "slots.yml")["slots"]
CORE, _ = ld.core_names(ld.load_yaml(ROOT / "examples" / "services.yml"))
ROLES = json.loads((ROOT / "examples" / "model_roles.json").read_text())["roles"]
LAKE_SLICE = "data/" + ml.slice_name("example-lake", "lake")


@pytest.fixture(scope="module")
def tree():
    tree, found = ld.discover(fixtures=EXAMPLES)
    assert found == []
    return tree


@pytest.fixture(scope="module")
def guests():
    return gh.read(GUESTS)


def _lake_entry(site: dict) -> dict:
    return next(c for c in site["slots"]["lake-catalog"] if c.get("placement"))


def _check(tree, site, guests=None):
    return ld.check(
        tree, slots=SLOTS, roles=ROLES, in_tree_roots=(EXAMPLES,), core=CORE, site=site,
        guests=guests,
    )  # fmt: skip


def _problems(tree, site, guests=None) -> list[str]:
    return [p.message for p in _check(tree, site, guests).problems if p.where == "site"]


def _render(tree, report) -> dict[str, str]:
    def units(mod: str) -> set[str]:
        return mr._units(tree.mods[mod], tree.dirs[mod], ld.load_yaml)

    return ml.render(report.site, tree.mods, units)


def _raised(path: Path, fp: dict) -> dict:
    site = ld.load_yaml(path)
    _lake_entry(site)["footprint"] = {"lake": fp}
    return site


# ----------------------------------------------------------------------------- the slice


def test_a_raise_within_the_host_renders_the_bigger_slice(tree):
    site = _raised(SMALL_LAB, {"cpu": 5, "memory_mb": 8192})
    report = _check(tree, site)
    assert [p.message for p in report.problems if p.where == "site"] == []
    body = _render(tree, report)[LAKE_SLICE]
    assert "CPUQuota=500%\n" in body
    assert "MemoryHigh=7372M\nMemoryMax=8192M\nMemorySwapMax=0\n" in body


def test_a_raise_within_a_guest_renders_the_bigger_slice(tree, guests):
    site = _raised(GUEST_SITE, {"memory_mb": 8192, "disk_gb": 900})
    report = _check(tree, site, guests)
    assert [p.message for p in report.problems if p.where == "site"] == []
    files = _render(tree, report)
    assert "MemoryMax=8192M\n" in files[LAKE_SLICE]
    # an undeclared dimension keeps the module's own value
    assert "CPUQuota=400%\n" in files[LAKE_SLICE]
    # disk is the raised value in the quota script's report too
    assert "run guest_disk example-lake 900 vm " in files["data/hnx-module-quota.sh"]


def test_no_raise_renders_byte_for_byte_what_the_module_declares(tree):
    """The default: every slice is exactly the declared footprint's (CPUQuota 100 % a core,
    MemoryHigh 90 %), so a placement that names no footprint is unchanged."""
    report = _check(tree, ld.load_yaml(SMALL_LAB))
    files = _render(tree, report)
    assert files[LAKE_SLICE] == (
        ml.HEADER
        + "[Unit]\n"
        + "Description=hnx module example-lake, host role lake on data (its footprint as limits)\n"
        + "\n[Slice]\nCPUAccounting=yes\nCPUQuota=400%\nMemoryAccounting=yes\n"
        + "MemoryHigh=3686M\nMemoryMax=4096M\nMemorySwapMax=0\n"
    )
    # an eight-core 16 GiB role renders exactly the slice it always has
    eight = ml._slice("m", "server", {"cpu": 8, "memory_mb": 16384}, 1, "h")
    assert "CPUQuota=800%\nMemoryAccounting=yes\nMemoryHigh=14745M\nMemoryMax=16384M\n" in eight


def test_the_placed_rows_carry_the_declared_role_when_nothing_is_raised(tree):
    site = ld.load_yaml(SMALL_LAB)
    sel = mr.selected(site, tree.mods)
    for mod, _inst, role, h, _host in mr._placed(site, sel):
        declared = next(x for x in tree.mods[mod]["requires"]["hosts"] if x["role"] == role)
        assert h is declared


# ----------------------------------------------------------------------------- refusals


def test_a_raise_the_guest_cannot_hold_is_refused(tree, guests):
    site = _raised(GUEST_SITE, {"memory_mb": 20000, "cpu": 9})
    got = _problems(tree, site, guests)
    assert (
        "example-lake (lake)/lake: needs memory_mb 20000, host data (guest:data-1) has 14336 (less headroom)"
        in got
    )
    assert "example-lake (lake)/lake: needs vCPU 9, host data (guest:data-1) has 8" in got
    assert any(p.startswith("data (guest:data-1): memory_mb ") for p in got)


def test_a_raise_that_fits_alone_but_not_beside_the_other_placements_is_refused(tree, guests):
    """14336 MB is left on the guest; the lake alone at 13000 fits, but the store (1024) and the
    receiver (384) are on the same guest: the host's sum is still judged."""
    site = _raised(GUEST_SITE, {"memory_mb": 13000})
    got = _problems(tree, site, guests)
    assert not [p for p in got if p.startswith("example-lake (lake)/lake: needs")]
    assert "data (guest:data-1): memory_mb 14408 exceeds 14336" in got


def test_a_raise_below_the_module_s_own_footprint_is_refused_and_never_rendered_below(tree):
    site = _raised(SMALL_LAB, {"memory_mb": 1024})
    got = _problems(tree, site)
    assert (
        "slots.lake-catalog: example-lake (lake)/lake: footprint memory_mb 1024 is below the "
        "module's own 4096, its minimum"
    ) in got
    # rendered anyway (a caller that skipped the check): never below the module's own
    files = _render(tree, _check(tree, site))
    assert "MemoryMax=4096M\n" in files[LAKE_SLICE]


def test_a_raise_for_a_role_the_entry_does_not_place_is_refused(tree):
    site = ld.load_yaml(SMALL_LAB)
    _lake_entry(site)["footprint"] = {"query": {"cpu": 6}}
    got = _problems(tree, site)
    assert (
        "slots.lake-catalog: example-lake (lake): footprint names query, not a placed host role"
        in got
    )


def test_two_different_raises_of_one_placement_are_refused(tree):
    site = ld.load_yaml(SMALL_LAB)
    _lake_entry(site)["footprint"] = {"lake": {"cpu": 6}}
    site["slots"]["lake-query"][0]["footprint"] = {"lake": {"cpu": 5}}
    got = _problems(tree, site)
    assert "example-lake (lake)/lake: footprint raised twice, differently" in got


def test_a_feature_placement_can_be_raised(tree):
    site = ld.load_yaml(SMALL_LAB)
    site["features"]["external-collector"]["footprint"] = {"receiver": {"memory_mb": 1024}}
    report = _check(tree, site)
    assert [p.message for p in report.problems if p.where == "site"] == []
    files = _render(tree, report)
    assert "MemoryMax=1024M\n" in files["data/" + ml.slice_name("external-collector", "receiver")]


@pytest.mark.parametrize(
    "fp",
    [
        {},
        {"gpu_memory_mb": 1024},
        {"resources": [{"kind": "gpu", "exclusive": False}]},
        {"cpu": 0},
        {"memory_mb": 8},
        {"memory_mb": "8192"},
        {"cpu": 300},
    ],
)
def test_the_schema_takes_only_cpu_memory_and_disk(tree, fp):
    site = _raised(SMALL_LAB, fp)
    got = _problems(tree, site)
    assert got and all("footprint" in p or "lake" in p for p in got), got
