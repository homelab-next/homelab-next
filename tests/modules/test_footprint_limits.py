# SPDX-License-Identifier: Apache-2.0
"""Footprints as limits (ADR-0027 follow-up 8): slices, unit drop-ins and the disk quota script
rendered from the three example sites, and the quota script run against stubbed ``findmnt``,
``zfs``, ``losetup``, ``mkfs.ext4`` and ``systemctl``."""

from __future__ import annotations

import copy
import os
import subprocess
from pathlib import Path

import pytest
import yaml

from homelabnext.modules import limits as ml
from homelabnext.modules import rules as mr

ROOT = Path(__file__).resolve().parents[2]
MODULES_DIR = ROOT / "examples/modules"


def load(p):
    return yaml.safe_load(Path(p).read_text())


MODULES = {p.parent.name: load(p) for p in sorted(MODULES_DIR.glob("*/module.yml"))}
SITES = {p.stem: load(p) for p in sorted((MODULES_DIR / "sites").glob("*.yml"))}


def units(mod: str) -> set[str]:
    return mr._units(MODULES[mod], MODULES_DIR / mod, load)


def render(site: str, mods=None):
    return ml.render(SITES[site], mods or MODULES, units)


@pytest.mark.parametrize("site", sorted(SITES))
def test_every_placement_gets_a_slice_with_its_footprint(site):
    files = render(site)
    sel = mr.selected(SITES[site], MODULES)
    placed = list(mr._placed(SITES[site], sel))
    assert placed
    for mod, _inst, role, h, host in placed:
        body = files[f"{host}/{ml.slice_name(mod, role)}"]
        n = h.get("count", 1)
        assert f"CPUQuota={max(1, round(h['footprint']['cpu'] * n * 100))}%\n" in body
        assert f"MemoryMax={h['footprint']['memory_mb'] * n}M\n" in body
        assert "MemorySwapMax=0\n" in body
    slices = [k for k in files if k.endswith(".slice")]
    assert len(slices) == len(placed)


def test_slice_names_nest_by_module_and_never_collide():
    assert (
        ml.slice_name("external-collector", "receiver") == "hnx-external_collector-receiver.slice"
    )
    assert ml.slice_name("external-collector") == "hnx-external_collector.slice"
    # a module id that is a prefix of another, with a role that would complete it
    assert ml.slice_name("external", "collector-receiver") != ml.slice_name(
        "external-collector", "receiver"
    )
    for bad in ("Bad", "a_b", "a/b", "../x", "", "a--b"):
        with pytest.raises(ml.LimitsError):
            ml.slice_name(bad, "r")
        with pytest.raises(ml.LimitsError):
            ml.slice_name("m", bad)


def test_count_multiplies_and_cpu_is_a_percentage_of_one_core():
    mods = copy.deepcopy(MODULES)
    host = next(h for h in mods["example-lake"]["requires"]["hosts"] if h["role"] == "lake")
    host["count"] = 2
    host["footprint"]["cpu"] = 0.25
    body = render("small-lab", mods)["data/hnx-example_lake-lake.slice"]
    assert "CPUQuota=50%\n" in body
    assert f"MemoryMax={host['footprint']['memory_mb'] * 2}M\n" in body
    quota = render("small-lab", mods)["data/hnx-module-quota.sh"]
    assert f"cap example-lake {host['footprint']['disk_gb'] * 2}\n" in quota


def test_a_module_s_fleet_units_run_in_its_slice():
    files = render("full")
    host = SITES["full"]["features"]["publishing"]["placement"]["publisher"]
    dropin = files[f"{host}/publishing-run.service.d/50-hnx-slice.conf"]
    assert dropin.endswith("[Service]\nSlice=hnx-publishing-publisher.slice\n")
    assert f"{host}/hnx-publishing-publisher.slice" in files


def test_units_under_two_placed_roles_are_refused():
    mods = copy.deepcopy(MODULES)

    def two(mod):
        return {"collector-run"} if mod == "external-collector" else set()

    with pytest.raises(ml.LimitsError, match="could run under any of 2"):
        ml.render(SITES["small-lab"], mods, two)


def test_a_bad_unit_name_is_refused():
    with pytest.raises(ml.LimitsError, match="unit name"):
        ml.render(SITES["full"], MODULES, lambda m: {"../evil"} if m == "publishing" else set())


def test_unknown_hosts_roles_and_modules_are_refused():
    site = copy.deepcopy(SITES["small-lab"])
    site["features"]["external-collector"]["placement"]["receiver"] = "nowhere"
    with pytest.raises(ml.LimitsError, match="unknown host"):
        ml.render(site, MODULES, units)
    site = copy.deepcopy(SITES["small-lab"])
    site["features"]["external-collector"]["placement"]["ghost"] = "data"
    with pytest.raises(ml.LimitsError, match="not one of its host roles"):
        ml.render(site, MODULES, units)
    site = copy.deepcopy(SITES["small-lab"])
    site["features"]["no-such-module"] = {}
    with pytest.raises(ml.LimitsError, match="without a manifest"):
        ml.render(site, MODULES, units)


def test_disk_is_summed_per_module_per_host_and_gpu_memory_is_reported_unenforced():
    files = render("small-lab")
    readme = files["README.md"]
    assert "| core | example-inference | server |" in readme and "(not enforced)" in readme
    assert "cap external-collector 10\n" in files["data/hnx-module-quota.sh"]
    assert "cap external-collector 20\n" in files["collector-edge/hnx-module-quota.sh"]


def test_render_is_deterministic():
    assert render("full") == render("full")
    assert list(render("full")) == sorted(render("full"))


def test_write_makes_the_script_executable(tmp_path):
    ml.write(render("small-lab"), tmp_path)
    assert os.access(tmp_path / "data/hnx-module-quota.sh", os.X_OK)
    assert (tmp_path / "data/hnx-example_lake-lake.slice").is_file()


# ---------------------------------------------------------------- the quota script, stubbed

STUB = r"""#!/bin/sh
echo "$(basename "$0") $*" >>"$HNX_LOG"
case "$(basename "$0")" in
  findmnt)
    # findmnt -n -o FIELD --target DIR: answers from $HNX_MNT/<dir with / as _>.<field>
    f=$(echo "$5" | tr / _)
    v="$HNX_MNT/$f.$3"
    if [ -f "$v" ]; then cat "$v"; else
      case "$3" in TARGET) echo /;; FSTYPE) echo ext4;; SOURCE) echo /dev/sda1;; esac
    fi ;;
  zfs) [ "$2" = "-H" ] && cat "$HNX_MNT/zfs.quota" ;;
  losetup) cat "$HNX_MNT/losetup" 2>/dev/null ;;
  systemd-escape) echo "escaped.mount" ;;
esac
exit 0
"""


@pytest.fixture
def host(tmp_path):
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    for name in ("findmnt", "zfs", "losetup", "mkfs.ext4", "systemctl", "systemd-escape"):
        (bin_ / name).write_text(STUB)
        (bin_ / name).chmod(0o755)
    root = tmp_path / "modules"
    mnt = tmp_path / "mnt"
    mnt.mkdir()
    units_dir = tmp_path / "units"
    units_dir.mkdir()
    script = tmp_path / "quota.sh"
    script.write_text(ml._quota_script({"m": 2}))
    script.chmod(0o755)
    log = tmp_path / "log"
    env = {
        "PATH": f"{bin_}:{os.environ['PATH']}",
        "HNX_LOG": str(log),
        "HNX_MNT": str(mnt),
        "HNX_MODULES_ROOT": str(root),
        "HNX_UNIT_DIR": str(units_dir),
    }

    def mount(dir_, **fields):
        key = str(dir_).replace("/", "_")
        for k, v in fields.items():
            (mnt / f"{key}.{k}").write_text(v + "\n")

    def run(*args):
        if log.exists():
            log.unlink()
        r = subprocess.run([str(script), *args], env=env, capture_output=True, text=True)
        calls = log.read_text().splitlines() if log.exists() else []
        return r, calls

    return root, mnt, units_dir, mount, run


def test_a_zfs_dataset_gets_its_quota(host):
    root, mnt, _u, mount, run = host
    mount(root / "m", TARGET=str(root / "m"), FSTYPE="zfs", SOURCE="tank/hnx/m")
    (mnt / "zfs.quota").write_text("0\n")
    r, calls = run()
    assert r.returncode == 0, r.stderr
    assert "zfs set quota=2G tank/hnx/m" in calls


def test_a_zfs_dataset_with_the_right_quota_is_left_alone_and_check_passes(host):
    root, mnt, _u, mount, run = host
    mount(root / "m", TARGET=str(root / "m"), FSTYPE="zfs", SOURCE="tank/hnx/m")
    (mnt / "zfs.quota").write_text(f"{2 * 1073741824}\n")
    (root / "m").mkdir(parents=True)
    for args in ((), ("--check",)):
        r, calls = run(*args)
        assert r.returncode == 0, r.stderr
        assert not any(c.startswith("zfs set") for c in calls)


def test_check_changes_nothing_and_owes_a_missing_cap(host):
    root, _m, units_dir, _mount, run = host
    (root / "m").mkdir(parents=True)
    r, calls = run("--check")
    assert r.returncode == 3 and "has no cap" in r.stderr
    assert not any(c.split()[0] in ("mkfs.ext4", "systemctl") for c in calls)
    assert not (root / ".images").exists() and not any(units_dir.iterdir())


def test_elsewhere_an_image_is_made_and_mounted(host):
    root, _m, units_dir, _mount, run = host
    r, calls = run()
    assert r.returncode == 0, r.stderr
    img = root / ".images" / "m.img"
    assert img.stat().st_size == 2 * 1073741824 and img.stat().st_blocks == 0  # sparse
    assert f"mkfs.ext4 -q -F -L hnx-m {img}" in calls
    unit = (units_dir / "escaped.mount").read_text()
    assert f"What={img}\nWhere={root / 'm'}\n" in unit and "Options=loop,nodev,nosuid" in unit
    assert "systemctl enable --now escaped.mount" in calls
    assert oct((root / ".images").stat().st_mode & 0o777) == "0o700"


def test_an_image_is_never_mounted_over_existing_data(host):
    root, _m, units_dir, _mount, run = host
    (root / "m").mkdir(parents=True)
    (root / "m" / "precious").write_text("x")
    r, calls = run()
    assert r.returncode == 3 and "already holds files" in r.stderr
    assert not any(c.startswith("mkfs") for c in calls) and not any(units_dir.iterdir())


def test_a_mounted_image_of_the_right_size_passes_and_a_wrong_one_is_owed(host):
    root, mnt, _u, mount, run = host
    img = root / ".images" / "m.img"
    img.parent.mkdir(parents=True)
    img.write_bytes(b"")
    os.truncate(img, 2 * 1073741824)
    mount(root / "m", TARGET=str(root / "m"), FSTYPE="ext4", SOURCE="/dev/loop7")
    (root / "m").mkdir()
    (mnt / "losetup").write_text(f"{img}\n")
    r, _ = run("--check")
    assert r.returncode == 0, r.stderr
    os.truncate(img, 1073741824)
    r, _ = run()
    assert r.returncode == 3 and "want 2G" in r.stderr


def test_a_foreign_mount_is_not_touched(host):
    root, _mnt, _u, mount, run = host
    (root / "m").mkdir(parents=True)
    mount(root / "m", TARGET=str(root / "m"), FSTYPE="nfs", SOURCE="server:/x")
    r, calls = run()
    assert r.returncode == 3 and "not made by this script" in r.stderr
    assert not any(c.startswith(("mkfs", "zfs set", "systemctl")) for c in calls)


def test_a_symlinked_data_root_is_refused(host, tmp_path):
    root, _m, _u, _mount, run = host
    root.mkdir()
    (tmp_path / "elsewhere").mkdir()
    os.symlink(tmp_path / "elsewhere", root / "m")
    r, calls = run()
    assert r.returncode == 3 and "symbolic link" in r.stderr
    assert not any(c.startswith(("mkfs", "systemctl")) for c in calls)


def test_the_script_rejects_unknown_arguments(host):
    _r, _m, _u, _mount, run = host
    r, _ = run("--nope")
    assert r.returncode == 2
