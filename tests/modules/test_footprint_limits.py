# SPDX-License-Identifier: Apache-2.0
"""Footprints as limits (ADR-0027 follow-up 8): slices, unit drop-ins and the disk quota script
rendered from the three example sites, and the quota script run against stubbed ``findmnt``,
``zfs``, ``losetup``, ``fallocate``, ``mkfs.ext4`` and ``systemctl``.  The script is always
rendered with a root and unit directory under ``tmp_path``: it never sees the real ones."""

from __future__ import annotations

import copy
import os
import subprocess
from pathlib import Path

import pytest
import yaml

from homelabnext.generators import fleet_units as fu
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


def render(site, mods=None):
    return ml.render(SITES[site] if isinstance(site, str) else site, mods or MODULES, units)


def lab_placements(site: str):
    sel = mr.selected(SITES[site], MODULES)
    hosts = SITES[site]["hosts"]
    return [p for p in mr._placed(SITES[site], sel) if hosts[p[4]]["kind"] != "external"]


@pytest.mark.parametrize("site", sorted(SITES))
def test_every_placement_in_the_lab_gets_a_slice_with_its_footprint(site):
    files = render(site)
    placed = lab_placements(site)
    assert placed
    for mod, _inst, role, h, host in placed:
        body = files[f"{host}/{ml.slice_name(mod, role)}"]
        n = h.get("count", 1)
        mem = h["footprint"]["memory_mb"] * n
        assert f"CPUQuota={max(1, round(h['footprint']['cpu'] * n * 100))}%\n" in body
        assert f"MemoryHigh={mem * 9 // 10}M\nMemoryMax={mem}M\nMemorySwapMax=0\n" in body
    assert len([k for k in files if k.endswith(".slice")]) == len(
        {(p[4], p[0], p[2]) for p in placed}
    )


def test_external_hosts_are_listed_not_rendered():
    files = render("small-lab")
    assert not any(k.startswith("collector-edge/") for k in files)
    assert "- external-collector/edge on collector-edge" in files["README.md"]


def test_slice_names_nest_by_module_and_never_collide():
    assert (
        ml.slice_name("external-collector", "receiver") == "hnx-external_collector-receiver.slice"
    )
    assert ml.slice_name("external-collector") == "hnx-external_collector.slice"
    assert ml.slice_name("external", "collector-receiver") != ml.slice_name(
        "external-collector", "receiver"
    )
    for bad in ("Bad", "a_b", "a/b", "../x", "", "a--b", "a\n"):
        with pytest.raises(ml.LimitsError):
            ml.slice_name(bad, "r")
        with pytest.raises(ml.LimitsError):
            ml.slice_name("m", bad)


def _lake(mods):
    return next(h for h in mods["example-lake"]["requires"]["hosts"] if h["role"] == "lake")


def test_count_multiplies_and_cpu_is_a_percentage_of_one_core():
    mods = copy.deepcopy(MODULES)
    host = _lake(mods)
    host["count"] = 2
    host["footprint"]["cpu"] = 0.25
    files = render("small-lab", mods)
    body = files["data/hnx-example_lake-lake.slice"]
    assert "CPUQuota=50%\n" in body
    assert f"MemoryMax={host['footprint']['memory_mb'] * 2}M\n" in body
    assert (
        f"run example-lake {host['footprint']['disk_gb'] * 2}\n"
        in files["data/hnx-module-quota.sh"]
    )


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("memory_mb", "64\nMemoryMax=infinity\n#"),
        ("memory_mb", "9"),
        ("memory_mb", None),
        ("memory_mb", 10**30),
        ("cpu", True),
        ("cpu", -5),
        ("cpu", float("nan")),
        ("cpu", float("inf")),
        ("disk_gb", 0.5),
        ("disk_gb", -5),
        ("disk_gb", "1; id"),
        ("gpu_memory_mb", "x"),
    ],
)
def test_a_bad_footprint_value_is_refused_never_rendered(key, value):
    mods = copy.deepcopy(MODULES)
    _lake(mods)["footprint"][key] = value
    with pytest.raises(ml.LimitsError, match=key):
        render("small-lab", mods)


@pytest.mark.parametrize("count", [0, -1, 17, True, "2", 1.5])
def test_a_bad_count_is_refused(count):
    mods = copy.deepcopy(MODULES)
    _lake(mods)["count"] = count
    with pytest.raises(ml.LimitsError, match="count"):
        render("small-lab", mods)


def test_two_instances_of_one_provider_on_one_host_share_the_slice_summed():
    site = copy.deepcopy(SITES["small-lab"])
    one = site["slots"]["object-store"][0]
    site["slots"]["object-store"].append({**one, "instance": "archive"})
    fp = MODULES["example-object-store"]["requires"]["hosts"][0]["footprint"]
    files = render(site)
    body = files["data/hnx-example_object_store-store.slice"]
    assert f"MemoryMax={fp['memory_mb'] * 2}M\n" in body
    assert f"run example-object-store {fp['disk_gb'] * 2}\n" in files["data/hnx-module-quota.sh"]


def test_a_module_s_fleet_units_run_in_its_slice_under_their_rendered_names():
    files = render("full")
    host = SITES["full"]["features"]["publishing"]["placement"]["publisher"]
    spec = load(MODULES_DIR / "publishing/units/fleet_units.yml")
    services = [n for n in fu.render(spec) if n.endswith(".service")]
    assert services
    for svc in services:
        dropin = files[f"{host}/{svc}.d/50-hnx-slice.conf"]
        assert dropin.endswith("[Service]\nSlice=hnx-publishing-publisher.slice\n")
    assert f"{host}/hnx-publishing-publisher.slice" in files


def test_units_are_required():
    with pytest.raises(TypeError):
        ml.render(SITES["full"], MODULES)  # type: ignore[call-arg]


def test_units_under_two_placed_roles_or_none_are_refused():
    site = copy.deepcopy(SITES["small-lab"])
    site["hosts"]["collector-edge"]["kind"] = "vm"

    def two(mod):
        return {"external-collector-run"} if mod == "external-collector" else set()

    with pytest.raises(ml.LimitsError, match=r"exactly one placed host role.*has 2"):
        ml.render(site, MODULES, two)

    def unplaced(mod):
        return {"core-staff-run"} if mod == "core-staff" else set()

    with pytest.raises(ml.LimitsError, match="has 0"):
        ml.render(SITES["small-lab"], MODULES, unplaced)


@pytest.mark.parametrize("name", ["../evil", "sshd", "publishingx-run", "Publishing-run"])
def test_a_unit_not_bound_to_its_module_is_refused(name):
    with pytest.raises(ml.LimitsError, match="not bound"):
        ml.render(SITES["full"], MODULES, lambda m: {name} if m == "publishing" else set())


def test_a_longer_module_id_keeps_its_units():
    """Module ``ab`` may not claim ``ab-cd-run`` when module ``ab-cd`` is selected."""
    assert ml._bound("ab-run", "ab", {"ab", "ab-cd"})
    assert not ml._bound("ab-cd-run", "ab", {"ab", "ab-cd"})
    assert ml._bound("ab-cd-run", "ab-cd", {"ab", "ab-cd"})


def test_unknown_hosts_roles_and_modules_are_refused():
    site = copy.deepcopy(SITES["small-lab"])
    site["features"]["external-collector"]["placement"]["receiver"] = "nowhere"
    with pytest.raises(ml.LimitsError, match="unknown host"):
        render(site)
    site = copy.deepcopy(SITES["small-lab"])
    site["features"]["external-collector"]["placement"]["ghost"] = "data"
    with pytest.raises(ml.LimitsError, match="not one of its host roles"):
        render(site)
    site = copy.deepcopy(SITES["small-lab"])
    site["features"]["no-such-module"] = {}
    with pytest.raises(ml.LimitsError, match="without a manifest"):
        render(site)


def test_disk_zero_is_no_cap_and_gpu_memory_is_reported_unenforced():
    mods = copy.deepcopy(MODULES)
    _lake(mods)["footprint"]["disk_gb"] = 0
    files = render("small-lab", mods)
    assert "example-lake" not in files["data/hnx-module-quota.sh"]
    assert "| core | example-inference | server |" in files["README.md"]
    assert "(not enforced)" in files["README.md"]
    assert "run external-collector 10\n" in files["data/hnx-module-quota.sh"]


def test_render_is_deterministic():
    assert render("full") == render("full")
    assert list(render("full")) == sorted(render("full"))


def test_write_makes_the_script_executable(tmp_path):
    ml.write(render("small-lab"), tmp_path)
    assert os.access(tmp_path / "data/hnx-module-quota.sh", os.X_OK)
    assert (tmp_path / "data/hnx-example_lake-lake.slice").is_file()


def test_the_script_s_paths_are_plain():
    for bad in ("relative", "/a b", "/a/../b", "/a;rm"):
        with pytest.raises(ml.LimitsError):
            ml._quota_script({"m": 1}, root=bad)


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
  zfs)
    if [ "$1" = get ]; then cat "$HNX_MNT/zfs.$6"; fi
    if [ "$1" = set ] && [ -f "$HNX_MNT/zfs.fail" ]; then exit 1; fi ;;
  losetup) cat "$HNX_MNT/losetup" 2>/dev/null ;;
  systemd-escape) echo "escaped-$(basename "$3").mount" ;;
  fallocate) if [ -f "$HNX_MNT/fallocate.fail" ]; then exit 1; fi; truncate -s "$2" "$3" ;;
  mkfs.ext4) if [ -f "$HNX_MNT/mkfs.fail" ]; then exit 1; fi ;;
esac
exit 0
"""
TOOLS = ("findmnt", "zfs", "losetup", "mkfs.ext4", "systemctl", "systemd-escape", "fallocate")
G = 1073741824


@pytest.fixture
def host(tmp_path):
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    for name in TOOLS:
        (bin_ / name).write_text(STUB)
        (bin_ / name).chmod(0o755)
    root = tmp_path / "modules"
    mnt = tmp_path / "mnt"
    mnt.mkdir()
    units_dir = tmp_path / "units"
    units_dir.mkdir()
    log = tmp_path / "log"
    env = {"PATH": f"{bin_}:{os.environ['PATH']}", "HNX_LOG": str(log), "HNX_MNT": str(mnt)}

    def mount(dir_, **fields):
        key = str(dir_).replace("/", "_")
        for k, v in fields.items():
            (mnt / f"{key}.{k}").write_text(v + "\n")

    def run(*args, caps=None):
        script = tmp_path / "quota.sh"
        body = ml._quota_script(caps or {"m": 2}, str(root), str(units_dir))
        assert ml.DATA_ROOT not in body and ml.UNIT_DIR not in body
        script.write_text(body)
        script.chmod(0o755)
        if log.exists():
            log.unlink()
        r = subprocess.run([str(script), *args], env=env, capture_output=True, text=True)
        calls = log.read_text().splitlines() if log.exists() else []
        return r, calls

    return root, mnt, units_dir, mount, run


def _zfs(mnt, mount, root, have):
    mount(root / "m", TARGET=str(root / "m"), FSTYPE="zfs", SOURCE="tank/hnx/m")
    (mnt / "zfs.refquota").write_text(f"{have}\n")
    (mnt / "zfs.refreservation").write_text(f"{have}\n")


def test_a_zfs_dataset_gets_its_refquota_and_refreservation(host):
    root, mnt, _u, mount, run = host
    _zfs(mnt, mount, root, 0)
    r, calls = run()
    assert r.returncode == 0, r.stderr
    assert "zfs set refquota=2G refreservation=2G tank/hnx/m" in calls


def test_a_zfs_dataset_with_the_right_values_is_left_alone_and_check_passes(host):
    root, mnt, _u, mount, run = host
    _zfs(mnt, mount, root, 2 * G)
    (root / "m").mkdir(parents=True)
    for args in ((), ("--check",)):
        r, calls = run(*args)
        assert r.returncode == 0, r.stderr
        assert not any(c.startswith("zfs set") for c in calls)


def test_a_failing_zfs_set_is_owed_and_the_next_module_is_still_capped(host):
    root, mnt, _u, mount, run = host
    _zfs(mnt, mount, root, 0)
    (mnt / "zfs.fail").write_text("")
    r, calls = run(caps={"m": 2, "n": 1})
    assert r.returncode == 3 and "m: failed" in r.stderr
    assert any(c.startswith("mkfs.ext4") and "hnx-n" in c for c in calls), calls


def test_a_zfs_parent_dataset_is_not_imaged(host):
    root, _mnt, _u, mount, run = host
    mount(root / "m", TARGET=str(root), FSTYPE="zfs", SOURCE="tank/hnx")
    r, calls = run()
    assert r.returncode == 3 and "not its own dataset" in r.stderr
    assert not any(c.startswith(("fallocate", "mkfs")) for c in calls)


def test_check_changes_nothing_and_owes_a_missing_cap(host):
    root, _m, units_dir, _mount, run = host
    (root / "m").mkdir(parents=True)
    r, calls = run("--check")
    assert r.returncode == 3 and "has no cap" in r.stderr
    assert not any(c.split()[0] in ("mkfs.ext4", "systemctl", "fallocate") for c in calls)
    assert not (root / ".images").exists() and not any(units_dir.iterdir())


def test_elsewhere_an_allocated_image_is_made_and_mounted_keeping_owner_and_mode(host):
    root, _m, units_dir, _mount, run = host
    (root / "m").mkdir(parents=True)
    os.chown(root / "m", 4242, 4343)
    (root / "m").chmod(0o750)
    r, calls = run()
    assert r.returncode == 0, r.stderr
    img = root / ".images" / "m.img"
    assert img.stat().st_size == 2 * G and not (root / ".images" / "m.img.tmp").exists()
    assert f"fallocate -l 2G {img}.tmp" in calls
    assert f"mkfs.ext4 -q -F -m 0 -L hnx-m {img}.tmp" in calls
    unit = (units_dir / "escaped-m.mount").read_text()
    assert f"What={img}\nWhere={root / 'm'}\n" in unit and "Options=loop,nodev,nosuid" in unit
    assert "systemctl enable --now escaped-m.mount" in calls
    st = (root / "m").stat()
    assert (st.st_uid, st.st_gid, st.st_mode & 0o777) == (4242, 4343, 0o750)
    assert oct((root / ".images").stat().st_mode & 0o777) == "0o700"


@pytest.mark.parametrize("fails", ["fallocate", "mkfs"])
def test_a_failed_build_leaves_nothing_and_the_rerun_builds_it(host, fails):
    root, mnt, units_dir, _mount, run = host
    (mnt / f"{fails}.fail").write_text("")
    r, _ = run()
    assert r.returncode == 3
    assert not (root / ".images" / "m.img").exists() and not any(units_dir.iterdir())
    (mnt / f"{fails}.fail").unlink()
    r, _ = run()
    assert r.returncode == 0, r.stderr
    assert (root / ".images" / "m.img").exists()


def test_an_image_built_but_not_mounted_is_mounted_not_rebuilt(host):
    root, _m, units_dir, _mount, run = host
    img = root / ".images" / "m.img"
    img.parent.mkdir(parents=True)
    img.write_bytes(b"data")
    (root / ".images" / "m.img.tmp").write_bytes(b"half")
    r, calls = run()
    assert r.returncode == 0, r.stderr
    assert img.read_bytes() == b"data" and not (root / ".images" / "m.img.tmp").exists()
    assert not any(c.startswith(("fallocate", "mkfs")) for c in calls)
    assert "systemctl enable --now escaped-m.mount" in calls
    assert (units_dir / "escaped-m.mount").exists()


def test_an_image_is_never_mounted_over_existing_data(host):
    root, _m, units_dir, _mount, run = host
    (root / "m").mkdir(parents=True)
    (root / "m" / "precious").write_text("x")
    r, calls = run()
    assert r.returncode == 3 and "already holds files" in r.stderr
    assert not any(c.startswith(("mkfs", "fallocate")) for c in calls)
    assert not any(units_dir.iterdir())


def test_a_mounted_image_of_the_right_size_passes_and_a_wrong_one_is_owed(host):
    root, mnt, _u, mount, run = host
    img = root / ".images" / "m.img"
    img.parent.mkdir(parents=True)
    img.write_bytes(b"")
    os.truncate(img, 2 * G)
    mount(root / "m", TARGET=str(root / "m"), FSTYPE="ext4", SOURCE="/dev/loop7")
    (root / "m").mkdir()
    (mnt / "losetup").write_text(f"{img}\n")
    r, _ = run("--check")
    assert r.returncode == 0, r.stderr
    os.truncate(img, G)
    r, _ = run()
    assert r.returncode == 3 and "want 2G" in r.stderr


def test_a_foreign_mount_is_not_touched(host):
    root, _mnt, _u, mount, run = host
    (root / "m").mkdir(parents=True)
    mount(root / "m", TARGET=str(root / "m"), FSTYPE="nfs", SOURCE="server:/x")
    r, calls = run()
    assert r.returncode == 3 and "not made by this script" in r.stderr
    assert not any(c.startswith(("mkfs", "zfs set", "systemctl", "fallocate")) for c in calls)


def test_symlinks_are_refused(host, tmp_path):
    root, _m, _u, _mount, run = host
    root.mkdir()
    (tmp_path / "elsewhere").mkdir()
    os.symlink(tmp_path / "elsewhere", root / "m")
    r, calls = run()
    assert r.returncode == 3 and "symbolic link" in r.stderr
    os.unlink(root / "m")
    os.symlink(tmp_path / "elsewhere", root / ".images")
    r, calls = run()
    assert r.returncode == 3 and "symbolic link" in r.stderr
    os.unlink(root / ".images")
    (root / ".images").mkdir()
    os.symlink(tmp_path / "victim", root / ".images" / "m.img")
    r, calls = run()
    assert r.returncode == 3 and "symbolic link" in r.stderr
    assert not (tmp_path / "victim").exists()
    assert not any(c.startswith(("mkfs", "fallocate")) for c in calls)


def test_a_failing_tool_in_check_mode_still_exits_3(host):
    root, mnt, _u, mount, run = host
    _zfs(mnt, mount, root, 0)
    (root / "m").mkdir(parents=True)
    (mnt / "zfs.refquota").unlink()  # the stubbed zfs get now fails
    r, _ = run("--check")
    assert r.returncode == 3


def test_the_script_rejects_unknown_arguments(host):
    _r, _m, _u, _mount, run = host
    r, _ = run("--nope")
    assert r.returncode == 2
