#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: ci-runner-slot
#   kind: service
#   purpose: Run one CI job slot - claim one single-use runner registration from the spool, boot a throwaway VM from the pinned golden image with it, wait for the VM to power off after its one job, then destroy every file of it; also the forced command the registration feeder reaches over SSH (put, status).
#   owner: platform
#   trigger: [role:ci_runner]
#   inputs: the JSON config named by HNX_CI_CONFIG (slot.json); the spool directory; SSH_ORIGINAL_COMMAND for the feed side
#   outputs: one VM run per slot run; the slot's state.json; the last console log per slot; spool files (feed side)
#   installs_to: /usr/local/libexec/homelabnext/hnx-ci-slot
#   exit:
#     "0": the slot ran one VM to its end, or found no registration and waits for the next start
#     "1": the request was refused (a bad name, a bad registration, an unknown command)
#     "2": the configuration or the golden image is missing or invalid
"""One ephemeral CI job slot.

The slot unit (``hnx-<id>-slot@<n>.service``) runs ``run --slot N`` once and is restarted by
systemd after every run, so each run is exactly one job:

1. the slot's working directory is emptied (nothing of the previous run survives);
2. one single-use runner registration is claimed from the spool by an atomic rename (two slots
   can never claim the same one); with none there, the run ends and systemd starts it again;
3. a copy-on-write disk over the pinned golden image and a seed image carrying only that
   registration are created, and the VM boots with user-mode networking (its traffic leaves as
   this unit's user, which the host's egress table holds to DNS and the internet);
4. the VM runs the one job it registered for and powers itself off; a VM that outlives the job
   time limit is killed;
5. the working directory is emptied again: the disk, the seed and the registration are gone.

The feed side (``feed``, the forced command of the feeder's SSH key) takes ``put <name>`` with
the encoded registration on stdin, or ``status``, and nothing else.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

NAME = re.compile(r"hnx-ci-[a-z0-9][a-z0-9-]{0,62}\Z")
#: an encoded registration: base64 text, bounded
JIT = re.compile(r"[A-Za-z0-9+/=]{16,65536}\Z")
GOLDEN = re.compile(r"golden-[0-9a-f]{16}\.qcow2\Z")
KEYS = {
    "data_root": str,
    "vcpus": int,
    "memory_mb": int,
    "disk_gb": int,
    "job_timeout_s": int,
    "claim_wait_s": int,
    "qemu": str,
    "qemu_img": str,
    "iso_tool": str,
    "slots": int,
    "console_keep_bytes": int,
}


class Refused(Exception):
    """A request or an input that must not be acted on."""


def load_config(path: str | os.PathLike[str]) -> dict:
    """The slot configuration, every key present and of its type, the data root absolute."""
    try:
        cfg = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise Refused(f"config {path}: {e}") from None
    if not isinstance(cfg, dict):
        raise Refused(f"config {path}: not an object")
    for key, typ in KEYS.items():
        if not isinstance(cfg.get(key), typ) or isinstance(cfg.get(key), bool):
            raise Refused(f"config {path}: {key} missing or not {typ.__name__}")
    root = Path(cfg["data_root"])
    if not root.is_absolute() or len(root.parts) < 4 or ".." in root.parts:
        raise Refused(f"config {path}: data_root {root} is not an absolute path of 3+ components")
    for key in ("vcpus", "memory_mb", "disk_gb", "job_timeout_s", "slots"):
        if cfg[key] < 1:
            raise Refused(f"config {path}: {key} must be positive")
    return cfg


def _paths(cfg: dict) -> dict[str, Path]:
    root = Path(cfg["data_root"])
    return {
        "root": root,
        "spool": root / "spool",
        "slots": root / "slots",
        "images": root / "images",
    }


def slot_dir(cfg: dict, slot: int) -> Path:
    """The slot's working directory: <data root>/slots/<n>, never anything else."""
    if not 0 <= slot < cfg["slots"]:
        raise Refused(f"slot {slot} is outside 0..{cfg['slots'] - 1}")
    return _paths(cfg)["slots"] / str(slot)


def empty_dir(path: Path, parent: Path) -> None:
    """Remove ``path`` and everything under it, then create it empty (mode 0700).

    Refused unless ``path`` is a direct child of ``parent`` (itself absolute, 3+ components) and
    neither is a symbolic link: the slot directory is the only thing this ever deletes."""
    parent = Path(parent)
    if not parent.is_absolute() or len(parent.parts) < 4 or ".." in parent.parts:
        raise Refused(f"refusing to empty under {parent}")
    if path.parent != parent or path.name in ("", ".", ".."):
        raise Refused(f"refusing to empty {path}: not a direct child of {parent}")
    if parent.is_symlink() or parent.resolve() != parent:
        raise Refused(f"refusing to empty under {parent}: it is or passes through a link")
    if path.is_symlink():
        raise Refused(f"refusing to empty {path}: it is a link")
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(mode=0o700)


def golden_image(cfg: dict) -> Path:
    """The golden image named by images/current (one file name, the image present)."""
    images = _paths(cfg)["images"]
    try:
        name = (images / "current").read_text(encoding="utf-8").strip()
    except OSError as e:
        raise Refused(f"no golden image pointer: {e}") from None
    if not GOLDEN.match(name):
        raise Refused(f"golden image pointer {name!r} is not a golden image name")
    img = images / name
    if not img.is_file() or img.is_symlink():
        raise Refused(f"golden image {img} is missing")
    return img


def claim(cfg: dict, dest: Path) -> str | None:
    """Move the oldest spooled registration to ``dest``/jit; its runner name, or None."""
    spool = _paths(cfg)["spool"]
    try:
        entries = [e for e in os.scandir(spool) if e.name.endswith(".jit")]
    except OSError:
        return None
    entries.sort(key=lambda e: (e.stat(follow_symlinks=False).st_mtime, e.name))
    for e in entries:
        name = e.name[: -len(".jit")]
        if not NAME.match(name) or e.is_symlink():
            continue
        try:
            os.rename(e.path, dest / "jit")
        except FileNotFoundError:  # another slot took it first
            continue
        (dest / "runner").write_text(name + "\n", encoding="utf-8")
        return name
    return None


def user_data(jit: str) -> str:
    """The job VM's cloud-config: the registration as a root-only file, and the job unit started.

    The golden image carries the job unit; this seed only hands it the one registration."""
    if not JIT.match(jit):
        raise Refused("the registration is not encoded text")
    return (
        "#cloud-config\n"
        "write_files:\n"
        "  - path: /run/hnx-ci/jit\n"
        "    permissions: '0600'\n"
        "    owner: root:root\n"
        f"    content: {jit}\n"
        "runcmd:\n"
        "  - [systemctl, start, --no-block, hnx-ci-job.service]\n"
    )


def write_state(d: Path, **state) -> None:
    state["at"] = int(time.time())
    tmp = d / ".state.json.tmp"
    tmp.write_text(json.dumps(state, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o640)
    os.replace(tmp, d / "state.json")


def qemu_argv(cfg: dict, d: Path) -> list[str]:
    """The VM: KVM, the host CPU, virtio disk on the slot's overlay, the seed read-only, user-mode
    networking with no host forwarding and no IPv6, no display, the console to a file."""
    return [
        cfg["qemu"],
        "-name", f"hnx-ci-{d.name}",
        "-machine", "q35,accel=kvm",
        "-cpu", "host",
        "-smp", str(cfg["vcpus"]),
        "-m", str(cfg["memory_mb"]),
        "-nodefaults", "-no-user-config", "-display", "none", "-no-reboot",
        "-serial", f"file:{d / 'console.log'}",
        "-drive", f"file={d / 'disk.qcow2'},if=virtio,format=qcow2,cache=unsafe,discard=unmap",
        "-drive", f"file={d / 'seed.iso'},if=virtio,format=raw,readonly=on",
        "-netdev", "user,id=n0,ipv6=off",
        "-device", "virtio-net-pci,netdev=n0",
        "-device", "virtio-rng-pci",
    ]  # fmt: skip


def _keep_console(d: Path, keep: Path, limit: int) -> None:
    log = d / "console.log"
    if not log.is_file() or log.is_symlink() or limit <= 0:
        return
    with log.open("rb") as f:
        f.seek(max(0, log.stat().st_size - limit))
        data = f.read()
    tmp = keep.with_name(keep.name + ".tmp")
    tmp.write_bytes(data)
    os.chmod(tmp, 0o640)
    os.replace(tmp, keep)


def run_slot(cfg: dict, slot: int, runner=subprocess.run, sleep=time.sleep) -> int:
    """One slot run (see the module docstring). Returns the exit code."""
    p = _paths(cfg)
    d = slot_dir(cfg, slot)
    empty_dir(d, p["slots"])
    golden = golden_image(cfg)
    name = None
    deadline = time.monotonic() + cfg["claim_wait_s"]
    while name is None:
        name = claim(cfg, d)
        if name is None:
            if time.monotonic() >= deadline:
                write_state(d, state="waiting")
                return 0
            sleep(2)
    write_state(d, state="booting", runner=name)
    try:
        jit = (d / "jit").read_text(encoding="utf-8").strip()
        seed = d / "seed"
        seed.mkdir(mode=0o700)
        (seed / "user-data").write_text(user_data(jit), encoding="utf-8")
        (seed / "meta-data").write_text(
            f"instance-id: {name}\nlocal-hostname: {name}\n", encoding="utf-8"
        )
        (d / "jit").unlink()
        runner(
            [cfg["iso_tool"], "-quiet", "-output", str(d / "seed.iso"), "-volid", "cidata",
             "-joliet", "-rock", str(seed / "user-data"), str(seed / "meta-data")],
            check=True,
        )  # fmt: skip
        runner(
            [cfg["qemu_img"], "create", "-q", "-f", "qcow2", "-F", "qcow2",
             "-b", str(golden), str(d / "disk.qcow2"), f"{cfg['disk_gb']}G"],
            check=True,
        )  # fmt: skip
        write_state(d, state="running", runner=name)
        try:
            r = runner(qemu_argv(cfg, d), timeout=cfg["job_timeout_s"], check=False)
            outcome = f"exit {r.returncode}"
        except subprocess.TimeoutExpired:
            outcome = "killed at the job time limit"
        print(f"slot {slot}: runner {name}: VM ended ({outcome})", flush=True)
    finally:
        _keep_console(d, p["slots"] / f"{slot}.last.log", cfg["console_keep_bytes"])
        empty_dir(d, p["slots"])
        write_state(d, state="done", runner=name)
    return 0


# ----------------------------------------------------------------------------- the golden image


def build_golden(
    cfg: dict,
    base: Path,
    user_data_file: Path,
    name: str,
    marker: str,
    vcpus: int,
    memory_mb: int,
    disk_gb: int,
    timeout_s: int,
    runner=subprocess.run,
) -> Path:
    """Build ``images/<name>`` once: the base image copied and grown in images/.build/, booted with
    the build seed until it powers off, kept only when its console printed ``marker``, then
    renamed into place and named in images/current. An image already there is only re-pointed."""
    if not GOLDEN.match(name) or not re.fullmatch(r"HNX-CI-BUILD-OK [0-9a-f]{16}", marker):
        raise Refused(f"bad golden image name {name!r} or marker")
    images = _paths(cfg)["images"]
    final = images / name
    if not final.is_file():
        if base.parent != images or not base.is_file():
            raise Refused(f"base image {base} is not a file in {images}")
        work = images / ".build"
        empty_dir(work, images)
        try:
            seed = work / "seed"
            seed.mkdir(mode=0o700)
            shutil.copyfile(user_data_file, seed / "user-data")
            (seed / "meta-data").write_text(f"instance-id: build-{name[7:23]}\n", encoding="utf-8")
            runner(
                [
                    cfg["iso_tool"],
                    "-quiet",
                    "-output",
                    str(work / "seed.iso"),
                    "-volid",
                    "cidata",
                    "-joliet",
                    "-rock",
                    str(seed / "user-data"),
                    str(seed / "meta-data"),
                ],
                check=True,
            )
            runner(
                [
                    cfg["qemu_img"],
                    "convert",
                    "-q",
                    "-O",
                    "qcow2",
                    str(base),
                    str(work / "disk.qcow2"),
                ],
                check=True,
            )
            runner(
                [cfg["qemu_img"], "resize", "-q", str(work / "disk.qcow2"), f"{disk_gb}G"],
                check=True,
            )
            argv = qemu_argv({**cfg, "vcpus": vcpus, "memory_mb": memory_mb}, work)
            try:
                runner(argv, timeout=timeout_s, check=False)
            except subprocess.TimeoutExpired:
                raise Refused(f"the golden image build ran past {timeout_s} s") from None
            console = (
                (work / "console.log").read_bytes() if (work / "console.log").is_file() else b""
            )
            if marker.encode() not in console:
                tail = console[-2000:].decode("utf-8", "replace")
                raise Refused(
                    f"the golden image build did not finish (no marker); console tail:\n{tail}"
                )
            runner(
                [
                    cfg["qemu_img"],
                    "convert",
                    "-q",
                    "-O",
                    "qcow2",
                    str(work / "disk.qcow2"),
                    str(work / "golden.qcow2"),
                ],
                check=True,
            )
            os.chmod(work / "golden.qcow2", 0o440)
            os.rename(work / "golden.qcow2", final)
        finally:
            empty_dir(work, images)
            work.rmdir()
    tmp = images / ".current.tmp"
    tmp.write_text(name + "\n", encoding="utf-8")
    os.chmod(tmp, 0o644)
    os.replace(tmp, images / "current")
    return final


# ----------------------------------------------------------------------------- the feed side


def feed_put(cfg: dict, name: str, data: str) -> None:
    """Spool one registration: validated, written beside its final name, renamed into place."""
    if not NAME.match(name):
        raise Refused(f"bad runner name {name!r}")
    jit = data.strip()
    if not JIT.match(jit):
        raise Refused("the registration is not encoded text of a sane size")
    spool = _paths(cfg)["spool"]
    final = spool / f"{name}.jit"
    if final.exists():
        raise Refused(f"{name} is already spooled")
    fd, tmp = tempfile.mkstemp(dir=spool, prefix=".put-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(jit + "\n")
        os.chmod(tmp, 0o640)
        os.rename(tmp, final)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def feed_status(cfg: dict) -> dict:
    """What the feeder needs: the spooled names, each slot's state, the slot count, the image."""
    p = _paths(cfg)
    spooled = sorted(
        e.name[: -len(".jit")]
        for e in os.scandir(p["spool"])
        if e.name.endswith(".jit") and NAME.match(e.name[: -len(".jit")])
    )
    slots = {}
    for n in range(cfg["slots"]):
        try:
            st = json.loads((p["slots"] / str(n) / "state.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            st = {"state": "unknown"}
        slots[str(n)] = {k: st.get(k) for k in ("state", "runner", "at")}
    try:
        golden = golden_image(cfg).name
    except Refused:
        golden = None
    return {"slots_total": cfg["slots"], "spooled": spooled, "slots": slots, "golden": golden}


def feed(cfg: dict, command: str, stdin) -> int:
    words = command.split()
    if words[:1] == ["status"] and len(words) == 1:
        print(json.dumps(feed_status(cfg), sort_keys=True))
        return 0
    if words[:1] == ["put"] and len(words) == 2:
        feed_put(cfg, words[1], stdin.read(70000))
        print("ok")
        return 0
    raise Refused(f"unknown command {command[:80]!r} (put <name> | status)")


def main(argv: list[str]) -> int:
    try:
        cfg = load_config(os.environ.get("HNX_CI_CONFIG", "/etc/hnx/ci-runner/slot.json"))
    except Refused as e:
        print(f"hnx-ci-slot: {e}", file=sys.stderr)
        return 2
    try:
        if argv[:1] == ["run"] and len(argv) == 3 and argv[1] == "--slot" and argv[2].isdigit():
            signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
            return run_slot(cfg, int(argv[2]))
        if argv == ["feed"]:
            return feed(cfg, os.environ.get("SSH_ORIGINAL_COMMAND", ""), sys.stdin)
        if argv[:1] == ["build"] and len(argv) == 9:
            _, base, ud, name, marker, vcpus, mem, disk, timeout = argv
            if not all(x.isdigit() for x in (vcpus, mem, disk, timeout)):
                raise Refused(
                    "usage: build BASE USER_DATA NAME MARKER VCPUS MEMORY_MB DISK_GB TIMEOUT_S"
                )
            print(
                build_golden(
                    cfg,
                    Path(base),
                    Path(ud),
                    name,
                    marker,
                    int(vcpus),
                    int(mem),
                    int(disk),
                    int(timeout),
                )
            )
            return 0
        if argv == ["status"]:
            print(json.dumps(feed_status(cfg), sort_keys=True, indent=1))
            return 0
    except Refused as e:
        print(f"hnx-ci-slot: refused: {e}", file=sys.stderr)
        return 2 if "golden" in str(e) or "config" in str(e) else 1
    print("usage: hnx-ci-slot run --slot N | feed | status | build ...", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
