# SPDX-License-Identifier: Apache-2.0
"""The ci-runner module's two scripts, run in-process against a scratch data root.

* The slot script: a slot run empties its directory, claims exactly one spooled registration by
  rename, boots one VM (a fake) and leaves nothing behind, so the next run starts from nothing; two
  slots never claim the same registration; every destructive path refuses anything that is not a
  direct child of the slots (or images) directory; the feed side accepts only ``put <name>`` with
  encoded text and ``status``; the golden image is kept only when its build printed the marker.
* The feeder: how many registrations it mints, which runners are orphans, and the routing variable
  set on while the pool answers and off once it has not for long enough.
"""

from __future__ import annotations

import importlib.util
import io
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
FILES = ROOT / "modules" / "ci-runner" / "roles" / "ci_runner" / "files"


def _load(name: str, file: str):
    spec = importlib.util.spec_from_file_location(name, FILES / file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


slot = _load("hnx_ci_slot", "hnx_ci_slot.py")
feeder = _load("hnx_ci_feeder", "hnx_ci_feeder.py")
ENC = "QUJDREVG" * 4  # encoded text of the registration's shape, nothing real


@pytest.fixture
def cfg(tmp_path):
    root = tmp_path / "var" / "lib" / "pool"
    for d in ("spool", "slots", "images"):
        (root / d).mkdir(parents=True)
    (root / "images" / "golden-0123456789abcdef.qcow2").write_bytes(b"img")
    (root / "images" / "current").write_text("golden-0123456789abcdef.qcow2\n")
    c = {"data_root": str(root), "vcpus": 2, "memory_mb": 2048, "disk_gb": 20, "job_timeout_s": 60,
         "claim_wait_s": 0, "qemu": "qemu", "qemu_img": "qemu-img", "iso_tool": "iso", "slots": 2,
         "console_keep_bytes": 100}  # fmt: skip
    path = tmp_path / "slot.json"
    path.write_text(json.dumps(c))
    return slot.load_config(path)


class FakeRun:
    """Stands in for subprocess.run: records argv, writes what the real tools would."""

    def __init__(self, console=b"booted\n", timeout=False):
        self.calls, self.console, self.timeout = [], console, timeout

    def __call__(self, argv, **kw):
        self.calls.append(argv)
        if argv[0] == "iso":
            Path(argv[argv.index("-output") + 1]).write_bytes(b"iso")
        elif argv[0] == "qemu-img":
            Path(argv[-1] if argv[1] == "convert" else argv[-2]).write_bytes(b"disk")
        elif argv[0] == "qemu":
            serial = next(a for a in argv if a.startswith("file:"))[5:]
            Path(serial).write_bytes(self.console)
            # a job writes into its disk; the slot must not keep it
            disk = next(a for a in argv if a.startswith("file=") and "qcow2" in a)
            Path(disk[5:].split(",")[0]).write_bytes(b"job wrote this")
            if self.timeout:
                raise subprocess.TimeoutExpired(argv, kw.get("timeout"))
        return SimpleNamespace(returncode=0)


def _spool(cfg, *names):
    for n in names:
        slot.feed_put(cfg, n, ENC)


def test_a_slot_run_boots_one_vm_with_one_registration_and_leaves_nothing(cfg):
    _spool(cfg, "hnx-ci-a")
    run = FakeRun()
    assert slot.run_slot(cfg, 0, runner=run) == 0
    qemu = [c for c in run.calls if c[0] == "qemu"]
    assert len(qemu) == 1 and "user,id=n0,ipv6=off" in qemu[0]
    d = Path(cfg["data_root"]) / "slots" / "0"
    assert list(d.iterdir()) == []
    assert slot.slot_state(d)["state"] == "waiting"
    assert d.stat().st_mode & 0o777 == 0o700
    assert not list((Path(cfg["data_root"]) / "spool").iterdir())
    assert (Path(cfg["data_root"]) / "slots" / "0.last.log").read_bytes() == b"booted\n"


def test_the_next_job_in_a_slot_sees_none_of_the_previous_job_s_files(cfg):
    _spool(cfg, "hnx-ci-a", "hnx-ci-b")
    d = Path(cfg["data_root"]) / "slots" / "0"
    slot.run_slot(cfg, 0, runner=FakeRun())
    (d / "left-behind").write_text("x")  # anything at all in the slot directory
    seen = []

    class Peek(FakeRun):
        def __call__(self, argv, **kw):
            if argv[0] == "qemu":
                seen.extend(sorted(p.name for p in d.iterdir()))
            return super().__call__(argv, **kw)

    slot.run_slot(cfg, 0, runner=Peek())
    assert seen == ["disk.qcow2", "runner", "seed", "seed.iso"]  # nothing of job one


def test_the_seed_carries_the_registration_and_the_jit_file_is_gone_before_boot(cfg):
    _spool(cfg, "hnx-ci-a")
    d = Path(cfg["data_root"]) / "slots" / "0"
    got = {}

    class Peek(FakeRun):
        def __call__(self, argv, **kw):
            if argv[0] == "qemu":
                got["user-data"] = (d / "seed" / "user-data").read_text()
                got["jit"] = (d / "jit").exists()
            return super().__call__(argv, **kw)

    slot.run_slot(cfg, 0, runner=Peek())
    assert f"content: {ENC}" in got["user-data"] and got["jit"] is False
    assert "hnx-ci-job.service" in got["user-data"]


def test_a_vm_past_the_time_limit_is_killed_and_the_slot_still_emptied(cfg):
    _spool(cfg, "hnx-ci-a")
    assert slot.run_slot(cfg, 0, runner=FakeRun(timeout=True)) == 0
    d = Path(cfg["data_root"]) / "slots" / "0"
    assert list(d.iterdir()) == []


def test_with_nothing_spooled_the_run_ends_waiting_and_boots_nothing(cfg):
    run = FakeRun()
    assert slot.run_slot(cfg, 1, runner=run, sleep=lambda s: None) == 0
    assert run.calls == []
    assert slot.slot_state(Path(cfg["data_root"]) / "slots" / "1")["state"] == "waiting"


def test_a_slot_s_state_is_read_from_what_its_directory_holds(cfg, tmp_path):
    d = Path(cfg["data_root"]) / "slots" / "0"
    assert slot.slot_state(d)["state"] == "unknown"  # not there
    d.mkdir()
    (d / "runner").write_text("hnx-ci-a\n")
    assert slot.slot_state(d) | {"at": 0} == {"state": "booting", "runner": "hnx-ci-a", "at": 0}
    (d / "disk.qcow2").write_bytes(b"x")
    assert slot.slot_state(d)["state"] == "running"


def test_two_slots_never_claim_the_same_registration(cfg):
    _spool(cfg, "hnx-ci-a")
    slots = Path(cfg["data_root"]) / "slots"
    for n in ("0", "1"):
        (slots / n).mkdir()
    assert slot.claim(cfg, slots / "0") == "hnx-ci-a"
    assert slot.claim(cfg, slots / "1") is None


def test_a_spool_entry_with_a_bad_name_or_a_link_is_never_claimed(cfg):
    spool = Path(cfg["data_root"]) / "spool"
    (spool / "Evil Name.jit").write_text(ENC)
    (spool / "hnx-ci-link.jit").symlink_to(spool / "Evil Name.jit")
    d = Path(cfg["data_root"]) / "slots" / "0"
    d.mkdir()
    assert slot.claim(cfg, d) is None


@pytest.mark.parametrize(
    "target",
    ["/", "/var", "/var/lib", "../escape", "slots-sibling"],
)
def test_empty_dir_refuses_anything_but_a_direct_child_of_its_parent(cfg, tmp_path, target):
    parent = Path(cfg["data_root"]) / "slots"
    path = Path(target) if target.startswith("/") else parent / target
    if target == "slots-sibling":
        path = parent.parent / "images"
    with pytest.raises(slot.Refused):
        slot.empty_dir(path, parent)
    assert (Path(cfg["data_root"]) / "images" / "current").exists()


def test_empty_dir_refuses_a_shallow_parent_and_a_linked_slot(cfg, tmp_path):
    with pytest.raises(slot.Refused):
        slot.empty_dir(Path("/tmp/x"), Path("/tmp"))
    parent = Path(cfg["data_root"]) / "slots"
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep").write_text("x")
    (parent / "0").symlink_to(outside)
    with pytest.raises(slot.Refused):
        slot.empty_dir(parent / "0", parent)
    assert (outside / "keep").exists()


def test_a_slot_number_outside_the_pool_is_refused(cfg):
    with pytest.raises(slot.Refused):
        slot.slot_dir(cfg, 2)


@pytest.mark.parametrize(
    "bad",
    [
        {"data_root": "/var"},
        {"data_root": "rel/a/b/c"},
        {"slots": 0},
        {"vcpus": True},
        {"qemu": None},
    ],
)
def test_a_bad_configuration_is_refused(tmp_path, bad):
    c = {"data_root": "/var/lib/a/b", "vcpus": 2, "memory_mb": 2048, "disk_gb": 20,
         "job_timeout_s": 60, "claim_wait_s": 0, "qemu": "q", "qemu_img": "qi", "iso_tool": "i",
         "slots": 2, "console_keep_bytes": 0, **bad}  # fmt: skip
    p = tmp_path / "c.json"
    p.write_text(json.dumps(c))
    with pytest.raises(slot.Refused):
        slot.load_config(p)


def test_a_missing_or_bad_golden_pointer_is_refused(cfg):
    images = Path(cfg["data_root"]) / "images"
    (images / "current").write_text("../../etc/passwd\n")
    with pytest.raises(slot.Refused):
        slot.golden_image(cfg)
    (images / "current").write_text("golden-ffffffffffffffff.qcow2\n")
    with pytest.raises(slot.Refused):
        slot.golden_image(cfg)


# ----------------------------------------------------------------------------- the feed side


def test_the_feed_side_takes_put_and_status_only(cfg, capsys):
    assert slot.feed(cfg, "put hnx-ci-a", io.StringIO(ENC + "\n")) == 0
    assert slot.feed(cfg, "status", io.StringIO()) == 0
    out = capsys.readouterr().out.splitlines()
    st = json.loads(out[-1])
    assert st["spooled"] == ["hnx-ci-a"] and st["slots_total"] == 2
    assert st["golden"] == "golden-0123456789abcdef.qcow2"
    for cmd in ("", "sh", "status; id", "put", "put ../x", "put hnx-ci-a extra", "rm hnx-ci-a"):
        with pytest.raises(slot.Refused):
            slot.feed(cfg, cmd, io.StringIO(ENC))


@pytest.mark.parametrize("data", ["", "not base64!", "#cloud-config\nruncmd: [id]", "A" * 70000])
def test_put_refuses_anything_but_encoded_text(cfg, data):
    with pytest.raises(slot.Refused):
        slot.feed_put(cfg, "hnx-ci-a", data)
    assert not list((Path(cfg["data_root"]) / "spool").iterdir())


def test_put_refuses_a_name_already_spooled(cfg):
    _spool(cfg, "hnx-ci-a")
    with pytest.raises(slot.Refused):
        slot.feed_put(cfg, "hnx-ci-a", ENC)


def test_the_user_data_refuses_text_that_could_add_cloud_config():
    with pytest.raises(slot.Refused):
        slot.user_data("x\nruncmd: [id]")


# ----------------------------------------------------------------------------- the golden image


def _build(cfg, run, tmp_path):
    images = Path(cfg["data_root"]) / "images"
    (images / "base-0.img").write_bytes(b"base")
    ud = tmp_path / "user-data"
    ud.write_text("#cloud-config\n")
    return slot.build_golden(cfg, images / "base-0.img", ud, "golden-aaaaaaaaaaaaaaaa.qcow2",
                             "HNX-CI-BUILD-OK 0000000000000000", 2, 2048, 20, 60, runner=run)  # fmt: skip


def test_the_golden_image_is_kept_and_pointed_at_only_with_the_marker(cfg, tmp_path):
    images = Path(cfg["data_root"]) / "images"
    with pytest.raises(slot.Refused):
        _build(cfg, FakeRun(console=b"failed\n"), tmp_path)
    assert (
        not (images / "golden-aaaaaaaaaaaaaaaa.qcow2").exists() and not (images / ".build").exists()
    )
    assert (images / "current").read_text().strip() == "golden-0123456789abcdef.qcow2"
    out = _build(cfg, FakeRun(console=b"...HNX-CI-BUILD-OK 0000000000000000\n"), tmp_path)
    assert out.name == "golden-aaaaaaaaaaaaaaaa.qcow2" and out.is_file()
    assert (images / "current").read_text().strip() == out.name
    assert (images / "golden-0123456789abcdef.qcow2").exists()  # the old image is kept


def test_a_base_image_outside_the_images_directory_is_refused(cfg, tmp_path):
    other = tmp_path / "base.img"
    other.write_bytes(b"x")
    with pytest.raises(slot.Refused):
        slot.build_golden(cfg, other, other, "golden-aaaaaaaaaaaaaaaa.qcow2",
                          "HNX-CI-BUILD-OK 0000000000000000", 2, 2048, 20, 60, runner=FakeRun())  # fmt: skip


# ----------------------------------------------------------------------------- the feeder


def _status(states, spooled=(), total=None, golden="golden-x"):
    return {"slots_total": len(states) if total is None else total, "spooled": list(spooled),
            "golden": golden,
            "slots": {str(i): {"state": s, "runner": f"hnx-ci-r{i}"} for i, s in enumerate(states)}}  # fmt: skip


def test_it_mints_one_per_idle_slot_plus_the_buffer_never_more_than_the_pool():
    assert feeder.wanted(_status(["running", "running"]), 2) == 2
    assert feeder.wanted(_status(["waiting", "done", "running", "running"]), 1) == 3
    assert feeder.wanted(_status(["waiting", "waiting"], spooled=["a", "b"]), 2) == 0
    assert feeder.wanted(_status(["waiting"] * 3), 5) == 3
    # a slot whose state cannot be read is not idle: an unreadable slot directory mints nothing
    assert feeder.wanted(_status(["unknown"] * 4), 2) == 2


def test_an_orphan_is_offline_idle_prefixed_and_held_by_no_slot():
    st = _status(["running", "done"], spooled=["hnx-ci-s"])
    runners = [
        {"id": 1, "name": "hnx-ci-r0", "status": "offline", "busy": False},  # booting in slot 0
        {
            "id": 2,
            "name": "hnx-ci-r1",
            "status": "offline",
            "busy": False,
        },  # slot 1 is done: orphan
        {"id": 3, "name": "hnx-ci-s", "status": "offline", "busy": False},  # spooled
        {"id": 4, "name": "hnx-ci-x", "status": "online", "busy": True},
        {"id": 5, "name": "deploy-1", "status": "offline", "busy": False},  # not the pool's
    ]
    assert [r["id"] for r in feeder.orphans(runners, feeder.held(st))] == [2]


class FakeForge:
    def __init__(self):
        self.vars, self.minted, self.deleted = {}, [], []

    def mint(self, name, labels):
        self.minted.append((name, tuple(labels)))
        return ENC

    def runners(self):
        return []

    def delete_runner(self, rid):
        self.deleted.append(rid)

    def get_var(self, name):
        return self.vars.get(name)

    def set_var(self, name, value):
        self.vars[name] = value


class FakeHost:
    def __init__(self, status):
        self.st, self.puts = status, []

    def status(self):
        if isinstance(self.st, Exception):
            raise self.st
        return json.loads(json.dumps(self.st))

    def put(self, name, jit):
        self.puts.append((name, jit))


def _args(**kw):
    a = {"labels": ["self-hosted", "linux", "x64", "pool"], "on_value": "on", "off_value": "off",
         "selection_var": "POOL", "tag": "t", "buffer": 1, "reap_every": 1, "down_after": 100.0}  # fmt: skip
    a.update(kw)
    return SimpleNamespace(**a)


def test_a_round_feeds_the_idle_slots_and_routes_to_the_pool():
    forge, host = FakeForge(), FakeHost(_status(["waiting", "running"]))
    feeder.Feeder(forge, host, _args()).round()
    assert len(host.puts) == 2 and all(n.startswith("hnx-ci-t-") for n, _ in host.puts)
    assert forge.minted[0][1] == ("self-hosted", "linux", "x64", "pool")
    assert forge.vars["POOL"] == "on"


def test_an_unreachable_pool_is_routed_away_only_after_the_grace_period():
    forge, host = FakeForge(), FakeHost(_status(["waiting"]))
    now = [0.0]
    f = feeder.Feeder(forge, host, _args(), clock=lambda: now[0])
    f.round()
    host.st = RuntimeError("no route")
    now[0] = 50.0
    with pytest.raises(RuntimeError):
        f.round()
    assert forge.vars["POOL"] == "on"
    now[0] = 200.0
    with pytest.raises(RuntimeError):
        f.round()
    assert forge.vars["POOL"] == "off"


def test_a_host_without_a_golden_image_gets_no_registrations():
    forge, host = FakeForge(), FakeHost(_status(["waiting"], golden=None))
    feeder.Feeder(forge, host, _args()).round()
    assert host.puts == [] and forge.minted == []


class _OtherForge(FakeForge):
    def __init__(self, queued):
        super().__init__()
        self.queued = queued

    def queued_jobs(self, labels):
        return self.queued


def test_another_repository_is_fed_only_against_its_queued_jobs():
    other = _OtherForge(3)
    labels = ["self-hosted", "linux", "x64", "ov"]
    forge, host = FakeForge(), FakeHost(_status(["waiting"] * 6))
    extras = [(other, labels, "ov")]
    feeder.Feeder(forge, host, _args(extras=extras)).round()
    mine = [n for n, _ in host.puts if n.startswith("hnx-ci-t-")]
    theirs = [n for n, _ in host.puts if n.startswith("hnx-ci-ov-")]
    assert len(theirs) == 3 and other.minted and other.minted[0][1] == tuple(labels)
    assert len(mine) == 3 and forge.minted  # the room left: 6 idle + 1 buffer, 3 taken by the other
    # its registrations in the spool or booting already cover its queue
    st = _status(["waiting"] * 6, spooled=["hnx-ci-ov-x", "hnx-ci-ov-y", "hnx-ci-ov-z"])
    other2, host2 = _OtherForge(3), FakeHost(st)
    feeder.Feeder(FakeForge(), host2, _args(extras=[(other2, labels, "ov")])).round()
    assert not [n for n, _ in host2.puts if n.startswith("hnx-ci-ov-")]
    assert feeder.supply(st, "ov") == 3 and feeder.supply(st, "other") == 0


def test_a_failing_demand_query_does_not_stop_the_main_feed(capsys):
    class Broken(_OtherForge):
        def queued_jobs(self, labels):
            raise RuntimeError("api down")

    forge, host = FakeForge(), FakeHost(_status(["waiting"]))
    feeder.Feeder(forge, host, _args(extras=[(Broken(1), ["x"], "ov")])).round()
    assert len(host.puts) == 1 and "ov demand failed" in capsys.readouterr().out


def test_also_parses_and_refuses_a_malformed_spec():
    a = feeder.parse(["--repo", "o/r", "--host", "h", "--ssh-key", "k",
                      "--also", "o/ov=self-hosted,hnx-ci-overlay=ov"])  # fmt: skip
    assert a.extras == [("o/ov", ["self-hosted", "hnx-ci-overlay"], "ov")]
    with pytest.raises(SystemExit):
        feeder.parse(["--repo", "o/r", "--host", "h", "--ssh-key", "k", "--also", "bad"])


class _IdleForge(FakeForge):
    def __init__(self, runners, queued=0):
        super().__init__()
        self._runners, self.queued = runners, queued

    def runners(self):
        return self._runners

    def queued_jobs(self, labels):
        return self.queued


def _idle(n, prefix="hnx-ci-t-"):
    return [{"id": i, "name": f"{prefix}{i}", "status": "online", "busy": False} for i in range(n)]


def test_idle_runners_of_the_main_repository_are_released_for_another_repositorys_queue():
    status = _status(["running"] * 4, spooled=["hnx-ci-ov-a", "hnx-ci-ov-b"])  # no slot free
    main = _IdleForge(_idle(3))
    other = _OtherForge(2)
    f = feeder.Feeder(main, FakeHost(status), _args(extras=[(other, ["ov"], "ov")], idle_ttl=0))
    f.round()
    assert sorted(main.deleted) == [0, 1]  # one for one with the queued jobs it starves


def test_nothing_is_released_while_a_slot_is_free_or_nothing_waits():
    main = _IdleForge(_idle(3))
    feeder.Feeder(
        main,
        FakeHost(_status(["waiting", "running"])),
        _args(extras=[(_OtherForge(2), ["ov"], "ov")], idle_ttl=0),
    ).round()
    assert main.deleted == []
    main2 = _IdleForge(_idle(3))
    feeder.Feeder(
        main2,
        FakeHost(_status(["running"] * 3)),
        _args(extras=[(_OtherForge(0), ["ov"], "ov")], idle_ttl=0),
    ).round()
    assert main2.deleted == []


def test_runners_idle_past_the_ttl_are_released_keeping_the_buffer():
    now = [0.0]
    main = _IdleForge(_idle(4))
    f = feeder.Feeder(
        main,
        FakeHost(_status(["running"] * 4)),
        _args(idle_ttl=100.0, reap_every=2),
        clock=lambda: now[0],
    )
    f.round()  # round 1: nothing yet
    f.round()  # round 2 (the reclaim round): first sight, not old
    assert main.deleted == []
    now[0] = 150.0
    f.rounds = 3
    f.round()  # round 4: the oldest go, the buffer (1) stays
    assert sorted(main.deleted) == [0, 1, 2]
