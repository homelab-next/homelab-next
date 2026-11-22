# SPDX-License-Identifier: Apache-2.0
"""The handoff of module cti-pipeline: after a job's steps all succeed, hnx-cti-run (as the lane's
user) carries each staged item to the lane's own handoff directory, where the publishing module's
group reads it.

* the wrapper: new items are copied whole (built beside, renamed in; 0640/0750 whatever the unit's
  umask), an unchanged item is left alone, a changed one under a handed-off name is a conflict
  (never overwritten), links, hard links, devices and a missing sidecar refuse the item, non-item
  entries are skipped, pruning removes only what the lane dropped (and only what this wrapper made),
  a failed step hands nothing off and a conflict fails the job;
* the role: one spec per instance naming its own lane's source and destination (the lanes never
  share a path or a group), the drop-in lets the unit write only its lane's handoff directory, and
  the directories and groups are the ones the publishing module's read needs and nothing wider.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from tests.modules.test_cti_pipeline_scripts import (  # noqa: F401
    ROOT,
    _clock,
    _creds,
    _main,
    _run_file,
    _spec,
    run,
    state,
)
from tests.modules.test_cti_pipeline_units import LANES_SITE, ROLE, render, role_vars

NOW = 1_795_086_000.0


@pytest.fixture(scope="module")
def site():
    ctx = role_vars(LANES_SITE)
    return ctx, {i["instance"]: i for i in ctx["cti_pipeline_instances"]}


def _item(lane_root: Path, kind: str, name: str, files: dict | None = None, sidecar=True) -> Path:
    d = lane_root / "publishable" / kind / name
    d.mkdir(parents=True)
    for rel, data in (files or {"index.html": "<p>x</p>"}).items():
        (d / rel).parent.mkdir(parents=True, exist_ok=True)
        (d / rel).write_text(data)
    if sidecar:
        (d / "sidecar.json").write_text(
            json.dumps({"tlp": "clear", "producer": "p", "sha256s": {}})
        )
    return d


def _with_handoff(tmp_path, lane="shadow", keep=2):
    spec_path, body = _spec(tmp_path, lane)
    dest = tmp_path / "var" / "lib" / "handoff" / "intel" / lane
    dest.mkdir(parents=True)
    os.chmod(dest, 0o700)  # the group read is the role's (dirs.yml); the wrapper test needs none
    body["handoff"] = {
        "source": body["lane_root"] + "/publishable",
        "dest": str(dest),
        "keep": keep,
    }
    body["steps"] = [["{python}", "-c", "pass"]]
    spec_path.write_text(json.dumps(body))
    root = Path(body["lane_root"])
    (root / "publishable").mkdir()
    return spec_path, body, root, dest


def _hand(body, now=NOW):
    return run.handoff(body, now)


# ---------------------------------------------------------------------------------- the wrapper


def test_handed_off_dirs_are_the_lane_out_group_at_0750_with_no_setgid_bit(tmp_path):
    _p, body, root, dest = _with_handoff(tmp_path)
    others = [g for g in os.getgroups() if g != os.getgid()]
    out_gid = others[0] if others else os.getgid()  # a group the test user may chown to
    os.chown(dest, -1, out_gid)
    _item(root, "site", "b1", {"index.html": "<p>x</p>", "assets/a.css": "p{}"})
    old = os.umask(0o077)
    try:
        _hand(body)
    finally:
        os.umask(old)
    got = dest / "site" / "b1"
    for d in (dest / "site", got, got / "assets"):
        st = d.stat()
        assert st.st_gid == out_gid
        # no setgid: the unit's RestrictSUIDSGID forbids setting it
        assert oct(st.st_mode & 0o7777) == "0o750"
    for f in (got / "index.html", got / "assets" / "a.css", got / "sidecar.json"):
        assert f.stat().st_gid == out_gid and oct(f.stat().st_mode & 0o777) == "0o640"


def test_handoff_survives_a_sandbox_that_refuses_any_setgid_chmod(tmp_path, monkeypatch):
    """The job unit runs with RestrictSUIDSGID=yes: a chmod that sets S_ISGID fails with EPERM.
    The handoff must not ask for it, and must still hand off every entry with its group."""
    import errno
    import stat as stat_mod

    real_chmod = os.chmod

    def sandboxed_chmod(path, mode, *a, **kw):
        if mode & stat_mod.S_ISGID:
            raise PermissionError(errno.EPERM, "setgid refused by RestrictSUIDSGID", str(path))
        return real_chmod(path, mode, *a, **kw)

    _p, body, root, dest = _with_handoff(tmp_path)
    _item(root, "site", "b1", {"index.html": "<p>x</p>", "assets/a.css": "p{}"})
    monkeypatch.setattr(run.os, "chmod", sandboxed_chmod)
    counts = _hand(body)
    assert counts["copied"] == 1 and counts["refused"] == 0
    got = dest / "site" / "b1"
    for d in (dest / "site", got, got / "assets"):
        assert oct(d.stat().st_mode & 0o7777) == "0o750"
    assert (got / "assets" / "a.css").read_text() == "p{}"


def test_new_items_are_copied_whole_with_group_readable_modes_whatever_the_umask(tmp_path):
    _p, body, root, dest = _with_handoff(tmp_path)
    _item(root, "site", "b1", {"index.html": "<p>x</p>", "assets/a.css": "p{}"})
    _item(root, "podcast", "e1", {"metadata.json": "{}"})
    old = os.umask(0o077)  # the unit's UMask
    try:
        counts = _hand(body)
    finally:
        os.umask(old)
    assert counts == {
        "copied": 2,
        "unchanged": 0,
        "conflicts": 0,
        "refused": 0,
        "skipped": 0,
        "pruned": 0,
    }
    got = dest / "site" / "b1"
    assert (got / "index.html").read_text() == "<p>x</p>" and (got / "assets" / "a.css").exists()
    assert (
        got / "sidecar.json"
    ).exists()  # the publishing module judges it; it is carried, not dropped
    assert oct((got / "index.html").stat().st_mode & 0o777) == "0o640"
    assert oct((got / "assets").stat().st_mode & 0o777) == "0o750"
    assert oct(got.stat().st_mode & 0o777) == "0o750"
    assert oct((dest / "site").stat().st_mode & 0o777) == "0o750"
    assert not list(dest.rglob(".tmp-*"))  # built beside and renamed: nothing half-built left


def test_a_second_handoff_leaves_an_unchanged_item_alone(tmp_path):
    _p, body, root, dest = _with_handoff(tmp_path)
    _item(root, "site", "b1")
    _hand(body)
    before = (dest / "site" / "b1").stat().st_mtime_ns
    counts = _hand(body)
    assert counts["unchanged"] == 1 and counts["copied"] == 0
    assert (dest / "site" / "b1").stat().st_mtime_ns == before


def test_a_changed_item_under_a_handed_off_name_is_a_conflict_and_is_never_overwritten(tmp_path):
    _p, body, root, dest = _with_handoff(tmp_path)
    src = _item(root, "site", "b1")
    _hand(body)
    (src / "index.html").write_text("<p>changed</p>")
    assert _hand(body)["conflicts"] == 1
    assert (dest / "site" / "b1" / "index.html").read_text() == "<p>x</p>"
    (src / "extra.txt").write_text("more")  # an added file is a change too
    assert _hand(body)["conflicts"] == 1


def test_what_cannot_be_judged_is_refused_and_what_is_not_an_item_is_skipped(tmp_path):
    _p, body, root, dest = _with_handoff(tmp_path)
    _item(root, "site", "nosidecar", sidecar=False)
    linked = _item(root, "site", "withlink")
    (linked / "evil").symlink_to("/etc/passwd")
    hard = _item(root, "site", "hard")
    os.link(hard / "index.html", root / "elsewhere")
    (root / "publishable" / "site" / "latest").symlink_to(linked)  # a "latest" link the app keeps
    (root / "publishable" / "site" / "stray.txt").write_text("x")
    (root / "publishable" / "site" / ".hidden").mkdir()
    _item(root, "site", "good")
    counts = _hand(body)
    assert counts["copied"] == 1 and counts["refused"] == 3 and counts["skipped"] == 2
    assert sorted(p.name for p in (dest / "site").iterdir()) == ["good"]


def test_a_kind_directory_that_is_a_link_is_skipped_and_a_destination_link_is_an_error(tmp_path):
    _p, body, root, dest = _with_handoff(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (root / "publishable" / "podcast").symlink_to(elsewhere)
    assert _hand(body)["skipped"] == 1
    (dest / "site").symlink_to(elsewhere)
    _item(root, "site", "b1")
    with pytest.raises(run.HandoffError):
        _hand(body)
    assert not list(elsewhere.iterdir())  # nothing was written through the link


def test_an_item_name_outside_the_contract_is_skipped(tmp_path):
    _p, body, root, dest = _with_handoff(tmp_path)
    _item(root, "site", "-bad")
    _item(root, "site", "bad name")
    assert _hand(body)["copied"] == 0
    assert not list((dest / "site").iterdir())


def test_prune_removes_only_what_the_lane_dropped_beyond_keep_and_older_than_an_hour(tmp_path):
    _p, body, root, dest = _with_handoff(tmp_path, keep=1)
    for n in range(4):
        _item(root, "site", f"b{n}")
    _hand(body)
    for n in range(4):  # all old
        d = dest / "site" / f"b{n}"
        os.utime(d, (NOW - 10_000 - n * 100, NOW - 10_000 - n * 100))
    # the lane still stages b0 and b3; it dropped b1 and b2
    import shutil

    for n in (1, 2):
        shutil.rmtree(root / "publishable" / "site" / f"b{n}")
    counts = _hand(body)
    assert counts["pruned"] == 1  # of the two dropped, the newest (b1) stays (keep 1); b2 goes
    assert sorted(p.name for p in (dest / "site").iterdir()) == ["b0", "b1", "b3"]


def test_nothing_younger_than_an_hour_is_pruned_and_a_current_item_never_is(tmp_path):
    _p, body, root, dest = _with_handoff(tmp_path, keep=1)
    for n in range(3):
        _item(root, "site", f"b{n}")
    _hand(body)
    import shutil

    for n in range(3):
        shutil.rmtree(root / "publishable" / "site" / f"b{n}")
    just_made = (
        (dest / "site" / "b0").stat().st_mtime
    )  # the filesystem's own clock, not the wall clock
    assert _hand(body, now=just_made + 10)["pruned"] == 0  # just made: younger than an hour
    assert len(list((dest / "site").iterdir())) == 3
    _item(root, "site", "b0")  # staged again: current, however old
    for p in (dest / "site").iterdir():
        os.utime(p, (NOW - 99_999, NOW - 99_999))
    _hand(body)
    assert (dest / "site" / "b0").exists()


def test_stale_half_built_directories_go_after_a_day_and_nothing_else_odd_is_touched(tmp_path):
    _p, body, root, dest = _with_handoff(tmp_path)
    _item(root, "site", "b1")
    _hand(body)
    kind = dest / "site"
    stale, fresh, other = kind / (".tmp-" + "a" * 12), kind / (".tmp-" + "b" * 12), kind / ".keepme"
    for d in (stale, fresh, other):
        d.mkdir()
    os.utime(stale, (NOW - 200_000, NOW - 200_000))
    os.utime(other, (NOW - 200_000, NOW - 200_000))
    os.utime(fresh, (NOW - 10, NOW - 10))
    victim = tmp_path / "victim"
    victim.mkdir()
    (victim / "precious").write_text("x")
    link = kind / "linked-old"
    link.symlink_to(victim)
    _hand(body)
    assert not stale.exists() and fresh.exists() and other.exists()
    assert (
        link.is_symlink() and (victim / "precious").exists()
    )  # a link is never followed or removed


def test_a_job_hands_off_only_after_every_step_succeeded(tmp_path, monkeypatch):
    spec_path, body, root, dest = _with_handoff(tmp_path, lane="real")
    _item(root, "site", "b1")
    body["steps"] = [["{python}", "-c", "pass"], ["{python}", "-c", "raise SystemExit(3)"]]
    spec_path.write_text(json.dumps(body))
    _run_file(body)
    assert _main(spec_path, "fresh-real", _creds(tmp_path), monkeypatch) == 1
    assert not (dest / "site").exists()  # a failed job delivered nothing
    body["steps"] = [["{python}", "-c", "pass"]]
    spec_path.write_text(json.dumps(body))
    _run_file(body, dispatch="1" * 32)
    assert _main(spec_path, "fresh-real", _creds(tmp_path), monkeypatch) == 0
    rec = json.loads(Path(body["runs_dir"], "fresh.json").read_text())
    assert rec["ok"] and rec["handoff"]["copied"] == 1
    assert (dest / "site" / "b1" / "sidecar.json").exists()


def test_a_conflict_does_not_fail_the_job_but_is_recorded_and_fails_health_until_cleared(
    tmp_path, monkeypatch, capsys
):
    spec_path, body, root, dest = _with_handoff(tmp_path, lane="real")
    src = _item(root, "site", "b1")
    _item(root, "site", "nosidecar", sidecar=False)
    _hand(body)
    (src / "index.html").write_text("MARKER-CONTENT")
    _run_file(body)
    assert (
        _main(spec_path, "fresh-real", _creds(tmp_path), monkeypatch) == 0
    )  # the job's work is done
    rec = json.loads(Path(body["runs_dir"], "fresh.json").read_text())
    assert rec["ok"] is True and rec["handoff"]["conflicts"] == 1
    assert rec["handoff_conflicts"] == ["b1"] and rec["handoff_refused"] == ["nosidecar"]
    out = capsys.readouterr().out
    assert (
        "handoff" in out and "MARKER-CONTENT" not in out and "b1" not in out
    )  # counters only in the log
    # ... but the health judgement fails while the last run reports any, naming the ids
    verdict = state.handoff_health(body["runs_dir"])
    assert verdict["ok"] is False
    assert verdict["jobs"] == {
        "fresh": {"handoff_conflicts": ["b1"], "handoff_refused": ["nosidecar"]}
    }
    assert state.main(["handoff-health", body["runs_dir"]]) == 1
    # the clear step: remove the stale handed-off item and the unusable one; the next run reports none
    import shutil

    shutil.rmtree(dest / "site" / "b1")
    shutil.rmtree(root / "publishable" / "site" / "nosidecar")
    _run_file(body, dispatch="2" * 32)
    assert _main(spec_path, "fresh-real", _creds(tmp_path), monkeypatch) == 0
    assert state.handoff_health(body["runs_dir"])["ok"] is True
    assert state.main(["handoff-health", body["runs_dir"]]) == 0


def test_handoff_health_is_ok_with_no_records_and_ignores_unreadable_ones(tmp_path):
    assert state.handoff_health(str(tmp_path / "absent"))["ok"] is True
    (tmp_path / "bad.json").write_text("{not json")
    (tmp_path / "list.json").write_text("[]")
    (tmp_path / "fine.json").write_text(json.dumps({"ok": True, "handoff_conflicts": []}))
    assert state.handoff_health(str(tmp_path))["ok"] is True


def test_a_spec_without_a_handoff_block_hands_nothing_off(tmp_path):
    _p, body, root, _dest = _with_handoff(tmp_path)
    body.pop("handoff")
    _item(root, "site", "b1")
    assert run.handoff(body) is None


@pytest.mark.parametrize(
    "mutate",
    [
        lambda h, root: h.update(source="relative/x"),
        lambda h, root: h.update(dest="/var/x"),  # too shallow
        lambda h, root: h.update(dest=root + "/inside/deep/er"),  # nested in the lane root
        lambda h, root: h.update(dest=os.path.dirname(root)),  # above it
        lambda h, root: h.update(source=root + "/publishable/../x"),
        lambda h, root: h.update(source=os.path.dirname(root) + "/other/publishable"),
        lambda h, root: h.update(keep=0),
        lambda h, root: h.update(keep=True),
        lambda h, root: h.update(extra=1),
        lambda h, root: h.pop("keep"),
    ],
)
def test_a_malformed_handoff_block_is_refused_before_any_step(tmp_path, mutate):
    _p, body, _root, _dest = _with_handoff(tmp_path)
    mutate(body["handoff"], body["lane_root"])
    with pytest.raises(run.Refused):
        run.handoff_guard(body)


def test_a_well_formed_handoff_block_is_accepted(tmp_path):
    _p, body, _root, _dest = _with_handoff(tmp_path)
    run.handoff_guard(body)


# ------------------------------------------------------------------------------------ the role


def test_each_lane_hands_off_to_its_own_directory_and_the_lanes_never_share_one(site):
    ctx, inst = site
    shadow = json.loads(render("job-spec.json.j2", ctx, inst["fresh-shadow"]))
    real = json.loads(render("job-spec.json.j2", ctx, inst["fresh-real"]))
    assert shadow["handoff"] == {
        "source": "/var/lib/hnx-modules/intel/shadow/publishable",
        "dest": "/var/lib/hnx-handoff/intel/shadow",
        "keep": 20,
    }
    assert real["handoff"]["dest"] == "/var/lib/hnx-handoff/intel/real"
    assert "/intel/real" not in json.dumps(shadow)
    assert ctx["cti_pipeline_handoff_group"] == {
        "real": "hnx-intel-out-real",
        "shadow": "hnx-intel-out-shadow",
    }
    # what the role renders, the wrapper accepts
    for spec in (shadow, real):
        run.handoff_guard(spec)


def test_the_dropin_lets_a_unit_write_only_its_own_lanes_handoff_directory(site):
    ctx, inst = site
    shadow = render("job-lane.conf.j2", ctx, inst["fresh-shadow"])
    rw = [x for x in shadow.splitlines() if x.startswith("ReadWritePaths=")]
    assert rw == [
        "ReadWritePaths=/var/lib/hnx-modules/intel/shadow",
        "ReadWritePaths=/var/lib/hnx-handoff/intel/shadow",
    ]
    real = render("job-lane.conf.j2", ctx, inst["fresh-real"])
    assert "handoff/intel/shadow" not in real


def test_a_site_may_turn_the_handoff_off(site):
    ctx, inst = site
    off = {**ctx, "cti_pipeline_handoff_enabled": False}
    assert "handoff" not in json.loads(render("job-spec.json.j2", off, inst["fresh-shadow"]))
    assert "hnx-handoff" not in render("job-lane.conf.j2", off, inst["fresh-shadow"])


def _tasks():
    from homelabnext.modules import loader as ld

    return {t["name"]: t for t in ld.load_yaml(ROLE / "tasks" / "dirs.yml")}


def test_the_handoff_directories_are_traversable_not_listable_and_each_lanes_is_its_users(site):
    tasks = _tasks()
    shared = tasks["Create the handoff directories (traversable by all, listable by none)"]
    modes = {i["path"]: i["mode"] for i in shared["loop"]}
    assert sorted(modes.values()) == ["0711", "0755"]
    assert shared["ansible.builtin.file"]["owner"] == "{{ cti_pipeline_owner }}"  # root's
    lane = tasks[
        "Create each lane's handoff directory (the lane user's, read by that lane's group only; new entries inherit the group)"
    ]["ansible.builtin.file"]
    assert lane["mode"] == "2750"  # setgid: entries inherit the lane's read group; others: nothing
    assert "cti_pipeline_lane_user[item]" in lane["owner"]
    assert "cti_pipeline_handoff_group[item]" in lane["group"]
    grp = tasks[
        "Create each lane's handoff read group (the publishing module's user joins the one it reads)"
    ]
    assert grp["ansible.builtin.group"]["system"] is True
    assert "cti_pipeline_handoff_enabled" in grp["when"]


def test_without_account_management_the_handoff_groups_must_already_exist():
    tasks = _tasks()
    t = tasks[
        "Without account management, each lane's handoff group must already exist (the directories chown to it)"
    ]
    assert t["ansible.builtin.getent"]["database"] == "group"
    assert (
        "not (cti_pipeline_manage_accounts | bool)" in t["when"]
        and "cti_pipeline_handoff_enabled" in t["when"]
    )
    names = list(tasks)
    assert names.index(
        next(n for n in names if n.startswith("Without account management"))
    ) < names.index(next(n for n in names if n.startswith("Create each lane's handoff directory")))


def test_health_judges_the_handoff_per_active_lane_and_names_the_clear_step():
    from homelabnext.modules import loader as ld

    tasks = {t["name"]: t for t in ld.load_yaml(ROLE / "tasks" / "health.yml")[0]["block"]}
    judge = next(t for n, t in tasks.items() if n.startswith("Judge each active lane's handoff"))
    assert "handoff-health" in judge["ansible.builtin.command"]["argv"]
    assert judge["failed_when"] is False
    check = tasks["No handoff conflict or refusal is outstanding"]
    assert "Remove the" in check["ansible.builtin.assert"]["fail_msg"]


# ---------------------------------------------------------------- the unit holds its lane's out group


def test_each_lanes_unit_joins_only_its_own_out_group(site):
    ctx, inst = site
    real = render("job-lane.conf.j2", ctx, inst["fresh-real"]).splitlines()
    shadow = render("job-lane.conf.j2", ctx, inst["fresh-shadow"]).splitlines()
    assert "SupplementaryGroups=hnx-intel-out-real" in real
    assert "SupplementaryGroups=hnx-intel-out-shadow" not in real
    assert "SupplementaryGroups=hnx-intel-out-shadow" in shadow
    assert "SupplementaryGroups=hnx-intel-out-real" not in shadow
    off = {**ctx, "cti_pipeline_handoff_enabled": False}
    assert "out-" not in render("job-lane.conf.j2", off, inst["fresh-shadow"])


def test_the_group_exists_before_the_dropin_that_names_it():
    main = (ROLE / "tasks" / "main.yml").read_text()
    assert main.index("dirs.yml") < main.index("config.yml")
    assert "cti_pipeline_handoff_group[item]" in (ROLE / "tasks" / "dirs.yml").read_text()


def test_handoff_dirs_get_their_mode_at_creation_never_via_a_directory_chmod(tmp_path, monkeypatch):
    """No directory is ever chmod'd: the 0750 is given at creation (umask cleared for the call), so a
    narrow or a wide process umask both yield exactly 0750."""
    real_chmod = os.chmod

    def no_dir_chmod(path, mode, *a, **kw):
        assert not os.path.isdir(path), f"a directory chmod: {path}"
        return real_chmod(path, mode, *a, **kw)

    for umask in (0o077, 0o000):
        sub = tmp_path / f"u{umask:o}"
        sub.mkdir()
        _p, body, root, dest = _with_handoff(sub)
        _item(root, "site", "b1", {"index.html": "<p>x</p>", "assets/deep/a.css": "p{}"})
        old = os.umask(umask)
        try:
            with monkeypatch.context() as m:
                m.setattr(run.os, "chmod", no_dir_chmod)
                _hand(body)
        finally:
            os.umask(old)
        got = dest / "site" / "b1"
        for d in (dest / "site", got, got / "assets", got / "assets" / "deep"):
            assert oct(d.stat().st_mode & 0o7777) == "0o750"


def test_an_existing_handoff_dir_with_another_mode_fails_loudly_and_is_not_rechmodded(tmp_path):
    _p, body, root, dest = _with_handoff(tmp_path)
    _item(root, "site", "b1", {"index.html": "<p>x</p>"})
    (dest / "site").mkdir(mode=0o700)
    with pytest.raises(run.HandoffError):
        _hand(body)
    assert oct((dest / "site").stat().st_mode & 0o7777) == "0o700"
