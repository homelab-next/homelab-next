# SPDX-License-Identifier: Apache-2.0
"""Producer lanes (``lane_sources``): a lane's output directory is read as a publishable area but is
always stage-only (no network, no deploy, whatever the run's mode), staged and snapshotted apart
from every other lane and the publishable area, and its items say which lane they came from."""

from __future__ import annotations

import dataclasses
import json
import os

import pytest

from homelabnext.publishing import config as cf
from homelabnext.publishing import run as rn
from tests.publishing.helpers import episode, make_item
from tests.publishing.test_publishing_pages_stage_run import Recorder, setup_lab


def _with_lanes(base, lanes):
    doc = json.loads((base / "config.json").read_text())
    (base / "config.json").write_text(json.dumps({**doc, "lane_sources": lanes}))
    return cf.load(base / "config.json")


def _lab(tmp_path, mode="stage", lanes=("shadow",)):
    base, pub, _cfg = setup_lab(tmp_path, mode)
    dirs = {name: base / "handoff" / name for name in lanes}
    cfg = _with_lanes(base, [{"lane": n, "dir": str(d)} for n, d in dirs.items()])
    return base, pub, dirs, cfg


def test_a_lane_item_is_gated_and_staged_apart_with_its_lane_named(tmp_path):
    base, pub, dirs, cfg = _lab(tmp_path)
    make_item(dirs["shadow"], "site", "s1", {"index.html": "<p>shadow</p>"})
    make_item(pub, "site", "p1", {"index.html": "<p>primary</p>"})
    rep = rn.run(cfg)
    assert rep.code == 0
    by_item = {d["item"]: d for d in rep.done}
    assert by_item["shadow:s1"]["lane"] == "shadow" and "lane" not in by_item["p1"]
    lane_plans = list((base / "staging" / "lane-shadow").glob("site/s1-*/plan.json"))
    assert len(lane_plans) == 1 and json.loads(lane_plans[0].read_text())["lane"] == "shadow"
    plain = list((base / "staging").glob("site/p1-*/plan.json"))
    assert len(plain) == 1 and "lane" not in json.loads(plain[0].read_text())
    # nothing of the lane under the primary staging kinds, nothing of the primary under the lane
    assert not list((base / "staging").glob("site/s1-*"))
    assert not list((base / "staging" / "lane-shadow").glob("site/p1-*"))


@pytest.mark.parametrize("mode", ["dry-run", "live"])
def test_a_lane_item_is_never_deployed_or_uploaded_even_in_live(tmp_path, mode):
    base, _pub, dirs, cfg = _lab(tmp_path, mode, lanes=("shadow",))
    make_item(dirs["shadow"], "site", "s1", {"index.html": "<p>shadow</p>"})
    episode(dirs["shadow"])
    rec = Recorder()

    class Runner:
        def __init__(self):
            self.calls = []

        def __call__(self, *a, **k):
            self.calls.append(a)
            raise AssertionError("no deploy expected")

    runner = Runner()
    rep = rn.run(cfg, transport=rec, runner=runner)
    assert rec.calls == [] and runner.calls == []
    assert {d["result"] for d in rep.done} == {"staged"}
    assert not (base / "state" / "published-manifest.jsonl").exists()


def test_the_lanes_do_not_mix_and_a_same_id_in_two_lanes_stays_two_items(tmp_path):
    base, _pub, dirs, cfg = _lab(tmp_path, lanes=("real", "shadow"))
    make_item(dirs["real"], "site", "same", {"index.html": "<p>real</p>"})
    make_item(dirs["shadow"], "site", "same", {"index.html": "<p>shadow</p>"})
    rep = rn.run(cfg)
    assert rep.code == 0
    assert sorted(d["item"] for d in rep.done) == ["real:same", "shadow:same"]
    for lane, word in (("real", "real"), ("shadow", "shadow")):
        (staged,) = (base / "staging" / f"lane-{lane}").glob("site/same-*")
        assert word in (staged / "index.html").read_text()
    assert (base / "state" / "snapshots-real").is_dir()
    assert (base / "state" / "snapshots-shadow").is_dir()
    assert not (base / "state" / "snapshots").exists()


def test_a_blocked_lane_item_is_named_with_its_lane_and_in_the_gate_log(tmp_path):
    base, _pub, dirs, cfg = _lab(tmp_path)
    make_item(dirs["shadow"], "site", "s1", {"index.html": "<p>TLP:AMBER</p>"})
    rep = rn.run(cfg)
    assert rep.code == 1 and rep.blocked == ["shadow:s1"]
    rows = [json.loads(x) for x in (base / "state" / "gate.jsonl").read_text().splitlines()]
    assert rows[-1]["lane"] == "shadow" and rows[-1]["ok"] is False
    assert not list((base / "staging" / "lane-shadow").glob("site/*"))


def test_a_lane_item_that_cannot_be_read_blocks_it_never_stages(tmp_path):
    _base, pub, dirs, cfg = _lab(tmp_path)
    link = dirs["shadow"] / "site" / "evil"
    link.parent.mkdir(parents=True)
    link.symlink_to(pub)
    rep = rn.run(cfg)
    assert rep.blocked == ["shadow:evil"]


def test_a_missing_lane_directory_is_an_empty_lane(tmp_path):
    _base, _pub, _dirs, cfg = _lab(tmp_path)
    assert rn.run(cfg).done == []


@pytest.mark.parametrize(
    "lanes, why",
    [
        ("x", "list"),
        ([{"lane": "shadow", "dir": "/srv/a/b/c", "live": True}], "stage-only"),
        ([{"lane": "Bad Lane", "dir": "/srv/a/b/c"}], "slug"),
        ([{"lane": "a", "dir": "relative/x"}], "absolute"),
        ([{"lane": "a", "dir": "/srv/a/../c"}], "absolute"),
        ([{"lane": "a", "dir": "/srv/a/b"}, {"lane": "a", "dir": "/srv/a/c"}], "twice"),
        ([{"lane": "a", "dir": "/srv/a/b"}, {"lane": "b", "dir": "/srv/a/b"}], "own"),
    ],
)
def test_a_malformed_lane_source_is_refused_at_load(tmp_path, lanes, why):
    base, _pub, _cfg = setup_lab(tmp_path, "stage")
    doc = json.loads((base / "config.json").read_text())
    (base / "config.json").write_text(json.dumps({**doc, "lane_sources": lanes}))
    with pytest.raises(cf.ConfigError, match=why):
        cf.load(base / "config.json")


def test_a_lane_dir_may_not_be_the_publishable_dir(tmp_path):
    base, pub, _cfg = setup_lab(tmp_path, "stage")
    doc = json.loads((base / "config.json").read_text())
    (base / "config.json").write_text(
        json.dumps({**doc, "lane_sources": [{"lane": "a", "dir": str(pub)}]})
    )
    with pytest.raises(cf.ConfigError, match="own"):
        cf.load(base / "config.json")


def test_lane_staging_is_pruned_apart_from_the_primary(tmp_path):
    base, _pub, dirs, cfg = _lab(tmp_path)
    cfg = dataclasses.replace(cfg, staging_keep=1, staging_min_age_s=60)
    now = 5_000_000.0
    lane_staging = base / "staging" / "lane-shadow" / "podcast"
    primary_staging = base / "staging" / "podcast"
    for root in (lane_staging, primary_staging):
        for n in range(3):
            d = root / f"old{n}-{'a' * 12}"
            d.mkdir(parents=True)
            os.utime(d, (now - 900_000 - n, now - 900_000 - n))
    episode(dirs["shadow"], "e1")
    rn.run(cfg, clock=lambda: now)
    left = {p.name.split("-")[0] for p in lane_staging.iterdir()}
    assert left == {"e1"}  # the old ones went; the newest is kept
    assert len(list(primary_staging.iterdir())) == 1  # the primary is pruned by its own run


# ---- review fixes: unreadable lane, FIFO swap, link-y lane directories


def test_an_unreadable_lane_directory_is_reported_failed_never_silent(tmp_path):
    base, _pub, dirs, cfg = _lab(tmp_path, lanes=("shadow", "other"))
    make_item(dirs["other"], "site", "o1", {"index.html": "<p>ok</p>"})
    make_item(dirs["shadow"], "site", "s1", {"index.html": "<p>x</p>"})
    os.chmod(dirs["shadow"], 0)
    try:
        if os.access(dirs["shadow"], os.R_OK):
            pytest.skip("running as a user that ignores directory modes")
        rep = rn.run(cfg)
    finally:
        os.chmod(dirs["shadow"], 0o700)
    assert rep.failed == ["shadow:unreadable"] and rep.code == 1
    assert [d["item"] for d in rep.done] == ["other:o1"]  # the other lane still ran
    rows = [json.loads(x) for x in (base / "state" / "gate.jsonl").read_text().splitlines()]
    assert any(r.get("lane") == "shadow" and "lane-unreadable" in r.get("failed", "") for r in rows)


def test_a_file_where_the_lane_directory_belongs_is_reported_too(tmp_path):
    _base, _pub, dirs, cfg = _lab(tmp_path)
    dirs["shadow"].parent.mkdir(parents=True)
    dirs["shadow"].write_text("not a directory")
    assert rn.run(cfg).failed == ["shadow:unreadable"]


def test_a_file_swapped_for_a_fifo_after_the_listing_is_refused_not_waited_on(tmp_path):
    import signal

    from homelabnext.publishing import gate as gt

    root = make_item(tmp_path, "site", "b1", {"index.html": "<p>x</p>"})
    item = gt.load_item(root, "site")
    (root / "index.html").unlink()
    os.mkfifo(root / "index.html", 0o600)  # a lane user swaps the regular file after the listing
    signal.signal(
        signal.SIGALRM, lambda *_: (_ for _ in ()).throw(AssertionError("blocked on the FIFO"))
    )
    signal.alarm(5)
    try:
        with pytest.raises(gt.GateError):
            gt.snapshot_item(root, "site", tmp_path / "snap")
        with pytest.raises(gt.GateError):
            gt._read_tree(root, item.files)
    finally:
        signal.alarm(0)


def test_a_fifo_as_the_sidecar_is_refused_not_waited_on(tmp_path):
    import signal

    from homelabnext.publishing import gate as gt

    root = make_item(tmp_path, "site", "b1", {"index.html": "<p>x</p>"})
    (root / "sidecar.json").unlink()
    os.mkfifo(root / "sidecar.json", 0o600)
    signal.signal(
        signal.SIGALRM, lambda *_: (_ for _ in ()).throw(AssertionError("blocked on the FIFO"))
    )
    signal.alarm(5)
    try:
        with pytest.raises(gt.GateError):
            gt.load_item(root, "site")
    finally:
        signal.alarm(0)


def test_a_kind_directory_swapped_for_a_link_is_refused_through_the_lane_anchor(tmp_path):
    from homelabnext.publishing import gate as gt

    lane = tmp_path / "lane"
    make_item(lane, "site", "b1", {"index.html": "<p>x</p>"})
    item = gt.load_item(lane / "site" / "b1", "site")
    elsewhere = tmp_path / "elsewhere"
    (lane / "site").rename(elsewhere)  # the lane user swaps its kind directory for a link
    (lane / "site").symlink_to(elsewhere)
    with pytest.raises(gt.GateError):
        gt._read_tree(lane / "site" / "b1", item.files, anchor=lane)


@pytest.mark.parametrize("target", ["publishable", "staging", "state", "creds"])
def test_a_lane_dir_that_is_or_links_to_another_directory_of_the_run_is_refused(tmp_path, target):
    base, pub, _cfg = setup_lab(tmp_path, "stage")
    real = {
        "publishable": pub,
        "staging": base / "staging",
        "state": base / "state",
        "creds": base / "creds",
    }[target]
    real.mkdir(parents=True, exist_ok=True)
    link = tmp_path / "linkdir"
    link.symlink_to(real)
    doc = json.loads((base / "config.json").read_text())
    for bad in (str(link), str(real) + "//", str(real / "inside")):
        (base / "config.json").write_text(
            json.dumps({**doc, "lane_sources": [{"lane": "a", "dir": bad}]})
        )
        with pytest.raises(cf.ConfigError, match="own"):
            cf.load(base / "config.json")


def test_run_refuses_a_lane_item_whose_kind_dir_is_swapped_for_a_link_after_the_check(
    tmp_path, monkeypatch
):
    """Through run(): the lane user swaps its kind directory for a link between the item check and the
    read.  Only the descriptor chain from the lane directory (anchor) refuses it; with the
    final-component O_NOFOLLOW alone the files are read through the link and the item passes."""
    from homelabnext.publishing import gate as gt

    base, _pub, dirs, cfg = _lab(tmp_path)
    make_item(dirs["shadow"], "site", "s1", {"index.html": "<p>shadow</p>"})
    real_load = gt.load_item
    elsewhere = tmp_path / "elsewhere"

    def load_then_swap(root, kind):
        item = real_load(root, kind)
        if root.parent.parent == dirs["shadow"] and not elsewhere.exists():
            (dirs["shadow"] / "site").rename(elsewhere)  # same bytes, now behind a link
            (dirs["shadow"] / "site").symlink_to(elsewhere)
        return item

    monkeypatch.setattr(gt, "load_item", load_then_swap)
    rep = rn.run(cfg)
    assert rep.blocked == ["shadow:s1"] and rep.done == []
    assert not list((base / "staging" / "lane-shadow").glob("site/*"))
