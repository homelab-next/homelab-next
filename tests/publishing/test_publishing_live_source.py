# SPDX-License-Identifier: Apache-2.0
"""The live source: ONE directory (a producer lane's handoff) that replaces the publishable area as
what is deployed; the shadow lane can never be it and every lane source stays stage-only."""

from __future__ import annotations

import json
import os

import pytest

from homelabnext.publishing import config as cf
from homelabnext.publishing import run as rn
from tests.publishing.helpers import episode, make_item
from tests.publishing.test_publishing_pages_stage_run import FakeBucket, Recorder, Runner, setup_lab

CREDS = ("deny-list", "cloudflare-api-token", "r2-access-key-id", "r2-secret-access-key")


def _write(base, **extra):
    doc = json.loads((base / "config.json").read_text())
    (base / "config.json").write_text(json.dumps({**doc, **extra}))
    return base / "config.json"


def _lab(tmp_path, mode="live"):
    base, pub, _ = setup_lab(tmp_path, mode, creds=CREDS)
    real, shadow = base / "handoff" / "real", base / "handoff" / "shadow"
    cfg = cf.load(
        _write(
            base,
            live_source={"lane": "real", "dir": str(real)},
            lane_sources=[{"lane": "shadow", "dir": str(shadow)}],
        )
    )
    return base, pub, real, shadow, cfg


def test_the_live_source_is_what_deploys_and_a_shadow_lane_item_is_only_staged(tmp_path):
    base, pub, real, shadow, cfg = _lab(tmp_path)
    assert cfg.publishable_dir == real and cfg.live_source.lane == "real"
    make_item(real, "site", "r1", {"index.html": "<p>real</p>"})
    episode(real)
    make_item(shadow, "site", "s1", {"index.html": "<p>shadow</p>"})
    make_item(pub, "site", "old", {"index.html": "<p>unused default area</p>"})
    bucket, runner = FakeBucket(), Runner()
    rep = rn.run(cfg, transport=bucket, runner=runner)
    assert rep.code == 0
    by = {d["item"]: d["result"] for d in rep.done}
    assert by["r1"] == "deployed" and by["shadow:s1"] == "staged"
    assert "old" not in by  # exactly one live source: the default area is no longer read
    deploys = [c for c in runner.calls if c[0][-1] != "--version"]
    assert len(deploys) == 1  # the live item only; the shadow item never reached the runner
    assert list((base / "staging" / "lane-shadow").glob("site/s1-*/plan.json"))
    assert not list((base / "staging").glob("site/s1-*"))


def test_a_blocked_live_item_is_gated_and_never_pushed(tmp_path):
    _base, _pub, real, _shadow, cfg = _lab(tmp_path)
    make_item(real, "site", "r1", {"index.html": "<p>x</p>"}, tlp="amber")
    bucket, runner = FakeBucket(), Runner()
    rep = rn.run(cfg, transport=bucket, runner=runner)
    assert rep.blocked == ["r1"] and runner.calls == [] and bucket.calls == []


def test_an_unreadable_live_source_is_reported_not_silently_empty(tmp_path):
    base, _pub, real, _shadow, _cfg = _lab(tmp_path)
    real.parent.mkdir(parents=True, exist_ok=True)
    real.write_text("a file where the directory belongs")
    cfg = cf.load(base / "config.json")
    rep = rn.run(cfg, transport=FakeBucket(), runner=Runner())
    assert "live:unreadable" in rep.failed and rep.code != 0


def test_a_live_kind_directory_swapped_for_a_link_is_refused(tmp_path):
    _base, _pub, real, _shadow, cfg = _lab(tmp_path)
    make_item(real, "site", "r1", {"index.html": "<p>x</p>"})
    elsewhere = tmp_path / "elsewhere"
    (real / "site").rename(elsewhere)
    (real / "site").symlink_to(elsewhere)
    runner = Runner()
    rep = rn.run(cfg, transport=FakeBucket(), runner=runner)
    assert rep.blocked and not [c for c in runner.calls if c[0][-1] != "--version"]


def test_a_live_fifo_is_refused_not_waited_on(tmp_path):
    _base, _pub, real, _shadow, cfg = _lab(tmp_path)
    make_item(real, "site", "r1", {"index.html": "<p>x</p>"})
    f = real / "site" / "r1" / "index.html"
    f.unlink()
    os.mkfifo(f)
    runner = Runner()
    rep = rn.run(cfg, transport=FakeBucket(), runner=runner)
    assert rep.blocked == ["r1"] and not [c for c in runner.calls if c[0][-1] != "--version"]


def test_a_hard_linked_live_file_is_refused(tmp_path):
    _base, _pub, real, _shadow, cfg = _lab(tmp_path)
    make_item(real, "site", "r1", {"index.html": "<p>x</p>"})
    os.link(real / "site" / "r1" / "index.html", real.parent / "other-link")
    rep = rn.run(cfg, transport=FakeBucket(), runner=Runner())
    assert rep.blocked == ["r1"]


def test_live_snapshots_and_staging_are_apart_from_the_shadow_lane(tmp_path):
    base, _pub, real, shadow, cfg = _lab(tmp_path)
    make_item(real, "site", "same", {"index.html": "<p>real</p>"})
    make_item(shadow, "site", "same", {"index.html": "<p>shadow</p>"})
    rep = rn.run(cfg, transport=FakeBucket(), runner=Runner())
    assert sorted(d["item"] for d in rep.done) == ["same", "shadow:same"]
    assert (base / "state" / "snapshots").is_dir() and (
        base / "state" / "snapshots-shadow"
    ).is_dir()


@pytest.mark.parametrize(
    "live, why",
    [
        ("x", "live_source is"),
        ({"lane": "real"}, "live_source is"),
        ({"lane": "real", "dir": "/srv/a/b", "live": True}, "live_source is"),
        ({"lane": "Bad Lane", "dir": "/srv/a/b"}, "slug"),
        ({"lane": "shadow", "dir": "/srv/a/b"}, "shadow lane"),
        ({"lane": "pre-shadow", "dir": "/srv/a/b"}, "shadow lane"),
        ({"lane": "real", "dir": "relative/x"}, "absolute"),
        ({"lane": "real", "dir": "/srv/a/../c"}, "absolute"),
        ({"lane": "real", "dir": "/var/lib/hnx-handoff/cti/shadow"}, "shadow path"),
        ({"lane": "real", "dir": "/var/lib/hnx-handoff/cti/shadow/site"}, "shadow path"),
        ({"lane": "real", "dir": "/var/lib/hnx-handoff/cti-out-shadow"}, "shadow path"),
    ],
)
def test_a_malformed_or_shadow_live_source_is_refused_at_load(tmp_path, live, why):
    base, _pub, _cfg = setup_lab(tmp_path, "stage")
    path = _write(base, live_source=live)
    with pytest.raises(cf.ConfigError, match=why):
        cf.load(path)


def test_a_link_to_the_shadow_directory_is_refused_by_real_path(tmp_path):
    base, _pub, _cfg = setup_lab(tmp_path, "stage")
    shadow = base / "handoff" / "shadow"
    shadow.mkdir(parents=True)
    link = tmp_path / "innocent"
    link.symlink_to(shadow)
    for d in (str(link), str(link / "site")):
        with pytest.raises(cf.ConfigError, match="shadow path"):
            cf.load(_write(base, live_source={"lane": "real", "dir": d}))


@pytest.mark.parametrize("target", ["lane", "staging", "state", "creds"])
def test_the_live_dir_may_not_be_or_nest_with_another_directory_of_the_run(tmp_path, target):
    base, _pub, _cfg = setup_lab(tmp_path, "stage")
    (base / "handoff" / "other").mkdir(parents=True)
    real = {
        "lane": base / "handoff" / "other",
        "staging": base / "staging",
        "state": base / "state",
        "creds": base / "creds",
    }[target]
    real.mkdir(parents=True, exist_ok=True)
    link = tmp_path / "linkdir"
    link.symlink_to(real)
    lanes = [{"lane": "other", "dir": str(base / "handoff" / "other")}]
    for bad in (str(link), str(real) + "//", str(real / "inside")):
        with pytest.raises(cf.ConfigError, match="own"):
            cf.load(_write(base, live_source={"lane": "real", "dir": bad}, lane_sources=lanes))


def test_a_lane_source_may_not_be_the_live_dir(tmp_path):
    base, _pub, _cfg = setup_lab(tmp_path, "stage")
    real = str(base / "handoff" / "real")
    with pytest.raises(cf.ConfigError, match="own"):
        cf.load(
            _write(
                base,
                live_source={"lane": "real", "dir": real},
                lane_sources=[{"lane": "other", "dir": real}],
            )
        )


def test_no_live_source_is_the_old_behaviour(tmp_path):
    _base, pub, cfg = setup_lab(tmp_path, "stage")
    assert cfg.live_source is None and cfg.publishable_dir == pub


def test_stage_mode_with_a_live_source_makes_no_network_call(tmp_path):
    base, _pub, real, _shadow, _cfg = _lab(tmp_path)
    cfg = cf.load(_write(base, mode="stage"))
    make_item(real, "site", "r1", {"index.html": "<p>x</p>"})
    rec, runner = Recorder(), Runner()
    rep = rn.run(cfg, transport=rec, runner=runner)
    assert rec.calls == [] and runner.calls == [] and {d["result"] for d in rep.done} == {"staged"}
