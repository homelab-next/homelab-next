# SPDX-License-Identifier: Apache-2.0
"""The delta-review nits: an HTML tokeniser for markup, Hangul fillers and Armenian look-alikes, no
excusal for the item's own episode, and pruning of the staging area."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
from pathlib import Path

import pytest

from homelabnext.publishing import gate as gt
from homelabnext.publishing import normalise, r2, snapshots
from homelabnext.publishing import run as rn
from tests.publishing.helpers import FEED, FakeBucket, build_mp3, episode, make_item, policy
from tests.publishing.test_publishing_hardening import DENY2, verdict
from tests.publishing.test_publishing_pages_stage_run import setup_lab
from tests.publishing.test_publishing_round3 import cps, rules


# ----------------------------------------------------------------------------- html.parser
@pytest.mark.parametrize(
    "html",
    [
        'secret<span title="a>b">host</span>',
        "secret<span title='x>y'>host</span>",
        'sec<a href="?q=1>2" class="p">ret</a>host',
    ],
)
def test_a_quoted_greater_than_in_an_attribute_does_not_hide_a_name(tmp_path, html):
    assert "deny-list" in rules(verdict(tmp_path, {"index.html": f"<p>{html}</p>"})), html


def test_strip_markup_reads_attributes_comments_and_cdata_as_a_browser_does():
    assert normalise.strip_markup('secret<span title="a>b">host</span>') == "secrethost"
    assert normalise.strip_markup("sec<!-- a > b -->ret") == "secret"
    assert normalise.strip_markup("a<![CDATA[b]]>c") == "abc"
    assert (
        normalise.strip_markup("x &amp; y") == "x &amp; y"
    )  # entities are decoded by canon, not here
    assert normalise.strip_markup("<unclosed") is not None  # malformed input never raises


# ----------------------------------------------------------------------------- fillers and look-alikes
@pytest.mark.parametrize("filler", [0x115F, 0x1160, 0x3164, 0xFFA0, 0x17B4, 0x034F])
def test_invisible_filler_characters_are_stripped(tmp_path, filler):
    text = cps("secret", filler, "host")
    assert "deny-list" in rules(verdict(tmp_path, {"index.html": f"<p>{text}</p>"})), hex(filler)


@pytest.mark.parametrize(
    "name", [cps("secret", 0x0570, "ost"), cps("secret", 0x0570, 0x0585, "st")]
)
def test_armenian_look_alikes_are_folded(tmp_path, name):
    # "secret" + Armenian ho (+ o) + "st" reads as the denied word once folded
    assert "deny-list" in rules(verdict(tmp_path, {"index.html": f"<p>{name}</p>"}))


def test_the_armenian_ho_and_oh_fold_to_latin():
    assert normalise.canon(cps("secret", 0x0570, 0x0585, "st")) == "secrethost"
    assert normalise.canon(cps("secret", 0x0570, "ost")) == "secrethost"


# ----------------------------------------------------------------------------- own episode never excused
def test_a_legacy_exception_is_never_applied_to_the_item_being_published(tmp_path):
    # a denied word that appears ONLY in the episode's title (not in its key, guid or enclosure), and
    # the item's own key is listed as a "reviewed legacy" object with its own sha256, to excuse itself
    meta = json.dumps(
        {"period": "weekly", "date": "2026-01-05", "title": "zzdeniedzz", "description": "d"}
    )
    item = gt.load_item(
        make_item(
            tmp_path,
            "podcast",
            "ep",
            {"metadata.json": meta, "weekly_2026-01-05.mp3": build_mp3()},
        ),
        "podcast",
    )
    own_key = "episodes/weekly_2026-01-05.json"
    sha = hashlib.sha256(meta.encode()).hexdigest()
    strict = policy("zzdeniedzz\n")
    b = FakeBucket()
    b.objects[own_key] = (meta.encode(), {"x-amz-meta-sha256": sha})
    b.objects["episodes/weekly_2026-01-05.mp3"] = (
        (item.root / "weekly_2026-01-05.mp3").read_bytes(),
        {"x-amz-meta-sha256": item.sidecar["sha256s"]["weekly_2026-01-05.mp3"]},
    )
    client = r2.R2Client("https://store.example.test", "b", "id" * 4, "s" * 20, b)
    with pytest.raises(r2.FeedBlocked):
        r2.plan_episode(client, item, FEED, strict, {own_key: sha})
    del b.objects[own_key]  # (its text is still in the bucket: it would block the next feed too)
    # the same exception does excuse an OLDER object with that text (so the test can tell the two apart)
    old = json.dumps({"period": "daily", "date": "2025-12-01", "title": "zzdeniedzz"}).encode()
    b.objects["episodes/daily_2025-12-01.json"] = (old, {})
    b.objects["episodes/daily_2025-12-01.mp3"] = (build_mp3(), {})
    clean = gt.load_item(episode(tmp_path / "c", "c1", date="2026-02-02"), "podcast")
    plan = r2.plan_episode(
        client,
        clean,
        FEED,
        strict,
        {"episodes/daily_2025-12-01.json": hashlib.sha256(old).hexdigest()},
    )
    assert plan.excused == ("episodes/daily_2025-12-01.json",)


# ----------------------------------------------------------------------------- staging pruning
def _staged(base: Path, kind: str, name: str, age_s: float, now: float) -> Path:
    d = base / kind / f"{name}-{hashlib.sha256(name.encode()).hexdigest()[:12]}"
    d.mkdir(parents=True)
    (d / "plan.json").write_text("{}")
    os.utime(d, (now - age_s, now - age_s))
    return d


def test_staging_is_pruned_by_age_keeping_the_newest_and_the_young(tmp_path):
    now = 1_000_000.0
    root = tmp_path / "srv" / "lab" / "staging"
    items = [_staged(root, "site", f"b{n}", 200_000 + n * 1000, now) for n in range(5)]
    young = _staged(root, "site", "fresh", 100, now)
    pod = _staged(root, "podcast", "ep", 900_000, now)
    leftover = root / "site" / ".failed-0123456789ab"
    leftover.mkdir()
    os.utime(leftover, (now - 900_000, now - 900_000))
    gone = snapshots.prune(
        root, keep=2, min_age_s=172_800, protect_ids=set(), now=now, digest_len=12
    )
    left = {p.name for p in (root / "site").iterdir()}
    assert left == {
        items[0].name,
        young.name,
    }  # the newest two (fresh, b0); the rest are older than 2 days
    assert pod.exists()  # the only podcast item is within keep
    assert len(gone) == 5  # b1..b4 and the leftover


def test_staging_pruning_refuses_links_odd_names_and_the_wrong_digest_length(tmp_path):
    now = 1_000_000.0
    root = tmp_path / "srv" / "lab" / "staging"
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "precious").write_text("keep")
    (root / "site").mkdir(parents=True)
    (root / "site" / ("b-" + "0" * 12)).symlink_to(outside)
    odd = root / "site" / "operator-notes"
    odd.mkdir()
    os.utime(odd, (now - 9_999_999, now - 9_999_999))
    sixteen = _staged(
        tmp_path / "other", "site", "x", 9_999_999, now
    )  # a 12-hex name under a 16 pattern
    for n in range(3):
        _staged(root, "site", f"o{n}", 9_000_000 + n, now)
    snapshots.prune(root, keep=1, min_age_s=0, protect_ids=set(), now=now, digest_len=16)
    assert all(p.exists() for p in [odd, outside / "precious"])  # nothing matched a 16-hex name
    snapshots.prune(root, keep=1, min_age_s=0, protect_ids=set(), now=now, digest_len=12)
    assert odd.exists() and (outside / "precious").exists() and sixteen.exists()


def test_a_stage_run_prunes_old_staged_items_and_keeps_this_runs(tmp_path):
    _base, pub, cfg = setup_lab(tmp_path, "stage", deny=DENY2)
    cfg = dataclasses.replace(cfg, staging_keep=1, staging_min_age_s=60)
    now = 1_000_000.0
    for n in range(3):
        _staged(cfg.staging_dir, "site", f"old{n}", 500_000 + n, now)
    make_item(pub, "site", "b1", {"index.html": "<p>ok</p>"})
    rep = rn.run(cfg, clock=lambda: now)
    assert rep.code == 0
    left = {p.name for p in (cfg.staging_dir / "site").iterdir()}
    assert any(n.startswith("b1-") for n in left) and not any(n.startswith("old1") for n in left)


def test_the_staging_settings_are_read_from_the_config(tmp_path):
    from homelabnext.publishing import config as cf

    base, _pub, _cfg = setup_lab(tmp_path, "stage", deny=DENY2)
    doc = json.loads((base / "config.json").read_text())
    (base / "config.json").write_text(
        json.dumps({**doc, "staging_keep": 7, "staging_min_age_s": 99})
    )
    cfg = cf.load(base / "config.json")
    assert (cfg.staging_keep, cfg.staging_min_age_s) == (7, 99.0)
    assert cf.load(base / "config.json").snapshots_keep == 5


def test_the_current_items_are_never_pruned_however_old_their_staging_is(tmp_path):
    """60 current items staged three days ago survive repeated runs with a tiny keep."""
    _base, pub, cfg = setup_lab(tmp_path, "stage", deny=DENY2)
    cfg = dataclasses.replace(cfg, staging_keep=1, staging_min_age_s=60)
    for n in range(60):
        episode(pub, f"e{n}", period=f"p{n % 3}", date=f"2026-01-{n // 3 + 1:02d}")
    now = 2_000_000.0
    assert rn.run(cfg, clock=lambda: now).code == 0
    staged = sorted((cfg.staging_dir / "podcast").iterdir())
    assert len(staged) == 60
    for d in staged:  # three days old
        os.utime(d, (now - 259_200, now - 259_200))
    for _ in range(2):
        assert rn.run(cfg, clock=lambda: now).code == 0
        assert sorted((cfg.staging_dir / "podcast").iterdir()) == staged


def test_a_reused_staged_item_is_touched_so_age_follows_use(tmp_path):
    _base, pub, cfg = setup_lab(tmp_path, "stage", deny=DENY2)
    episode(pub)
    rn.run(cfg)
    d = next((cfg.staging_dir / "podcast").iterdir())
    os.utime(d, (1_000, 1_000))
    rn.run(cfg)
    assert d.stat().st_mtime > 1_000_000


def test_prune_does_not_touch_a_link_even_to_a_sibling_snapshot(tmp_path):
    """A link named like a snapshot that points at ANOTHER directory under the same root: only the
    symlink check stands between it and rmtree (which refuses links by raising)."""
    now = 1_000_000.0
    root = tmp_path / "srv" / "lab" / "staging"
    target = _staged(root, "site", "target", 0, now)
    link = root / "site" / ("old-" + "1" * 12)
    link.symlink_to(target)
    for n in range(3):
        _staged(root, "site", f"x{n}", 5_000_000 + n, now)
    gone = snapshots.prune(root, keep=1, min_age_s=0, protect_ids=set(), now=now, digest_len=12)
    assert link.is_symlink() and (target / "plan.json").exists()
    assert f"site/{link.name}" not in gone
