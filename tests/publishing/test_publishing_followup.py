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
from tests.publishing.helpers import FEED, FakeBucket, episode, make_item, policy
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
    item = gt.load_item(episode(tmp_path, "ep"), "podcast")
    # the policy that would block this item's text (as a stricter deny-list would): the item's own
    # key is listed as a "reviewed legacy" object with its own sha256, to excuse itself
    meta = (item.root / "metadata.json").read_bytes()
    own_key = "episodes/weekly_2026-01-05.json"
    sha = hashlib.sha256(meta).hexdigest()
    strict = policy("weekly\n")  # the word in the title
    b = FakeBucket()
    b.objects[own_key] = (meta, {"x-amz-meta-sha256": sha})
    b.objects["episodes/weekly_2026-01-05.mp3"] = (
        (item.root / "weekly_2026-01-05.mp3").read_bytes(),
        {"x-amz-meta-sha256": item.sidecar["sha256s"]["weekly_2026-01-05.mp3"]},
    )
    client = r2.R2Client("https://store.example.test", "b", "id" * 4, "s" * 20, b)
    with pytest.raises(r2.FeedBlocked):
        r2.plan_episode(client, item, FEED, strict, {own_key: sha})


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
