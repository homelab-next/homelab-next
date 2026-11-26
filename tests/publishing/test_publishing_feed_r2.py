# SPDX-License-Identifier: Apache-2.0
"""The feed builder (golden), the signer (a published vector) and the idempotent, additive episode
publish against an in-memory bucket."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from homelabnext.publishing import feed as fd
from homelabnext.publishing import gate as gt
from homelabnext.publishing import r2
from tests.publishing.helpers import DENY, FEED, FakeBucket, build_mp3, episode, policy

POL = policy(DENY)

HERE = Path(__file__).parent


def client(bucket: FakeBucket) -> r2.R2Client:
    return r2.R2Client("https://store.example.test", "b", "id" * 4, "s" * 20, bucket)


@pytest.mark.static
def test_the_feed_matches_the_golden_fixture():
    eps = [
        fd.Episode("weekly_2026-01-05", "2026-01-05", "weekly 2026-01-05", "First", 1024),
        fd.Episode("weekly_2026-01-12", "2026-01-12", "weekly 2026-01-12", "Second & later", 2048),
        fd.Episode("daily_2026-01-05", "2026-01-05", "daily 2026-01-05", "", 512),
    ]
    assert fd.build_feed(eps, FEED) == (HERE / "fixtures/feed.expected.xml").read_text()
    assert fd.build_feed(list(reversed(eps)), FEED) == fd.build_feed(
        eps, FEED
    )  # input order never matters


def test_an_episode_key_cannot_escape_or_be_malformed():
    for meta in (
        {"period": "../x", "date": "2026-01-01"},
        {"period": "A", "date": "2026-01-01"},
        [],
    ):
        with pytest.raises(fd.FeedError):
            fd.stem_of(meta)
    with pytest.raises(ValueError):  # a date that matches the shape but is not a day
        fd.stem_of({"period": "a", "date": "2026-13-01"})


def test_the_signer_reproduces_a_published_signature_vector():
    secret = "".join(["wJalrXUtnF", "EMI/K7MDEN", "G/bPxRfiCY", "EXAMPLEKEY"])
    key_id = "AKIA" + "IOSFODNN7" + "EXAMPLE"
    h = r2.sign(
        "GET",
        "https://examplebucket.s3.amazonaws.com/test.txt",
        {"Range": "bytes=0-9"},
        b"",
        key_id=key_id,
        secret=secret,
        region="us-east-1",
        service="s3",
        now=datetime(2013, 5, 24, tzinfo=UTC),
    )
    assert h["Authorization"].endswith(
        "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
    )


def test_first_publish_uploads_audio_metadata_then_the_feed(tmp_path):
    b = FakeBucket()
    item = gt.load_item(episode(tmp_path), "podcast")
    plan = r2.plan_episode(client(b), item, FEED, POL)
    assert b.methods().count("PUT") == 0  # planning writes nothing
    assert r2.apply_plan(client(b), plan) == [
        "episodes/weekly_2026-01-05.mp3",
        "episodes/weekly_2026-01-05.json",
        "feed.xml",
    ]
    assert "weekly_2026-01-05" in fd.guids(b.objects["feed.xml"][0].decode())


def test_publishing_twice_is_a_no_op(tmp_path):
    b = FakeBucket()
    item = gt.load_item(episode(tmp_path), "podcast")
    r2.apply_plan(client(b), r2.plan_episode(client(b), item, FEED, POL))
    before = {k: v[0] for k, v in b.objects.items()}
    b.calls.clear()
    plan = r2.plan_episode(client(b), item, FEED, POL)
    assert not plan.uploads and not plan.feed_changes
    assert r2.apply_plan(client(b), plan) == []
    assert "PUT" not in b.methods()
    assert {k: v[0] for k, v in b.objects.items()} == before


def test_a_second_episode_adds_and_keeps_the_first(tmp_path):
    b = FakeBucket()
    r2.apply_plan(
        client(b),
        r2.plan_episode(client(b), gt.load_item(episode(tmp_path, "e1"), "podcast"), FEED, POL),
    )
    second = gt.load_item(
        episode(tmp_path, "e2", date="2026-01-12", mp3=build_mp3(title="zz")), "podcast"
    )
    r2.apply_plan(client(b), r2.plan_episode(client(b), second, FEED, POL))
    assert fd.guids(b.objects["feed.xml"][0].decode()) == {"weekly_2026-01-05", "weekly_2026-01-12"}
    assert "episodes/weekly_2026-01-05.mp3" in b.objects


def test_nothing_is_ever_deleted_and_an_existing_key_is_never_overwritten(tmp_path):
    b = FakeBucket()
    item = gt.load_item(episode(tmp_path, "e1"), "podcast")
    r2.apply_plan(client(b), r2.plan_episode(client(b), item, FEED, POL))
    changed = gt.load_item(episode(tmp_path, "e1b", mp3=build_mp3(title="qq")), "podcast")
    with pytest.raises(r2.Conflict):
        r2.plan_episode(client(b), changed, FEED, POL)
    assert "DELETE" not in b.methods()
    assert not any(n.startswith(("delete", "remove")) for n in dir(r2.R2Client))


def test_the_feed_is_never_shrunk(tmp_path):
    b = FakeBucket()
    r2.apply_plan(
        client(b),
        r2.plan_episode(client(b), gt.load_item(episode(tmp_path, "e1"), "podcast"), FEED, POL),
    )
    # the remote feed claims an episode whose objects are gone: the new feed would drop it
    feed = (
        b.objects["feed.xml"][0]
        .decode()
        .replace(
            "</channel>", '<item><guid isPermaLink="false">lost_2025-01-01</guid></item></channel>'
        )
    )
    b.objects["feed.xml"] = (feed.encode(), {})
    with pytest.raises(r2.R2Error, match="drop"):
        r2.plan_episode(
            client(b),
            gt.load_item(episode(tmp_path, "e2", date="2026-02-02"), "podcast"),
            FEED,
            POL,
        )


def test_an_item_missing_its_audio_is_refused(tmp_path):
    item = gt.load_item(episode(tmp_path), "podcast")
    (item.root / "weekly_2026-01-05.mp3").unlink()
    with pytest.raises(gt.GateError):
        gt.load_item(item.root, "podcast")
