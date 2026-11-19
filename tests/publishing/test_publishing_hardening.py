# SPDX-License-Identifier: Apache-2.0
"""The review's findings (B1-B5, S1-S4) as tests: what is gated is what a reader sees, binaries are
what they say they are and their metadata is read, names and the sidecar are content, what is
published is a private snapshot, a notification can never stop the gate, and stage touches nothing."""

from __future__ import annotations

import base64
import json
import os
import shutil
from pathlib import Path

import pytest

from homelabnext.publishing import config as cf
from homelabnext.publishing import gate as gt
from homelabnext.publishing import pages as pg
from homelabnext.publishing import r2
from homelabnext.publishing import run as rn
from homelabnext.publishing.transport import Request
from tests.publishing.helpers import (
    DENY,
    FEED,
    FakeBucket,
    build_mp3,
    build_png,
    episode,
    make_item,
    policy,
)
from tests.publishing.test_publishing_pages_stage_run import (
    Runner,
    pcfg,
    setup_lab,
)
from tests.publishing.test_publishing_pages_stage_run import install as install_wrangler


def uni(text: str) -> str:
    """Text from ``\\uXXXX`` escapes (so no look-alike character sits in this file)."""
    return text.encode("ascii").decode("unicode_escape")


DENY2 = DENY + "secrethost\ninternal-only\n"
ALL_CREDS = ("deny-list", "cloudflare-api-token", "r2-access-key-id", "r2-secret-access-key")


def verdict(tmp_path, files, kind="site", name="b1", tlp="clear", deny=DENY2):
    root = make_item(tmp_path, kind, name, files, tlp=tlp)
    return gt.evaluate(gt.load_item(root, kind), policy(deny))


def rules(v):
    return {r.rule for r in v.reasons}


# ----------------------------------------------------------------------------- B1
@pytest.mark.parametrize(
    "marker",
    [
        "TLP&#58;RED",
        "TLP&colon;RED",
        "&#x54;LP:RED",
        "TLP%3ARED",
        "TLP%253ARED",
        uni(r"\uff34\uff2c\uff30:\uff32\uff25\uff24"),  # fullwidth
        uni(r"T\u200bLP:RED"),  # zero-width space
        uni(r"TL\u00adP:RED"),  # soft hyphen
        uni(r"\u0422LP:RED"),  # Cyrillic Te
    ],
)
def test_an_encoded_or_look_alike_tlp_marker_is_read_as_the_reader_reads_it(tmp_path, marker):
    v = verdict(tmp_path, {"index.html": f"<p>{marker} do not share</p>"})
    assert not v.ok and "tlp-above-ceiling" in rules(v), marker


@pytest.mark.parametrize(
    "name",
    [
        uni(r"secret\u200bhost"),
        uni(r"secret\u00adhost"),
        uni(r"\uff53\uff45\uff43\uff52\uff45\uff54\uff48\uff4f\uff53\uff54"),
        "secret%68ost",
        "secret&#104;ost",
        "s\u0435crethost",  # Cyrillic ie
    ],
)
def test_an_obfuscated_deny_listed_name_is_still_found(tmp_path, name):
    v = verdict(tmp_path, {"index.html": f"<a>{name}</a>"})
    assert "deny-list" in rules(v), name


def test_json_escapes_are_decoded_before_every_check(tmp_path):
    raw = '{"period":"weekly","date":"2026-01-05","title":"TLP\\u003aRED from secrethost","description":"10\\u002e20\\u002e1\\u002e5"}'
    v = verdict(
        tmp_path,
        {"metadata.json": raw, "weekly_2026-01-05.mp3": build_mp3()},
        kind="podcast",
        name="ep",
    )
    assert not v.ok and {"tlp-above-ceiling", "deny-list"} <= rules(v)


def test_a_json_file_that_is_not_json_is_refused(tmp_path):
    assert "json-invalid" in rules(verdict(tmp_path, {"data.json": "{not json"}))


def test_a_base64_data_uri_is_decoded_and_scanned(tmp_path):
    blob = base64.b64encode(b"TLP:RED secrethost internal notes").decode()
    v = verdict(tmp_path, {"index.html": f'<img src="data:text/plain;base64,{blob}">'})
    assert not v.ok and {"tlp-above-ceiling", "deny-list"} <= rules(v)


def test_the_rendered_feed_is_gated_before_upload(tmp_path):
    """The review's case: clean new item, but an episode already in the bucket carries a marker in
    its metadata; the feed that would be written (built from it) is refused, nothing is written."""
    b = FakeBucket()
    old_meta = json.dumps(
        {
            "period": "daily",
            "date": "2025-12-01",
            "title": "TLP:RED from secrethost",
            "description": "x",
        }
    ).encode()
    b.objects["episodes/daily_2025-12-01.json"] = (old_meta, {})
    b.objects["episodes/daily_2025-12-01.mp3"] = (build_mp3(), {})
    item = gt.load_item(episode(tmp_path), "podcast")
    client = r2.R2Client("https://store.example.test", "b", "id" * 4, "s" * 20, b)
    with pytest.raises(r2.FeedBlocked):
        r2.plan_episode(client, item, FEED, policy(DENY2))
    assert "PUT" not in b.methods()


def test_gate_artifact_refuses_a_marker_in_generated_text():
    v = gt.gate_artifact("feed.xml", "<title>TLP:RED x</title>", policy(DENY2))
    assert not v.ok and v.label == "red"
    assert gt.gate_artifact("feed.xml", "<title>fine</title>", policy(DENY2)).ok


def test_a_feed_refused_by_the_gate_is_a_blocked_item_in_a_live_run(tmp_path):
    _, pub, cfg = setup_lab(tmp_path, "live", creds=ALL_CREDS, deny=DENY2)
    episode(pub)
    bucket = FakeBucket()
    bucket.objects["episodes/daily_2025-12-01.json"] = (
        json.dumps({"period": "daily", "date": "2025-12-01", "title": "secrethost"}).encode(),
        {},
    )
    bucket.objects["episodes/daily_2025-12-01.mp3"] = (build_mp3(), {})
    rep = rn.run(cfg, transport=bucket, runner=Runner())
    assert rep.blocked == ["ep1"] and "PUT" not in bucket.methods()


# ----------------------------------------------------------------------------- B2
def test_a_text_payload_named_as_audio_or_image_is_refused(tmp_path):
    for n, (name, body) in enumerate(
        (("a.mp3", b"TLP:RED secrethost"), ("a.png", b"TLP:RED"), ("a.woff2", b"secrethost"))
    ):
        v = verdict(tmp_path / str(n), {name: body})
        assert "media-invalid" in rules(v), name


def test_a_binary_named_as_text_is_refused(tmp_path):
    assert "media-invalid" in rules(verdict(tmp_path, {"a.txt": build_png()}))
    assert "media-invalid" in rules(verdict(tmp_path / "n", {"a.txt": b"abc\x00def"}))


def test_id3_text_frames_are_scanned(tmp_path):
    assert "deny-list" in rules(verdict(tmp_path, {"a.mp3": build_mp3(title="secrethost")}))
    assert "tlp-above-ceiling" in rules(
        verdict(tmp_path / "c", {"a.mp3": build_mp3(comment="TLP:AMBER notes")})
    )
    assert verdict(tmp_path / "ok", {"a.mp3": build_mp3(title="Weekly briefing")}).ok


def test_an_unparsable_id3_tag_is_refused(tmp_path):
    bad = b"ID3\x03\x00\x00\x7f\x7f\x7f\x7f" + b"x" * 20
    assert "media-invalid" in rules(verdict(tmp_path, {"a.mp3": bad}))


def test_png_text_chunks_are_scanned_and_a_bad_chunk_is_refused(tmp_path):
    assert "deny-list" in rules(verdict(tmp_path, {"a.png": build_png("secrethost")}))
    assert verdict(tmp_path / "ok", {"a.png": build_png()}).ok
    broken = bytearray(build_png("hello"))
    broken[40] ^= 0xFF
    assert "media-invalid" in rules(verdict(tmp_path / "b", {"a.png": bytes(broken)}))


def test_jpeg_comment_segments_are_scanned(tmp_path):
    import struct

    com = b"secrethost in a comment"
    jpg = b"\xff\xd8\xff\xfe" + struct.pack(">H", len(com) + 2) + com + b"\xff\xd9"
    assert "deny-list" in rules(verdict(tmp_path, {"a.jpg": jpg}))
    assert "media-invalid" in rules(verdict(tmp_path / "t", {"a.jpg": b"\xff\xd8\xff\xfe\x00"}))


# ----------------------------------------------------------------------------- B3
def test_names_the_item_id_and_the_sidecar_text_are_content(tmp_path):
    assert "deny-list" in rules(verdict(tmp_path / "1", {"secrethost.html": "<p>x</p>"}))
    assert "deny-list" in rules(verdict(tmp_path / "2", {"internal-only/index.html": "<p>x</p>"}))
    assert "tlp-above-ceiling" in rules(verdict(tmp_path / "3", {"TLP_RED.html": "<p>x</p>"}))
    assert "deny-list" in rules(verdict(tmp_path / "4", {"a.html": "x"}, name="secrethost-build"))
    root = make_item(tmp_path / "5", "site", "b1", {"a.html": "x"})
    sc = json.loads((root / gt.SIDECAR).read_text())
    sc["title"] = "TLP:RED secrethost"
    (root / gt.SIDECAR).write_text(json.dumps(sc))
    v = gt.evaluate(gt.load_item(root, "site"), policy(DENY2))
    assert {"tlp-above-ceiling", "deny-list"} <= rules(v)


def test_a_reason_never_carries_the_name_it_found(tmp_path):
    v = verdict(tmp_path, {"secrethost.html": "<p>x</p>"})
    assert all("secrethost" not in json.dumps(r.as_dict()) for r in v.reasons)


def test_the_sidecar_is_never_in_what_is_published(tmp_path):
    root = make_item(tmp_path / "src", "site", "b1", {"index.html": "<p>ok</p>"})
    item = gt.snapshot_item(root, "site", tmp_path / "snap")
    assert not (item.root / gt.SIDECAR).exists()
    assert sorted(p.name for p in item.root.iterdir()) == ["index.html"]


@pytest.mark.parametrize("name", ["wrangler.toml", "functions/api.js", "_worker.js"])
def test_deploy_configuration_and_code_are_never_content(tmp_path, name):
    root = make_item(tmp_path, "site", "b1", {"index.html": "x", name: "x"})
    with pytest.raises(gt.GateError):
        gt.load_item(root, "site")


# ----------------------------------------------------------------------------- B4
def test_the_snapshot_is_what_was_read_whatever_the_producer_does_next(tmp_path):
    root = make_item(tmp_path / "src", "site", "b1", {"index.html": "<p>ok</p>"})
    item = gt.snapshot_item(root, "site", tmp_path / "snap")
    (root / "index.html").write_text("<p>TLP:RED changed after the copy</p>")
    (root / "extra.html").write_text("added after the copy")
    assert (item.root / "index.html").read_text() == "<p>ok</p>"
    assert not (item.root / "extra.html").exists()
    assert gt.evaluate(item, policy(DENY2)).ok


def test_the_snapshot_is_private_and_reused_without_growth(tmp_path):
    root = make_item(tmp_path / "src", "site", "b1", {"index.html": "<p>ok</p>"})
    a = gt.snapshot_item(root, "site", tmp_path / "snap")
    b = gt.snapshot_item(root, "site", tmp_path / "snap")
    assert a.root == b.root
    assert oct(a.root.stat().st_mode & 0o777) == "0o700"
    assert sorted(p.name for p in (tmp_path / "snap" / "site").iterdir()) == [a.root.name]


def test_pages_deploys_the_snapshot_not_the_producers_directory(tmp_path):
    _, pub, cfg = setup_lab(tmp_path, "live", creds=ALL_CREDS, deny=DENY2)
    src = make_item(pub, "site", "b1", {"index.html": "<p>ok</p>"})
    seen: dict = {}

    class Tamper(Runner):
        def __call__(self, argv, env, timeout, cwd):
            if argv[-1] == "--version":  # the producer writes between the gate and the deploy
                (src / "index.html").write_text("<p>TLP:RED late change</p>")
                (src / "late.html").write_text("late")
            else:
                dist = Path(argv[4])
                seen["dist"] = dist
                seen["files"] = sorted(p.name for p in dist.iterdir())
                seen["index"] = (dist / "index.html").read_text()
            return super().__call__(argv, env, timeout, cwd)

    rep = rn.run(cfg, transport=FakeBucket(), runner=Tamper())
    assert rep.code == 0, rep
    assert seen["files"] == ["index.html"] and seen["index"] == "<p>ok</p>"
    assert pub not in seen["dist"].parents and gt.SIDECAR not in seen["files"]


def test_r2_uploads_the_snapshot_and_stamps_the_hash_of_the_bytes_it_sends(tmp_path):
    import hashlib

    b = FakeBucket()
    item = gt.snapshot_item(episode(tmp_path / "s"), "podcast", tmp_path / "snap")
    client = r2.R2Client("https://store.example.test", "b", "id" * 4, "s" * 20, b)
    plan = r2.plan_episode(client, item, FEED, policy(DENY2))
    assert all(u.sha256 == hashlib.sha256(u.body).hexdigest() for u in plan.uploads)
    (item.root / "weekly_2026-01-05.mp3").write_bytes(build_mp3(title="swapped"))
    with pytest.raises(r2.R2Error, match="no longer matches"):
        r2.plan_episode(client, item, FEED, policy(DENY2))


# ----------------------------------------------------------------------------- B5 / S1
class RecordingOpener:
    def __init__(self, fail=False):
        self.calls, self.fail = [], fail

    def __call__(self, req, timeout=None):
        self.calls.append(req)
        if self.fail:
            raise OSError("notify unreachable")

        class R:
            status = 200

            def read(self):
                return b""

            def close(self):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *a):
                pass

        return R()


def notify_lab(tmp_path, mode="dry-run"):
    base, pub, cfg = setup_lab(tmp_path, mode, creds=("deny-list",), deny=DENY2)
    cred = base / "creds" / "notify-token"
    cred.write_text("n" * 12)
    os.chmod(cred, 0o600)
    import dataclasses

    cfg = dataclasses.replace(cfg, notify_url="https://notify.example.test", notify_topic="pub")
    return base, pub, cfg


def test_build_notifier_sends_through_the_sender_with_the_token(tmp_path):
    _base, pub, cfg = notify_lab(tmp_path)
    make_item(pub, "site", "b1", {"a.html": "secrethost"})
    opener = RecordingOpener()
    n = rn.build_notifier(cfg, opener=opener)
    rep = rn.run(cfg, notifier=n)
    assert rep.blocked == ["b1"] and len(opener.calls) == 1
    req = opener.calls[0]
    assert req.full_url == "https://notify.example.test/pub"
    assert req.get_header("Authorization") == "Bearer " + "n" * 12


def test_a_notification_that_fails_never_stops_the_gate_run(tmp_path, capsys):
    base, pub, cfg = notify_lab(tmp_path)
    make_item(pub, "site", "b1", {"a.html": "secrethost"})
    n = rn.build_notifier(cfg, opener=RecordingOpener(fail=True))
    rep = rn.run(cfg, notifier=n)
    assert rep.blocked == ["b1"] and rep.code == 1
    assert "notification not sent" in capsys.readouterr().err
    assert "notify_failed" in (base / "state" / "gate.jsonl").read_text()


def test_main_survives_a_notifier_that_cannot_be_built(tmp_path, capsys, monkeypatch):
    base, pub, _cfg = notify_lab(tmp_path)
    make_item(pub, "site", "b1", {"a.html": "secrethost"})
    doc = json.loads((base / "config.json").read_text())
    doc["notify"] = {"url": "https://notify.example.test", "topic": "pub"}
    (base / "config.json").write_text(json.dumps(doc))

    def boom(cfg, opener=None):
        raise RuntimeError("cannot build")

    monkeypatch.setattr(rn, "build_notifier", boom)
    assert rn.main(["--config", str(base / "config.json")]) == 1  # blocked, not a crash
    assert json.loads(capsys.readouterr().out)["blocked"] == ["b1"]


class Raising:
    def send(self, req: Request):
        raise AssertionError("a network call in stage mode")


def test_stage_mode_touches_no_client_at_all_notification_included(tmp_path, monkeypatch):
    base, pub, cfg = notify_lab(tmp_path, "stage")
    make_item(pub, "site", "b1", {"a.html": "<p>ok</p>"})
    episode(pub)
    sent = RecordingOpener()
    n = rn.build_notifier(cfg, opener=sent)
    runner = Runner()
    rep = rn.run(cfg, transport=Raising(), runner=runner, notifier=n)
    assert rep.code == 0 and sent.calls == [] and runner.calls == []
    # and the entry point does not even build one
    doc = json.loads((base / "config.json").read_text())
    doc["notify"] = {"url": "https://notify.example.test", "topic": "pub"}
    (base / "config.json").write_text(json.dumps(doc))
    monkeypatch.setattr(rn, "build_notifier", lambda *a, **k: pytest.fail("built in stage"))
    assert rn.main(["--config", str(base / "config.json")]) == 0


# ----------------------------------------------------------------------------- S2
def test_a_symlinked_item_or_kind_directory_is_refused(tmp_path):
    _, pub, cfg = setup_lab(tmp_path, "stage", deny=DENY2)
    real = make_item(tmp_path / "elsewhere", "site", "real", {"a.html": "<p>ok</p>"})
    (pub / "site").mkdir(parents=True)
    (pub / "site" / "linked").symlink_to(real)
    rep = rn.run(cfg)
    assert rep.blocked == ["linked"] and rep.code == 1
    # a symlinked kind directory
    shutil.rmtree(pub / "site")
    (pub / "site").symlink_to(tmp_path / "elsewhere" / "site")
    rep = rn.run(cfg)
    assert rep.blocked == ["site"] and rep.done == []


def test_a_hard_linked_file_is_refused(tmp_path):
    root = make_item(tmp_path, "site", "b1", {"a.html": "<p>ok</p>"})
    os.link(root / "a.html", tmp_path / "other-name")
    with pytest.raises(gt.GateError, match="hard link"):
        gt.load_item(root, "site")


# ----------------------------------------------------------------------------- S3
def test_wrangler_runs_on_the_verified_node_in_an_empty_directory(tmp_path):
    d = install_wrangler(tmp_path)
    dist, work = tmp_path / "dist", tmp_path / "work"
    dist.mkdir()
    work.mkdir()
    r = Runner()
    pg.deploy(pcfg(d), dist, token="t" * 5, account_id="", home=tmp_path, workdir=work, runner=r)
    argv, env, cwd = r.calls[-1]
    assert argv[0] == str(pcfg(d).node) and cwd == str(work)
    assert env["PATH"].split(":")[0] == str(pcfg(d).node.parent)
    (work / "wrangler.toml").write_text("x")
    with pytest.raises(pg.PagesError, match="not empty"):
        pg.deploy(pcfg(d), dist, token="t", account_id="", home=tmp_path, workdir=work, runner=r)


def test_the_deploy_refuses_a_directory_holding_configuration(tmp_path):
    d = install_wrangler(tmp_path)
    dist, work = tmp_path / "dist", tmp_path / "work"
    dist.mkdir()
    work.mkdir()
    (dist / "wrangler.toml").write_text("name = 'x'")
    with pytest.raises(pg.PagesError, match="configuration"):
        pg.deploy(
            pcfg(d), dist, token="t", account_id="", home=tmp_path, workdir=work, runner=Runner()
        )


# ----------------------------------------------------------------------------- S4
def test_the_feed_is_replaced_only_if_it_is_the_version_that_was_read(tmp_path):
    b = FakeBucket()
    client = r2.R2Client("https://store.example.test", "b", "id" * 4, "s" * 20, b)
    r2.apply_plan(
        client,
        r2.plan_episode(
            client, gt.load_item(episode(tmp_path, "e1"), "podcast"), FEED, policy(DENY2)
        ),
    )
    plan = r2.plan_episode(
        client,
        gt.load_item(episode(tmp_path, "e2", date="2026-02-02"), "podcast"),
        FEED,
        policy(DENY2),
    )
    assert plan.feed_etag
    other = b.objects["feed.xml"][0] + b"<!-- another publisher -->"
    b.objects["feed.xml"] = (other, {})  # someone else wrote the feed after it was read
    with pytest.raises(r2.PreconditionFailed):
        r2.apply_plan(client, plan)
    assert b.objects["feed.xml"][0] == other  # nothing was lost


def test_a_live_run_reads_again_once_when_the_feed_moved(tmp_path):
    _, pub, cfg = setup_lab(tmp_path, "live", creds=ALL_CREDS, deny=DENY2)
    episode(pub)

    class Racy(FakeBucket):
        raced = False

        def send(self, req):
            if req.method == "PUT" and req.url.endswith("/feed.xml") and not self.raced:
                self.raced = True
                if "feed.xml" in self.objects:
                    self.objects["feed.xml"] = (self.objects["feed.xml"][0] + b"<!-- x -->", {})
                else:
                    self.objects["feed.xml"] = (b"<rss><guid>a_2020-01-01</guid></rss>", {})
            return super().send(req)

    b = Racy()
    b.objects["feed.xml"] = (b"<rss></rss>", {})
    rep = rn.run(cfg, transport=b, runner=Runner())
    assert rep.code == 0 and "weekly_2026-01-05" in b.objects["feed.xml"][0].decode()


# ----------------------------------------------------------------------------- nits
def test_a_credential_owned_by_someone_else_is_refused(tmp_path, monkeypatch):
    f = tmp_path / "deny-list"
    f.write_text("x")
    os.chmod(f, 0o600)
    monkeypatch.setattr(os, "geteuid", lambda: os.stat(f).st_uid + 4242)
    with pytest.raises(cf.ConfigError, match="owned by"):
        cf.read_credential(tmp_path, "deny-list")


def test_unverified_legacy_episodes_are_reported(tmp_path):
    b = FakeBucket()
    item = gt.load_item(episode(tmp_path / "a"), "podcast")
    client = r2.R2Client("https://store.example.test", "b", "id" * 4, "s" * 20, b)
    r2.apply_plan(client, r2.plan_episode(client, item, FEED, policy(DENY2)))
    for k, (body, _) in list(b.objects.items()):
        if k.startswith("episodes/"):
            b.objects[k] = (body, {})  # an episode from before this module: no sha256 stamp
    plan = r2.plan_episode(client, item, FEED, policy(DENY2))
    assert sorted(plan.unverified) == sorted(plan.unchanged) and plan.unverified
