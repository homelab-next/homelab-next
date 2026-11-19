# SPDX-License-Identifier: Apache-2.0
"""The delta review (N1, N2 and the should-fixes): text anywhere in a media file, a directory of
wrangler's own per deploy, rendered text and script escapes, a directory-fd snapshot, pruning,
reviewed legacy exceptions, and the confusable and fixed-point nits."""

from __future__ import annotations

import hashlib
import json
import os
import struct
import urllib.parse
import zlib
from pathlib import Path

import pytest

from homelabnext.publishing import gate as gt
from homelabnext.publishing import normalise, r2, snapshots
from homelabnext.publishing import pages as pg
from homelabnext.publishing import run as rn
from tests.publishing.helpers import (
    FEED,
    FakeBucket,
    build_mp3,
    episode,
    make_item,
    policy,
)
from tests.publishing.test_publishing_hardening import (
    ALL_CREDS,
    DENY2,
    RecordingOpener,
    notify_lab,
    verdict,
)
from tests.publishing.test_publishing_pages_stage_run import Runner, install, pcfg, setup_lab

PAYLOAD = b"TLP:RED from secrethost AKIA" + b"A" * 16


def rules(v):
    return {r.rule for r in v.reasons}


def chunk(t: bytes, d: bytes) -> bytes:
    return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d))


def png_with(*extra: tuple[bytes, bytes], idat: bytes | None = None, tail: bytes = b"") -> bytes:
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    body = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr)
    for t, d in extra:
        body += chunk(t, d)
    body += chunk(b"IDAT", idat if idat is not None else zlib.compress(b"\x00\x00\x00\x00"))
    return body + chunk(b"IEND", b"") + tail


def id3(frames: list[bytes]) -> bytes:
    payload = b"".join(frames)
    size = len(payload)
    ss = bytes([(size >> 21) & 0x7F, (size >> 14) & 0x7F, (size >> 7) & 0x7F, size & 0x7F])
    return b"ID3\x03\x00\x00" + ss + payload + b"\xff\xfb\x90\x00" + b"\x00" * 64


def frame(fid: bytes, payload: bytes, flags: int = 0) -> bytes:
    return fid + struct.pack(">I", len(payload)) + bytes([0, flags]) + payload


# ----------------------------------------------------------------------------- N1
def test_text_placed_anywhere_in_an_mp3_is_found_not_only_near_the_end(tmp_path):
    filler = b"\x01\x02\x03\x04" * 5000
    mp3 = build_mp3(body=filler + PAYLOAD + filler)
    assert {"tlp-above-ceiling", "deny-list"} <= rules(verdict(tmp_path / "a", {"a.mp3": mp3}))
    u16 = "TLP:RED secrethost".encode("utf-16-le")
    mp3 = build_mp3(body=filler + u16 + filler)
    assert not verdict(tmp_path / "b", {"a.mp3": mp3}).ok
    assert verdict(tmp_path / "ok", {"a.mp3": build_mp3(body=filler)}).ok


def test_bytes_after_the_png_end_chunk_are_refused_and_plain_text_in_a_chunk_is_found(tmp_path):
    assert "media-invalid" in rules(verdict(tmp_path / "a", {"a.png": png_with(tail=PAYLOAD)}))
    plain = png_with(idat=b"\x00" * 10 + PAYLOAD)  # plaintext inside the image data chunk
    assert "deny-list" in rules(verdict(tmp_path / "b", {"a.png": plain}))
    assert verdict(tmp_path / "ok", {"a.png": png_with()}).ok


@pytest.mark.parametrize("ctype", [b"ZZZZ", b"prVt", b"zZZZ"])
def test_unknown_critical_and_private_png_chunks_are_refused(tmp_path, ctype):
    v = verdict(tmp_path, {"a.png": png_with((ctype, zlib.compress(PAYLOAD)))})
    assert "media-invalid" in rules(v)


def test_jpeg_scan_data_and_bytes_after_the_end_marker(tmp_path):
    head = b"\xff\xd8\xff\xdb\x00\x04\x00\x00\xff\xda\x00\x04\x00\x00"
    filler = b"\x11\x22" * 40000
    assert not verdict(tmp_path / "a", {"a.jpg": head + filler + PAYLOAD + filler + b"\xff\xd9"}).ok
    assert "media-invalid" in rules(
        verdict(tmp_path / "b", {"a.jpg": head + filler + b"\xff\xd9" + PAYLOAD})
    )
    assert verdict(tmp_path / "ok", {"a.jpg": head + filler + b"\xff\xd9"}).ok


def test_id3_compressed_encrypted_private_and_picture_frames(tmp_path):
    tit = frame(b"TIT2", b"\x00weekly")
    assert verdict(tmp_path / "ok", {"a.mp3": id3([tit])}).ok
    for n, f in enumerate(
        (
            frame(b"TIT2", zlib.compress(b"\x00" + PAYLOAD), 0x80),  # compression flag
            frame(b"TIT2", b"\x00x", 0x40),  # encryption flag
            frame(b"PRIV", b"owner\x00" + PAYLOAD),  # a frame type outside the accepted set
            frame(b"APIC", b"\x00image/x\x00\x03\x00" + zlib.compress(PAYLOAD)),  # not a picture
        )
    ):
        assert "media-invalid" in rules(verdict(tmp_path / str(n), {"a.mp3": id3([tit, f])})), n
    pic = frame(
        b"APIC", b"\x00image/png\x00\x03\x00" + png_with((b"tEXt", b"Comment\x00secrethost"))
    )
    assert "deny-list" in rules(verdict(tmp_path / "p", {"a.mp3": id3([pic])}))
    clean = frame(b"APIC", b"\x00image/png\x00\x03\x00" + png_with())
    assert verdict(tmp_path / "c", {"a.mp3": id3([clean])}).ok


@pytest.mark.parametrize("name", ["a.gif", "a.webp", "a.woff", "a.woff2"])
def test_formats_whose_bodies_are_compressed_are_refused_outright(tmp_path, name):
    assert "unknown-file-type" in rules(verdict(tmp_path, {name: b"GIF89a" + b"x" * 20}))


def test_an_icon_holding_a_png_is_refused(tmp_path):
    ico = b"\x00\x00\x01\x00\x01\x00" + b"\x89PNG\r\n\x1a\n" + b"x" * 20
    assert "media-invalid" in rules(verdict(tmp_path, {"favicon.ico": ico}))


# ----------------------------------------------------------------------------- N2
def test_two_live_deploys_in_a_row_each_get_a_directory_of_their_own(tmp_path):
    d = install(tmp_path)
    dist = tmp_path / "dist"
    dist.mkdir()
    cwds = []

    class Wrangler(Runner):
        def __call__(self, argv, env, timeout, cwd):
            cwds.append(cwd)
            assert not any(Path(cwd).iterdir())  # empty when the deploy starts
            if (
                argv[-1] != "--version"
            ):  # what wrangler 4.157.0 does: it leaves .wrangler/tmp behind
                (Path(cwd) / ".wrangler" / "tmp").mkdir(parents=True)
            return super().__call__(argv, env, timeout, cwd)

    r = Wrangler()
    for _ in range(2):
        pg.deploy(pcfg(d), dist, token="t" * 5, account_id="", home=tmp_path, runner=r)
    assert len(set(cwds)) == 2 and not any(Path(c).exists() for c in cwds)


def test_a_live_run_deploys_a_changed_site_after_a_first_deploy(tmp_path):
    _, pub, cfg = setup_lab(tmp_path, "live", creds=ALL_CREDS, deny=DENY2)

    class Wrangler(Runner):
        def __call__(self, argv, env, timeout, cwd):
            if argv[-1] != "--version":
                (Path(cwd) / ".wrangler" / "tmp").mkdir(parents=True)
            return super().__call__(argv, env, timeout, cwd)

    runner = Wrangler()
    make_item(pub, "site", "b1", {"index.html": "<p>one</p>"})
    assert rn.run(cfg, transport=FakeBucket(), runner=runner).code == 0
    make_item(pub, "site", "b2", {"index.html": "<p>two</p>"})
    rep = rn.run(cfg, transport=FakeBucket(), runner=runner)
    assert rep.code == 0 and {d["result"] for d in rep.done if d["item"] == "b2"} == {"deployed"}


# ----------------------------------------------------------------------------- should-fix: rendered text
@pytest.mark.parametrize(
    "html",
    [
        'vault<span class="p">.</span>example<span class="p">.</span>internal',
        "secret<b></b>host",
        "secre<![CDATA[t]]>host",
        "<text><tspan>sec</tspan><tspan>rethost</tspan></text>",
        "sec<!-- split -->rethost",
    ],
)
def test_a_name_split_by_markup_is_whole_when_rendered(tmp_path, html):
    assert "deny-list" in rules(verdict(tmp_path, {"index.html": f"<p>{html}</p>"})), html


@pytest.mark.parametrize(
    ("name", "body"),
    [
        ("a.js", 'var h = "sec\\x72ethost";'),
        ("a.js", 'var h = "\\u0073ecrethost";'),
        ("a.js", 'var h = "\\u{73}ecrethost";'),
        ("a.html", '<script>var h="secret\\x68ost"</script>'),
        ("a.css", 'a::after{content:"secret\\68 ost"}'),
    ],
)
def test_script_and_style_escapes_are_decoded(tmp_path, name, body):
    assert "deny-list" in rules(verdict(tmp_path, {name: body})), body


def test_ordinary_text_is_not_a_false_positive(tmp_path):
    assert verdict(
        tmp_path, {"index.html": "<p>An actor <b>used</b> a loader; 18,000 devices.</p>"}
    ).ok


# ----------------------------------------------------------------------------- should-fix: snapshot
def test_a_directory_swapped_for_a_link_after_the_listing_is_refused(tmp_path):
    root = make_item(tmp_path / "src", "site", "b1", {"sub/a.html": "<p>ok</p>", "b.html": "x"})
    item = gt.load_item(root, "site")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "a.html").write_text("<p>from outside the item</p>")
    (root / "sub").rename(tmp_path / "moved")
    (root / "sub").symlink_to(outside)
    with pytest.raises(gt.GateError, match="without following links"):
        gt._read_tree(root, item.files)


def test_a_reused_snapshot_holding_an_extra_file_is_refused(tmp_path):
    root = make_item(tmp_path / "src", "site", "b1", {"index.html": "<p>ok</p>"})
    first = gt.snapshot_item(root, "site", tmp_path / "snap")
    (first.root / "evil.html").write_text("added to the snapshot")
    with pytest.raises(gt.GateError, match="other files"):
        gt.snapshot_item(root, "site", tmp_path / "snap")


def test_the_snapshot_directories_are_created_private(tmp_path):
    old = os.umask(0o000)
    try:
        root = make_item(tmp_path / "src", "site", "b1", {"index.html": "x"})
        gt.snapshot_item(root, "site", tmp_path / "snap")
    finally:
        os.umask(old)
    for d in (tmp_path / "snap", tmp_path / "snap" / "site"):
        assert oct(d.stat().st_mode & 0o777) == "0o700"


# ----------------------------------------------------------------------------- should-fix: pruning
def _snap(base: Path, kind: str, name: str, age_s: float, now: float) -> Path:
    d = base / kind / f"{name}-{hashlib.sha256(name.encode()).hexdigest()[:16]}"
    d.mkdir(parents=True)
    (d / "f").write_text("x")
    os.utime(d, (now - age_s, now - age_s))
    return d


def test_prune_keeps_the_newest_the_protected_and_the_young_and_removes_the_rest(tmp_path):
    now = 1_000_000.0
    base = tmp_path / "state" / "snapshots"
    old = [_snap(base, "site", f"b{n}", 10_000 + n * 100, now) for n in range(6)]  # b0 newest
    referenced = _snap(base, "site", "live", 90_000, now)
    young = _snap(base, "site", "fresh", 10, now)
    gone = snapshots.prune(base, keep=3, min_age_s=3600, protect_ids={"live"}, now=now)
    assert sorted(p.name for p in (base / "site").iterdir()) == sorted(
        p.name for p in (old[0], old[1], referenced, young)
    )
    assert len(gone) == 4


def test_prune_refuses_links_odd_names_and_a_link_as_the_root(tmp_path):
    now = 1_000_000.0
    base = tmp_path / "state" / "snapshots"
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "precious").write_text("keep")
    (base / "site").mkdir(parents=True)
    (base / "site" / ("b-" + "0" * 16)).symlink_to(outside)  # named like a snapshot, but a link
    odd = base / "site" / "not-a-snapshot"
    odd.mkdir()
    os.utime(odd, (now - 99_999, now - 99_999))
    for n in range(3):
        _snap(base, "site", f"x{n}", 50_000 + n, now)
    snapshots.prune(base, keep=1, min_age_s=0, protect_ids=set(), now=now)
    assert (outside / "precious").exists() and odd.exists()
    link = tmp_path / "linked"
    link.symlink_to(base)
    assert snapshots.prune(link, keep=1, min_age_s=0, protect_ids=set(), now=now) == []
    with pytest.raises(ValueError):
        snapshots.prune(base, keep=0, min_age_s=0, protect_ids=set(), now=now)


def test_a_run_prunes_old_orphan_snapshots_but_keeps_the_current_one(tmp_path):
    import dataclasses

    base, pub, cfg = setup_lab(tmp_path, "live", creds=ALL_CREDS, deny=DENY2)
    cfg = dataclasses.replace(cfg, snapshots_keep=1, snapshots_min_age_s=60)
    snaps = base / "state" / "snapshots"
    orphans = [_snap(snaps, "site", f"orphan{n}", 99_000 + n, 1_000_000.0) for n in range(3)]
    make_item(pub, "site", "b1", {"index.html": "<p>one</p>"})
    assert rn.run(cfg, transport=FakeBucket(), runner=Runner(), clock=lambda: 1_000_000.0).code == 0
    left = {p.name for p in (snaps / "site").iterdir()}
    assert any(n.startswith("b1-") for n in left)  # the one in use is there
    assert not any(o.name in left for o in orphans[1:])  # the old unreferenced ones are gone


# ----------------------------------------------------------------------------- should-fix: legacy exceptions
LEGACY_KEY = "episodes/daily_2025-12-01.json"


def _bucket_with_legacy(meta: dict) -> tuple[FakeBucket, str]:
    b = FakeBucket()
    body = json.dumps(meta).encode()
    b.objects[LEGACY_KEY] = (body, {})
    b.objects["episodes/daily_2025-12-01.mp3"] = (build_mp3(), {})
    return b, hashlib.sha256(body).hexdigest()


def _plan(b, tmp_path, legacy=None):
    client = r2.R2Client("https://store.example.test", "b", "id" * 4, "s" * 20, b)
    item = gt.load_item(episode(tmp_path), "podcast")
    return r2.plan_episode(client, item, FEED, policy(DENY2), legacy)


def test_a_reviewed_legacy_exception_excuses_deny_list_and_posture_text_only(tmp_path):
    meta = {
        "period": "daily",
        "date": "2025-12-01",
        "title": "secrethost: we run X",
        "description": "d",
    }
    b, sha = _bucket_with_legacy(meta)
    with pytest.raises(r2.FeedBlocked):
        _plan(b, tmp_path / "a")
    plan = _plan(b, tmp_path / "b", {LEGACY_KEY: sha})
    assert plan.excused == (LEGACY_KEY,) and "daily_2025-12-01" in plan.feed_xml
    # a different object under the same key (its sha256 differs) is not excused
    with pytest.raises(r2.FeedBlocked):
        _plan(b, tmp_path / "c", {LEGACY_KEY: "0" * 64})


def test_a_legacy_exception_never_excuses_a_tlp_marker_or_a_secret(tmp_path):
    for n, text in enumerate(("TLP:RED briefing", "token = " + "x" * 24)):
        meta = {"period": "daily", "date": "2025-12-01", "title": text, "description": "d"}
        b, sha = _bucket_with_legacy(meta)
        with pytest.raises(r2.FeedBlocked):
            _plan(b, tmp_path / str(n), {LEGACY_KEY: sha})


def test_legacy_exceptions_are_validated_in_the_config(tmp_path):
    from homelabnext.publishing import config as cf

    base, _pub, _cfg = setup_lab(tmp_path, "stage", deny=DENY2)
    doc = json.loads((base / "config.json").read_text())
    good = {"key": LEGACY_KEY, "sha256": "a" * 64}
    for bad in ([{"key": "../x", "sha256": "a" * 64}], [{"key": LEGACY_KEY, "sha256": "zz"}], "x"):
        (base / "config.json").write_text(json.dumps({**doc, "legacy_exceptions": bad}))
        with pytest.raises(cf.ConfigError):
            cf.load(base / "config.json")
    (base / "config.json").write_text(json.dumps({**doc, "legacy_exceptions": [good]}))
    assert cf.load(base / "config.json").legacy_exceptions == {LEGACY_KEY: "a" * 64}


# ----------------------------------------------------------------------------- nits
def cps(*parts: int | str) -> str:
    """Text from code points (ints) and plain strings, so no look-alike character sits in this file."""
    return "".join(chr(p) if isinstance(p, int) else p for p in parts)


@pytest.mark.parametrize(
    "marker",
    [
        cps(0x1D1B, 0x029F, 0x1D18, ":", 0x0280, 0x1D07, 0x1D05),  # small capitals
        cps(0x13A2, 0x13DE, 0x13E2, ":RED"),  # Cherokee
        cps(0x2CA6, "LP:RED"),  # Coptic
        cps(0x0422, "LP:RED"),  # Cyrillic
    ],
)
def test_more_look_alike_scripts_are_folded(tmp_path, marker):
    assert "tlp-above-ceiling" in rules(verdict(tmp_path, {"a.html": f"<p>{marker}</p>"}))


@pytest.mark.parametrize(
    "name",
    [
        cps("secret", 0x04BB, "ost"),  # Cyrillic shha for the h of "host"
        cps("secret", 0xFE0F, "host"),  # a variation selector: invisible
        cps("s", 0x0301, "ecrethost"),  # a combining mark
        cps(0x202E, "tsohterces"),  # a bidi override: displayed reversed, stored reversed
    ],
)
def test_a_cyrillic_h_a_variation_selector_a_combining_mark_and_a_bidi_reversal(tmp_path, name):
    assert "deny-list" in rules(verdict(tmp_path, {"a.html": f"<p>{name}</p>"}))


def test_decoding_runs_to_a_fixed_point_and_a_text_that_never_settles_is_blocked(tmp_path):
    deep = "TLP:RED"
    for _ in range(6):
        deep = urllib.parse.quote(deep, safe="")
    assert "tlp-above-ceiling" in rules(verdict(tmp_path / "a", {"a.html": deep}))  # still decoded
    never = "TLP:RED"
    for _ in range(12):
        never = urllib.parse.quote(never, safe="")
    assert "decoding-not-converged" in rules(verdict(tmp_path / "b", {"a.html": never}))
    with pytest.raises(normalise.NotConverged):
        normalise.canon(never)


# ----------------------------------------------------------------------------- the surviving mutant
def test_run_in_stage_mode_sends_nothing_even_for_a_blocked_item(tmp_path):
    _base, pub, cfg = notify_lab(tmp_path, "stage")
    make_item(pub, "site", "b1", {"a.html": "secrethost"})  # a blocked item would page elsewhere
    opener = RecordingOpener()
    n = rn.build_notifier(cfg, opener=opener)
    rep = rn.run(cfg, notifier=n)
    assert rep.blocked == ["b1"] and opener.calls == []
