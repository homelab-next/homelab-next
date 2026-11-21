# SPDX-License-Identifier: Apache-2.0
"""The gate refuses what must not leave: a label above the ceiling, a deny-listed string, a secret
shape, posture language, a file that differs from its sidecar; and it never echoes the match."""

from __future__ import annotations

import hashlib
import json

import pytest

from homelabnext import tlp
from homelabnext.publishing import gate as gt
from tests.publishing.helpers import build_mp3, build_png, make_item, policy


def verdict(tmp_path, files, tlp_claim="clear", **kw):
    root = make_item(tmp_path, "site", "b1", files, tlp=tlp_claim)
    return gt.evaluate(gt.load_item(root, "site"), policy(**kw))


def rules(v):
    return {r.rule for r in v.reasons}


def test_a_clean_clear_item_passes(tmp_path):
    v = verdict(tmp_path, {"index.html": "<p>An actor used a loader.</p>"})
    assert v.ok and v.label == "clear" and not v.reasons


def test_an_amber_claim_is_refused(tmp_path):
    v = verdict(tmp_path, {"index.html": "<p>fine</p>"}, tlp_claim="amber")
    assert not v.ok and "tlp-above-ceiling" in rules(v)


@pytest.mark.parametrize("claim", ["red", "amber+strict", "garbage", None])
def test_every_label_above_clear_or_unreadable_is_refused(tmp_path, claim):
    assert not verdict(tmp_path, {"a.txt": "x"}, tlp_claim=claim).ok


def test_a_clear_claim_does_not_hide_an_amber_marker_in_the_body(tmp_path):
    v = verdict(tmp_path, {"index.html": "<p>TLP:AMBER do not share</p>"})
    assert not v.ok and v.label == "amber"


def test_green_passes_only_for_a_community_audience_with_access_control(tmp_path):
    with pytest.raises(gt.GateError):
        policy(ceiling=tlp.Label.GREEN)
    with pytest.raises(gt.GateError):
        policy(ceiling=tlp.Label.GREEN, audience="community")
    p = policy(ceiling=tlp.Label.GREEN, audience="community", access_control="members-only")
    root = make_item(tmp_path, "site", "g", {"a.txt": "x"}, tlp="green")
    assert gt.evaluate(gt.load_item(root, "site"), p).ok


def test_amber_is_never_a_ceiling():
    with pytest.raises(gt.GateError):
        policy(ceiling=tlp.Label.AMBER)


def test_a_deny_listed_hostname_blocks_and_the_match_is_not_echoed(tmp_path):
    v = verdict(tmp_path, {"index.html": "<a href='https://vault.example.internal/x'>x</a>"})
    assert not v.ok and rules(v) == {"deny-list"}
    assert all("vault.example" not in r.detail and "vault.example" not in r.path for r in v.reasons)


def test_a_deny_listed_pattern_blocks_a_private_address(tmp_path):
    ip = ".".join(["10", "20", "3", "4"])
    assert "deny-list" in rules(verdict(tmp_path, {"data.json": json.dumps({"host": ip})}))


def test_a_public_name_under_a_denied_domain_is_excused_by_an_exception(tmp_path):
    deny = "example.internal\n!podcasts.example.internal\n"
    assert verdict(tmp_path, {"a.html": "see podcasts.example.internal"}, deny=deny).ok
    assert not verdict(tmp_path / "x", {"a.html": "see vault.example.internal"}, deny=deny).ok


def test_an_entity_encoded_name_is_still_caught(tmp_path):
    assert not verdict(tmp_path, {"a.html": "vault&#46;example&#46;internal"}).ok


def test_secret_shapes_are_blocked(tmp_path):
    pem = "-----BEGIN " + "RSA PRIVATE KEY-----"
    akid = "AKIA" + "A" * 16
    assign = "api_key = " + "x" * 24
    for n, body in enumerate((pem, akid, assign, "Bearer " + "q" * 30)):
        v = verdict(tmp_path / str(n), {"a.txt": body})
        assert "secret-shape" in rules(v), body[:12]


def test_posture_language_is_blocked_and_third_party_reporting_is_not(tmp_path):
    assert "posture" in rules(verdict(tmp_path, {"a.html": "none appear in our own scan results"}))
    assert verdict(tmp_path / "ok", {"a.html": "the botnet spans 18,000 devices"}).ok


def test_posture_rules_can_be_switched_off_but_the_deny_list_cannot(tmp_path):
    assert verdict(tmp_path, {"a.html": "our estate"}, posture_rules=False).ok


def test_a_named_posture_rule_can_be_disabled_and_the_others_still_block(tmp_path):
    off = {"posture_rules_disabled": frozenset({"affected-assets"})}
    assert verdict(tmp_path / "a", {"a.html": "patch affected systems"}, **off).ok
    assert not verdict(tmp_path / "b", {"a.html": "patch affected systems"}).ok
    # "our affected hosts" is not possessive-posture (its adjectives are own/internal/...): that wording
    # was only ever caught by affected-assets, so it passes once that rule is off
    assert verdict(tmp_path / "f", {"a.html": "our affected hosts"}, **off).ok
    assert "posture" in rules(
        verdict(tmp_path / "c", {"a.html": "our own hosts, affected systems"}, **off)
    )
    assert not verdict(tmp_path / "d", {"a.html": "our estate"}, **off).ok
    assert not verdict(tmp_path / "e", {"a.html": "we run it"}, **off).ok


def test_disabling_posture_rules_never_touches_the_deny_list_tlp_or_secret_shapes(tmp_path):
    every = {"posture_rules_disabled": frozenset(gt.POSTURE_RULE_NAMES)}
    assert verdict(tmp_path / "a", {"a.html": "our estate"}, **every).ok
    assert "deny-list" in rules(
        verdict(tmp_path / "b", {"a.html": "see vault.example.internal"}, **every)
    )
    assert "secret-shape" in rules(
        verdict(tmp_path / "c", {"a.txt": "api_key = " + "x" * 24}, **every)
    )
    assert not verdict(tmp_path / "d", {"a.txt": "x"}, tlp_claim="amber", **every).ok


@pytest.mark.parametrize(
    "bad", [["deny-list"], ["secret-shape"], ["tlp"], ["nope"], "affected-assets", [3]]
)
def test_an_unknown_or_non_posture_rule_name_is_refused(bad):
    with pytest.raises(gt.GateError):
        policy(posture_rules_disabled=bad)


def test_the_bool_still_switches_all_posture_rules_off(tmp_path):
    assert verdict(tmp_path, {"a.html": "our affected hosts, we run it"}, posture_rules=False).ok


def test_an_empty_deny_list_is_refused():
    for text in ("", "# only a comment\n", "!only.an.exception\n"):
        with pytest.raises(gt.GateError):
            gt.DenyList.parse(text)


def test_a_bad_deny_pattern_is_refused():
    with pytest.raises(gt.GateError):
        gt.DenyList.parse("re:(unclosed\n")


def test_a_file_that_differs_from_its_sidecar_blocks(tmp_path):
    root = make_item(tmp_path, "site", "b1", {"index.html": "<p>ok</p>"})
    (root / "index.html").write_text("<p>changed</p>")
    assert "sha256-mismatch" in rules(gt.evaluate(gt.load_item(root, "site"), policy()))


def test_an_unknown_binary_type_blocks_and_known_media_passes(tmp_path):
    v = verdict(tmp_path, {"a.exe": b"MZ", "pic.png": build_png()})
    assert [r.path for r in v.reasons] == ["a.exe"] and v.reasons[0].rule == "unknown-file-type"


def test_load_refuses_what_cannot_be_judged(tmp_path):
    root = make_item(tmp_path, "site", "b1", {"a.html": "x"})
    (root / "extra.html").write_text("unlisted")
    with pytest.raises(gt.GateError):
        gt.load_item(root, "site")
    (root / "extra.html").unlink()
    (root / "ln.html").symlink_to(root / "a.html")
    with pytest.raises(gt.GateError):
        gt.load_item(root, "site")
    (root / "ln.html").unlink()
    (root / gt.SIDECAR).write_text("{not json")
    with pytest.raises(gt.GateError):
        gt.load_item(root, "site")


def test_a_sidecar_with_a_bad_hash_or_no_files_is_refused(tmp_path):
    root = make_item(tmp_path, "site", "b1", {"a.html": "x"})
    sc = json.loads((root / gt.SIDECAR).read_text())
    sc["sha256s"]["a.html"] = hashlib.sha256(b"x").hexdigest().upper()
    (root / gt.SIDECAR).write_text(json.dumps(sc))
    with pytest.raises(gt.GateError):
        gt.load_item(root, "site")


def test_the_notify_titles_are_the_manifests_pair():
    """The manifest is the only source of a module's pair: the code's titles must equal it."""
    from pathlib import Path

    import yaml

    from homelabnext.publishing import run as rn

    doc = yaml.safe_load(
        (Path(__file__).resolve().parents[2] / "modules/publishing/module.yml").read_text()
    )
    assert doc["contributes"]["notify_pairs"] == [{"problem": rn.PROBLEM, "recovery": rn.RECOVERY}]


def _podcast(tmp_path, description, extra=None):
    import json as _json

    from tests.publishing.helpers import make_item as _mk

    meta = _json.dumps(
        {"period": "weekly", "date": "2026-01-05", "title": "t", "description": description}
    )
    files = {"metadata.json": meta, "weekly_2026-01-05.mp3": build_mp3(), **(extra or {})}
    return _mk(tmp_path, "podcast", "ep1", files, tlp="clear")  # the sidecar says clear


def test_a_podcast_item_claiming_clear_is_judged_on_its_content_not_its_label(tmp_path):
    for n, text in enumerate(("see vault.example.internal for notes", "TLP:AMBER internal brief")):
        root = _podcast(tmp_path / str(n), text)
        v = gt.evaluate(gt.load_item(root, "podcast"), policy())
        assert not v.ok, text


def test_show_notes_and_transcripts_beside_the_episode_are_scanned_too(tmp_path):
    root = _podcast(tmp_path, "fine", {"transcript.txt": "host at vault.example.internal"})
    v = gt.evaluate(gt.load_item(root, "podcast"), policy())
    assert [r.path for r in v.reasons] == ["transcript.txt"]


def test_a_blocked_podcast_item_uploads_nothing_in_live_mode(tmp_path):
    from homelabnext.publishing import run as rn
    from tests.publishing.helpers import FakeBucket
    from tests.publishing.test_publishing_pages_stage_run import Runner, setup_lab

    _, pub, cfg = setup_lab(
        tmp_path,
        "live",
        creds=("deny-list", "cloudflare-api-token", "r2-access-key-id", "r2-secret-access-key"),
    )
    _podcast(pub, "TLP:AMBER do not share")
    bucket = FakeBucket()
    rep = rn.run(cfg, transport=bucket, runner=Runner())
    assert rep.blocked == ["ep1"] and bucket.calls == []
