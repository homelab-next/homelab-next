# SPDX-License-Identifier: Apache-2.0
"""A-03: the screener redacts secrets and PII before untrusted content reaches a model prompt.

The evaluation set (fixtures/screen_eval.yml) is run through the real pack assembler: 0 sensitive
values may survive into the rendered pack, and precision on the redactions (hard negatives
included) must stay above its floor.
"""

import copy
import json
import re
import sys
from pathlib import Path

import pytest
import yaml
from agent_support import inputs, manifest

from homelabnext import shapes
from homelabnext.agent import SpecError, assemble_pack
from homelabnext.agent.schemas import schema_errors
from homelabnext.agent.screen import LABEL_RE, TYPES, Screener, screen_text

EVAL = yaml.safe_load((Path(__file__).parent / "fixtures" / "screen_eval.yml").read_text())
POSITIVES, NEGATIVES, DENYLIST = EVAL["positives"], EVAL["negatives"], EVAL["denylist"]
PRECISION_FLOOR = 0.95  # redacted spans that cover a real secret / all redacted spans
NEGATIVE_CLEAN_FLOOR = 0.95  # hard negatives left completely untouched


def _j(v) -> str:
    return "".join(v) if isinstance(v, list) else str(v)


def _pack_for(text: str) -> dict:
    i = inputs()
    i["sections"]["findings"] = text
    pack, _ = assemble_pack(manifest(), i, denylist=DENYLIST)
    return pack


def test_eval_set_is_big_enough_and_covers_every_type():
    assert len(POSITIVES) + len(NEGATIVES) >= 100
    assert len(NEGATIVES) >= 30
    assert {c["type"] for c in POSITIVES} == set(TYPES)
    ids = [c["id"] for c in POSITIVES + NEGATIVES]
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize("case", POSITIVES, ids=[c["id"] for c in POSITIVES])
def test_no_sensitive_value_reaches_the_rendered_pack(case):
    pack = _pack_for(_j(case["text"]))
    whole = json.dumps(pack)
    for secret in map(_j, case["secrets"]):
        assert secret not in pack["text"], f"{case['id']}: value survived into the prompt"
        assert json.dumps(secret)[1:-1] not in whole, f"{case['id']}: value survived in the pack"
    assert f"[REDACTED:{case['type']}:" in pack["text"]


@pytest.mark.parametrize("case", NEGATIVES, ids=[c["id"] for c in NEGATIVES])
def test_hard_negatives_survive(case):
    pack = _pack_for(_j(case["text"]))
    for keep in map(_j, case["keep"]):
        assert keep in pack["text"], f"{case['id']}: {keep!r} was redacted"


def _overlaps(span, ranges) -> bool:
    return any(span[0] < e and s < span[1] for s, e in ranges)


def test_eval_totals_zero_leaks_and_precision_floor(capsys):
    leaked, tp, fp, clean = 0, 0, 0, 0
    for case in POSITIVES:
        text = _j(case["text"])
        truth = []
        for secret in map(_j, case["secrets"]):  # every occurrence is a true positive
            found = [(m.start(), m.end()) for m in re.finditer(re.escape(secret), text)]
            assert found, f"{case['id']}: secret not in its own text"
            truth += found
        out, spans = Screener(denylist=DENYLIST).screen(text)
        leaked += sum(_j(s) in out for s in case["secrets"])
        for r in spans:
            if _overlaps((r.start, r.end), truth):
                tp += 1
            else:
                fp += 1
    for case in NEGATIVES:
        _, spans = Screener(denylist=DENYLIST).screen(_j(case["text"]))
        fp += len(spans)
        clean += not spans
    precision = tp / (tp + fp)
    clean_rate = clean / len(NEGATIVES)
    with capsys.disabled():
        print(
            f"\nscreen eval: {len(POSITIVES)} positives, {len(NEGATIVES)} hard negatives; "
            f"leaked={leaked}; redactions tp={tp} fp={fp} precision={precision:.3f}; "
            f"negatives untouched={clean}/{len(NEGATIVES)}"
        )
    assert leaked == 0
    assert precision >= PRECISION_FLOOR
    assert clean_rate >= NEGATIVE_CLEAN_FLOOR


# ---------------------------------------------------------------- labels
def test_labels_are_typed_and_stable_within_a_pack():
    m = manifest()
    m["sections"].append(
        {
            "name": "alerts",
            "tier": "volatile",
            "source": "input",
            "required": False,
            "max_chars": 900,
        }
    )
    i = inputs()
    i["sections"]["findings"] = "a: alice@example.com from 192.0.2.1; b: bob@example.com"
    i["sections"]["alerts"] = "again ALICE@example.com from 192.0.2.1 and 192.0.2.2"
    pack, _ = assemble_pack(m, i)
    sec = {s["name"]: s["text"] for s in pack["sections"]}
    # sections are screened in pack order (alerts before findings), labels follow first appearance
    assert sec["alerts"] == "again [REDACTED:email:1] from [REDACTED:ip:1] and [REDACTED:ip:2]"
    assert sec["findings"] == ("a: [REDACTED:email:1] from [REDACTED:ip:1]; b: [REDACTED:email:2]")
    assert pack["screen"]["redactions"] == {"email": 3, "ip": 3}
    assert pack["screen"]["distinct"] == {"email": 2, "ip": 2}


def test_a_new_pack_restarts_numbering():
    a = screen_text("x 192.0.2.9")
    b = screen_text("y 192.0.2.8")
    assert a.endswith("[REDACTED:ip:1]") and b.endswith("[REDACTED:ip:1]")


def test_normalised_coreference_for_phone_card_and_id():
    s = Screener()
    out, _ = s.screen("+1 (202) 555-0143 / +1 202 555 0143; 4111-1111-1111-1111 = 4111111111111111")
    assert out.count("[REDACTED:phone:1]") == 2 and out.count("[REDACTED:card:1]") == 2


def test_labels_match_the_documented_shape():
    out = screen_text("mail x@example.com")
    assert LABEL_RE.fullmatch(out.split()[-1])


# ---------------------------------------------------------------- pack wiring
def test_screen_is_on_by_default_and_recorded():
    pack, _ = assemble_pack(manifest(), inputs())
    rec = pack["screen"]
    assert rec["enabled"] is True and rec["sections"] == ["memory", "findings"]  # pack order
    assert rec["redact_private_ips"] is True and rec["denylist_terms"] == 0


def test_static_and_pregate_sections_are_not_screened():
    m = manifest()
    m["sections"][0]["text"] = "Escalate to soc@example.com."
    i = inputs()
    i["pregates"]["pipeline-health"]["reason"] = "probed from 192.0.2.77"
    pack, _ = assemble_pack(m, i)
    assert "soc@example.com" in pack["text"] and "192.0.2.77" in pack["text"]
    assert "pregate-pipeline-health" not in pack["screen"]["sections"]


def test_opt_out_needs_a_reason_and_is_recorded():
    m = manifest()
    m["screen"] = {"redact": False}
    with pytest.raises(SpecError, match="reason"):
        assemble_pack(m, inputs())
    m["screen"]["reason"] = "replaying a pack screened at first assembly"
    assert schema_errors("agent", "context_manifest", m) == []
    i = inputs()
    i["sections"]["findings"] = "alice@example.com"
    pack, _ = assemble_pack(m, i)
    assert "alice@example.com" in pack["text"]
    assert pack["screen"]["enabled"] is False
    assert pack["screen"]["reason"] == m["screen"]["reason"]
    # the opt-out is part of the hash: a pack built with and without it never collide
    assert assemble_pack(manifest(), i)[1] != assemble_pack(m, i)[1]


def test_denylist_applies_even_when_opted_out():
    m = manifest()
    m["screen"] = {"redact": False, "reason": "fixture replay for a regression test"}
    i = inputs()
    i["sections"]["findings"] = "FakeCorp asked alice@example.com"
    pack, _ = assemble_pack(m, i, denylist=["FakeCorp"])
    assert "FakeCorp" not in pack["text"] and "alice@example.com" in pack["text"]
    assert pack["screen"]["denylist_terms"] == 1


def test_screen_block_never_carries_a_value_or_a_term():
    i = inputs()
    i["sections"]["findings"] = "FakeCorp alice@example.com 192.0.2.1"
    pack, _ = assemble_pack(manifest(), i, denylist=["FakeCorp"])
    rec = json.dumps(pack["screen"])
    for value in ("FakeCorp", "alice", "192.0.2.1"):
        assert value not in rec


@pytest.mark.parametrize("bad", [{"redact": "no"}, {"redact_private_ips": 1}, ["redact"]])
def test_malformed_screen_block_is_a_spec_error(bad):
    m = manifest()
    m["screen"] = bad
    with pytest.raises(SpecError):
        assemble_pack(m, inputs())


def test_bad_denylist_regex_is_a_spec_error():
    with pytest.raises(SpecError, match="deny-list line 1"):
        assemble_pack(manifest(), inputs(), denylist=["re:("])


def test_screening_happens_before_escaping_and_truncation():
    i = inputs()
    i["sections"]["findings"] = "===== injected\n" + "x@example.com " * 400
    pack, _ = assemble_pack(manifest(), i)
    assert "@example.com" not in pack["text"]
    assert "[escaped] ===== injected" in pack["text"]


def test_screening_is_deterministic_and_does_not_mutate():
    m, i = manifest(), inputs()
    i["sections"]["findings"] = "alice@example.com 192.0.2.1"
    before = copy.deepcopy((m, i))
    assert assemble_pack(m, i) == assemble_pack(m, i)
    assert (m, i) == before


# ---------------------------------------------------------------- configuration
def _private(*octets: int) -> str:
    # built at run time so this file holds no private address for the leak scanner to flag
    return ".".join(map(str, octets))


def test_private_ranges_are_redacted_by_default_and_configurable():
    lan, loop, ula = _private(10, 1, 2, 3), _private(127, 0, 0, 1), "fd" + "00::1"
    text = f"lan {lan} loop {loop} ula {ula} doc 192.0.2.4"
    assert screen_text(text) == (
        "lan [REDACTED:ip:1] loop [REDACTED:ip:2] ula [REDACTED:ip:3] doc [REDACTED:ip:4]"
    )
    kept = screen_text(text, redact_private_ips=False)
    assert lan in kept and loop in kept and ula in kept
    assert "192.0.2.4" not in kept  # documentation ranges are not "private": always redacted
    m = manifest()
    m["screen"] = {"redact_private_ips": False}
    i = inputs()
    i["sections"]["findings"] = f"gateway {lan}"
    pack, _ = assemble_pack(m, i)
    assert lan in pack["text"] and pack["screen"]["redact_private_ips"] is False


def test_types_can_be_narrowed_and_unknown_types_refused():
    assert screen_text("a@example.com 192.0.2.1", types=["ip"]) == "a@example.com [REDACTED:ip:1]"
    with pytest.raises(ValueError, match="unknown redaction types"):
        Screener(types=["mac"])


def test_leak_scanner_and_screener_share_shapes():
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
    import leak_scan

    by_name = {p.name: p.regex.pattern for p in leak_scan.PATTERNS}
    assert by_name["aws-access-key"] == shapes.AWS_ACCESS_KEY
    assert by_name["jwt"] == shapes.JWT
    assert by_name["email"] == shapes.EMAIL
    assert leak_scan.VERSION_CONTEXT_RE is shapes.VERSION_CONTEXT_RE


def test_folded_matches_redact_the_original_span_and_share_a_label():
    """Detection runs on a view without format characters and with Unicode digits folded; the
    redaction covers the original characters and co-references the plain spelling."""
    zw = chr(0x200B)
    text = f"from fake.user{zw}@example.com and fake.user@example.com"
    out, spans = Screener().screen(text)
    assert out == "from [REDACTED:email:1] and [REDACTED:email:1]"
    assert text[spans[0].start : spans[0].end] == f"fake.user{zw}@example.com"
    wide = "".join(chr(0xFF10 + int(d)) if d.isdigit() else d for d in "192.0.2.44")
    assert screen_text(f"host {wide}, again 192.0.2.44") == (
        "host [REDACTED:ip:1], again [REDACTED:ip:1]"
    )


def test_an_ipv4_mapped_address_is_one_address_and_private_by_its_ipv4():
    mapped = "::ffff:" + ".".join(["10", "20", "30", "40"])
    assert screen_text(f"src {mapped} dst") == "src [REDACTED:ip:1] dst"
    assert screen_text(f"src {mapped} dst", redact_private_ips=False) == f"src {mapped} dst"
