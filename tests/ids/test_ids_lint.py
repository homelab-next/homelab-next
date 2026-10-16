# SPDX-License-Identifier: Apache-2.0
import pytest

# Built from parts so the repository text never contains a private-range literal.
PRIV4 = ".".join(["10", "1", "2", "3"])
PRIV4B = ".".join(["172", "16", "4", "1"])
PRIV4C = ".".join(["10", "0", "0", "5"])
ULA6 = "fd" + "00::1"

from homelabnext.ids import lint_id, scan_document, scan_text


def codes(vs):
    return {v.code for v in vs}


def test_clean_ids_have_no_violations():
    for t in ("cap:lake-query", "det:auth-failure-burst", "table:ocsf.authentication"):
        assert lint_id(t) == []


@pytest.mark.parametrize(
    "text,code",
    [
        ("viking://resources/charters/reader", "PRODUCT_URI"),
        ("det:viking://x", "PRODUCT_URI"),
        ("svc:192.0.2.10", "IP_LITERAL"),  # even documentation addresses are refused inside an id
        (f"svc:{PRIV4}", "IP_LITERAL"),
        ("svc:2001:db8::1", "IP_LITERAL"),
        ("det:rule-900299", "RULE_NUMBER"),
        ("det:900299", "RULE_NUMBER"),
        ("det:sid2001", "RULE_NUMBER"),
        ("det:Auth", "GRAMMAR"),
    ],
)
def test_lint_id_flags(text, code):
    assert code in codes(lint_id(text))


def test_scan_text_viking_uri():
    assert codes(scan_text("read viking://resources/x for context")) == {"PRODUCT_URI"}


def test_scan_text_ips_documentation_allowed_by_default():
    assert scan_text("host 192.0.2.7 and 198.51.100.1 and 2001:db8::5") == []
    assert codes(scan_text("host 192.0.2.7", allow_documentation=False)) == {"IP_LITERAL"}


@pytest.mark.parametrize("text", [f"see {PRIV4C}", f"gateway {PRIV4B}", f"v6 {ULA6}"])
def test_scan_text_real_looking_ips_flagged(text):
    assert "IP_LITERAL" in codes(scan_text(text))


@pytest.mark.parametrize(
    "text",
    [
        "rule 900299 fires",
        "Rule ID: 900299",
        "rule_id=900299",
        "sid: 2001234",
        "signature id 900001",
    ],
)
def test_scan_text_rule_numbers_flagged(text):
    assert "RULE_NUMBER" in codes(scan_text(text))


def test_scan_text_ignores_innocent_numbers():
    assert scan_text("retry 3 times, 2026-01-01, version 1.2.3, port 8080 of 5 rules") == []


def test_scan_document_walks_structures_and_reports_paths():
    doc = {
        "charter": {
            "detections": ["det:auth-failure-burst", "det:rule-900299"],
            "ctx": "viking://a/b",
            "note": "ok",
        }
    }
    vs = scan_document(doc)
    assert {(v.code, v.where) for v in vs} == {
        ("RULE_NUMBER", "$.charter.detections[1]"),
        ("PRODUCT_URI", "$.charter.ctx"),
    }


def test_scan_document_clean():
    assert scan_document({"a": ["cap:lake-query", "free text 192.0.2.4"]}) == []
