# SPDX-License-Identifier: Apache-2.0
"""``maintained_upstream`` (schema 1.1): shipped profiles never expire, overlays always do."""

from __future__ import annotations

import json
from datetime import date

import pytest
from cust_helpers import TODAY, make_doc, write_custom

from homelabnext.customization import lint, load_tree
from homelabnext.customization.cli import main as custom_main
from homelabnext.customization.loader import REPO_ROOT, validate_doc
from homelabnext.customization.plugins import x09_customizations as x09
from homelabnext.customization.register import render_register, state_of
from homelabnext.invariants import Context

FAR = date(2035, 6, 1)  # well past every review_by in the tree
FROZEN = REPO_ROOT / "schemas" / "_frozen"


def shipped_doc(**over):
    """A valid shipped-profile style document: maintained upstream, no review_by."""
    return make_doc(maintained_upstream=True, review_by=None, **over)


def codes(findings):
    return sorted({f.code for f in findings})


# ---- schema ------------------------------------------------------------------------------------


def test_schema_id_is_minor_2_and_baselines_exist():
    """1.1 added maintained_upstream; 1.2 lets a link name a record by uid (ADR-0019)."""
    schema = json.loads((REPO_ROOT / "schemas/platform/customization.schema.json").read_text())
    assert schema["$id"].endswith("/platform/customization/1.2")
    for minor in ("1.0", "1.1", "1.2"):
        assert (FROZEN / f"{minor}/platform/customization.schema.json").is_file()


def test_every_1_0_document_still_validates():
    """Additive: the 1.0 examples validate under 1.1 and the frozen 1.0 baseline, unchanged."""
    from jsonschema import Draft202012Validator

    old = json.loads((FROZEN / "1.0/platform/customization.schema.json").read_text())
    assert old["$id"].endswith("/1.0")
    old_required = set(old["required"])
    assert "review_by" in old_required
    docs = [
        json.loads(p.read_text())
        for p in sorted((REPO_ROOT / "schemas/platform/examples").glob("customization.*.json"))
        if "maintained" not in p.name
    ]
    assert len(docs) >= 6
    for d in docs:
        assert "maintained_upstream" not in d and "review_by" in d
        assert validate_doc(d) == [], d["id"]
        # the 1.0 baseline accepts them too (shape check; $ref targets are not needed for required)
        assert old_required <= set(d)
    # and nothing in the 1.0 property set was lost
    new = json.loads((REPO_ROOT / "schemas/platform/customization.schema.json").read_text())
    assert set(old["properties"]) <= set(new["properties"])
    assert set(new["properties"]) - set(old["properties"]) == {"maintained_upstream"}
    assert Draft202012Validator.check_schema(new) is None


def test_default_is_false_and_review_by_still_required_without_the_flag():
    assert validate_doc(make_doc()) == []
    errs = validate_doc(make_doc(review_by=None))
    assert errs and any("review_by" in e for e in errs)
    errs = validate_doc(make_doc(review_by=None, maintained_upstream=False))
    assert errs and any("review_by" in e for e in errs)


def test_maintained_upstream_true_makes_review_by_optional_in_schema():
    assert validate_doc(shipped_doc()) == []
    assert validate_doc(make_doc(maintained_upstream=True)) == []  # may keep review_by


@pytest.mark.parametrize("bad", ["yes", 1, "true", None, [], {}])
def test_non_boolean_fails_schema(bad):
    errs = validate_doc({**make_doc(), "maintained_upstream": bad})
    assert errs and any("maintained_upstream" in e for e in errs)


# ---- lint: provenance is the loader's source root ------------------------------------------------


def test_overlay_with_flag_is_rejected_cu015(tmp_path, uni):
    write_custom(tmp_path, "a", make_doc(maintained_upstream=True))
    items, problems = load_tree(tmp_path, "local")
    assert not problems and not items[0].upstream_maintained
    assert "CU015" in codes(lint(items, uni, TODAY))


def test_overlay_flag_without_review_by_is_rejected_twice(tmp_path, uni):
    write_custom(tmp_path, "a", shipped_doc())
    items, _ = load_tree(tmp_path, "local")
    got = codes(lint(items, uni, TODAY))
    assert "CU015" in got and "CU007" in got  # forged exemption, and the review_by it lacks


def test_overlay_flag_does_not_stop_expiry(tmp_path, uni):
    write_custom(tmp_path, "a", make_doc(maintained_upstream=True))
    items, _ = load_tree(tmp_path, "local")
    got = codes(lint(items, uni, date(2027, 6, 1)))
    assert "CU008" in got and "CU015" in got
    assert state_of(items[0], date(2027, 6, 1), {}) == "expired"


def test_same_file_is_exempt_only_when_loaded_as_shipped(tmp_path, uni):
    write_custom(tmp_path, "a", shipped_doc())
    shipped, _ = load_tree(tmp_path, "public")
    overlay, _ = load_tree(tmp_path, "local")
    assert shipped[0].upstream_maintained and not overlay[0].upstream_maintained
    assert lint(shipped, uni, FAR) == []
    assert "CU015" in codes(lint(overlay, uni, FAR))


def test_shipped_with_flag_keeps_other_date_checks(tmp_path, uni):
    write_custom(tmp_path, "a", make_doc(maintained_upstream=True, review_by="2026-08-01"))
    items, _ = load_tree(tmp_path, "public")  # review_by before created
    assert "CU007" in codes(lint(items, uni, FAR))


def test_flag_false_in_shipped_dir_still_expires(tmp_path, uni):
    write_custom(tmp_path, "a", make_doc())
    items, _ = load_tree(tmp_path, "public")
    assert "CU008" in codes(lint(items, uni, FAR))


# ---- shipped profiles at a far-future date ---------------------------------------------------


def test_the_three_profiles_are_flagged_and_never_expire(uni):
    items, problems = load_tree(REPO_ROOT / "profiles", "public")
    assert not problems and len(items) == 3
    assert all(c.doc["maintained_upstream"] is True and c.upstream_maintained for c in items)
    for today in (TODAY, date(2028, 1, 1), FAR):
        assert lint(items, uni, today) == [], today


def test_x09_passes_shipped_profiles_far_in_the_future():
    r = x09.make_check(lambda: FAR).fn(Context(REPO_ROOT))
    assert r.status == "pass", r.evidence


def test_x09_still_fails_an_expired_overlay_while_shipped_pass(tmp_path):
    (tmp_path / "profiles").mkdir()
    write_custom(
        tmp_path / "profiles",
        "p",
        shipped_doc(
            id="custom:shipped-one",
            action={"role": "example_service", "vars": {"example_service_other_setting": 1}},
        ),
    )
    write_custom(tmp_path / "customizations", "u", make_doc(review_by="2026-12-01"))
    ok = x09.make_check(lambda: TODAY).fn(Context(tmp_path))
    assert ok.status == "pass", ok.evidence
    late = x09.make_check(lambda: FAR).fn(Context(tmp_path))
    assert late.status == "fail"
    assert "CU008" in late.evidence and "custom:test-port" in late.evidence
    assert "custom:shipped-one" not in late.evidence


def test_x09_fails_on_forged_flag_in_overlay(tmp_path):
    write_custom(tmp_path / "customizations", "u", shipped_doc())
    r = x09.make_check(lambda: TODAY).fn(Context(tmp_path))
    assert r.status == "fail" and "CU015" in r.evidence


def test_x09_env_dir_is_an_overlay_too(tmp_path, monkeypatch):
    env_dir = tmp_path / "env"
    write_custom(env_dir, "u", shipped_doc())
    monkeypatch.setenv("HNX_CUSTOMIZATIONS_DIR", str(env_dir))
    (tmp_path / "root").mkdir()
    r = x09.make_check(lambda: TODAY).fn(Context(tmp_path / "root"))
    assert r.status == "fail" and "CU015" in r.evidence


# ---- hnx custom check / list / register ------------------------------------------------------


@pytest.fixture
def clean_env(monkeypatch):
    monkeypatch.delenv("HNX_CUSTOMIZATIONS_DIR", raising=False)
    monkeypatch.delenv("HNX_CUSTOMIZATIONS_CONFIG", raising=False)


def test_cli_check_shipped_profiles_pass_far_future(clean_env, capsys):
    assert custom_main(["check", "--today", FAR.isoformat(), "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == []


def test_cli_check_overlay_with_old_review_by_fails_and_flag_is_rejected(
    clean_env, tmp_path, capsys
):
    write_custom(tmp_path, "old", make_doc(review_by="2026-12-01"))
    write_custom(tmp_path, "forged", make_doc(id="custom:forged-one", maintained_upstream=True))
    rc = custom_main(["check", "--dir", str(tmp_path), "--today", FAR.isoformat(), "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 1
    by_id = {(f["customization"], f["code"]) for f in out}
    assert ("custom:test-port", "CU008") in by_id
    assert ("custom:forged-one", "CU015") in by_id
    assert not [f for f in out if f["customization"].startswith("custom:board-sensor")]


def test_cli_list_marks_upstream_maintained(clean_env, capsys):
    assert custom_main(["list", "--today", FAR.isoformat(), "--json"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert rows and all(r["upstream_maintained"] and r["state"] == "inactive" for r in rows)


def test_register_marks_upstream_maintained_entries(tmp_path):
    shipped, _ = load_tree(REPO_ROOT / "profiles", "public")
    write_custom(tmp_path, "u", make_doc())
    overlay, _ = load_tree(tmp_path, "local")
    html, data = render_register([*shipped, *overlay], FAR)
    rows = {r["id"]: r for r in data["customizations"]}
    assert all(rows[c.id]["upstream_maintained"] for c in shipped)
    assert rows["custom:test-port"]["upstream_maintained"] is False
    assert rows["custom:test-port"]["state"] == "expired"
    assert html.count("maintained upstream") >= len(shipped)
    assert "never expires" in html
