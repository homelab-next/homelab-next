# SPDX-License-Identifier: Apache-2.0
"""A customization's ``links``: a uid, or a legacy code resolved through ``aliases.yml`` with
one warning naming the uid; an unknown or retired code is an error (ADR-0019)."""

from __future__ import annotations

import dataclasses
import warnings

import pytest
from cust_helpers import TODAY, load_one, make_doc, write_custom

from homelabnext.customization import lint, render_register
from homelabnext.customization.links import resolve_links, rewrite_links, warn_legacy
from homelabnext.identity.aliases import AliasMap, LegacyRecordCode, load_aliases

LL3 = "01a15e4e-758c-7313-9e19-d41a6db86c3d"  # examples/registers: the lesson once LL-003
RB1 = "01a15e4e-758c-7316-80d6-f77f5bb552dc"  # ... and the runbook once RB-001


def one(uni, tmp_path, **links):
    write_custom(tmp_path, "c", make_doc(links=links))
    return lint(load_one(tmp_path), uni, TODAY)


def by(findings, code):
    return [f for f in findings if f.code == code]


def test_the_example_aliases_are_the_ones_these_tests_name(repo_root):
    codes = load_aliases(repo_root / "examples/registers").codes
    assert codes["LL-003"] == LL3 and codes["RB-001"] == RB1


def test_a_uid_link_is_clean(uni, tmp_path):
    assert one(uni, tmp_path, lesson=LL3, runbook=RB1) == []


def test_a_legacy_code_resolves_with_one_warning_naming_the_uid(uni, tmp_path):
    f = one(uni, tmp_path, lesson="LL-003")
    assert [x.code for x in f] == ["CU017"] and f[0].severity == "warning"
    assert "LL-003" in f[0].message and LL3 in f[0].message and "(LL 3)" in f[0].message


@pytest.mark.parametrize(
    ("links", "why"),
    [
        ({"lesson": "LL-900"}, "LL-900 is not in aliases.yml"),
        ({"runbook": "RB-900"}, "RB-900 is not in aliases.yml"),
        ({"lesson": "01a15e4e-0000-7000-8000-00000000000f"}, "no lesson in the registers"),
        ({"lesson": RB1}, "is a runbook, not a lesson"),
    ],
)
def test_an_unresolvable_link_is_an_error(uni, tmp_path, links, why):
    f = one(uni, tmp_path, **links)
    assert [x.code for x in by(f, "CU016")] == ["CU016"] and by(f, "CU016")[0].severity == "error"
    assert why in by(f, "CU016")[0].message


def test_a_retired_code_is_an_error_even_with_a_successor(uni, tmp_path):
    retired = {"LL-006": {"reason": "a duplicate of LL-003", "replaced_by": LL3}}
    u = dataclasses.replace(uni, aliases=uni.aliases.merged(AliasMap({}, (), retired)))
    f = one(u, tmp_path, lesson="LL-006")
    assert [x.code for x in f] == ["CU016"]
    assert "retired" in f[0].message and LL3 in f[0].message  # names the successor's uid


def test_no_registers_means_no_link_check(uni, tmp_path):
    u = dataclasses.replace(uni, aliases=None, records=None)
    assert one(u, tmp_path, lesson="LL-900") == []


def test_resolve_and_warn_once():
    amap = AliasMap({"LL-003": LL3})
    (lk,) = resolve_links({"links": {"lesson": "LL-003"}}, amap)
    assert (lk.uid, lk.legacy) == (LL3, True)
    with pytest.warns(LegacyRecordCode) as got:
        warn_legacy(lk, "x.yml#links.lesson")
    assert len(got) == 1 and LL3 in str(got[0].message)
    (uid_link,) = resolve_links({"links": {"lesson": LL3}}, amap)
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        warn_legacy(uid_link)  # a uid never warns


def test_the_register_shows_the_computed_number(uni, tmp_path):
    write_custom(tmp_path, "c", make_doc(links={"lesson": "LL-003", "runbook": "RB-900"}))
    html, data = render_register(load_one(tmp_path), TODAY, universe=uni)
    (row,) = data["customizations"]
    assert row["links"] == {"lesson": "LL-003", "runbook": "RB-900"}  # as written
    assert row["linked"][0] == {"key": "lesson", "ref": "LL-003", "uid": LL3, "label": "LL 3"}
    assert row["linked"][1]["uid"] is None and "not in aliases.yml" in row["linked"][1]["problem"]
    assert f"lesson LL 3 ({LL3})" in html and "runbook RB-900 (unresolved" in html


def test_rewrite_touches_only_link_values():
    codes = {"LL-003": LL3, "RB-001": RB1}
    yml = "reason: see LL-003 first\nlinks: {lesson: LL-003, runbook: 'RB-001'}\n"
    assert rewrite_links(yml, codes) == (
        f"reason: see LL-003 first\nlinks: {{lesson: {LL3}, runbook: '{RB1}'}}\n"
    )
    js = '{"links": {"lesson": "LL-003", "runbook": "LL-003"}}'
    assert rewrite_links(js, codes) == f'{{"links": {{"lesson": "{LL3}", "runbook": "LL-003"}}}}'
    assert rewrite_links(rewrite_links(yml, codes), codes) == rewrite_links(yml, codes)
