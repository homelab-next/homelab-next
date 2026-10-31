# SPDX-License-Identifier: Apache-2.0
"""``homelabnext.modules.lake_access`` and the selection's ``tlp_readers`` (ADR-0033 decision 6)."""

import re

import pytest

from homelabnext.modules import lake_access, rules


def _site(*readers):
    return {"lake_catalog": "lake", "tlp_readers": list(readers)}


def _r(reader, ceiling, **extra):
    return {"reader": reader, "ceiling": ceiling, "why": "w", **extra}


def test_no_declaration_renders_nothing():
    assert lake_access.render({}) is None


def test_each_reader_gets_its_row_filter():
    doc = lake_access.render(
        _site(
            _r("profile:analyst", "green"),
            _r("group:soc", "red"),
            _r("module:pipe", "red", write=True),
            _r("user:alice", "amber+strict"),
        )
    )
    every = {(r.get("user") or r.get("group")): r for r in doc["tables"] if r.get("table") == ".*"}
    assert every["^profile:analyst$"]["filter"] == "coalesce(tlp, 'red') IN ('clear', 'green')"
    assert "filter" not in every["^soc$"] and "group" in every["^soc$"]
    assert every["^module:pipe$"]["privileges"] == ["SELECT", "INSERT", "DELETE"]
    assert "'amber+strict'" in every["^user:alice$"]["filter"]
    assert "'red'" not in every["^user:alice$"]["filter"].split("IN")[1]


def test_a_reader_name_is_matched_exactly():
    (_, rule) = lake_access.render(_site(_r("user:a.b", "clear")))["tables"]
    assert re.fullmatch(rule["user"], "user:a.b") and not re.fullmatch(rule["user"], "user:aXb")


@pytest.mark.parametrize(
    "entry, needle",
    [
        (_r("profile:x", "black"), "not a TLP label"),
        (_r("profile:x", "Red"), "not a TLP label"),
        (_r("profile:x", "green", write=True), "ceiling is red"),
        (_r("nobody", "green"), "not a reader id"),
    ],
)
def test_render_refuses(entry, needle):
    with pytest.raises(lake_access.LakeAccessError, match=needle):
        lake_access.render(_site(entry))


MODS = {
    "collector": {
        "requires": {"capabilities": [{"cap": "cap:lake-query"}]},
        "contributes": {
            "agents": [
                {
                    "key": "collector-analyst",
                    "profile": "profile:collector-analyst",
                    "needs": [{"cap": "cap:lake-query", "access": "read", "scope": []}],
                }
            ]
        },
    },
    "other": {"requires": {"capabilities": [{"cap": "cap:notify"}]}},
}


def test_the_lake_readers_of_the_selection():
    assert rules.lake_readers(MODS) == {
        "module:collector": "module collector",
        "profile:collector-analyst": "collector's agent collector-analyst",
    }


def test_reader_problems():
    full = _site(_r("module:collector", "red"), _r("profile:collector-analyst", "green"))
    assert rules.tlp_reader_problems(full, MODS) == []
    assert rules.tlp_reader_problems({}, MODS) == []  # undeclared: not judged
    missing = rules.tlp_reader_problems(_site(_r("module:collector", "red")), MODS)
    assert missing == [
        "tlp_readers: profile:collector-analyst (collector's agent collector-analyst) reads the "
        "lake but has no ceiling: it would read nothing"
    ]
    twice = _site(*full["tlp_readers"], _r("module:collector", "red"))
    assert "tlp_readers: module:collector is listed twice" in rules.tlp_reader_problems(twice, MODS)
    writer = _site(*full["tlp_readers"], _r("module:pipe", "amber", write=True))
    assert "tlp_readers: module:pipe writes rows, so its ceiling is red" in (
        rules.tlp_reader_problems(writer, MODS)
    )


def _rules(*readers, catalog="lake"):
    return lake_access.render({"lake_catalog": catalog, "tlp_readers": list(readers)})


def test_the_most_restrictive_rule_comes_first_whatever_the_order_written():
    a = _rules(_r("group:soc", "red"), _r("user:alice", "clear"), _r("group:guests", "green"))
    b = _rules(_r("group:guests", "green"), _r("user:alice", "clear"), _r("group:soc", "red"))
    assert a == b
    who = [r.get("user") or r.get("group") for r in a["tables"] if r.get("table") == ".*"]
    # users before groups, each by ascending ceiling
    assert who == ["^user:alice$", "^guests$", "^soc$"]


def test_writers_insert_and_delete_but_never_update():
    (_, rule) = _rules(_r("module:pipe", "red", write=True))["tables"]
    assert rule["privileges"] == ["SELECT", "INSERT", "DELETE"]


def test_only_the_lake_catalog_is_reachable_and_nobody_owns_a_schema():
    doc = _rules(_r("profile:x", "green"), _r("module:w", "red", write=True))
    assert doc["catalogs"][-1] == {"catalog": ".*", "allow": "none"}
    assert {c["allow"] for c in doc["catalogs"][:-1]} == {"read-only", "all"}
    assert all(r["catalog"] == "^lake$" for r in doc["tables"] + doc["catalogs"][:-1])
    assert doc["schemas"] == [{"owner": False}] and doc["queries"] == [{"allow": ["execute"]}]
    info = [r for r in doc["tables"] if r.get("schema") == "^information_schema$"]
    assert len(info) == 2 and all("filter" not in r for r in info)


def test_an_empty_list_denies_everyone():
    doc = _rules()
    assert doc["tables"] == [] and doc["catalogs"] == [{"catalog": ".*", "allow": "none"}]


@pytest.mark.parametrize(
    "site, needle",
    [
        ({"tlp_readers": []}, "needs lake_catalog"),
        ({"tlp_readers": [], "lake_catalog": "Lake.x"}, "needs lake_catalog"),
        ({"tlp_readers": {}, "lake_catalog": "lake"}, "not a list"),
        (
            {"lake_catalog": "lake", "tlp_readers": [_r("user:a", "red"), _r("user:a", "red")]},
            "listed twice",
        ),
        ({"lake_catalog": "lake", "tlp_readers": [_r("foo:x", "red")]}, "not a reader id"),
        ({"lake_catalog": "lake", "tlp_readers": [_r("user:A", "red")]}, "not a reader id"),
        ({"lake_catalog": "lake", "tlp_readers": [_r("user:a", "TLP:RED")]}, "not a TLP label"),
        ({"lake_catalog": "lake", "tlp_readers": ["x"]}, "not a mapping"),
    ],
)
def test_render_refuses_what_the_loader_would(site, needle):
    with pytest.raises(lake_access.LakeAccessError, match=needle):
        lake_access.render(site)


def test_a_prefers_only_reader_and_a_profileless_agent_are_found():
    mods = {
        "m": {
            "requires": {},
            "prefers": {"capabilities": [{"cap": "cap:lake-query", "instance": "x"}]},
            "contributes": {
                "agents": [{"key": "m-a", "needs": [{"cap": "cap:lake-query", "access": "read"}]}]
            },
        }
    }
    assert set(rules.lake_readers(mods)) == {"module:m", "profile:m-a"}
