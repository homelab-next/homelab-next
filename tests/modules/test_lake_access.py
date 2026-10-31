# SPDX-License-Identifier: Apache-2.0
"""``homelabnext.modules.lake_access`` and the selection's ``tlp_readers`` (ADR-0033 decision 6)."""

import re

import pytest

from homelabnext.modules import lake_access, rules


def _site(*readers):
    return {"tlp_readers": list(readers)}


def _r(reader, ceiling, **extra):
    return {"reader": reader, "ceiling": ceiling, "why": "w", **extra}


def test_no_declaration_renders_nothing():
    assert lake_access.render({}) is None


def test_each_reader_gets_one_rule_with_its_row_filter():
    doc = lake_access.render(
        _site(
            _r("profile:analyst", "green"),
            _r("group:soc", "red"),
            _r("module:pipe", "red", write=True),
            _r("user:alice", "amber+strict"),
        )
    )
    rules_ = doc["tables"]
    assert rules_[0] == {
        "user": "^profile:analyst$",
        "catalog": ".*",
        "schema": ".*",
        "table": ".*",
        "privileges": ["SELECT"],
        "filter": "coalesce(tlp, 'red') IN ('clear', 'green')",
    }
    assert rules_[1]["group"] == "^soc$" and "filter" not in rules_[1]
    assert rules_[2]["privileges"] == ["SELECT", "INSERT", "DELETE", "UPDATE"]
    assert (
        "'amber+strict'" in rules_[3]["filter"]
        and "'red'" not in rules_[3]["filter"].split("IN")[1]
    )


def test_a_reader_name_is_matched_exactly():
    (rule,) = lake_access.render(_site(_r("user:a.b", "clear")))["tables"]
    assert re.fullmatch(rule["user"], "user:a.b") and not re.fullmatch(rule["user"], "user:aXb")


@pytest.mark.parametrize(
    "entry, needle",
    [
        (_r("profile:x", "black"), "not a TLP label"),
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
