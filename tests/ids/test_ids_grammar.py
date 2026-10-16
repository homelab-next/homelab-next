# SPDX-License-Identifier: Apache-2.0
import pytest

from homelabnext.ids import KINDS, IdError, format_id, is_valid, parse

VALID = [
    "cap:lake-query",
    "svc:siem",
    "det:auth-failure-burst",
    "profile:reader",
    "persona:analyst",
    "skill:summarise",
    "mdl:fast-classifier",
    "memory:analyst/known-benign",
    "table:ocsf.detection_finding",
    "table:ocsf.detection_finding_v2",
    "cap:a",
    "det:x1-y2",
]
INVALID = [
    "",
    "cap:",
    ":x",
    "cap",
    "cap:Lake",
    "cap:lake_query",
    "cap:-a",
    "cap:a-",
    "cap:a--b",
    "cap:1a",
    "host:hv-01",
    "memory:a",
    "memory:a/",
    "memory:/a",
    "memory:a/b/c",
    "table:ocsf",
    "table:a.b.c",
    "table:Ocsf.x",
    "cap:a b",
    "cap:a\n",
    "viking://x/y",
    "svc:192.0.2.1",
    "det:900001",
    "det:rule-900001",
    "det:sid-5",
    "cap:" + "a" * 65,
    "cap:é",
]


@pytest.mark.parametrize("text", VALID)
def test_valid_ids_round_trip(text):
    lid = parse(text)
    assert str(lid) == text
    assert format_id(lid.kind, *lid.parts) == text


@pytest.mark.parametrize("text", INVALID)
def test_invalid_ids_rejected(text):
    assert not is_valid(text)
    with pytest.raises(IdError):
        parse(text)


def test_every_kind_has_a_valid_example():
    kinds = {parse(t).kind for t in VALID}
    assert kinds == set(KINDS)


def test_length_cap():
    assert is_valid("cap:" + "a" * 64)
    assert not is_valid("memory:" + "a" * 64 + "/" + "b" * 64)  # 136 chars


def test_non_string_rejected():
    assert not is_valid(None)
    assert not is_valid(7)


def test_format_id_rejects_bad_parts():
    with pytest.raises(IdError):
        format_id("memory", "only-one")
    with pytest.raises(IdError):
        format_id("nope", "x")
