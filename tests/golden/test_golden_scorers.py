# SPDX-License-Identifier: Apache-2.0
import pytest

from homelabnext.golden import SCORERS, ScoreError, TaskError, parse_suite, score


@pytest.mark.parametrize(
    ("out", "expect", "want"),
    [
        (" Accept \n", {"scorer": "exact", "value": "accept"}, 1.0),
        ("reject", {"scorer": "exact", "value": "accept"}, 0.0),
        ("b", {"scorer": "one_of", "values": ["a", "B"]}, 1.0),
        ("c", {"scorer": "one_of", "values": ["a", "b"]}, 0.0),
        ("alpha beta", {"scorer": "contains", "all": ["alpha", "beta", "gamma"]}, 2 / 3),
        ("alpha oops", {"scorer": "contains", "all": ["alpha"], "none": ["oops"]}, 0.0),
        ("order 12345", {"scorer": "regex", "pattern": r"\d{5}"}, 1.0),
        ("order", {"scorer": "regex", "pattern": r"\d{5}"}, 0.0),
        ('{"label": "accept", "confidence": 0.9}', {"scorer": "json_fields", "fields": {"label": "accept", "confidence": {"min": 0.8}}}, 1.0),
        ('```json\n{"label": "accept"}\n```', {"scorer": "json_fields", "fields": {"label": "accept"}}, 1.0),
        ('{"label": "reject", "confidence": 0.9}', {"scorer": "json_fields", "fields": {"label": "accept", "confidence": {"min": 0.8}}}, 0.5),
        ('{"label": "x"}', {"scorer": "json_fields", "fields": {"label": {"one_of": ["a", "b"]}}}, 0.0),
        ("not json", {"scorer": "json_fields", "fields": {"label": "a"}}, 0.0),
        ("[1]", {"scorer": "json_fields"}, 0.0),
        ("short", {"scorer": "max_length", "max_chars": 10}, 1.0),
        ("far too long here", {"scorer": "max_length", "max_chars": 10}, 0.0),
        ('{"n": 1}', {"scorer": "json_schema", "schema": {"type": "object", "required": ["n"]}}, 1.0),
        ('{"m": 1}', {"scorer": "json_schema", "schema": {"type": "object", "required": ["n"]}}, 0.0),
    ],
)  # fmt: skip
def test_scorers(out, expect, want):
    assert score(out, expect)[0] == pytest.approx(want)


def test_every_scorer_has_a_case():
    assert set(SCORERS) == {
        "exact", "one_of", "contains", "regex", "json_fields", "json_schema", "max_length",
    }  # fmt: skip


def test_unknown_scorer_and_missing_argument_are_refused():
    with pytest.raises(ScoreError, match="unknown scorer"):
        score("x", {"scorer": "eval"})
    with pytest.raises(ScoreError, match=r"needs expect\.value"):
        score("x", {"scorer": "exact"})


BASE = {
    "suite": "s",
    "tasks": [{"id": "t", "prompt": "p", "expect": {"scorer": "exact", "value": "v"}}],
}


@pytest.mark.parametrize(
    ("mutate", "needle"),
    [
        (lambda d: d.update(suite="Bad Name"), "suite: must be a slug"),
        (lambda d: d.update(tasks=[]), "non-empty"),
        (lambda d: d["tasks"].append(dict(d["tasks"][0])), "duplicate id"),
        (lambda d: d["tasks"][0].pop("prompt"), "prompt missing"),
        (lambda d: d["tasks"][0].update(weight=0), "weight"),
        (lambda d: d["tasks"][0]["expect"].update(scorer="nope"), "unknown scorer"),
        (lambda d: d.update(pass_score=1.5), "pass_score"),
    ],
)
def test_malformed_suites_are_refused(mutate, needle):
    import copy

    doc = copy.deepcopy(BASE)
    mutate(doc)
    with pytest.raises(TaskError, match=needle):
        parse_suite(doc)
