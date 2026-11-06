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
        # a field failing two constraints counts once: 2 of 3 fields match
        ('{"a": 1, "b": 2, "c": 99}', {"scorer": "json_fields", "fields": {"a": 1, "b": 2, "c": {"one_of": [1, 2], "max": 5}}}, 2 / 3),
        # an expected {} is a value to equal, not an empty constraint that accepts anything
        ('{"c": 99}', {"scorer": "json_fields", "fields": {"c": {}}}, 0.0),
        ('{"c": {}}', {"scorer": "json_fields", "fields": {"c": {}}}, 1.0),
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


@pytest.mark.parametrize(
    ("expect", "needle"),
    [
        ({"scorer": "one_of", "values": "accept"}, "list of strings"),
        ({"scorer": "regex", "pattern": "("}, "does not compile"),
        ({"scorer": "contains", "all": "alpha"}, "list of strings"),
        ({"scorer": "max_length", "max_chars": "10"}, "non-negative integer"),
        ({"scorer": "json_fields", "fields": {"n": {"min": "1"}}}, "finite number"),
        ({"scorer": "json_schema", "schema": {"type": "nope"}}, "invalid"),
        ({"scorer": "json_fields", "fields": {"n": {"min": float("nan")}}}, "finite number"),
        ({"scorer": "json_fields", "fields": {"n": {"min": 5, "max": 1}}}, "exceeds max"),
        ({"scorer": "json_fields", "fields": {"n": {"one_of": "ab"}}}, "must be a list"),
        ({"scorer": "json_fields", "fields": [1]}, "must be a mapping"),
        ({"scorer": "contains", "none": "x"}, "list of strings"),
        ({"scorer": "exact", "value": "a", "strip": "yes"}, "must be a boolean"),
    ],
)
def test_malformed_expect_fails_at_load_with_the_task_id(expect, needle):
    doc = {"suite": "s", "tasks": [{"id": "bad-task", "prompt": "p", "expect": expect}]}
    with pytest.raises(TaskError, match=rf"task bad-task: .*{needle}"):
        parse_suite(doc)


def test_deeply_nested_json_scores_zero_not_a_crash():
    out = "[" * 100000 + "]" * 100000
    assert score(out, {"scorer": "json_fields", "fields": {"a": 1}})[0] == 0.0


def test_recursive_schema_on_deep_output_scores_zero_not_a_crash():
    out = "[" * 600 + "]" * 600
    e = {"scorer": "json_schema", "schema": {"type": "array", "items": {"$ref": "#"}}}
    assert score(out, e)[0] == 0.0


def test_unresolvable_ref_scores_zero_not_a_crash():
    e = {"scorer": "json_schema", "schema": {"$ref": "other.json#/x"}}
    assert score("{}", e)[0] == 0.0
