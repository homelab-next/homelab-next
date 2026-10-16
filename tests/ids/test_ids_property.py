# SPDX-License-Identifier: Apache-2.0
"""Deterministic property tests (fixed seed, stdlib only; no hypothesis dependency)."""

import json
import random
import re
import string
from pathlib import Path

from jsonschema import Draft202012Validator

from homelabnext.ids import KINDS, format_id, grammar, is_valid, lint_id, parse

SCHEMA = json.loads(
    (Path(__file__).resolve().parents[2] / "schemas/ids/logical-id.schema.json").read_text()
)
VALIDATOR = Draft202012Validator(SCHEMA)
N = 600


def gen_slug(r, sep="-"):
    def seg():
        s = r.choice(string.ascii_lowercase)
        s += "".join(r.choice(string.ascii_lowercase) for _ in range(r.randint(0, 5)))
        s += "".join(r.choice("0123456789") for _ in range(r.randint(0, 3)))  # never 4+ digits
        return s

    return sep.join(seg() for _ in range(r.randint(1, 3)))


def gen_id(r):
    kind = r.choice(KINDS)
    if kind == "memory":
        parts = [gen_slug(r), gen_slug(r)]
    elif kind == "table":
        parts = [gen_slug(r, "_"), gen_slug(r, "_")]
    else:
        parts = [gen_slug(r)]
    return kind, parts


def test_generated_ids_round_trip_validate_and_lint_clean():
    r = random.Random(20261015)
    seen_kinds = set()
    for _ in range(N):
        kind, parts = gen_id(r)
        text = format_id(kind, *parts)
        seen_kinds.add(kind)
        assert str(parse(text)) == text
        assert parse(text).parts == tuple(parts)
        assert lint_id(text) == []
        assert VALIDATOR.is_valid(text), text
    assert seen_kinds == set(KINDS)


def mutate(r, text):
    kind = r.choice(["viking", "ip", "rule", "upper", "space", "kind", "digits", "empty"])
    body = text.split(":", 1)[1]
    if kind == "viking":
        return "viking://" + body
    if kind == "ip":
        return f"{text.split(':')[0]}:{r.randint(1, 255)}.{r.randint(0, 255)}.{r.randint(0, 255)}.{r.randint(0, 255)}"
    if kind == "rule":
        return text + "-rule-" + str(r.randint(900000, 900999))
    if kind == "upper":
        return text.split(":")[0] + ":" + body.upper()
    if kind == "space":
        return text + " x"
    if kind == "kind":
        return "host:" + body
    if kind == "digits":
        return text + "-" + str(r.randint(1000, 99999))
    return text.split(":")[0] + ":"


def test_mutated_ids_are_rejected_by_grammar_schema_and_lint_alike():
    r = random.Random(20261016)
    for _ in range(N):
        kind, parts = gen_id(r)
        bad = mutate(r, format_id(kind, *parts))
        assert not is_valid(bad), bad
        assert not VALIDATOR.is_valid(bad), bad
        assert lint_id(bad), bad


def test_python_grammar_and_json_schema_agree_on_random_strings():
    r = random.Random(7)
    alphabet = "abcxyz0189:-_./ ABC"
    for _ in range(3000):
        s = "".join(r.choice(alphabet) for _ in range(r.randint(0, 14)))
        if r.random() < 0.6:
            s = r.choice(KINDS) + ":" + s
        # JSON `$` accepts a trailing newline; our alphabet has none.
        assert is_valid(s) == VALIDATOR.is_valid(s), s


def test_per_kind_defs_match_python_patterns():
    for kind in KINDS:
        rx = re.compile(SCHEMA["$defs"][f"{kind}_id"]["pattern"])
        assert rx.pattern == grammar.schema_pattern(kind)
