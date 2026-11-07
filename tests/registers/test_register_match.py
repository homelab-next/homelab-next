# SPDX-License-Identifier: Apache-2.0
"""``match`` (lesson 2.2, runbook 2.3): the bounded matcher the orchestrator matches a job's
task against (orchestrator/internal/lessons).  The record validation and the schemas hold it to
the same bounds, and the orchestrator's register fixtures are records this validation accepts."""

import copy
import json
import pathlib

import pytest

from homelabnext.registers import RegisterError, load_register
from homelabnext.registers.schema import (
    MATCH_KEYWORD_LEN,
    MATCH_MAX_ITEMS,
    MATCH_PATH_LEN,
    validate_lessons,
    validate_runbooks,
)

REPO = pathlib.Path(__file__).resolve().parents[2]
FIXTURES = REPO / "orchestrator" / "internal" / "lessons" / "testdata"
EX = REPO / "examples" / "registers"


def test_the_orchestrators_fixtures_are_valid_records():
    lessons = validate_lessons(load_register(FIXTURES / "lessons"))
    runbooks = validate_runbooks(load_register(FIXTURES / "runbooks"))
    assert sum("match" in e for e in lessons) == 4 and sum("match" in e for e in runbooks) == 1


@pytest.mark.parametrize("name", ["lesson", "runbook"])
def test_the_bounds_are_the_schemas(name):
    m = json.loads((REPO / "schemas" / "registers" / f"{name}.schema.json").read_text())
    m = m["properties"]["match"]["properties"]
    assert m["keywords"]["maxItems"] == m["paths"]["maxItems"] == MATCH_MAX_ITEMS
    assert (m["keywords"]["items"]["minLength"], m["keywords"]["items"]["maxLength"]) == MATCH_KEYWORD_LEN
    assert m["paths"]["items"]["maxLength"] == MATCH_PATH_LEN


def _with_match(kind, match):
    reg = load_register(FIXTURES / kind)
    e = copy.deepcopy(next(x for x in reg[kind] if "match" in x))
    e["match"] = match
    reg[kind] = [e]
    return reg


@pytest.mark.parametrize(
    "match",
    [
        {},
        {"pattern": "cert.*"},
        {"keywords": []},
        {"keywords": "certificate expired"},
        {"keywords": ["ab"]},
        {"keywords": ["k" * 81]},
        {"keywords": [" leading space"]},
        {"keywords": ["zero​width"]},
        {"keywords": ["two\nlines"]},
        {"keywords": ["TLS handshake", "tls handshake"]},
        {"keywords": [f"keyword {i:02d}" for i in range(MATCH_MAX_ITEMS + 1)]},
        {"keywords": [7]},
        {"paths": ["/etc/proxy/"]},
        {"paths": ["roles/../secrets/"]},
        {"paths": ["roles//proxy/"]},
        {"paths": ["./roles/"]},
        {"paths": [".."]},
        {"paths": ["roles\\proxy"]},
        {"paths": ["p" * (MATCH_PATH_LEN + 1)]},
        {"paths": ["roles/", "roles/"]},
    ],
)
@pytest.mark.parametrize("kind", ["lessons", "runbooks"])
def test_a_match_outside_its_bounds_is_refused(kind, match):
    validate = validate_lessons if kind == "lessons" else validate_runbooks
    with pytest.raises(RegisterError, match="match"):
        validate(_with_match(kind, match))


@pytest.mark.parametrize("kind", ["lessons", "runbooks"])
def test_a_bounded_match_is_accepted(kind):
    validate = validate_lessons if kind == "lessons" else validate_runbooks
    validate(_with_match(kind, {"keywords": ["tls handshake"], "paths": ["roles/proxy/", ".github/"]}))


def test_the_example_registers_declare_no_match():
    """No example record declares a match, so none is injected into a prompt (the orchestrator's
    test of the same registers relies on it)."""
    for kind in ("lessons", "runbooks"):
        assert not [e["uid"] for e in load_register(EX / kind)[kind] if "match" in e]
