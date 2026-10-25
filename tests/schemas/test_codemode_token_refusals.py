# SPDX-License-Identifier: Apache-2.0
"""The reasons a Code Mode call carries without a request id are the broker contract's token
refusals plus the transport's two and the runner's own fault (runner-fault), in schemas/codemode
and in the contract alike."""

import json
from pathlib import Path

from conformance.protocols.broker import TOKEN_REFUSALS

ROOT = Path(__file__).resolve().parents[2]
REQUESTLESS = [*TOKEN_REFUSALS, "broker-unreachable", "rate-limited", "runner-fault"]


def _enums(doc):
    if isinstance(doc, dict):
        for key, value in doc.items():
            if key == "enum" and "rate-limited" in value:
                yield value
            else:
                yield from _enums(value)
    elif isinstance(doc, list):
        for value in doc:
            yield from _enums(value)


def test_the_requestless_reasons_are_the_token_refusals():
    for name in ("execution_result", "journal_step"):
        doc = json.loads((ROOT / "schemas" / "codemode" / f"{name}.schema.json").read_text())
        enums = list(_enums(doc))
        assert enums and all(e == REQUESTLESS for e in enums), (name, enums)


def test_the_readme_names_every_token_refusal():
    text = (ROOT / "schemas" / "codemode" / "README.md").read_text(encoding="utf-8")
    missing = [r for r in TOKEN_REFUSALS if f"`{r}`" not in text]
    assert not missing, missing


def test_request_denied_names_its_request_and_is_no_token_refusal():
    assert "request-denied" not in TOKEN_REFUSALS and "request-denied" not in REQUESTLESS
    from homelabnext.broker.service import REQUEST_DENIED

    assert REQUEST_DENIED == "request-denied"


def _example(name):
    return json.loads((ROOT / "schemas" / "codemode" / "examples" / name).read_text())


def test_a_request_denied_call_carries_its_request_ids():
    from homelabnext.agent.schemas import schema_errors

    result = _example("execution_result.denied-handled.json")
    step = _example("journal_step.denied.json")
    result["calls"][0]["reason"] = step["reason"] = "request-denied"
    assert schema_errors("codemode", "execution_result", result) == []
    assert schema_errors("codemode", "journal_step", step) == []
    for doc in (result["calls"][0], step):
        doc.pop("request_id")
        doc.pop("request_digest")
    assert schema_errors("codemode", "execution_result", result), (
        "a request-denied call without ids"
    )
    assert schema_errors("codemode", "journal_step", step), "a request-denied step without ids"
