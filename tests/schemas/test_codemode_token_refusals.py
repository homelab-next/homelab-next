# SPDX-License-Identifier: Apache-2.0
"""The reasons a Code Mode call carries without a request id are the broker contract's token
refusals plus the transport's two, in schemas/codemode and in the contract alike."""

import json
from pathlib import Path

from conformance.protocols.broker import TOKEN_REFUSALS

ROOT = Path(__file__).resolve().parents[2]
REQUESTLESS = [*TOKEN_REFUSALS, "broker-unreachable", "rate-limited"]


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
