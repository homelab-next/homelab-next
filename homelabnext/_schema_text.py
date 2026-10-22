# SPDX-License-Identifier: Apache-2.0
"""A JSON Schema validation error, told without the value that failed it.

``jsonschema``'s ``ValidationError.message`` quotes the offending instance (``'<the value>' does
not match '^...$'``).  The lab-data readers decrypt SOPS files in memory (``homelabnext.sops``),
so a sealed value that fails validation would be printed into a terminal or a CI log by the
message meant to explain it.  :func:`safe_message` names the rule and what the *schema* expected
(a type, a pattern, an enum, a bound) instead; the caller adds the path.  Messages that only name
keys (``required``, ``additionalProperties``, ``dependentRequired``) are kept: SOPS leaves keys
in the clear, so they are structure, not sealed values.
"""

from __future__ import annotations

from typing import Any

__all__ = ["safe_message"]

_MAX = 200
#: keywords whose message names keys only (from the schema, or the document's own key names)
_KEYS_ONLY = frozenset({"required", "additionalProperties", "dependentRequired", "dependencies"})
_SHAPES = frozenset({"anyOf", "oneOf", "allOf", "not", "if", "then", "else", "contains"})


def _short(value: Any) -> str:
    text = repr(value)
    return text if len(text) <= _MAX else text[: _MAX - 3] + "..."


def safe_message(err: Any) -> str:
    """The rule ``err`` (a ``jsonschema.ValidationError``) broke, never the instance value."""
    kw, want = err.validator, err.validator_value
    if kw in _KEYS_ONLY:
        return str(err.message)[:_MAX]
    if kw == "type":
        return f"is not of type {_short(want)}"
    if kw == "enum":
        return f"is not one of {_short(want)}"
    if kw == "const":
        return f"is not the constant {_short(want)}"
    if kw == "pattern":
        return f"does not match {_short(want)}"
    if kw == "format":
        return f"is not a valid {_short(want)}"
    if kw == "propertyNames":
        return "has a property name the schema does not allow"
    if kw in _SHAPES:
        return f"does not match the allowed shapes ({kw})"
    if kw is None or want is False:  # a `false` subschema
        return "is not allowed here"
    if isinstance(want, (int, float, bool, str)):
        return f"fails {kw} {_short(want)}"
    return f"fails {kw}"
