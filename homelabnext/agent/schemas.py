# SPDX-License-Identifier: Apache-2.0
"""Validate agent and broker documents against their packaged JSON Schemas."""

from __future__ import annotations

import json
import re
from typing import Any

from homelabnext import paths
from homelabnext.schema_registry import schema_registry


def schema_errors(directory: str, name: str, doc: Any) -> list[str]:
    """Human-readable schema errors for ``schemas/<directory>/<name>.schema.json`` (empty = ok)."""
    from jsonschema import Draft202012Validator

    schema = json.loads(paths.schema_file(directory, f"{name}.schema.json").read_text("utf-8"))
    v = Draft202012Validator(schema, registry=schema_registry())
    return [
        f"{'/'.join(map(str, e.absolute_path)) or '$'}: {e.message}"
        for e in sorted(v.iter_errors(doc), key=lambda e: list(map(str, e.absolute_path)))
    ]


_PLAIN = re.compile(r"[a-z_]{1,32}")


def schema_error_shapes(directory: str, name: str, doc: Any) -> list[str]:
    """Schema errors as ``<path>: fails <keyword>`` only, never the validator's message (which
    quotes the offending value): for documents that may carry a secret or other content that
    must not be echoed.  A path element that is neither an index nor a plain lower-case name is
    shown as ``#``."""
    from jsonschema import Draft202012Validator

    schema = json.loads(paths.schema_file(directory, f"{name}.schema.json").read_text("utf-8"))
    v = Draft202012Validator(schema, registry=schema_registry())

    def part(p: Any) -> str:
        if isinstance(p, int) or (isinstance(p, str) and _PLAIN.fullmatch(p)):
            return str(p)
        return "#"

    return sorted(
        {
            f"{'/'.join(part(p) for p in e.absolute_path) or '$'}: fails {e.validator}"
            for e in v.iter_errors(doc)
        }
    )
