# SPDX-License-Identifier: Apache-2.0
"""Validate agent and broker documents against their packaged JSON Schemas."""

from __future__ import annotations

import json
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
