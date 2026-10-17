# SPDX-License-Identifier: Apache-2.0
"""Validate agent and broker documents against their packaged JSON Schemas."""

from __future__ import annotations

import json
from functools import cache
from typing import Any

from homelabnext import paths

_DIRS = ("ids", "agent", "broker")


@cache
def _registry():
    from referencing import Registry, Resource
    from referencing.jsonschema import DRAFT202012

    reg = Registry()
    base = paths.schemas_dir()
    for d in _DIRS:
        for f in sorted((base / d).glob("*.json")):
            doc = json.loads(f.read_text(encoding="utf-8"))
            reg = reg.with_resource(
                doc["$id"], Resource.from_contents(doc, default_specification=DRAFT202012)
            )
    return reg


def schema_errors(directory: str, name: str, doc: Any) -> list[str]:
    """Human-readable schema errors for ``schemas/<directory>/<name>.schema.json`` (empty = ok)."""
    from jsonschema import Draft202012Validator

    schema = json.loads(paths.schema_file(directory, f"{name}.schema.json").read_text("utf-8"))
    v = Draft202012Validator(schema, registry=_registry())
    return [
        f"{'/'.join(map(str, e.absolute_path)) or '$'}: {e.message}"
        for e in sorted(v.iter_errors(doc), key=lambda e: list(map(str, e.absolute_path)))
    ]
