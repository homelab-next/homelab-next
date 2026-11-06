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


def _schema(directory: str, name: str) -> dict[str, Any]:
    return json.loads(paths.schema_file(directory, f"{name}.schema.json").read_text("utf-8"))


def schema_property_names(directory: str, name: str) -> frozenset[str]:
    """Every property name the schema itself defines, at any depth (refs to other files are not
    followed): the names safe to echo in an error path."""
    names: set[str] = set()

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            props = node.get("properties")
            if isinstance(props, dict):
                names.update(props)
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(_schema(directory, name))
    return frozenset(names)


def schema_error_shapes(directory: str, name: str, doc: Any) -> list[str]:
    """Schema errors as ``<path>: fails <keyword>`` only, never the validator's message (which
    quotes the offending value): for documents that may carry a secret or other content that
    must not be echoed.  A property name the schema does not define is shown as ``#<i>``, its
    position in its mapping."""
    from jsonschema import Draft202012Validator

    v = Draft202012Validator(_schema(directory, name), registry=schema_registry())
    known = schema_property_names(directory, name)

    def path(parts: Any) -> str:
        out: list[str] = []
        node = doc
        for p in parts:
            if isinstance(p, str) and p not in known:
                keys = list(node) if isinstance(node, dict) else []
                out.append(f"#{keys.index(p)}" if p in keys else "#")
            else:
                out.append(str(p))
            try:
                node = node[p]
            except (KeyError, IndexError, TypeError):
                node = None
        return "/".join(out) or "$"

    return sorted({f"{path(e.absolute_path)}: fails {e.validator}" for e in v.iter_errors(doc)})
