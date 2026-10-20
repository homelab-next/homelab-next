# SPDX-License-Identifier: Apache-2.0
"""JSON Schema validation for the broker service: its own documents, lane content, params.

One registry over every packaged schema directory, so a lane's ``content_schema`` or a handler's
``params_schema`` may ``$ref`` any shared definition (ids, records, ...).  Validators are cached
per schema; the registry is built once per schemas directory.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from functools import cache
from pathlib import Path
from typing import Any

from homelabnext import paths


@cache
def _registry(sdir: str):
    from referencing import Registry, Resource
    from referencing.jsonschema import DRAFT202012

    reg = Registry()
    for p in sorted(Path(sdir).glob("*/*.json")):
        if p.parent.name.startswith("_"):
            continue
        doc = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(doc, dict) and "$id" in doc:
            reg = reg.with_resource(
                doc["$id"], Resource.from_contents(doc, default_specification=DRAFT202012)
            )
    return reg


@cache
def _named(sdir: str, ref: str):
    from jsonschema import Draft202012Validator

    directory, _, name = ref.partition("/")
    schema = json.loads((Path(sdir) / directory / f"{name}.schema.json").read_text("utf-8"))
    return Draft202012Validator(schema, registry=_registry(sdir))


def schema_exists(ref: str) -> bool:
    """True when ``ref`` (``<dir>/<name>``) names a packaged schema."""
    directory, sep, name = ref.partition("/")
    if not sep or not directory or not name or "/" in name or ".." in ref:
        return False
    return (paths.schemas_dir() / directory / f"{name}.schema.json").is_file()


def _messages(validator, doc: Any) -> list[str]:
    return [
        f"{'/'.join(map(str, e.absolute_path)) or '$'}: {e.message[:200]}"
        for e in sorted(validator.iter_errors(doc), key=lambda e: list(map(str, e.absolute_path)))
    ]


def named_errors(ref: str, doc: Any) -> list[str]:
    """Errors of ``doc`` against ``schemas/<dir>/<name>.schema.json`` (``ref`` = ``dir/name``)."""
    return _messages(_named(str(paths.schemas_dir()), ref), doc)


def inline_errors(schema: Mapping[str, Any], doc: Any) -> list[str]:
    """Errors of ``doc`` against an inline schema (a handler's ``params_schema``)."""
    from jsonschema import Draft202012Validator

    v = Draft202012Validator(dict(schema), registry=_registry(str(paths.schemas_dir())))
    return _messages(v, doc)


def schema_problems(schema: Any) -> list[str]:
    """Problems with an inline schema itself (it must be a valid 2020-12 schema)."""
    from jsonschema import Draft202012Validator
    from jsonschema.exceptions import SchemaError

    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as exc:
        return [exc.message[:200]]
    return []
