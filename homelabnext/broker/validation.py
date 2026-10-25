# SPDX-License-Identifier: Apache-2.0
"""JSON Schema validation for the broker service: its own documents, lane content, params.

One registry over every packaged schema directory, so a lane's ``content_schema`` or a handler's
``params_schema`` may ``$ref`` any shared definition (ids, records, ...).  Validators are cached
per schema; the registry is built once per schemas directory.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from functools import cache, lru_cache
from pathlib import Path
from typing import Any

from homelabnext import paths
from homelabnext.schema_registry import schema_registry


def _registry(sdir: str):
    return schema_registry(sdir)


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


@lru_cache(maxsize=256)
def _inline_validator(sdir: str, schema_json: str):
    from jsonschema import Draft202012Validator

    return Draft202012Validator(json.loads(schema_json), registry=_registry(sdir))


def inline_errors(schema: Mapping[str, Any], doc: Any) -> list[str]:
    """Errors of ``doc`` against an inline schema (a handler's ``params_schema``).  The validator
    is built once per distinct schema (keyed by its canonical JSON), not on every admit and run."""
    key = json.dumps(schema, sort_keys=True, ensure_ascii=False)
    return _messages(_inline_validator(str(paths.schemas_dir()), key), doc)


def schema_problems(schema: Any) -> list[str]:
    """Problems with an inline schema itself (it must be a valid 2020-12 schema)."""
    from jsonschema import Draft202012Validator
    from jsonschema.exceptions import SchemaError

    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as exc:
        return [exc.message[:200]]
    except RecursionError:
        return ["nested too deeply"]
    return []
