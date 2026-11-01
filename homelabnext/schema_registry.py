# SPDX-License-Identifier: Apache-2.0
"""The one place a ``referencing`` registry of JSON schemas is built, for validators whose schemas
``$ref`` shared definitions (ids, records, ...) by ``$id``.

* :func:`schema_registry` -- every ``*.json`` with an ``$id`` under a schemas directory (default:
  the packaged one, ``homelabnext.paths``), except the frozen baselines (``_frozen/``) and the
  instance folders (``examples/``, ``negative/``).  Built once per schemas directory.
* :func:`registry_of` -- the same from documents a caller already holds (a checker over another
  tree, a frozen-baseline fallback).
* :func:`validator` -- a Draft 2020-12 validator for ``schemas/<family>/<file>`` over
  :func:`schema_registry`.

Every schema is read as Draft 2020-12 unless it says otherwise (``$schema``).  ``jsonschema`` and
``referencing`` are imported lazily so ``hnx --help`` works on a bare install.  Code elsewhere
does not build a ``Registry()`` or call ``Resource.from_contents`` itself
(``tools/shared_helpers_lint.py``, rule ``schema``): one loader, one way to get the draft, an
``$id`` collision or the skipped folders right.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from functools import cache
from pathlib import Path
from typing import Any

from homelabnext import paths

__all__ = ["registry_of", "schema_registry", "validator"]

_SKIP = {"_frozen", "examples", "negative"}


def registry_of(docs: Iterable[Any], base=None):
    """``base`` (default: an empty registry) with every dict in ``docs`` that carries a string
    ``$id`` added under that ``$id``; anything else in ``docs`` is ignored."""
    from referencing import Registry, Resource
    from referencing.jsonschema import DRAFT202012

    reg = base if base is not None else Registry()
    for doc in docs:
        if isinstance(doc, dict) and isinstance(doc.get("$id"), str):
            reg = reg.with_resource(
                doc["$id"], Resource.from_contents(doc, default_specification=DRAFT202012)
            )
    return reg


def _docs(sdir: str):
    for p in sorted(Path(sdir).rglob("*.json")):
        if not _SKIP & set(p.relative_to(sdir).parts):
            yield json.loads(p.read_text(encoding="utf-8"))


@cache
def _build(sdir: str):
    return registry_of(_docs(sdir))


def schema_registry(schemas_dir: str | Path | None = None):
    """The registry for ``schemas_dir`` (default: the packaged schemas directory)."""
    return _build(str(schemas_dir if schemas_dir is not None else paths.schemas_dir()))


def validator(family: str, name: str, *, format_checker=None):
    """A Draft 2020-12 validator for ``schemas/<family>/<name>`` (the packaged schemas directory)
    whose ``$ref``s resolve through :func:`schema_registry`."""
    from jsonschema import Draft202012Validator

    schema = json.loads(paths.schema_file(family, name).read_text(encoding="utf-8"))
    return Draft202012Validator(schema, registry=schema_registry(), format_checker=format_checker)
