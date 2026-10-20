# SPDX-License-Identifier: Apache-2.0
"""One ``referencing`` registry over every packaged schema, for validators whose schemas ``$ref``
shared definitions (ids, records, ...) by ``$id``.

Every ``*.json`` with an ``$id`` under the schemas directory (``homelabnext.paths``), except the
frozen baselines (``_frozen/``) and the instance folders (``examples/``, ``negative/``).  Built once
per schemas directory; ``jsonschema``/``referencing`` are imported lazily so ``hnx --help`` works
on a bare install.
"""

from __future__ import annotations

import json
from functools import cache
from pathlib import Path

from homelabnext import paths

__all__ = ["schema_registry"]

_SKIP = {"_frozen", "examples", "negative"}


@cache
def _build(sdir: str):
    from referencing import Registry, Resource
    from referencing.jsonschema import DRAFT202012

    reg = Registry()
    for p in sorted(Path(sdir).rglob("*.json")):
        if _SKIP & set(p.relative_to(sdir).parts):
            continue
        doc = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(doc, dict) and "$id" in doc:
            reg = reg.with_resource(
                doc["$id"], Resource.from_contents(doc, default_specification=DRAFT202012)
            )
    return reg


def schema_registry(schemas_dir: str | Path | None = None):
    """The registry for ``schemas_dir`` (default: the packaged schemas directory)."""
    return _build(str(schemas_dir if schemas_dir is not None else paths.schemas_dir()))
