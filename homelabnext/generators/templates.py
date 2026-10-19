# SPDX-License-Identifier: Apache-2.0
"""Strict ``string.Template`` loader: a missing variable raises, never renders blank.

``string.Template`` does no escaping, so every value is checked with
:func:`homelabnext.generators.safe.checked` against the template's format first.  ``raw`` values
are fragments the generator itself composed from already-checked parts (an ``import`` line, a list
of backticked names); they are the only values exempt from the check.
"""

from __future__ import annotations

from collections.abc import Mapping
from importlib import resources
from string import Template

from .safe import check_fields

#: template name -> metacharacter set (see ``safe.FORMAT_METACHARS``)
FORMATS = {"caddy_site": "caddy", "service_section": "markdown"}


def render(name: str, raw: Mapping[str, str] | None = None, **values: str) -> str:
    check_fields(FORMATS[name], {f"{name}.{k}": v for k, v in values.items()})
    text = (resources.files("homelabnext.generators") / "templates" / f"{name}.tmpl").read_text(
        encoding="utf-8"
    )
    return Template(text).substitute(**values, **(raw or {}))
