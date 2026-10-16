# SPDX-License-Identifier: Apache-2.0
"""Strict ``string.Template`` loader: a missing variable raises, never renders blank."""

from __future__ import annotations

from importlib import resources
from string import Template


def render(name: str, **values: str) -> str:
    text = (resources.files("homelabnext.generators") / "templates" / f"{name}.tmpl").read_text(
        encoding="utf-8"
    )
    return Template(text).substitute(**values)
