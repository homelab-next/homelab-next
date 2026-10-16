# SPDX-License-Identifier: Apache-2.0
"""Schema drift between two table descriptions (``TableInfo`` from any ``LakeClient``)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from homelabnext.lake.tables import Column


@dataclass(frozen=True)
class Drift:
    kind: str  # missing_on_right | extra_on_right | type_changed | required_changed | key_changed
    column: str
    left: Any = None
    right: Any = None

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "column": self.column, "left": self.left, "right": self.right}

    def __str__(self) -> str:
        return f"{self.kind} {self.column}: {self.left!r} -> {self.right!r}"


def _flatten(cols: tuple[Column, ...], prefix: str = "") -> dict[str, Column]:
    out: dict[str, Column] = {}
    for c in cols:
        path = prefix + c.name
        out[path] = c
        if c.type == "struct":
            out.update(_flatten(c.fields, path + "."))
    return out


def schema_drift(left: Any, right: Any) -> list[Drift]:
    """Differences between two ``TableInfo`` objects, nested struct fields included."""
    fl, fr = _flatten(left.columns), _flatten(right.columns)
    out: list[Drift] = []
    for path in sorted(fl):
        if path not in fr:
            out.append(Drift("missing_on_right", path, fl[path].render(), None))
            continue
        a, b = fl[path], fr[path]
        if a.render() != b.render():
            out.append(Drift("type_changed", path, a.render(), b.render()))
        if a.required != b.required:
            out.append(Drift("required_changed", path, a.required, b.required))
    for path in sorted(set(fr) - set(fl)):
        out.append(Drift("extra_on_right", path, None, fr[path].render()))
    if tuple(left.key) != tuple(right.key):
        out.append(Drift("key_changed", "<key>", list(left.key), list(right.key)))
    return out
