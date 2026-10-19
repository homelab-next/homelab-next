# SPDX-License-Identifier: Apache-2.0
"""Shared helpers for the workflow tests: the repository's packs, mutated copies, rule lists."""

from __future__ import annotations

import copy
from functools import cache
from pathlib import Path

from homelabnext.workflows import check_pack, load_doc, load_universe

ROOT = Path(__file__).resolve().parents[2]
PACKS = ROOT / "workflows" / "packs"
MANIFEST = ROOT / "workflows" / "broker.manifest.json"


@cache
def universe():
    return load_universe(ROOT)


def pack(name: str) -> dict:
    return copy.deepcopy(load_doc(PACKS / f"{name}.yml"))


def manifest() -> dict:
    return copy.deepcopy(load_doc(MANIFEST))


def step(doc: dict, sid: str) -> dict:
    return next(s for s in doc["steps"] if s["id"] == sid)


def rules(doc: dict, **kw) -> set[str]:
    return {rule for rule, _ in check_pack(doc, universe(), **kw)}


def problems(doc: dict, **kw) -> list[tuple[str, str]]:
    return check_pack(doc, universe(), **kw)
