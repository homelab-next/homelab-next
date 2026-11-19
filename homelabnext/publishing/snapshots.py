# SPDX-License-Identifier: Apache-2.0
"""Pruning the private snapshots and the staged items (``state/snapshots/<kind>/<id>-<digest16>/``).

Every changed build adds a snapshot (a site) and every episode's audio stays in one, so they must go
by age or the disk fills.  Kept: the newest ``keep`` of each kind, anything younger than ``min_age_s``
(a concurrent or just-finished run), and every item id still in the publishable area or named by a
recent manifest line (the build the live site or feed came from).  Only a directory this module
named and made is ever removed: its resolved path must be directly under the resolved snapshot
root, deep enough, not a link, and named like a snapshot; nothing else is touched.
"""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

from homelabnext.publishing.gate import KINDS

_TMP = re.compile(r"^\.(tmp|failed)-[0-9a-f]{12}$")


def _name(digest_len: int) -> re.Pattern[str]:
    return re.compile(rf"^(?P<id>[A-Za-z0-9][A-Za-z0-9._-]*)-[0-9a-f]{{{digest_len}}}$")


def referenced_ids(manifest: Path, last: int = 50) -> set[str]:
    """The item ids of the newest manifest lines."""
    if not manifest.is_file():
        return set()
    out: set[str] = set()
    for line in manifest.read_text(encoding="utf-8").splitlines()[-last:]:
        try:
            item = json.loads(line).get("item")
        except ValueError:
            continue
        if isinstance(item, str):
            out.add(item)
    return out


def _removable(base: Path, path: Path, name: re.Pattern[str]) -> bool:
    real = path.resolve()
    return (
        not path.is_symlink()
        and path.is_dir()
        and real.parent == base.resolve()
        and len(real.parts) >= 5
        and bool(name.match(path.name) or _TMP.match(path.name))
    )


def prune(
    snapshots: Path,
    *,
    keep: int,
    min_age_s: float,
    protect_ids: set[str],
    now: float,
    digest_len: int = 16,
) -> list[str]:
    """Remove old snapshots (or, with ``digest_len=12``, old staged items: ``staging/<kind>/<id>-<12 hex>``);
    returns the names removed."""
    name = _name(digest_len)
    removed: list[str] = []
    if keep < 1:
        raise ValueError("keep at least one snapshot per kind")
    if snapshots.is_symlink():
        return removed
    for kind in KINDS:
        base = snapshots / kind
        if base.is_symlink() or not base.is_dir():
            continue
        entries = sorted(
            (p for p in base.iterdir() if _removable(base, p, name)),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        for p in entries[keep:]:
            m = name.match(p.name)
            if m and m.group("id") in protect_ids:
                continue
            if p.stat().st_mtime > now - min_age_s:
                continue
            shutil.rmtree(p)
            removed.append(f"{kind}/{p.name}")
    return removed
