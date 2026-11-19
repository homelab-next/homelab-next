# SPDX-License-Identifier: Apache-2.0
"""Stage-only output: the would-be publish set, written to a directory, with no network at all.

The shadow lane runs in this mode (it never publishes).  Each staged item lands in
``<staging>/<kind>/<id>-<digest12>/`` (the payload and a ``plan.json``) built in a sibling
temporary directory and renamed into place; nothing is ever removed, and an item already staged
with the same digest is left alone.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
from pathlib import Path

from homelabnext.publishing.gate import Item, Verdict, tree_digest
from homelabnext.state import atomic_write_text


class StageError(RuntimeError):
    pass


def safe_root(path: Path) -> Path:
    """Resolve ``path`` and refuse the places a staging root must not be."""
    if ".." in path.parts:
        raise StageError("a staging path may not contain ..")
    real = path.resolve()
    if len(real.parts) < 4:
        raise StageError(f"{real} is too shallow to be a staging root")
    return real


def _write_plan(
    directory: Path, item: Item, verdict: Verdict, plan: dict, lane: str | None = None
) -> None:
    doc = {
        "item": item.id,
        "kind": item.kind,
        "tlp": verdict.label,
        "mode": "stage",
        "plan": plan,
        "sha256s": item.sidecar["sha256s"],
    }
    if lane is not None:  # which producer lane the item came from (never inferred from the path)
        doc["lane"] = lane
    text = json.dumps(doc, indent=2, sort_keys=True) + "\n"
    atomic_write_text(directory / "plan.json", text, mode=0o640)


def stage_item(
    item: Item,
    verdict: Verdict,
    plan: dict,
    staging: Path,
    source: Path,
    lane: str | None = None,
) -> Path:
    """Write ``item`` and ``plan.json`` (the verdict and what each adapter would do)."""
    root = safe_root(staging)
    src = source.resolve()
    if root == src or src in root.parents or root in src.parents:
        raise StageError("the staging root and the publishable area may not nest")
    digest = tree_digest(item)[:12]
    final = root / item.kind / f"{item.id}-{digest}"
    if final.exists():
        os.utime(final)  # still current: the pruner goes by age
        return final
    parent = final.parent
    parent.mkdir(parents=True, exist_ok=True)
    tmp = parent / f".tmp-{secrets.token_hex(6)}"
    try:
        tmp.mkdir(mode=0o750)
        for rel in item.files:
            dest = tmp / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(item.path(rel), dest)
        _write_plan(tmp, item, verdict, plan, lane)
        os.rename(tmp, final)
    except BaseException:
        # leave no half-built directory that looks like a staged item: name it plainly instead
        if tmp.exists():
            os.rename(tmp, parent / f".failed-{tmp.name[5:]}")
        raise
    return final
