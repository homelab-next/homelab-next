# SPDX-License-Identifier: Apache-2.0
"""The forge provider's git housekeeping is bounded and kept out of the push path.

A repository with hundreds of MiB of loose objects was repacked by the ``git gc --auto`` that every
receive-pack starts; the unbounded ``pack-objects`` ran for hours throttled at the slice's
MemoryHigh and starved the web worker.  The container's environment therefore sets ``gc.auto=0``
(the product's own scheduled repository GC does the repack), bounded pack memory and one pack
thread in its ``[git.config]``, and a GC timeout long enough for a large repository."""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def _forge_env() -> dict:
    for manifest in sorted((ROOT / "modules").glob("*/module.yml")):
        slots = (yaml.safe_load(manifest.read_text()).get("provides") or {}).get("slots") or {}
        if "forge" in slots:
            for vars_file in manifest.parent.glob("roles/*/vars/main.yml"):
                for name, env in yaml.safe_load(vars_file.read_text()).items():
                    if name.endswith("_fixed_env"):
                        return env
    raise AssertionError("no forge provider with a fixed environment")


def _value(suffix: str) -> str:
    hits = [v for k, v in _forge_env().items() if k.endswith(suffix)]
    assert len(hits) == 1, suffix
    return hits[0]


def test_gc_is_off_in_the_push_path() -> None:
    assert _value("git_0X2E_config__gc_0X2E_auto") == "0"


def test_pack_memory_and_threads_are_bounded() -> None:
    assert _value("_config__pack_0X2E_threads") == "1"
    assert _value("_config__pack_0X2E_windowMemory") == "256m"
    assert _value("_config__pack_0X2E_deltaCacheSize") == "128m"


def test_scheduled_gc_has_a_timeout_longer_than_the_default() -> None:
    assert int(_value("git_0X2E_timeout__GC")) >= 600
