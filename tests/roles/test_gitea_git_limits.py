# SPDX-License-Identifier: Apache-2.0
"""Role ``gitea``: git's housekeeping is bounded and kept out of the push path.

A repository with hundreds of MiB of loose objects was repacked by the ``git gc --auto`` that every
receive-pack starts; the unbounded ``pack-objects`` ran for hours throttled at the slice's
MemoryHigh and starved the web worker.  The container's environment therefore sets ``gc.auto=0``
(Gitea's own scheduled repository GC does the repack), bounded pack memory and one pack thread in
Gitea's ``[git.config]``, and a GC timeout long enough for a large repository."""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
ENV = yaml.safe_load((ROOT / "modules/gitea/roles/gitea/vars/main.yml").read_text())["gitea_fixed_env"]


def test_gc_is_off_in_the_push_path() -> None:
    assert ENV["GITEA__git_0X2E_config__gc_0X2E_auto"] == "0"


def test_pack_memory_and_threads_are_bounded() -> None:
    assert ENV["GITEA__git_0X2E_config__pack_0X2E_threads"] == "1"
    assert ENV["GITEA__git_0X2E_config__pack_0X2E_windowMemory"] == "256m"
    assert ENV["GITEA__git_0X2E_config__pack_0X2E_deltaCacheSize"] == "128m"


def test_scheduled_gc_has_a_timeout_longer_than_the_default() -> None:
    assert int(ENV["GITEA__git_0X2E_timeout__GC"]) >= 600
