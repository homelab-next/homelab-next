# SPDX-License-Identifier: Apache-2.0
"""ADR-0040 decision 6: the leave-the-product export for core capability fakes.

Every core capability fake that has an open-format export (``conformance.fakes.portable``) must
round-trip through the full ``migration`` suite: the suite's round-trip MUST (export, import into
a freshly seeded fake, export again: equal manifest file list) is the evidence named by
``MIGRATION_PROOF`` in ``tests/modules/test_import_validation.py`` for that slot.  The suite's
other checks (traversal, symlinks, special files, strays, oversize trees, atomic refusal) also
run, so an adapter that skips any one of them fails here.
"""

from __future__ import annotations

import pytest

from conformance.fakes.portable import PORTABLE_FACTORIES
from homelabnext.conform.core import run_checks
from homelabnext.conform.registry import load_module


@pytest.mark.parametrize("slot", sorted(PORTABLE_FACTORIES))
def test_portable_adapter_runs_the_migration_suite_green(slot):
    suite = load_module("migration").SUITE
    factory = PORTABLE_FACTORIES[slot]
    results = run_checks(suite, factory)
    failed = [(r.check, r.evidence) for r in results if not r.ok]
    assert failed == [], failed
    assert {r.check for r in results if r.status == "pass"} == set(suite.ids())


@pytest.mark.parametrize("slot", sorted(PORTABLE_FACTORIES))
def test_portable_adapter_has_a_stable_fixed_point(slot, tmp_path):
    """export -> fresh fake -> import_ -> export again produces the same canonical tree (files
    and digests), with the fake's seed data reproducible.  This is the round-trip MUST stated
    with digests, not only the file list the migration suite compares."""
    factory = PORTABLE_FACTORIES[slot]
    a = factory()
    dest1 = tmp_path / "a"
    dest1.mkdir()
    m1 = a.export(dest1, a.export_formats[0])
    b = factory()
    b.import_(dest1, m1)
    dest2 = tmp_path / "b"
    dest2.mkdir()
    m2 = b.export(dest2, b.export_formats[0])
    assert [f["sha256"] for f in m1["files"]] == [f["sha256"] for f in m2["files"]], (m1, m2)
    assert [f["path"] for f in m1["files"]] == [f["path"] for f in m2["files"]]


def test_portable_factories_cover_every_promoted_slot():
    """A new MIGRATION_PROOF entry of the form ``adapter: Portable...`` must have a matching
    factory here, otherwise the round-trip test skips the slot silently."""
    import importlib

    pf = importlib.import_module("tests.modules.test_import_validation").MIGRATION_PROOF
    promoted = {slot for slot, proof in pf.items() if proof.startswith("adapter:")}
    assert promoted == set(PORTABLE_FACTORIES), (
        f"MIGRATION_PROOF adapter entries {sorted(promoted)} must equal "
        f"PORTABLE_FACTORIES {sorted(PORTABLE_FACTORIES)}"
    )
