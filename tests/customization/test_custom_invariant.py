# SPDX-License-Identifier: Apache-2.0
"""Invariant X-09: pass / fail / skip / error fixtures."""

from __future__ import annotations

from datetime import date

import pytest
from cust_helpers import make_doc, write_custom

from homelabnext.customization.loader import REPO_ROOT
from homelabnext.customization.plugins import x09_customizations as x09
from homelabnext.invariants import Context, Registry, load_directory


def run(root, today=date(2026, 10, 15)):
    return x09.make_check(lambda: today).fn(Context(root))


def test_pass_when_owned_and_in_date(tmp_path):
    write_custom(tmp_path / "customizations", "a", make_doc())
    r = run(tmp_path)
    assert r.status == "pass", r.evidence


def test_fail_when_expired(tmp_path):
    write_custom(tmp_path / "customizations", "a", make_doc())
    r = run(tmp_path, today=date(2027, 1, 1))
    assert r.status == "fail" and "CU008" in r.evidence and "custom:test-port" in r.evidence


@pytest.mark.parametrize("missing", ["owner", "reason", "review_by"])
def test_fail_when_unowned_or_unexplained(tmp_path, missing):
    write_custom(tmp_path / "customizations", "a", make_doc(**{missing: None}))
    r = run(tmp_path)
    assert r.status == "fail" and "CU001" in r.evidence and missing in r.evidence


def test_fail_on_conflict(tmp_path):
    write_custom(tmp_path / "customizations", "a", make_doc(id="custom:one"))
    write_custom(tmp_path / "customizations", "b", make_doc(id="custom:two"))
    assert run(tmp_path).status == "fail"


def test_skip_when_nothing_to_check(tmp_path):
    r = run(tmp_path)
    assert r.status == "skip" and r.evidence


def test_error_when_loader_breaks(tmp_path, monkeypatch):
    write_custom(tmp_path / "customizations", "a", make_doc())

    def boom(*a, **k):
        raise RuntimeError("disk on fire")

    monkeypatch.setattr(x09, "lint", boom)
    r = run(tmp_path)
    assert r.status == "error" and "disk on fire" in r.evidence


def test_env_dir_is_included(tmp_path, monkeypatch):
    overlay = tmp_path / "overlay"
    write_custom(overlay, "a", make_doc(review_by="2026-01-10", created="2025-12-01"))
    monkeypatch.setenv("HNX_CUSTOMIZATIONS_DIR", str(overlay))
    assert run(tmp_path / "empty-root").status == "fail"


def test_shipped_profiles_pass_at_repo_root():
    assert run(REPO_ROOT).status == "pass"


def test_loadable_with_plugins_dir():
    reg = Registry()
    names = load_directory(reg, REPO_ROOT / "homelabnext" / "customization" / "plugins")
    assert names == ["x09_customizations"] and "X-09" in reg.checks
