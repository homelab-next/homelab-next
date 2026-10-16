# SPDX-License-Identifier: Apache-2.0
"""``conformance/<cap>/test_*.py`` runs one check at a time against $HNX_CONFORM_TARGET."""

import pytest

from homelabnext.conform import testing


def test_default_target_is_the_fake(monkeypatch):
    monkeypatch.delenv("HNX_CONFORM_TARGET", raising=False)
    assert testing.target_name() == "fake"
    testing.assert_check("secrets", "put-get-roundtrip")


def test_failure_surfaces_with_check_name(monkeypatch):
    monkeypatch.setenv("HNX_CONFORM_TARGET", "broken")
    with pytest.raises(AssertionError, match="errors-never-contain-values"):
        testing.assert_check("secrets", "errors-never-contain-values")


def test_unmeasurable_run_fails_the_test(monkeypatch, tmp_path):
    t = tmp_path / "t.yml"
    t.write_text(
        "capabilities:\n  events:\n    adapter: conformance.fakes.object_store:FakeObjectStore\n"
        "    config: {bogus: 1}\n"
    )
    monkeypatch.setenv("HNX_CONFORM_TARGET", str(t))
    with pytest.raises(pytest.fail.Exception, match="could not build"):
        testing.assert_check("events", "ack-settles-once")


def test_skipped_and_should_checks_do_not_fail(monkeypatch):
    monkeypatch.delenv("HNX_CONFORM_TARGET", raising=False)
    testing.assert_check("object-store", "user-metadata-preserved")
