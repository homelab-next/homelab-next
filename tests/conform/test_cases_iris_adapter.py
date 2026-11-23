# SPDX-License-Identifier: Apache-2.0
"""The ``cases`` adapter on the case store's API (``adapters/cases_iris.py``) on the recorded stand-in of the product's API: the ``cases`` suite passes with ``--strict``, the
severity is resolved by name (the product's numbers are not in severity order), a wrong key is a
contract error and never a product failure, and a settings mistake is refused without echoing a value."""

from __future__ import annotations

import pytest

from conformance.fakes import iris_api as fake_api
from conformance.protocols.cases import CasesError, NotFound
from homelabnext.conform import testing
from homelabnext.conform.adapters import cases_iris as cases


@pytest.fixture
def store():
    s = cases.make_recorded()
    yield s
    s.close()


def test_the_cases_suite_passes_strict_on_the_recorded_stand_in(monkeypatch):
    monkeypatch.setenv("HNX_CONFORM_TARGET", "cases-iris")
    for check in testing.check_ids("cases"):
        testing.assert_check("cases", check)
    testing.assert_enough_executed("cases")


def test_severity_is_resolved_by_name_not_by_number(store):
    assert fake_api.SEVERITIES["Medium"] == 1 and fake_api.SEVERITIES["Low"] == 4
    for name in ("low", "medium", "high", "critical"):
        a = store.create_alert("sensor", f"t-{name}", name)
        assert store.get_alert(a.id).severity == name


def test_a_wrong_key_is_a_contract_error():
    fake = fake_api.FakeIris().start()
    try:
        bad = cases.IrisCases(fake.url, token=lambda: "not-the-key")
        with pytest.raises(CasesError):
            bad.create_alert("s", "t", "low")
    finally:
        fake.stop()


def test_a_dedup_key_is_matched_exactly_though_the_tag_filter_is_a_substring_match(store):
    a = store.create_alert("s", "one", "low", dedup_key="k")
    b = store.create_alert("s", "two", "low", dedup_key="k2")
    assert a.id != b.id and store.create_alert("s", "again", "low", dedup_key="k").id == a.id


def test_the_resolution_is_kept_and_is_not_a_note(store):
    case = store.promote(store.create_alert("s", "t", "low").id)
    store.add_note(case.id, "analyst", "looked")
    closed = store.set_status(case.id, "closed", resolution="benign scanner")
    assert closed.resolution == "benign scanner" and closed.notes == (("analyst", "looked"),)
    assert store.set_status(case.id, "open").resolution is None


def test_ids_that_are_not_numbers_are_not_found_without_a_call(store):
    with pytest.raises(NotFound):
        store.get_case("../../manage/cases/1")
    assert fake_api.FakeIris is not None


def test_settings_are_checked_and_a_credential_must_be_a_reference(monkeypatch):
    with pytest.raises(ValueError, match="unknown setting"):
        cases.make(base_url="https://case.example.internal", credential="secret:x/y", nope=1)
    with pytest.raises(ValueError, match="secret name"):
        cases.make(base_url="https://case.example.internal", credential="a-literal-value")
    monkeypatch.delenv("HNX_ENDPOINT_CASE_MANAGEMENT", raising=False)
    with pytest.raises(ValueError, match="no endpoint"):
        cases.make(credential="secret:x/y")
