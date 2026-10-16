# SPDX-License-Identifier: Apache-2.0
"""Targets: the same suite runs against any implementation named by an adapter."""

import pytest

from conformance.fakes.object_store import FakeObjectStore
from homelabnext.conform import CAPABILITIES, ConformError, run, run_capability, run_checks
from homelabnext.conform.registry import load_suite
from homelabnext.conform.target import binding_from_mapping, load_target

OBJ = "conformance.fakes.object_store"


def test_run_function_with_fake_and_adapter_mappings():
    fake = run("object-store", {"fake": True})
    via_adapter = run(
        "object-store", {"adapter": f"{OBJ}:FakeObjectStore", "features": ["metadata"]}
    )
    assert [r.to_dict() for r in fake] == [r.to_dict() for r in via_adapter]
    assert all(r.status == "pass" for r in via_adapter)


def test_adapter_config_is_passed_as_keyword_arguments():
    # the factory is called once per check with the same config
    res = run(
        "secrets",
        {"adapter": "conformance.fakes.secret_store:FakeSecretStore", "config": {}},
    )
    assert all(r.status in ("pass", "skip") for r in res)


def test_features_declared_in_the_target_enable_feature_checks():
    class NoFeatures(FakeObjectStore):
        features = frozenset()

    def factory():
        return NoFeatures()

    res = run_checks(load_suite("object-store"), factory)
    assert {r.check: r.status for r in res}["user-metadata-preserved"] == "skip"
    res = run_checks(load_suite("object-store"), factory, features=["metadata"])
    assert {r.check: r.status for r in res}["user-metadata-preserved"] == "pass"


def test_target_file_roundtrip(tmp_path):
    f = tmp_path / "t.yml"
    f.write_text(
        "name: mine\n"
        "capabilities:\n"
        "  object-store:\n"
        f"    adapter: {OBJ}:FakeObjectStore\n"
        "    features: [metadata]\n"
        "    waive: {user-metadata-preserved: 'backend drops user metadata'}\n"
    )
    t = load_target(str(f))
    assert t.name == "mine"
    run_ = run_capability("object-store", t)
    byid = {r.check: r for r in run_.results}
    assert byid["user-metadata-preserved"].status == "waived"
    assert run_.ok and run_.passing


def test_named_target_is_found_under_conformance_targets():
    assert load_target("example").name == "example"
    assert load_target("lake-iceberg").name == "lake-iceberg"


def test_target_without_a_binding_for_the_capability_is_a_config_error():
    with pytest.raises(ConformError, match="no binding"):
        run_capability("events", "example")


@pytest.mark.parametrize(
    ("doc", "msg"),
    [
        ({"adapter": "no-colon"}, "package.module:factory"),
        ({"adapter": "a.b:c", "config": []}, "'config'"),
        ({"adapter": "a.b:c", "waive": []}, "'waive'"),
    ],
)
def test_bad_bindings_are_rejected(doc, msg):
    with pytest.raises(ConformError, match=msg):
        binding_from_mapping("events", doc)


def test_unimportable_adapter_is_a_config_error():
    with pytest.raises(ConformError, match="cannot be imported"):
        run("events", {"adapter": "no_such_package_zz:factory"})
    with pytest.raises(ConformError, match="cannot be imported"):
        run("events", {"adapter": f"{OBJ}:NoSuchName"})


def test_waiving_a_must_check_is_a_config_error():
    t = {
        "adapter": f"{OBJ}:FakeObjectStore",
        "waive": {"put-get-roundtrip": "we do not care"},
    }
    with pytest.raises(ValueError, match="MUST"):
        run("object-store", t)
    with pytest.raises(ConformError, match="MUST"):
        run_capability(
            "object-store",
            load_target_from_mapping("object-store", t),
        )


def load_target_from_mapping(cap, doc):
    from homelabnext.conform.target import Target

    return Target("inline", {cap: binding_from_mapping(cap, doc)})


def test_a_subject_that_cannot_be_built_is_could_not_measure_not_a_failure():
    t = load_target_from_mapping(
        "events", {"adapter": "conformance.fakes.object_store:FakeObjectStore", "config": {"x": 1}}
    )
    run_ = run_capability("events", t)
    assert run_.error and "could not build subject" in run_.error
    assert not run_.ok and not run_.passing and run_.results == []


def test_unknown_and_unsuited_names():
    with pytest.raises(ConformError, match="unknown capability"):
        run_capability("teleporter", "fake")
    with pytest.raises(ConformError, match="unknown target"):
        load_target("no-such-target-zz")
    assert "lake-query" in CAPABILITIES


def test_a_missing_source_checkout_is_explained(monkeypatch, tmp_path):
    import importlib

    from homelabnext.conform import registry

    def no_conformance(name, *a, **kw):
        raise ModuleNotFoundError("No module named 'conformance'", name="conformance")

    monkeypatch.setattr(importlib, "import_module", no_conformance)
    with pytest.raises(ConformError, match="source checkout"):
        registry.load_module("events", tmp_path)
