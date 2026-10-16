# SPDX-License-Identifier: Apache-2.0
import pytest

from homelabnext.ids import IdError, MappingResolver, Resolver, UnresolvedId, parse


def test_resolves_to_adapter_locator():
    r = MappingResolver("engine-a", {"det:auth-failure-burst": "900001"})
    assert isinstance(r, Resolver)
    assert r.resolve("det:auth-failure-burst") == "900001"
    assert r.resolve(parse("det:auth-failure-burst")) == "900001"


def test_unknown_id_is_unresolved_not_invalid():
    r = MappingResolver("engine-a", {})
    with pytest.raises(UnresolvedId):
        r.resolve("det:other")


def test_malformed_id_refused_before_lookup():
    r = MappingResolver("engine-a", {})
    with pytest.raises(IdError):
        r.resolve("viking://x")


def test_map_keys_must_be_valid_ids():
    with pytest.raises(IdError):
        MappingResolver("engine-a", {"900299": "x"})
