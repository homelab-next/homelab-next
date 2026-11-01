# SPDX-License-Identifier: Apache-2.0
"""A VerifiedProfile is the only profile the acting consumers take: it is made only by verifying
a compiled profile against a ceiling policy and a lock of reviewed digests, and it cannot be
edited afterwards (an edited dict with a recomputed digest is the attack it closes)."""

import copy
import json
import pickle

import pytest
import yaml
from agent_support import library, lock_for, policy_for, spec

from homelabnext.agent import (
    UnverifiedProfile,
    VerifiedProfile,
    compile_profile,
    load_verified_profile,
    profile_digest,
    verified_profile,
    verify_profile,
)
from homelabnext.agent.compiler import require_verified


@pytest.fixture
def compiled():
    return compile_profile(spec(), library())


def test_it_is_made_only_by_verifying(compiled):
    with pytest.raises(TypeError, match="made only by"):
        VerifiedProfile(compiled, "forged")
    with pytest.raises(TypeError, match="made only by"):
        VerifiedProfile(compiled, "forged", object())
    vp = verified_profile(compiled, policy=policy_for(compiled), lock=lock_for(compiled))
    assert isinstance(vp, VerifiedProfile) and require_verified(vp, "x") is vp
    assert dict(vp) == compiled and vp.data() == compiled and vp.policy_source == "test-policy"
    assert verify_profile(vp) == []


def test_it_needs_both_a_policy_and_a_lock(compiled):
    policy, lock = policy_for(compiled), lock_for(compiled)
    with pytest.raises(UnverifiedProfile, match="CeilingPolicy"):
        verified_profile(compiled, policy=None, lock=lock)
    with pytest.raises(UnverifiedProfile, match="lock of reviewed digests"):
        verified_profile(compiled, policy=policy, lock=None)
    with pytest.raises(UnverifiedProfile, match="is a mapping"):
        verified_profile([compiled], policy=policy, lock=lock)
    with pytest.raises(UnverifiedProfile, match="not in the lock"):
        verified_profile(compiled, policy=policy, lock={})


def test_an_edited_and_re_digested_profile_does_not_verify(compiled):
    policy, lock = policy_for(compiled), lock_for(compiled)
    edited = copy.deepcopy(compiled)
    edited["memory_scopes"] = ["analyst", "someone-else"]
    edited["digest"] = profile_digest(edited)
    with pytest.raises(UnverifiedProfile, match="is not the reviewed"):
        verified_profile(edited, policy=policy, lock=lock)


def test_it_is_read_only_and_hands_out_copies(compiled):
    vp = verified_profile(compiled, policy=policy_for(compiled), lock=lock_for(compiled))
    compiled["memory_scopes"].append("someone-else")  # the source dict is not shared
    assert vp["memory_scopes"] == ["analyst"]
    vp["memory_scopes"].append("someone-else")  # nor is what it hands out
    assert vp.get("memory_scopes") == ["analyst"]
    with pytest.raises(TypeError):
        vp["id"] = "profile:other"  # type: ignore[index]
    with pytest.raises(AttributeError, match="read-only"):
        vp._doc = {}
    with pytest.raises(AttributeError, match="read-only"):
        del vp._doc
    assert copy.deepcopy(vp) is vp and copy.copy(vp) is vp
    with pytest.raises(TypeError, match="not pickled"):
        pickle.dumps(vp)
    assert "profile:reader" in repr(vp)


def test_require_verified_refuses_a_dict(compiled):
    with pytest.raises(UnverifiedProfile, match="start_session needs a VerifiedProfile"):
        require_verified(compiled, "start_session")


@pytest.mark.parametrize("suffix", [".json", ".yml"])
def test_load_verified_profile_reads_a_profile_file(compiled, tmp_path, suffix):
    path = tmp_path / f"profile{suffix}"
    dump = json.dumps if suffix == ".json" else yaml.safe_dump
    path.write_text(dump(compiled))
    vp = load_verified_profile(path, policy_for(compiled), lock_for(compiled))
    assert vp["digest"] == compiled["digest"]
    with pytest.raises(UnverifiedProfile, match=r"profile\..*not in the lock"):
        load_verified_profile(path, policy_for(compiled), {})


@pytest.mark.parametrize("text", ["{not json", "a: [b", None])
def test_load_verified_profile_refuses_an_unreadable_file(compiled, tmp_path, text):
    path = tmp_path / ("p.json" if text == "{not json" else "p.yml")
    if text is not None:
        path.write_text(text)
    with pytest.raises(UnverifiedProfile, match="cannot read profile"):
        load_verified_profile(path, policy_for(compiled), lock_for(compiled))
