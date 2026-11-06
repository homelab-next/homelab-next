# SPDX-License-Identifier: Apache-2.0
"""Agent memory is controlled (checklist M-09): validated writes only, owner-scoped reads."""

import pytest
from agent_support import (
    inputs,
    library,
    lock_for,
    manifest,
    policy_for,
    spec,
    verified,
    write,
)

from homelabnext.agent import (
    UnverifiedProfile,
    assemble_pack,
    compile_profile,
    profile_digest,
    verified_profile,
)
from homelabnext.agent.memory import (
    FileBackend,
    InMemoryBackend,
    MemoryAccessError,
    MemoryStore,
    MemoryUpdateError,
)


@pytest.fixture
def reader():
    return verified(compile_profile(spec(), library()))


@pytest.fixture
def other():
    s = spec()
    s["id"] = "profile:other-reader"
    return verified(compile_profile(s, library()))


def up(op, key, value=None, scope="analyst"):
    u = {"scope": scope, "op": op, "key": key}
    if value is not None:
        u["value"] = value
    return u


def test_add_replace_retire_through_validated_updates(reader):
    store = MemoryStore()
    write(store, reader, [up("add", "login-burst", "seen once"), up("add", "scanner", "x")])
    write(store, reader, [up("replace", "login-burst", "seen twice")])
    write(store, reader, [up("retire", "scanner")])
    assert store.read(reader, "analyst") == {"login-burst": "seen twice"}
    assert store.read(reader, "analyst", include_retired=True)["scanner"] == "x"


@pytest.mark.parametrize(
    "bad",
    [
        [{"scope": "analyst", "op": "upsert", "key": "k", "value": "v"}],  # unknown op
        [{"scope": "analyst", "op": "add", "key": "k", "value": "v", "owner": "x"}],  # extra field
        [{"scope": "analyst", "op": "add", "key": "Not A Slug", "value": "v"}],
        [{"scope": "analyst", "op": "add", "key": "k", "value": "v" * 2001}],  # over maxLength
        [up("add", "k")],  # add without a value
        [up("replace", "never-added", "v")],
        [up("retire", "never-added")],
        {"scope": "analyst"},  # not a list
    ],
)
def test_invalid_updates_are_refused(reader, bad):
    store = MemoryStore()
    with pytest.raises(MemoryUpdateError):
        write(store, reader, bad)
    assert store.read(reader, "analyst") == {}


def test_a_batch_is_all_or_nothing(reader):
    store = MemoryStore()
    with pytest.raises(MemoryUpdateError):
        write(store, reader, [up("add", "good", "v"), up("replace", "missing", "v")])
    assert store.read(reader, "analyst") == {}


def test_writing_a_scope_the_profile_lacks_is_refused(reader):
    with pytest.raises(MemoryAccessError, match="not in the profile's memory_scopes"):
        write(MemoryStore(), reader, [up("add", "k", "v", scope="responder")])


def test_cross_agent_read_is_refused(reader, other):
    store = MemoryStore()
    write(store, reader, [up("add", "secret-hunch", "v")])
    with pytest.raises(MemoryAccessError, match="cross-agent read"):
        store.read(other, "analyst", owner=reader["id"])
    # the same scope name on another profile is a different memory
    assert store.read(other, "analyst") == {}
    assert store.read(reader, "analyst", owner=reader["id"]) == {"secret-hunch": "v"}


def test_reading_a_scope_the_profile_lacks_is_refused(reader):
    with pytest.raises(MemoryAccessError):
        MemoryStore().read(reader, "responder")


@pytest.mark.parametrize("redigest", [False, True])
def test_a_profile_edited_after_compile_gets_no_access(reader, redigest):
    """Only a VerifiedProfile is accepted: a widened dict is refused even with its digest
    recomputed (anyone holding the dict can do that)."""
    widened = reader.data()
    widened["memory_scopes"] = ["analyst", "responder"]
    if redigest:
        widened["digest"] = profile_digest(widened)
    store = MemoryStore()
    with pytest.raises(UnverifiedProfile, match="needs a VerifiedProfile"):
        store.read(widened, "responder")
    with pytest.raises(UnverifiedProfile, match="needs a VerifiedProfile"):
        write(store, widened, [up("add", "k", "v", scope="responder")])
    with pytest.raises(UnverifiedProfile, match="needs a VerifiedProfile"):
        store.apply_report(widened, {})
    # and it cannot become one: the lock pins the reviewed digest
    with pytest.raises(UnverifiedProfile, match="does not verify"):
        verified_profile(widened, policy=policy_for(reader), lock=lock_for(reader))
    unsigned = {k: v for k, v in reader.items() if k != "digest"}
    with pytest.raises(UnverifiedProfile):
        store.read(unsigned, "analyst")


def _report(profile, pack_hash, updates, status="ok"):
    return {
        "pack_id": pack_hash,
        "profile": profile["id"],
        "status": status,
        "summary": "one burst",
        "cites": [{"source": "findings", "ref": "f1"}] if status == "ok" else [],
        "unknowns": [],
        "memory_updates": updates,
    }


def test_reports_update_only_their_own_agents_memory(reader, other):
    pack, h = assemble_pack(manifest(), inputs())
    store = MemoryStore()
    rep = _report(reader, h, [up("add", "login-burst", "seen once")])
    store.apply_report(reader, rep, pack=pack, pack_hash=h, manifest=manifest())
    assert store.read(reader, "analyst") == {"login-burst": "seen once"}
    with pytest.raises(MemoryAccessError, match="its own agent"):
        store.apply_report(other, rep, pack=pack, pack_hash=h)
    wrong_pack = dict(rep, pack_id="sha256:" + "1" * 64)
    with pytest.raises(MemoryUpdateError, match="pack_id"):
        store.apply_report(reader, wrong_pack, pack=pack, pack_hash=h)
    deferred = _report(reader, h, [up("add", "guess", "v")], status="deferred")
    with pytest.raises(MemoryUpdateError, match="deferred"):
        store.apply_report(reader, deferred, pack=pack, pack_hash=h)


def test_file_backend_persists_through_the_state_library(reader, tmp_path):
    path = tmp_path / "memory.json"
    write(MemoryStore(FileBackend(path)), reader, [up("add", "k", "v")])
    again = MemoryStore(FileBackend(path))
    assert again.read(reader, "analyst") == {"k": "v"}
    with pytest.raises(MemoryUpdateError):
        write(again, reader, [up("add", "k", "v2")])
    assert again.read(reader, "analyst") == {"k": "v"}


def test_the_store_has_no_unvalidated_write_path():
    public = {n for n in dir(MemoryStore) if not n.startswith("_")}
    assert public == {"apply_updates", "apply_report", "read", "history", "as_of"}
    assert isinstance(MemoryStore()._backend, InMemoryBackend)
