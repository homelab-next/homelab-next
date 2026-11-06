# SPDX-License-Identifier: Apache-2.0
"""Agent memory is sourced and labelled (ADR-0037 PR 2, decisions 7 to 10): packs record what
they rendered and its labels, a source must be an identifier the assembler wrote for something
rendered, a record's label has the pack's label as its floor and never falls, reads withhold
what is above the reader's ceiling by count only, exposure is stored once per pack, and closures
are capped.  Every store test runs on both backends."""

import json
from datetime import UTC, datetime, timedelta

import pytest
from agent_support import (
    canonical_pack,
    digest,
    inputs,
    item,
    labelled_manifest,
    labelled_pack,
    library,
    manifest,
    resolved,
    spec,
    uid,
    verified,
)

from homelabnext.agent import (
    ResolvedUids,
    SpecError,
    UnverifiedProfile,
    assemble_pack,
    compile_profile,
    resolve_input_uids,
    validate_report,
)
from homelabnext.agent.digest import digest_of
from homelabnext.agent.knowledge import Selection
from homelabnext.agent.memory import (
    MAX_CLOSURE,
    MAX_RANGE_LIST,
    FileBackend,
    InMemoryBackend,
    MemoryAccessError,
    MemoryLimitError,
    MemoryStore,
    MemoryUpdateError,
    byte_cap,
    exposure_budget,
    fold,
    record_cap,
)
from homelabnext.agent.pack import MAX_RENDERED, pack_label, rendered_count, rendered_identifiers
from homelabnext.agent.report import MAX_CITES, MAX_MEMORY_UPDATES, MEM_REFUSAL

T0 = datetime(2026, 11, 6, 9, 0, tzinfo=UTC)
FL = "fleet-ledger"


class Clock:
    def __init__(self, t=T0):
        self.t = t

    def __call__(self):
        return self.t

    def tick(self, minutes=1):
        self.t += timedelta(minutes=minutes)
        return self.t


def _profile(**extra):
    s = spec()
    s.update(extra)
    return verified(compile_profile(s, library()))


@pytest.fixture
def reader():
    return _profile()


@pytest.fixture
def ledger():
    return _profile(memory_scopes=["analyst", FL], platform_scopes=[FL])


@pytest.fixture(params=["memory", "file"])
def backend(request, tmp_path):
    if request.param == "memory":
        return InMemoryBackend()
    return FileBackend(tmp_path / "memory.json", deny_path=tmp_path / "memory-deny.json")


def up(op, key, value=None, scope="analyst", sources=None):
    u = {"scope": scope, "op": op, "key": key}
    if value is not None:
        u["value"] = value
    if sources is not None:
        u["sources"] = sources
    return u


def report(profile, pack_hash, updates, **fields):
    rep = {
        "pack_id": pack_hash,
        "profile": profile["id"],
        "status": "ok",
        "summary": "one burst",
        "cites": [{"source": "findings", "ref": "f1"}],
        "unknowns": [],
        "memory_updates": updates,
    }
    rep.update(fields)
    return rep


def knowledge(*nodes):
    """A selection of knowledge nodes ``(node id, text, label or None)``, ranked in order."""
    included = []
    for rank, (nid, text, label) in enumerate(nodes, 1):
        entry = {
            "id": nid,
            "kind": nid.split(":", 1)[0],
            "title": "a record",
            "path": None,
            "reviewed": [],
            "distance": 0,
            "score": 1.0,
            "via": "seed",
            "from": nid,
            "rules": [0],
            "max_chars": 10_000,
            "digest": "sha256:" + __import__("hashlib").sha256(text.encode()).hexdigest(),
            "text": text,
            "rank": rank,
            "section": f"knowledge-{rank:03d}-{nid.replace(':', '-')}",
        }
        if label is not None:
            entry["tlp"] = label
        included.append(entry)
    return Selection(
        profile="profile:reader",
        profile_digest="sha256:" + "a" * 64,
        graph_digest="sha256:" + "b" * 64,
        rules=(),
        seeds=(),
        included=tuple(included),
        excluded=(),
    )


def _items(pack):
    return {(i["section"], i["uid"]): i["tlp"] for i in pack["provenance"]["inputs"]}


# ---------------------------------------------------------------- the pack: identities, labels
def test_the_pack_records_rendered_items_and_their_labels():
    pack, _ = labelled_pack([item(1, "green"), item(2, "amber")], [item(3, "clear")])
    prov = pack["provenance"]
    assert _items(pack) == {
        ("findings", uid(1)): "green",
        ("findings", uid(2)): "amber",
        ("memory", uid(3)): "clear",
    }
    labels = {s["name"]: s["tlp"] for s in prov["sections"]}
    assert labels == {"charter": "green", "rules": "green", "memory": "clear", "findings": "amber"}
    assert prov["tlp"] == pack_label(pack) == "amber"
    assert rendered_identifiers(pack) == {
        uid(1): "green",
        digest(1): "green",
        uid(2): "amber",
        digest(2): "amber",
        uid(3): "clear",
        digest(3): "clear",
    }


def test_pregate_sections_unlabelled_static_and_item_less_inputs_are_red():
    # the canonical manifest: a pre-gate, unlabelled static sections, input sections with no
    # items -- every one of them is red, and so is the pack
    pack, _ = canonical_pack()
    labels = {s["name"]: s["tlp"] for s in pack["provenance"]["sections"]}
    assert set(labels.values()) == {"red"} and "pregate-pipeline-health" in labels
    assert pack_label(pack) == "red" and rendered_identifiers(pack) == {}
    # a single unlabelled static section makes an otherwise clear pack red
    clear, _ = labelled_pack([item(1, "clear")], [item(2, "clear")], static="clear")
    unlabelled, _ = labelled_pack([item(1, "clear")], [item(2, "clear")], static=None)
    assert pack_label(clear) == "clear" and pack_label(unlabelled) == "red"


def test_a_callers_label_is_clamped_to_the_stored_label():
    stored = {uid(1): "amber", uid(2): "green", uid(3): None}
    pack, _ = labelled_pack(
        [item(1, "clear"), item(2, "red"), item(3, "clear")], [item(4)],
        stored={**stored, uid(4): "green"},
    )  # fmt: skip
    assert _items(pack) == {
        ("findings", uid(1)): "amber",  # the caller may not lower it
        ("findings", uid(2)): "red",  # but may raise it
        ("findings", uid(3)): "red",  # a stored row without a label is red
        ("memory", uid(4)): "green",  # no caller label: the stored one
    }


def test_tlp_on_an_input_section_and_a_misspelt_static_label_are_refused():
    m = labelled_manifest()
    next(s for s in m["sections"] if s["name"] == "findings")["tlp"] = "clear"
    with pytest.raises(SpecError, match="tlp is declared on static sections only"):
        assemble_pack(m, inputs())
    m = labelled_manifest()
    m["sections"][0]["tlp"] = "TLP:GREEN"
    with pytest.raises(SpecError, match="charter"):
        assemble_pack(m, inputs())


def test_an_input_uid_not_issued_by_the_platform_is_refused():
    with pytest.raises(SpecError, match="not in the resolved uid map"):
        labelled_pack([item(1, "green")], stored={})
    for bad in ({"uid": "LL-042", "digest": digest(1)}, {"uid": uid(1), "digest": "abc"}):
        with pytest.raises(SpecError):
            labelled_pack([bad], stored={uid(1): "green"})
    with pytest.raises(SpecError, match="not an input section"):
        assemble_pack(
            labelled_manifest(),
            {**inputs(), "items": {"charter": [item(1)]}},
            resolved_uids=resolved({uid(1): "green"}, [item(1)]),
        )


def test_resolved_uids_is_a_sealed_type_built_by_a_reader_function():
    """M4: a plain mapping is refused, the type cannot be built directly, and a stored label is
    read as stored data (a non-canonical one is red)."""
    with pytest.raises(SpecError, match="input items need resolved_uids, a ResolvedUids"):
        assemble_pack(
            labelled_manifest(),
            {**inputs(), "items": {"findings": [item(1)]}},
            resolved_uids={uid(1): {"digest": digest(1), "tlp": "clear"}},
        )
    with pytest.raises(TypeError, match="made only by resolve_input_uids"):
        ResolvedUids({}, "forged")
    got = resolve_input_uids(
        [{"uid": uid(1), "digest": digest(1), "tlp": "TLP:CLEAR"}, {"uid": uid(2), "digest": digest(2)}],
        source="lake",
    )  # fmt: skip
    assert dict(got[uid(1)]) == {"digest": digest(1), "tlp": "red"}  # not canonical: red
    assert got[uid(2)]["tlp"] == "red" and got.source == "lake"
    with pytest.raises(TypeError):
        got[uid(1)]["tlp"] = "clear"  # read-only
    with pytest.raises(SpecError, match="stored with two digests"):
        resolve_input_uids([item(1), {"uid": uid(1), "digest": digest(2)}], source="lake")
    with pytest.raises(SpecError, match="stored under two uids"):
        resolve_input_uids([item(1), {"uid": uid(2), "digest": digest(1)}], source="lake")


def test_an_items_digest_must_be_the_stored_one():
    """M3: the caller's digest is checked against the reader's, not taken on trust."""
    with pytest.raises(SpecError, match="digest is not the one test-reader stored"):
        labelled_pack(
            [{"uid": uid(1), "digest": digest(99), "tlp": "clear"}],
            stored={uid(1): {"digest": digest(1), "tlp": "clear"}},
        )


def test_a_digest_paired_with_two_uids_is_refused():
    stored = {uid(1): {"digest": digest(1)}, uid(2): {"digest": digest(2)}}
    # the reader stored them apart; the caller claims one digest for both
    with pytest.raises(SpecError):
        labelled_pack(
            [item(1), {"uid": uid(2), "digest": digest(1)}],
            stored={**stored, uid(2): {"digest": digest(1)}},
        )
    sel = knowledge((f"lesson:{uid(7)}", "the lesson", "green"))
    lesson = sel.included[0]["digest"]
    with pytest.raises(SpecError, match="paired with two uids"):
        labelled_pack(
            [{"uid": uid(1), "digest": lesson}], stored={uid(1): {"digest": lesson}}, knowledge=sel
        )


def test_tlp_markers_in_an_input_sections_text_raise_its_label_never_lower_it():
    raised, _ = labelled_pack(
        [item(1, "clear")], [item(2, "clear")], static="clear",
        text={"findings": "TLP:AMBER advisory follows", "memory": "m"},
    )  # fmt: skip
    labels = {s["name"]: s["tlp"] for s in raised["provenance"]["sections"]}
    assert labels["findings"] == "amber" and pack_label(raised) == "amber"
    lowered, _ = labelled_pack(
        [item(1, "amber")], [item(2, "clear")], static="clear",
        text={"findings": "TLP:CLEAR, honest", "memory": "m"},
    )  # fmt: skip
    assert pack_label(lowered) == "amber"


def test_the_pack_records_the_profile_it_was_assembled_for(reader):
    pack, _ = labelled_pack([item(1, "clear")], [item(2, "clear")], profile=reader)
    assert pack["profile"] == {"id": reader["id"], "digest": reader["digest"]}
    bare, _ = assemble_pack(manifest(), inputs())
    assert bare["profile"] is None
    with pytest.raises(UnverifiedProfile):
        assemble_pack(manifest(), inputs(), profile=reader.data())


def test_an_input_uid_that_is_a_knowledge_uid_with_another_digest_is_refused():
    sel = knowledge((f"lesson:{uid(7)}", "the lesson", "green"))
    real = sel.included[0]["digest"]
    with pytest.raises(SpecError, match="also a knowledge item's uid with a different digest"):
        labelled_pack(
            [{"uid": uid(7), "digest": digest(9)}], stored={uid(7): "green"}, knowledge=sel
        )
    # the same pairing is fine; one uid paired with two digests across items is not
    labelled_pack([{"uid": uid(7), "digest": real}], stored={uid(7): "green"}, knowledge=sel)
    with pytest.raises(SpecError, match=r"paired with two digests|not the one test-reader stored"):
        labelled_pack(
            [item(1), {"uid": uid(1), "digest": digest(2)}],
            stored={uid(1): {"digest": digest(1), "tlp": "green"}},
        )


def test_only_what_survived_the_budget_is_recorded():
    sel = knowledge(
        (f"lesson:{uid(7)}", "short lesson", "green"),
        ("inv:C-08", "an invariant", "clear"),
        (f"runbook:{uid(8)}", "x" * 5000, "clear"),  # over the budget: dropped
    )
    pack, _ = labelled_pack([item(1, "green")], [item(2, "green")], knowledge=sel)
    kept = {k["id"]: k for k in pack["provenance"]["knowledge"]}
    dropped = sel.included[2]
    assert dropped["section"] not in {s["name"] for s in pack["sections"]}
    assert f"runbook:{uid(8)}" not in kept
    assert uid(8) not in rendered_identifiers(pack)
    assert dropped["digest"] not in rendered_identifiers(pack)
    assert kept[f"lesson:{uid(7)}"]["uid"] == uid(7)  # lesson:<uid> gives <uid>
    assert "uid" not in kept["inv:C-08"]  # a node id that is not a uid gives none
    assert pack_label(pack) == "green"


def test_a_knowledge_node_without_a_declared_label_is_red():
    sel = knowledge((f"lesson:{uid(7)}", "a lesson", None))
    pack, _ = labelled_pack([item(1, "clear")], [item(2, "clear")], knowledge=sel)
    assert pack["provenance"]["knowledge"][0]["tlp"] == "red" and pack_label(pack) == "red"


def test_the_rendered_cap_is_checked_before_assembly():
    many = [item(n, "clear") for n in range(MAX_RENDERED // 2 + 1)]
    assert rendered_count({"items": {"findings": many}}) > MAX_RENDERED
    with pytest.raises(SpecError, match="over the cap of 1024"):
        labelled_pack(many)
    labelled_pack(many[:-1])  # exactly the cap


# ---------------------------------------------------------------- decision 7: the source check
def test_a_rendered_source_is_accepted_and_labels_the_record(reader, backend):
    sel = knowledge((f"lesson:{uid(7)}", "the lesson", "green"))
    pack, h = labelled_pack([item(1, "clear")], [item(2, "clear")], static="clear", knowledge=sel)
    store = MemoryStore(backend, now=Clock())
    lesson = sel.included[0]["digest"]
    rep = report(reader, h, [up("add", "k", "v", sources=[uid(1), lesson, uid(7)])])
    applied = store.apply_report(reader, rep, pack=pack, pack_hash=h)
    assert applied == {"revs": {"analyst/k": 1}, "unsourced": [], "withheld": 0, "dropped": []}
    (rec,) = store.history(reader, "analyst", "k")["records"]
    assert rec["sources"] == [uid(1), lesson, uid(7)]
    # the closure adds each source's platform-issued aliases (ADR-0037 decision 13)
    assert rec["closure"] == [*rec["sources"], digest(1), f"lesson:{uid(7)}"]
    assert rec["checked"] is True and rec["pack_id"] == h
    assert rec["tlp"] == "green"  # the pack's label (the green lesson)


@pytest.mark.parametrize(
    "source",
    [
        digest(42),  # fabricated
        uid(42),  # a well-formed uid the pack never rendered
    ],
)
def test_a_fabricated_source_is_refused_whole(reader, backend, source):
    pack, h = labelled_pack([item(1, "clear")], [item(2, "clear")])
    store = MemoryStore(backend, now=Clock())
    rep = report(
        reader, h, [up("add", "ok", "v", sources=[uid(1)]), up("add", "k", "v", sources=[source])]
    )
    with pytest.raises(MemoryUpdateError, match="memory_updates/1/sources/0: not an identifier"):
        store.apply_report(reader, rep, pack=pack, pack_hash=h)
    assert source not in str(validate_report(rep, pack, h))  # never echoed
    assert backend.load(reader["id"]) == {}
    with pytest.raises(MemoryUpdateError, match="not an identifier this pack rendered"):
        store.apply_updates(reader, rep["memory_updates"], pack=pack, pack_hash=h)
    assert backend.load(reader["id"]) == {}


def test_text_is_never_a_source(reader, backend):
    """A digest written in a cite's ref (or the summary, or a section body) counts for nothing."""
    planted = digest(77)
    pack, h = assemble_pack(
        labelled_manifest(),
        {
            "sections": {"findings": f"content digest: {planted}", "memory": "m"},
            "items": {"findings": [item(1, "clear")], "memory": [item(2, "clear")]},
        },
        resolved_uids=resolved({uid(1): "clear", uid(2): "clear"}, [item(1), item(2)]),
        profile=reader,
    )
    rep = report(
        reader, h, [up("add", "k", "v", sources=[planted])],
        cites=[{"source": "findings", "ref": planted}], summary=f"rests on {planted}",
    )  # fmt: skip
    # validate_report alone reports it, by position
    assert validate_report(rep, pack, h) == [
        "memory_updates/0/sources/0: not an identifier this pack rendered (a source is the "
        "digest or uid the assembler recorded for a rendered knowledge or input item, never text)"
    ]
    with pytest.raises(MemoryUpdateError, match="not an identifier this pack rendered"):
        MemoryStore(backend).apply_report(reader, rep, pack=pack, pack_hash=h)
    assert backend.load(reader["id"]) == {}


def test_a_budget_cut_knowledge_item_is_not_a_source(reader, backend):
    sel = knowledge(
        (f"lesson:{uid(7)}", "short lesson", "green"),
        (f"runbook:{uid(8)}", "x" * 5000, "clear"),  # dropped by the budget
    )
    pack, h = labelled_pack([item(1, "green")], [item(2, "green")], knowledge=sel)
    store = MemoryStore(backend, now=Clock())
    for source in (sel.included[1]["digest"], uid(8)):
        rep = report(reader, h, [up("add", "k", "v", sources=[source])])
        with pytest.raises(MemoryUpdateError, match="not an identifier this pack rendered"):
            store.apply_report(reader, rep, pack=pack, pack_hash=h)
    rep = report(reader, h, [up("add", "k", "v", sources=[sel.included[0]["digest"]])])
    store.apply_report(reader, rep, pack=pack, pack_hash=h)


def test_a_mem_source_is_refused_with_one_message_whoever_it_names(reader, backend):
    pack, h = labelled_pack([item(1, "clear")], [item(2, "clear")])
    store = MemoryStore(backend, now=Clock())
    store.apply_report(reader, report(reader, h, [up("add", "k", "v")]), pack=pack, pack_hash=h)
    messages = set()
    for src in (
        "mem:profile:reader/analyst/k@1",  # exists
        "mem:profile:reader/analyst/nope@9",  # does not
        "mem:profile:other/analyst/k@1",  # another owner
    ):
        rep = report(reader, h, [up("replace", "k", "w", sources=[src])])
        with pytest.raises(MemoryUpdateError) as exc:
            store.apply_report(reader, rep, pack=pack, pack_hash=h)
        assert src not in str(exc.value)
        messages.add(str(exc.value))
        with pytest.raises(MemoryUpdateError, match="memory block"):
            store.apply_updates(reader, rep["memory_updates"], pack=pack, pack_hash=h)
    assert len(messages) == 1 and MEM_REFUSAL in messages.pop()


def test_no_sources_is_stored_unsourced(reader, backend):
    pack, h = labelled_pack([item(1, "clear")], [item(2, "clear")])
    store = MemoryStore(backend, now=Clock())
    applied = store.apply_updates(
        reader,
        [
            up("add", "a", "v"),
            up("add", "b", "v", sources=[]),
            up("add", "c", "v", sources=[uid(1)]),
        ],
        pack=pack,
        pack_hash=h,
    )
    assert applied["unsourced"] == ["analyst/a", "analyst/b"]
    assert applied["revs"] == {"analyst/a": 1, "analyst/b": 1, "analyst/c": 1}
    assert store.history(reader, "analyst", "a")["records"][0]["sources"] == []


def test_a_write_needs_its_pack_or_unchecked(reader, backend):
    pack, h = labelled_pack([item(1, "clear")], [item(2, "clear")])
    store = MemoryStore(backend, now=Clock())
    with pytest.raises(MemoryUpdateError, match="needs the pack its updates came from"):
        store.apply_updates(reader, [up("add", "k", "v")])
    with pytest.raises(MemoryUpdateError, match="applied only with its pack"):
        store.apply_report(reader, report(reader, h, [up("add", "k", "v")]))
    with pytest.raises(MemoryUpdateError, match="pack_hash is not the hash of the pack"):
        store.apply_updates(
            reader, [up("add", "k", "v")], pack=pack, pack_hash="sha256:" + "0" * 64
        )
    tampered = {**pack, "provenance": {**pack["provenance"], "tlp": "clear"}}
    with pytest.raises(MemoryUpdateError, match="pack_hash is not the hash of the pack"):
        store.apply_updates(reader, [up("add", "k", "v")], pack=tampered, pack_hash=h)
    with pytest.raises(MemoryUpdateError, match="pack_id does not equal"):
        store.apply_updates(
            reader, [up("add", "k", "v")], pack=pack, pack_hash=h, pack_id="sha256:" + "1" * 64
        )
    assert backend.load(reader["id"]) == {}


def test_verify_is_in_the_schema_but_refused_until_pr4(reader, backend):
    pack, h = labelled_pack([item(1, "clear")], [item(2, "clear")])
    store = MemoryStore(backend, now=Clock())
    store.apply_updates(reader, [up("add", "k", "v")], pack=pack, pack_hash=h)
    rep = report(reader, h, [up("verify", "k", sources=[uid(1)])])
    assert validate_report(rep, pack, h) == []  # report_result 1.2 carries it
    with pytest.raises(MemoryUpdateError, match="applies it only from ADR-0037 PR 4"):
        store.apply_report(reader, rep, pack=pack, pack_hash=h)


def test_the_list_limits_are_enforced_in_code(reader, backend):
    pack, h = labelled_pack([item(1, "clear")], [item(2, "clear")])
    many = [up("add", f"k{i}", "v") for i in range(MAX_MEMORY_UPDATES + 1)]
    cites = [{"source": "findings", "ref": f"r{i}"} for i in range(MAX_CITES + 1)]
    for rep, words in (
        (report(reader, h, many), "memory_updates: 65 items; at most 64"),
        (report(reader, h, [], cites=cites), "cites: 129 items; at most 128"),
    ):
        assert words in validate_report(rep, pack, h)[0]
        with pytest.raises(MemoryUpdateError, match=words):
            MemoryStore(backend).apply_report(reader, rep, pack=pack, pack_hash=h)
    with pytest.raises(MemoryUpdateError, match="at most 64"):
        MemoryStore(backend).apply_updates(reader, many, pack=pack, pack_hash=h)
    ok = report(reader, h, many[:MAX_MEMORY_UPDATES], cites=cites[:MAX_CITES])
    assert validate_report(ok, pack, h) == []


# ---------------------------------------------------------------- platform scopes
def test_unchecked_writes_only_platform_scopes_and_is_red(ledger, backend):
    store = MemoryStore(backend, now=Clock())
    pack, h = labelled_pack([item(1, "clear")], [item(2, "clear")], static="clear", profile=ledger)
    with pytest.raises(MemoryAccessError, match="may write only the profile's platform_scopes"):
        store.apply_updates(ledger, [up("add", "k", "v")], unchecked=True)
    with pytest.raises(MemoryAccessError, match="platform_scopes"):
        store.apply_updates(
            ledger, [up("add", "k", "v", scope=FL), up("add", "k", "v")], unchecked=True
        )
    with pytest.raises(MemoryUpdateError, match="takes no pack"):
        store.apply_updates(
            ledger, [up("add", "k", "v", scope=FL)], unchecked=True, pack=pack, pack_hash=h
        )
    with pytest.raises(MemoryUpdateError, match="platform scope; only an unchecked"):
        store.apply_updates(ledger, [up("add", "k", "v", scope=FL)], pack=pack, pack_hash=h)
    with pytest.raises(MemoryUpdateError, match="memory block"):
        store.apply_updates(
            ledger, [up("add", "k", "v", scope=FL, sources=["mem:profile:reader/a/b@1"])],
            unchecked=True,
        )  # fmt: skip
    assert backend.load(ledger["id"]) == {}
    applied = store.apply_updates(
        ledger, [up("add", "k", "v", scope=FL, sources=[digest(5)])], unchecked=True, pack_id=h
    )
    (rec,) = store.history(ledger, FL, "k")["records"]
    assert rec["checked"] is False and rec["tlp"] == "red" and rec["sources"] == [digest(5)]
    assert rec["pack_id"] == h and applied["unsourced"] == []
    with pytest.raises(MemoryUpdateError, match="pack_id must be sha256"):
        store.apply_updates(ledger, [up("add", "j", "v", scope=FL)], unchecked=True, pack_id="x")
    assert backend.load(ledger["id"])["exposure"] == {}  # an unchecked write exposes nothing


# ---------------------------------------------------------------- decision 8: labels
def test_the_pack_sets_the_floor_even_when_only_a_green_item_is_cited(reader, backend):
    pack, h = labelled_pack(
        [item(1, "green"), item(2, "amber")], [item(3, "clear")], static="clear"
    )
    store = MemoryStore(backend, now=Clock())
    store.apply_report(
        reader, report(reader, h, [up("add", "k", "v", sources=[uid(1)])]), pack=pack, pack_hash=h
    )
    (rec,) = store.history(reader, "analyst", "k")["records"]
    assert rec["tlp"] == "amber"  # the amber item was in the context, cited or not


def test_a_label_is_never_lowered_across_replace_retire_and_re_add(reader, backend):
    amber, ha = labelled_pack([item(1, "amber")], [item(2, "clear")], static="clear")
    clear, hc = labelled_pack([item(3, "clear")], [item(4, "clear")], static="clear")
    clock = Clock()
    store = MemoryStore(backend, now=clock)
    store.apply_updates(reader, [up("add", "k", "v1", sources=[uid(1)])], pack=amber, pack_hash=ha)
    for batch in (
        [up("replace", "k", "v2", sources=[uid(3)])],
        [up("retire", "k")],
        [up("add", "k", "v3", sources=[uid(3)])],
    ):
        clock.tick()
        store.apply_updates(reader, batch, pack=clear, pack_hash=hc)
    recs = store.history(reader, "analyst", "k")["records"]
    assert [r["tlp"] for r in recs] == ["amber"] * 4
    # sources accumulate since the last add, and restart at the next one
    one, three = [uid(1), digest(1)], [uid(3), digest(3)]  # each uid with its alias
    assert [r["closure"] for r in recs] == [
        one, [*one, *three], [*one, *three], three
    ]  # fmt: skip
    entry = backend.load(reader["id"])["entries"]["analyst"]["k"]
    assert entry["tlp"] == "amber" and entry["sources"] == [uid(3)]


def test_a_source_label_raises_the_record(reader, backend):
    """A source rendered twice (in two input sections) takes the stricter of its labels."""
    pack, h = labelled_pack(
        [item(1, "clear")], [item(1, "clear")], static="clear", stored={uid(1): "clear"}
    )
    assert rendered_identifiers(pack)[uid(1)] == "clear"
    sel = knowledge((f"lesson:{uid(7)}", "the lesson", "amber"))
    pack, h = labelled_pack([item(1, "clear")], [item(2, "clear")], static="clear", knowledge=sel)
    assert pack_label(pack) == "amber" and rendered_identifiers(pack)[uid(7)] == "amber"
    store = MemoryStore(backend, now=Clock())
    store.apply_updates(reader, [up("add", "k", "v", sources=[uid(7)])], pack=pack, pack_hash=h)
    assert store.history(reader, "analyst", "k")["records"][0]["tlp"] == "amber"


# ---------------------------------------------------------------- withheld reads
def test_reads_withhold_entries_above_the_ceiling_by_count_only(backend):
    green_reader = _profile(tlp_ceiling="green", mcp=[])
    green, hg = labelled_pack(
        [item(1, "green")], [item(2, "clear")], static="clear", profile=green_reader
    )
    amber, ha = labelled_pack(
        [item(3, "amber")], [item(4, "clear")], static="clear", profile=green_reader
    )
    clock = Clock()
    store = MemoryStore(backend, now=clock)
    store.apply_updates(green_reader, [up("add", "fine", "ok")], pack=green, pack_hash=hg)
    wrote = store.apply_updates(
        green_reader, [up("add", "secret-plan-x", "amber fact")], pack=amber, pack_hash=ha
    )
    # M1: the write result is filtered by the writer's own ceiling
    assert wrote == {"revs": {}, "unsourced": [], "withheld": 1, "dropped": []}
    clock.tick()
    store.apply_updates(
        green_reader, [up("replace", "fine", "now amber")], pack=amber, pack_hash=ha
    )
    clock.tick()
    store.apply_updates(green_reader, [up("add", "other", "o")], pack=green, pack_hash=hg)
    seen = store.read(green_reader, "analyst")
    assert seen == {"entries": {"other": "o"}, "withheld": 2}
    assert store.read(green_reader, "analyst", include_retired=True)["withheld"] == 2
    hist = store.history(green_reader, "analyst", "fine")
    assert [r["value"] for r in hist["records"]] == ["ok"] and hist["withheld"] == 1
    # M2: a withheld key and a missing key answer alike, with the scope's withheld count
    hidden = store.history(green_reader, "analyst", "secret-plan-x")
    missing = store.history(green_reader, "analyst", "no-such-key")
    assert hidden == missing == {"records": [], "withheld": 2}
    now = store.as_of(green_reader, "analyst", clock.t)
    assert now["entries"] == {"other": "o"} and now["withheld"] == 2 and now["compacted"] == []
    # before "fine" was replaced, it was green and readable at this ceiling
    then = store.as_of(green_reader, "analyst", T0)
    assert then["entries"] == {"fine": "ok"} and then["withheld"] == 1
    everything = json.dumps([seen, hist, now, then, hidden, wrote])
    assert "secret-plan-x" not in everything and "amber fact" not in everything
    assert "now amber" not in everything


def test_while_memory_is_red_a_reader_below_red_sees_only_withheld_counts(backend):
    green_reader = _profile(tlp_ceiling="green", mcp=[])
    store = MemoryStore(backend, now=Clock())
    pack, h = canonical_pack(green_reader)  # red: a pre-gate and unlabelled static sections
    wrote = store.apply_updates(
        green_reader, [up("add", "a", "1"), up("add", "b", "2")], pack=pack, pack_hash=h
    )
    assert wrote["revs"] == {} and wrote["withheld"] == 2 and wrote["unsourced"] == []
    assert store.read(green_reader, "analyst") == {"entries": {}, "withheld": 2}
    # the same memory read by its local-only (red) profile in full
    red_reader = _profile()
    assert store.read(red_reader, "analyst")["entries"] == {"a": "1", "b": "2"}


# ---------------------------------------------------------------- decision 9: exposure
def test_exposure_is_stored_once_per_pack(reader, backend):
    pack, h = labelled_pack([item(1, "clear")], [item(2, "clear")])
    other, ho = labelled_pack([item(3, "clear")], [item(4, "clear")])
    clock = Clock()
    store = MemoryStore(backend, now=clock)
    store.apply_updates(reader, [up("add", "a", "1"), up("add", "b", "1")], pack=pack, pack_hash=h)
    clock.tick()
    store.apply_updates(reader, [up("replace", "a", "2")], pack=pack, pack_hash=h)
    stored = backend.load(reader["id"])
    rendered = sorted(rendered_identifiers(pack))
    pairs = [[rendered.index(uid(n)), rendered.index(digest(n))] for n in (2, 1)]  # by section
    assert stored["exposure"] == {h: {"rendered": rendered, "memory": [], "pairs": pairs}}
    assert {r["pack_id"] for r in stored["log"]} == {h}
    clock.tick()
    store.apply_updates(reader, [up("add", "c", "1")], pack=other, pack_hash=ho)
    assert set(backend.load(reader["id"])["exposure"]) == {h, ho}
    # a batch that changes nothing stores no exposure
    third, ht = labelled_pack([item(5, "clear")], [item(6, "clear")])
    store.apply_updates(reader, [], pack=third, pack_hash=ht)
    assert ht not in backend.load(reader["id"])["exposure"]


def _seed(backend, owner, value):
    if isinstance(backend, InMemoryBackend):
        backend._data[owner] = value
    else:
        backend._store.put(owner, value)


def test_an_exposure_no_record_points_at_is_dropped(backend):
    """When its records age out (decision 6), a pack's exposure goes with them.  Platform writes
    are unchecked and expose nothing, so the log is seeded as a checked platform write would leave
    it (an operator action in PR 3)."""
    p = _profile(
        memory_scopes=["analyst", FL], platform_scopes=[FL], memory_limits={"tombstones": {FL: 1}}
    )
    ex = "sha256:" + "e" * 64
    log = [
        {
            "at": "2026-11-06T08:00:00.000000Z", "scope": FL, "key": "old", "op": "add", "rev": 1,
            "value": "v", "value_digest": digest(1), "pack_id": ex, "sources": [uid(1)],
            "checked": True, "tlp": "clear", "closure": [uid(1)],
        },
    ]  # fmt: skip
    _seed(
        backend,
        p["id"],
        {"entries": fold(log), "log": log, "exposure": {ex: {"rendered": [uid(1)], "memory": []}}},
    )
    clock = Clock()
    store = MemoryStore(backend, now=clock)
    store.apply_updates(p, [up("retire", "old", scope=FL)], unchecked=True)
    stored = backend.load(p["id"])
    (tomb,) = [r for r in stored["log"] if r["key"] == "old"]
    assert ex in tomb["pack_ids"] and ex in stored["exposure"]  # the tombstone still points at it
    for k in ("a", "b"):  # two more tombstones past the budget of 1: "old" ages out
        clock.tick()
        store.apply_updates(
            p, [up("add", k, "v", scope=FL), up("retire", k, scope=FL)], unchecked=True
        )
    stored = backend.load(p["id"])
    assert all(r["key"] != "old" for r in stored["log"])
    assert stored["exposure"] == {}


# ---------------------------------------------------------------- decision 10: the closure
def test_the_closure_is_capped(reader, backend):
    """The closure counts each source with its aliases (decision 13): a uid source brings its
    digest, so 16 uids add 32 identifiers and the cap of 256 is reached after 8 batches."""
    items = [item(n, "clear") for n in range(1, 140)]
    pack, h = labelled_pack(items, [item(500, "clear")])
    ids = [uid(n) for n in range(1, 140)] + [uid(500)]  # each closes over {uid, digest}
    store = MemoryStore(backend, now=Clock())
    store.apply_updates(reader, [up("add", "k", "v", sources=ids[:16])], pack=pack, pack_hash=h)
    for n in range(1, MAX_CLOSURE // 32):
        store.apply_updates(
            reader, [up("replace", "k", f"v{n}", sources=ids[16 * n : 16 * n + 16])],
            pack=pack, pack_hash=h,
        )  # fmt: skip
    assert len(store.history(reader, "analyst", "k")["records"][-1]["closure"]) == MAX_CLOSURE
    before = backend.load(reader["id"])
    with pytest.raises(MemoryUpdateError, match="over the closure cap of 256; retire the key"):
        store.apply_updates(
            reader, [up("replace", "k", "past", sources=ids[128:129])], pack=pack, pack_hash=h
        )
    assert backend.load(reader["id"]) == before
    # a source already in the closure adds nothing, so it is still accepted
    store.apply_updates(
        reader, [up("replace", "k", "same", sources=ids[:3])], pack=pack, pack_hash=h
    )
    # retired and added again, the key starts a new closure
    store.apply_updates(reader, [up("retire", "k")], pack=pack, pack_hash=h)
    store.apply_updates(
        reader, [up("add", "k", "new", sources=ids[128:129])], pack=pack, pack_hash=h
    )
    assert store.history(reader, "analyst", "k")["records"][-1]["closure"] == [
        uid(129),
        digest(129),
    ]


# ---------------------------------------------------------------- the byte cap
def test_a_scope_has_a_byte_cap_beside_its_record_cap(backend):
    p = _profile(memory_limits={"bytes": {"analyst": 4096}})
    assert byte_cap(p, "analyst") == 4096
    assert byte_cap(_profile(), "analyst") == 2_000 * record_cap(_profile(), "analyst")
    pack, h = labelled_pack([item(1, "clear")], [item(2, "clear")], profile=p)
    clock = Clock()
    store = MemoryStore(backend, now=clock)
    refused = None
    for n in range(20):
        clock.tick()
        before = backend.load(p["id"])
        try:
            store.apply_updates(p, [up("add", f"k{n}", "x" * 400)], pack=pack, pack_hash=h)
        except MemoryLimitError as exc:
            refused = exc
            break
    assert refused is not None and refused.unit == "bytes" and 0 < n < 20
    assert "byte cap of 4096 bytes" in str(refused)
    # a model scope's advice is what works: the reviewed profile or a purge, never "retire"
    assert "raise memory_limits.bytes in the reviewed profile" in str(refused)
    assert "operator purge" in str(refused) and "retire" not in str(refused)
    # no byte total is reported: it would count records the writer may not read
    assert refused.scopes == {"analyst": (None, 4096)}
    assert backend.load(p["id"]) == before  # refused whole


def test_the_scope_byte_count_excludes_exposure(backend):
    """A scope's byte cap counts its records only: a pack that rendered many identifiers does
    not push the scope over, however large its exposure."""
    p = _profile(memory_limits={"bytes": {"analyst": 4096}})
    big = [item(n, "clear") for n in range(1, 200)]  # ~400 identifiers, an exposure of ~29 kB
    pack, h = labelled_pack(big, [item(500, "clear")], profile=p)
    store = MemoryStore(backend, now=Clock())
    store.apply_updates(p, [up("add", "k", "v")], pack=pack, pack_hash=h)
    stored = backend.load(p["id"])
    assert len(json.dumps(stored["exposure"])) > 4096  # the exposure alone is over the scope cap


def test_exposure_alone_can_push_the_owner_over_its_budget(backend, tmp_path):
    """Exposures are charged once per owner (memory_limits.exposure_bytes): a new pack whose
    exposure would cross the budget is refused and paged, even though every scope is far under
    its own caps; the owner keeps writing from packs it already holds (the intended lockout)."""
    from homelabnext.notify import FakeSender, Notifier
    from homelabnext.state import StateStore

    p = _profile(memory_limits={"exposure_bytes": 65536})
    assert exposure_budget(p) == 65536 and exposure_budget(_profile()) == 50_000_000
    first, h1 = labelled_pack([item(n, "clear") for n in range(1, 300)], [item(900)], profile=p)
    second, h2 = labelled_pack(
        [item(n, "clear") for n in range(1000, 1300)], [item(1900)], profile=p
    )
    sender = FakeSender()
    clock = Clock()
    store = MemoryStore(
        backend, now=clock, notifier=Notifier(sender, StateStore(tmp_path / "n.json"))
    )
    store.apply_updates(p, [up("add", "a", "v")], pack=first, pack_hash=h1)
    before = backend.load(p["id"])
    clock.tick()
    with pytest.raises(MemoryLimitError, match="exposure budget of 65536 bytes") as exc:
        store.apply_updates(p, [up("add", "b", "v")], pack=second, pack_hash=h2)
    assert exc.value.unit == "exposure" and exc.value.scopes == {"*": (None, 65536)}
    assert "memory_limits.exposure_bytes" in str(exc.value)
    assert backend.load(p["id"]) == before
    assert any("pack exposures refuses writes" in m.body for m in sender.sent)
    clock.tick()
    store.apply_updates(p, [up("add", "c", "v")], pack=first, pack_hash=h1)  # a held pack: fine
    assert store.read(p, "analyst")["entries"] == {"a": "v", "c": "v"}


def test_an_exposure_budget_is_additive_in_profile_1_7():
    p = _profile(memory_limits={"exposure_bytes": 1_000_000, "bytes": {"analyst": 8192}})
    assert p["memory_limits"]["exposure_bytes"] == 1_000_000
    with pytest.raises(SpecError):
        _profile(memory_limits={"exposure_bytes": 10})  # under the schema's minimum


def test_a_byte_cap_on_a_scope_the_profile_lacks_is_refused():
    with pytest.raises(SpecError, match=r"memory_limits\.bytes: 'responder' is not one of"):
        _profile(memory_limits={"bytes": {"responder": 4096}})


def test_both_backends_hold_the_same_sourced_history(tmp_path):
    pack, h = labelled_pack([item(1, "green")], [item(2, "clear")], static="clear")
    reader = _profile()
    outs = []
    for backend in (
        InMemoryBackend(),
        FileBackend(tmp_path / "m.json", deny_path=tmp_path / "m-deny.json"),
    ):
        store = MemoryStore(backend, now=Clock())
        store.apply_updates(reader, [up("add", "k", "v", sources=[uid(1)])], pack=pack, pack_hash=h)
        outs.append(backend.load(reader["id"]))
    assert outs[0] == outs[1] and outs[0]["log"][0]["tlp"] == "green"


def test_the_canonical_manifest_still_assembles_without_items():
    pack, _ = assemble_pack(manifest(), inputs())
    assert pack["provenance"]["inputs"] == [] and pack["provenance"]["knowledge"] == []


# ---------------------------------------------------------------- M5: a pack is bound to its profile
def test_a_pack_assembled_for_another_profile_or_none_is_refused(reader, ledger, backend):
    store = MemoryStore(backend, now=Clock())
    theirs, ht = labelled_pack([item(1, "clear")], [item(2, "clear")], profile=ledger)
    unbound, hu = assemble_pack(manifest(), inputs())
    for pack, h in ((theirs, ht), (unbound, hu)):
        with pytest.raises(MemoryUpdateError, match="not assembled for this profile"):
            store.apply_updates(reader, [up("add", "k", "v")], pack=pack, pack_hash=h)
        with pytest.raises(MemoryUpdateError, match="not assembled for this profile"):
            store.apply_report(
                reader, report(reader, h, [up("add", "k", "v")]), pack=pack, pack_hash=h
            )
    assert backend.load(reader["id"]) == {}


# ---------------------------------------------------------------- M2: refusals name positions
def test_a_write_refusal_names_the_position_never_the_key(reader, backend):
    pack, h = labelled_pack([item(1, "clear")], [item(2, "clear")])
    store = MemoryStore(backend, now=Clock())
    store.apply_updates(reader, [up("add", "secret-plan-x", "v")], pack=pack, pack_hash=h)
    for batch, words in (
        (
            [up("add", "secret-plan-x", "again")],
            "memory_updates/0: add of a key that is already live",
        ),
        (
            [up("replace", "missing-plan-y", "v")],
            "memory_updates/0: replace of a key that is not live",
        ),
    ):
        with pytest.raises(MemoryUpdateError, match=words) as exc:
            store.apply_updates(reader, batch, pack=pack, pack_hash=h)
        assert "plan" not in str(exc.value)


# ---------------------------------------------------------------- L2: aged_out under the ceiling
def test_aged_out_is_said_only_when_the_aged_record_is_within_the_ceiling(backend):
    def ledger(**extra):
        return _profile(
            memory_scopes=["analyst", FL], platform_scopes=[FL], memory_limits={"tombstones": {FL: 1}},
            **extra,
        )  # fmt: skip

    red, green = ledger(), ledger(tlp_ceiling="green", mcp=[])
    clock = Clock()
    store = MemoryStore(backend, now=clock)
    for k in ("a", "b", "c"):  # tombstones past the budget of 1: one ages out (a red record)
        clock.tick()
        store.apply_updates(
            red, [up("add", k, "v", scope=FL), up("retire", k, scope=FL)], unchecked=True
        )
    t = T0 + timedelta(minutes=1)  # when "a" was added and retired: its tombstone aged out
    assert store.as_of(red, FL, t)["aged_out"] is True
    assert store.as_of(green, FL, t)["aged_out"] is False


# ---------------------------------------------------------------- design 1: a range over an add
def test_a_range_across_retire_and_add_keeps_only_the_effective_sources(ledger, backend):
    p = _profile(
        memory_scopes=["analyst", FL],
        platform_scopes=[FL],
        memory_limits={"keep_last": {FL: {"k": 1}}},
    )
    clock = Clock()
    store = MemoryStore(backend, now=clock)
    s1, s2, s3, s4 = (digest(n) for n in (1, 2, 3, 4))
    for u in (
        up("add", "k", "v1", scope=FL, sources=[s1]),
        up("retire", "k", scope=FL),
        up("add", "k", "v2", scope=FL, sources=[s2]),
        up("replace", "k", "v3", scope=FL, sources=[s3]),
        up("replace", "k", "v4", scope=FL, sources=[s4]),
    ):
        clock.tick()
        store.apply_updates(p, [u], unchecked=True)
    recs = store.history(p, FL, "k")["records"]
    assert recs[-1]["closure"] == [s2, s3, s4]  # s1 was retired with its value
    assert recs[0]["compacted"] == "range" and s1 in recs[0]["sources"]  # dependents keep it
    assert recs[0]["effective"] == [s2, s3]
    stored = backend.load(p["id"])
    assert fold(stored["log"]) == stored["entries"] and stored["entries"][FL]["k"]["sources"] == [
        s2, s3, s4
    ]  # fmt: skip


def test_a_range_record_keeps_at_most_256_digests_and_pack_ids_and_says_so(backend):
    p = _profile(
        memory_scopes=["analyst", FL], platform_scopes=[FL],
        memory_limits={"keep_last": {FL: {"cursor-*": 1}}, "records": {FL: 2000}},
    )  # fmt: skip
    store = MemoryStore(backend, now=Clock())
    store.apply_updates(
        p, [up("add", "cursor-a", "0", scope=FL)], unchecked=True, pack_id=digest(0)
    )
    for n in range(1, MAX_RANGE_LIST + 3):
        store.apply_updates(
            p, [up("replace", "cursor-a", str(n), scope=FL)], unchecked=True, pack_id=digest(n)
        )
    rng = store.history(p, FL, "cursor-a")["records"][0]
    assert rng["compacted"] == "range" and rng["truncated"] is True
    assert len(rng["value_digests"]) == MAX_RANGE_LIST and len(rng["pack_ids"]) == MAX_RANGE_LIST
    assert rng["pack_ids"][-1] == digest(MAX_RANGE_LIST + 1)  # the newest are kept
    assert digest(0) not in rng["pack_ids"]


# ---------------------------------------------------------------- design 4: unchecked overflow
def test_an_unchecked_update_past_the_closure_cap_is_dropped_not_fatal(backend):
    p = _profile(
        memory_scopes=["analyst", FL], platform_scopes=[FL],
        memory_limits={"keep_last": {FL: {"cursor-*": 2}}},
    )  # fmt: skip
    store = MemoryStore(backend, now=Clock())
    ids = [digest(n) for n in range(1, 300)]
    store.apply_updates(p, [up("add", "cursor-a", "0", scope=FL, sources=ids[:16])], unchecked=True)
    for n in range(1, MAX_CLOSURE // 16):
        store.apply_updates(
            p, [up("replace", "cursor-a", str(n), scope=FL, sources=ids[16 * n : 16 * n + 16])],
            unchecked=True,
        )  # fmt: skip
    got = store.apply_updates(
        p,
        [
            up("replace", "cursor-a", "past", scope=FL, sources=ids[256:258]),
            up("add", "item-b", "kept", scope=FL),
        ],
        unchecked=True,
    )
    assert len(got["dropped"]) == 1 and got["dropped"][0].startswith("memory_updates/0: ")
    assert "closure cap of 256" in got["dropped"][0] and "cursor" not in got["dropped"][0]
    assert got["revs"] == {"fleet-ledger/item-b": 1}  # this local-only profile reads red
    assert store.read(p, FL)["entries"] == {
        "cursor-a": str(MAX_CLOSURE // 16 - 1),
        "item-b": "kept",
    }


# ---------------------------------------------------------------- design 5: store-side checks
def test_the_store_refuses_a_pack_over_the_rendered_cap(reader, backend):
    """The assembler refuses such a pack, so a pack over the cap can only be built by hand; the
    store refuses it too, rather than store an exposure past its bound."""
    pack, _ = labelled_pack([item(1, "clear")], [item(2, "clear")], profile=reader)
    many = [{"section": "findings", **item(n, "clear")} for n in range(MAX_RENDERED)]
    forged = {**pack, "provenance": {**pack["provenance"], "inputs": many}}
    with pytest.raises(MemoryUpdateError, match="over the cap of 1024"):
        MemoryStore(backend).apply_updates(
            reader, [up("add", "k", "v")], pack=forged, pack_hash=digest_of(forged)
        )


def test_the_store_refuses_a_deferred_pack(reader, backend):
    bad = inputs()
    bad["pregates"] = {}
    pack, h = assemble_pack(manifest(), bad, profile=reader)
    assert pack["status"] == "deferred"
    with pytest.raises(MemoryUpdateError, match="the pack was deferred"):
        MemoryStore(backend).apply_updates(reader, [up("add", "k", "v")], pack=pack, pack_hash=h)
    with pytest.raises(MemoryUpdateError, match="deferred"):
        MemoryStore(backend).apply_report(
            reader, report(reader, h, [up("add", "k", "v")]), pack=pack, pack_hash=h
        )


def test_resolved_uids_cannot_be_subclassed():
    with pytest.raises(TypeError, match="sealed"):

        class Loose(ResolvedUids):  # a subclass could override the reads the assembler trusts
            pass


# ---------------------------------------------------------------- a dropped cursor pages
def test_a_dropped_platform_update_pages_once_per_crossing_and_recovers(backend, tmp_path):
    """The reviewer's probe: a cursor key replaced with 16 new sources per fold reaches the
    closure cap after 15 folds; every later fold drops it.  That pages once (by scope and count,
    never the key), and recovers on the scope's next batch with no drop."""
    from homelabnext.notify import FakeSender, Notifier
    from homelabnext.notify.core_pairs import AGENT_MEMORY_DROPPED
    from homelabnext.state import StateStore

    p = _profile(
        memory_scopes=["analyst", FL], platform_scopes=[FL],
        memory_limits={"keep_last": {FL: {"cursor-*": 2}}},
    )  # fmt: skip
    sender = FakeSender()
    clock = Clock()
    store = MemoryStore(
        backend, now=clock, notifier=Notifier(sender, StateStore(tmp_path / "n.json"))
    )
    ids = [digest(n) for n in range(1, 1000)]
    store.apply_updates(p, [up("add", "cursor-a", "0", scope=FL, sources=ids[:16])], unchecked=True)
    dropped = []
    for n in range(1, 40):
        clock.tick()
        got = store.apply_updates(
            p, [up("replace", "cursor-a", str(n), scope=FL, sources=ids[16 * n : 16 * n + 16])],
            unchecked=True,
        )  # fmt: skip
        dropped.append(len(got["dropped"]))
    assert dropped[:15] == [0] * 15 and set(dropped[15:]) == {1}  # frozen after 15 folds
    title, cleared = AGENT_MEMORY_DROPPED
    pages = [m for m in sender.sent if m.title == title]
    assert len(pages) == 1  # once per crossing, not once per fold
    assert FL in pages[0].body and "1 update" in pages[0].body and "cursor-a" not in pages[0].body
    clock.tick()
    store.apply_updates(p, [up("retire", "cursor-a", scope=FL)], unchecked=True)  # no drop
    assert [m.title for m in sender.sent if m.title in (title, cleared)] == [title, cleared]


def test_a_cursor_without_sources_never_drops(backend):
    """A cursor is position, not provenance: the fold writes its cursor-* keys with no sources
    (ADR-0037 decisions 10 and 17), so replacing one without end never reaches the closure cap,
    and keep_last keeps its records bounded."""
    p = _profile(
        memory_scopes=["analyst", FL], platform_scopes=[FL],
        memory_limits={"keep_last": {FL: {"cursor-*": 2}}},
    )  # fmt: skip
    store = MemoryStore(backend, now=Clock())
    store.apply_updates(p, [up("add", "cursor-a", "0", scope=FL)], unchecked=True)
    for n in range(1, 1001):
        got = store.apply_updates(p, [up("replace", "cursor-a", str(n), scope=FL)], unchecked=True)
        assert got["dropped"] == []
    recs = store.history(p, FL, "cursor-a")["records"]
    assert len(recs) == 3 and recs[-1]["rev"] == 1001 and recs[-1]["closure"] == []
    assert store.read(p, FL)["entries"] == {"cursor-a": "1000"}
