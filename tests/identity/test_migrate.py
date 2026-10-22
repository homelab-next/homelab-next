# SPDX-License-Identifier: Apache-2.0
"""``hnx records assign-uids``: numbered records get uids, losslessly and idempotently.

A small registers tree and a small strategy tree are written in the numbered form records had
before ADR-0019, migrated, and then checked against the new rules: every record has its uid
and file, every link resolves, every review current before is current after (through a
``rekey`` event), the computed numbers equal the old codes, a second run changes nothing, and a
legacy code met in an intent still resolves (with a warning).
"""

from __future__ import annotations

import datetime as dt
import random
import textwrap
import warnings

import pytest
import yaml

from homelabnext.identity.aliases import LegacyRecordCode, load_aliases
from homelabnext.identity.migrate import MigrationError, _digest, _load_entry, assign_uids
from homelabnext.identity.uid import UidGenerator, is_uid
from homelabnext.registers import events as ev

T0 = 1_792_500_000_000
NOW = dt.datetime(2026, 10, 21, 12, 0, tzinfo=dt.UTC)


def new_uid():
    times = iter(range(T0, T0 + 10_000))
    return UidGenerator(clock_ms=lambda: next(times), randbytes=random.Random(3).randbytes)


def md(path, front: str, body: str = "") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("---\n" + textwrap.dedent(front).strip() + "\n---\n\n" + textwrap.dedent(body))


def review(path, kind_dir: str, who: str, role: str, at: str) -> None:
    """A passing review of the record's current (numbered) content, as a sidecar event."""
    problems: list[str] = []
    evs = ev.read_events(ev.events_dir(path), problems)
    entry = _load_entry(path.read_text(), path.name, kind_dir, evs, problems)
    assert not problems, problems
    data = {"event": "review", "by": f"agent:{who}", "kind": "agent", "role": role}
    data.update(date=at[:10], verdict="pass", digest=_digest(entry, kind_dir))
    ev.create_event(ev.events_dir(path), data, when=dt.datetime.fromisoformat(at))


@pytest.fixture
def registers(tmp_path):
    reg = tmp_path / "registers"
    lessons, runbooks = reg / "lessons", reg / "runbooks"
    md(
        lessons / "LL-001.md",
        """
        id: LL-001
        title: Certificate expired on the proxy
        kind: pitfall
        status: open
        date: 2026-01-12
        author: unknown
        systems: [proxy]
        recurrences: 0
        related: [RB-001]
        """,
        """
        ## Symptom

        Clients saw an expired certificate on the internal proxy for an hour.

        ## Contributing factor

        Nothing watched the certificate's remaining lifetime from the client side.

        ## Root cause

        Renewal was assumed to be automatic and nothing verified that assumption.

        ## Open reason

        Not yet controlled: see LL-002 for the method and `LL-040` for an unrelated quote.
        """,
    )
    md(
        lessons / "LL-002.md",
        """
        id: LL-002
        title: Measure certificate lifetime from the client side
        kind: practice
        status: active
        date: 2026-02-01
        author: unknown
        systems: [proxy]
        applies_to: [tls]
        review_by: 2027-02-01
        """,
        """
        ## Method

        Probe the served certificate from a client and alert well before it expires ([[LL-001]]).
        """,
    )
    md(
        lessons / "LL-NEW-draft.md",
        """
        id: LL-NEW
        title: A draft lesson nobody numbered yet
        kind: pitfall
        status: open
        date: 2026-03-01
        author: unknown
        systems: [proxy]
        recurrences: 0
        """,
        """
        ## Symptom

        Something happened that nobody has diagnosed yet.

        ## Contributing factor

        It is still being looked at by the operator.

        ## Root cause

        Unknown at this point: the open reason says why.

        ## Open reason

        The diagnosis is in progress and no control exists.
        """,
    )
    md(
        runbooks / "RB-001.md",
        """
        id: RB-001
        title: Renew the proxy certificate
        systems: [proxy]
        review_by: 2027-04-19
        author: unknown
        """,
        """
        ## Purpose

        Renew the internal proxy certificate before it expires.

        ## Steps

        1. Request a new certificate from the internal CA.
           - verify: the new certificate's not-after is a year out
           - from_lessons: [[LL-002]]
        """,
    )
    review(
        lessons / "LL-002.md", "lessons", "example-checker", "check", "2026-10-19T00:00:00+00:00"
    )
    review(
        runbooks / "RB-001.md", "runbooks", "example-checker", "check", "2026-10-19T00:00:00+00:00"
    )
    return reg


@pytest.fixture
def strategy(tmp_path):
    root = tmp_path / "strategy"
    md(
        root / "strategy.md",
        """
        type: strategy
        name: tiny
        title: Keep a tiny lab running
        status: active
        date: 2026-10-20
        author: human:example-planner
        priorities: [Keep the core services available]
        assumptions: [The lab has one operator]
        constraints:
          - {rule: Authorized internal testing of the operator's own lab only, owner: human:example-operator}
        """,
        """
        ## Mission

        Keep the lab's core services available to its one operator.

        ## Intent

        Measure what matters and ask when a measure goes red (SO-001 first).

        ## End state

        Every core service answers and every outage is known within minutes.
        """,
    )
    obj = """
        id: {id}
        level: {level}
        title: {title}
        status: active
        date: 2026-10-20
        author: human:example-planner
        owner: human:example-operator
        {parent}measures: [{measures}]
        """
    for ident, level, title, parent, measures in (
        ("SO-001", "SO", "Core services stay available", "", "MOE-001"),
        ("SO-002", "SO", "Hostile activity is detected", "", "MOE-003"),
        ("OO-001", "OO", "The pages describe what runs", "parent: SO-001\n        ", "MOE-002"),
    ):
        md(
            root / "objectives" / f"{ident}.md",
            obj.format(id=ident, level=level, title=title, parent=parent, measures=measures),
            "\n## Statement\n\nA statement long enough to be a statement.\n",
        )
    for ident, objective, title in (
        ("MOE-001", "SO-001", "Share of monitors up"),
        ("MOE-002", "OO-001", "Pages match the registry"),
        ("MOE-003", "SO-002", "Share of techniques with a rule"),
    ):
        md(
            root / "measures" / f"{ident}.md",
            f"""
            id: {ident}
            title: {title}
            status: active
            date: 2026-10-20
            author: human:example-planner
            objective: {objective}
            kind: outcome
            source: manual
            unit: share
            target: {{op: '>=', green: 0.9}}
            confidence: high
            thinness: {{min_sample: 1}}
            definition_version: 1
            """,
            "\n## Definition\n\nThe share of what it counts, read by the operator by hand.\n",
        )
    req = """
        id: {id}
        title: {title}
        status: active
        date: 2026-10-20
        author: human:example-planner
        consumer: human:example-operator
        cadence: P1D
        ltiov: standing
        supports: [{supports}]
        {extra}
        """
    for ident, title, supports, extra in (
        ("CCIR-001", "Is a core service down?", "SO-001", ""),
        (
            "PIR-001",
            "Is anyone probing the lab?",
            "SO-002",
            "serves: [CCIR-001]\n        sirs:\n          - 1.1 Requests from outside.\n"
            "          - 1.2 Repeated authentication failures.",
        ),
    ):
        md(
            root / "requirements" / f"{ident}.md",
            req.format(id=ident, title=title, supports=supports, extra=extra),
            "\n## Question\n\nA question that is long enough to ask.\n\n"
            "## Decision supported\n\nWhat the operator does next.\n\n"
            "## Acceptance\n\nAn answer within a day, naming its source.\n",
        )
    md(
        root / "rfis" / "RFI-001.md",
        """
        id: RFI-001
        title: Which monitors cover the core services
        status: open
        date: 2026-10-20
        author: profile:example-checker
        raised_by: MOE-001
        triage: collection
        ltiov: 2026-11-19
        """,
        "\n## Question\n\nWhich monitors cover each service? MOE-001 has no reading to grade.\n",
    )
    review(
        root / "objectives" / "SO-001.md",
        "objectives",
        "example-checker",
        "check",
        "2026-10-20T00:00:00+00:00",
    )
    return root


def snapshot(root) -> dict[str, str]:
    return {str(p.relative_to(root)): p.read_text() for p in sorted(root.rglob("*")) if p.is_file()}


def migrate(*trees, **kw):
    return assign_uids(trees, new_uid=new_uid(), now=lambda: NOW, **kw)


def test_registers_are_migrated_losslessly(registers):
    from homelabnext.registers.records import load_register
    from homelabnext.registers.schema import (
        check_links,
        labels_of,
        review_evaluation,
        validate_lessons,
        validate_runbooks,
    )

    plan = migrate(registers)
    assert set(plan.assigned) >= {"LL-001", "LL-002", "RB-001"}
    names = sorted(p.name for p in (registers / "lessons").glob("*.md"))
    assert len(names) == 3 and all(is_uid(n[:-3]) for n in names)  # LL-NEW got one too
    ll = load_register(registers / "lessons")["lessons"]
    rb = load_register(registers / "runbooks")["runbooks"]
    validate_lessons({"lessons": ll})
    validate_runbooks({"runbooks": rb})
    check_links(ll, rb, set(), registers)  # every link resolves
    aliases = load_aliases(registers).codes
    assert set(aliases) == {"LL-001", "LL-002", "RB-001"}  # a placeholder had no identity
    by_code = {c: next(e for e in ll + rb if e["uid"] == u) for c, u in aliases.items()}
    assert by_code["LL-001"]["related"] == [aliases["RB-001"]]
    assert rb[0]["steps"][0]["from_lessons"] == [aliases["LL-002"]]
    # the computed numbers are the old codes (uids were assigned in code order)
    labels = labels_of(ll)
    assert labels[aliases["LL-001"]] == "LL 1" and labels[aliases["LL-002"]] == "LL 2"
    # prose: a bare code became a wiki-link, a code span is a quotation and stays
    text = (registers / "lessons" / f"{aliases['LL-001']}.md").read_text()
    assert f"see [[{aliases['LL-002']}]] for the method" in text and "`LL-040`" in text
    assert "- Related: [[" + aliases["RB-001"] + "]]" in text  # the Links block, regenerated
    # reviews current before are current after: a rekey carries them across
    for code in ("LL-002", "RB-001"):
        e = by_code[code]
        art = "runbook" if code.startswith("RB") else "lesson.practice"
        assert review_evaluation(e, art, "active").current, code
        evdir = registers / ("runbooks" if code.startswith("RB") else "lessons")
        rekeys = list((evdir / f"{aliases[code]}.events").glob("*-rekey-hnx-migrate.yml"))
        assert len(rekeys) == 1
        assert yaml.safe_load(rekeys[0].read_text())["by"] == "hnx:migrate"
    assert not (registers / "lessons" / "LL-001.md").exists()


def test_the_strategy_is_migrated_and_validates(strategy):
    from homelabnext.strategy.records import load_tree
    from homelabnext.strategy.rules import validate

    migrate(strategy)
    tree = load_tree(strategy)
    rep = validate(tree, policy=False, invariant_ids=set(), status_ids=set())
    assert rep.errors == []
    a = load_aliases(strategy).codes
    assert {tree.label(a[c]) for c in ("SO-001", "OO-001", "MOE-002", "PIR-001", "RFI-001")} == {
        "SO 1",
        "OO 1.1",
        "MOE 1.1.1",
        "PIR 1",
        "RFI 1",
    }
    oo = tree.get(a["OO-001"])
    assert oo["type"] == "OO" and oo["parent"] == a["SO-001"]
    assert "level" not in oo and "measures" not in oo  # the type and the measures' parents
    assert tree.get(a["MOE-002"])["parent"] == a["OO-001"]  # objective -> parent
    pir = tree.get(a["PIR-001"])
    assert pir["sirs"] == ["Requests from outside.", "Repeated authentication failures."]
    assert pir["serves"] == [a["CCIR-001"]] and pir["supports"] == [a["SO-002"]]
    assert is_uid(tree.strategy["uid"])
    assert f"[[{a['SO-001']}]] first" in tree.strategy["intent"]
    assert tree.get(a["RFI-001"])["question"].endswith(
        f"[[{a['MOE-001']}]] has no reading to grade."
    )


def test_a_second_run_changes_nothing(registers, strategy, tmp_path):
    migrate(registers, strategy)
    before = snapshot(tmp_path)
    plan = migrate(registers, strategy)
    assert not plan.changed and plan.assigned == {} and plan.rekeyed == []
    assert snapshot(tmp_path) == before


def test_a_dry_run_writes_nothing(registers):
    before = snapshot(registers)
    plan = migrate(registers, dry_run=True)
    assert plan.changed and plan.assigned
    assert snapshot(registers) == before


def test_the_also_files_are_rewritten(registers, tmp_path):
    note = tmp_path / "notes" / "intent.md"
    note.parent.mkdir()
    note.write_text("record: LL-001\nsuperseded_by: LL-0011\nalso LL-001-old\n")
    migrate(registers, also=[tmp_path / "notes"])
    u = load_aliases(registers).codes["LL-001"]
    assert note.read_text() == f"record: {u}\nsuperseded_by: LL-0011\nalso LL-001-old\n"


def test_two_records_claiming_one_code_stop_the_migration(registers):
    dup = registers / "lessons" / "LL-001-copy.md"
    dup.write_text((registers / "lessons" / "LL-001.md").read_text())
    before = snapshot(registers)
    with pytest.raises(MigrationError, match="LL-001 is also the code"):
        migrate(registers)
    assert snapshot(registers) == before  # nothing written


def test_a_dangling_reference_stops_the_migration(registers):
    p = registers / "lessons" / "LL-002.md"
    p.write_text(p.read_text().replace("title: Measure", "related: [RB-009]\ntitle: Measure"))
    before = snapshot(registers)
    with pytest.raises(MigrationError, match="RB-009 has no uid"):
        migrate(registers)
    assert snapshot(registers) == before


def test_a_record_directory_is_not_a_tree(registers):
    with pytest.raises(MigrationError, match="pass the tree"):
        migrate(registers / "lessons")


def test_a_legacy_code_in_an_intent_still_decides(strategy, tmp_path):
    """An intent filed before the migration names RFI-001: the decider resolves it through
    aliases.yml with a deprecation warning, and applies the transition to the uid record."""
    from homelabnext.records import Records
    from homelabnext.records.decider import init_tree
    from homelabnext.strategy.records import load_tree
    from homelabnext.strategy.rfis import StrategyDecider

    migrate(strategy)
    records = tmp_path / "records"
    init_tree(records)
    rec = Records(records, lambda: NOW, agent="profile:example-checker")
    rec.submit(
        {
            "type": "strategy-transition",
            "title": "Close the monitor coverage RFI as a no-find",
            "record": "RFI-001",
            "from": "open",
            "to": "no-find",
            "reason": "Searched the monitor list; none covers the core services yet.",
        },
        body="Filed before the uid migration.\n",
    )
    d = StrategyDecider(  # no review tiers here: the identity is what is under test
        strategy, records, decided_by="human:example-operator", clock=lambda: NOW, policy=False
    )
    with pytest.warns(LegacyRecordCode, match="RFI-001"):
        (out,) = d.decide_all()
    uid = load_aliases(strategy).codes["RFI-001"]
    assert (out.result, out.record) == ("applied", uid)
    assert load_tree(strategy).get(uid)["status"] == "no-find"


def test_without_warnings_a_migrated_tree_loads(strategy):
    from homelabnext.strategy.records import load_tree

    migrate(strategy)
    with warnings.catch_warnings():
        warnings.simplefilter("error")  # no legacy code is left to resolve
        load_tree(strategy)


def tombstone(registers, code="LL-009", replaced_by="LL-001"):
    p = registers / "lessons" / f"{code}.md"
    rb = f"\n  replaced_by: {replaced_by}" if replaced_by else ""
    p.write_text(f"---\nid: {code}\nretired:\n  reason: filed twice for the same outage{rb}\n---\n")
    return p


def test_a_tombstone_moves_to_the_alias_map_with_its_successors_uid(registers):
    """A code retired before uids (a tombstone) gets no uid: it lands in aliases.yml under
    `retired:` with the successor's uid, the register still validates, an old citation of it
    resolves to the successor, and a second run changes nothing."""
    from homelabnext.identity.aliases import resolve
    from homelabnext.registers.records import load_register
    from homelabnext.registers.schema import validate_lessons

    t = tombstone(registers)
    tombstone(registers, "LL-010", replaced_by=None)
    plan = migrate(registers)
    assert t in plan.removed and not t.exists() and "LL-009" not in plan.assigned
    validate_lessons(load_register(registers / "lessons"))  # no record fails validation
    amap = load_aliases(registers)
    assert amap.retired == {
        "LL-009": {
            "reason": "filed twice for the same outage",
            "replaced_by": amap.codes["LL-001"],
        },
        "LL-010": {"reason": "filed twice for the same outage"},
    }
    with pytest.warns(LegacyRecordCode, match="LL-009 is a retired legacy record code"):
        assert resolve("LL-009", amap) == amap.codes["LL-001"]
    assert resolve("LL-010", amap) == "LL-010"  # no successor: unresolved, for the caller
    before = snapshot(registers)
    assert not migrate(registers).changed
    assert snapshot(registers) == before


@pytest.mark.parametrize(
    ("code", "replaced_by", "match"),
    [
        ("LL-009", "LL-099", "replaced_by LL-099 names no record"),
        ("LL-001", "LL-002", "retired and live"),
    ],
)
def test_a_tombstone_that_cannot_be_carried_stops_the_migration(
    registers, code, replaced_by, match
):
    if code == "LL-001":
        (registers / "lessons" / "LL-001-retired.md").write_text(
            f"---\nid: {code}\nretired:\n  reason: a reused number\n  replaced_by: {replaced_by}\n---\n"
        )
    else:
        tombstone(registers, code, replaced_by)
    before = snapshot(registers)
    with pytest.raises(MigrationError, match=match):
        migrate(registers)
    assert snapshot(registers) == before


def test_an_occupied_events_directory_stops_the_migration_before_any_write(registers):
    """The rename target of a record's sidecar exists: refused in the pre-flight, with nothing
    written (it used to be found mid-write, after earlier records had been moved)."""
    gen = new_uid()
    uids = [gen() for _ in range(3)]  # LL-001, LL-002, LL-NEW in code order
    (registers / "lessons" / f"{uids[1]}.events").mkdir()
    before = snapshot(registers)
    with pytest.raises(MigrationError, match=rf"{uids[1]}\.events exists"):
        migrate(registers)
    assert snapshot(registers) == before
    assert (registers / "lessons" / "LL-001.md").exists()


def test_a_code_inside_a_links_alias_is_not_linked_again(registers):
    p = registers / "lessons" / "LL-002.md"
    p.write_text(
        p.read_text().replace("([[LL-001]])", "([[LL-001|the LL-001 outage]], [[ext|see LL-001]])")
    )
    migrate(registers)
    u = load_aliases(registers).codes
    text = (registers / "lessons" / f"{u['LL-002']}.md").read_text()
    assert f"([[{u['LL-001']}|the LL-001 outage]], [[ext|see LL-001]])" in text
    assert "[[" + u["LL-001"] + "|the [[" not in text
