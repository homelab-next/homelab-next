# SPDX-License-Identifier: Apache-2.0
"""Computed display numbers (homelabnext.identity.numbers): golden numbering of a cascade, and
what an insert, a reorder and a re-parent change -- the shown numbers, never a record."""

from __future__ import annotations

import random

from homelabnext.identity import Node, label_map, node_of, number_map, order_problems
from homelabnext.identity.uid import UidGenerator

T0 = 1_792_500_000_000


def uids(n: int, start: int = 0) -> list[str]:
    """``n`` uids in creation order (one millisecond apart from ``start``)."""
    times = iter(range(T0 + start, T0 + start + n))
    g = UidGenerator(clock_ms=lambda: next(times), randbytes=random.Random(start).randbytes)
    return [g() for _ in range(n)]


SO1, SO2, OO1, OO2, TO1, MOE1, MOE2, MOP1, PIR1, PIR2, PIR21, LL1 = uids(12)


def cascade(**changes) -> list[Node]:
    nodes = {
        SO1: Node(SO1, "SO"),
        SO2: Node(SO2, "SO"),
        OO1: Node(OO1, "OO", SO1),
        OO2: Node(OO2, "OO", SO1),
        TO1: Node(TO1, "TO", OO2),
        MOE1: Node(MOE1, "MOE", SO1),
        MOE2: Node(MOE2, "MOE", OO2),
        MOP1: Node(MOP1, "MOP", OO2),
        PIR1: Node(PIR1, "PIR"),
        PIR2: Node(PIR2, "PIR"),
        PIR21: Node(PIR21, "PIR", PIR2),
        LL1: Node(LL1, "lesson"),
    }
    nodes.update(changes)
    return list(nodes.values())


GOLDEN = {
    SO1: "SO 1",
    SO2: "SO 2",
    OO1: "OO 1.1",
    OO2: "OO 1.2",
    TO1: "TO 1.2.1",
    MOE1: "MOE 1.1",
    MOE2: "MOE 1.2.1",
    MOP1: "MOP 1.2.1",
    PIR1: "PIR 1",
    PIR2: "PIR 2",
    PIR21: "PIR 2.1",
    LL1: "LL 1",
}


def test_golden_numbers_of_a_cascade():
    assert label_map(cascade()) == GOLDEN
    assert number_map(cascade())[TO1] == "1.2.1"


def test_an_insert_renumbers_what_is_shown_and_nothing_else():
    (new,) = uids(1, start=100)  # created last: without an order it sorts after its siblings
    before = cascade()
    after = cascade(**{new: Node(new, "SO", None, 0.5)})  # ordered before both SOs
    got = label_map(after)
    assert got[new] == "SO 1"
    assert got[SO1] == "SO 2" and got[OO2] == "OO 2.2" and got[TO1] == "TO 2.2.1"
    assert got[SO2] == "SO 3"
    # no record changed: every node but the new one is the same object as before
    assert [n for n in after if n.uid != new] == before
    # without an order the same insert lands last and moves nobody
    plain = label_map(cascade(**{new: Node(new, "SO")}))
    assert plain[new] == "SO 3" and all(plain[u] == GOLDEN[u] for u in GOLDEN)


def test_a_reorder_swaps_two_siblings_and_their_subtrees():
    got = label_map(cascade(**{OO2: Node(OO2, "OO", SO1, 1), OO1: Node(OO1, "OO", SO1, 2)}))
    assert got[OO2] == "OO 1.1" and got[OO1] == "OO 1.2"
    assert got[TO1] == "TO 1.1.1" and got[MOE2] == "MOE 1.1.1"


def test_a_reparent_moves_the_subtree_under_its_new_parent():
    got = label_map(cascade(**{OO2: Node(OO2, "OO", SO2)}))
    assert got[OO2] == "OO 2.1" and got[TO1] == "TO 2.1.1" and got[MOP1] == "MOP 2.1.1"
    assert got[OO1] == "OO 1.1"  # its old sibling closes the gap


def test_ordered_siblings_come_first_then_creation_order():
    a, b, c = uids(3, start=200)
    got = label_map([Node(a, "RFI"), Node(b, "RFI", None, 10), Node(c, "RFI")])
    assert (got[b], got[a], got[c]) == ("RFI 1", "RFI 2", "RFI 3")


def test_a_dangling_parent_or_a_cycle_shows_a_question_mark():
    x, y, z = uids(3, start=300)
    got = number_map([Node(x, "OO", y), Node(y, "OO", x), Node(z, "TO", "missing")])
    assert got[z] == "?.1"
    assert "?" in got[x] and "?" in got[y]


def test_two_siblings_may_not_share_an_order():
    a, b, c = uids(3, start=400)
    nodes = [Node(a, "SO", None, 1), Node(b, "SO", None, 1), Node(c, "OO", a, 1)]
    problems = order_problems(nodes, {a: "SO 1", b: "SO 2"})
    assert problems == ["SO 2: order 1 is also the order of its sibling SO 1"]
    assert order_problems([Node(a, "SO", None, 1), Node(b, "SO", None, 2)]) == []


def test_node_of_reads_a_record_entry():
    entry = {"uid": SO1, "type": "OO", "parent": SO2, "order": 3, "title": "x"}
    assert node_of(entry) == Node(SO1, "OO", SO2, 3)
    assert node_of({"uid": SO1, "type": "SO", "order": True}).order is None  # not a number


def test_records_numbers_lists_the_example_strategy_in_doctrine_order(capsys):
    """Golden: `hnx records numbers examples/strategy` lists types in the doctrine's order (SO
    before OO before TO before TT, MOE before MOP, then requirements and RFIs), so a parent
    precedes its children; it used to sort by the type string (OO before SO, MOE before MOP
    only by accident)."""
    from pathlib import Path

    from homelabnext.identity.cli import main

    root = Path(__file__).resolve().parents[2]
    assert main(["numbers", str(root / "examples/strategy")]) == 0
    labels = [" ".join(ln.split()[:2]) for ln in capsys.readouterr().out.splitlines()]
    assert labels == [
        "SO 1", "SO 2", "OO 1.1", "OO 2.1", "TO 1.1.1", "TT 1.1.1.1",
        "MOE 1.1", "MOE 1.1.1", "MOE 1.1.1.1", "MOE 1.1.1.1.1", "MOE 2.1", "MOE 2.1.1",
        "MOP 1.1.1", "MOP 1.1.1.1", "CCIR 1", "FFIR 1", "PIR 1", "RFI 1", "RFI 2",
    ]  # fmt: skip
