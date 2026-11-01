# SPDX-License-Identifier: Apache-2.0
"""ADR-0009: what goes on the bus, and the only code that publishes through the bus protocol.

* Every module that publishes through an ``EventBus`` (a ``.publish(..., msg_id=...)`` call) is
  named in ADR-0009's Decision; the adapters that implement the protocol are not publishers.
* Every event type under ``schemas/events/`` has one of ADR-0009's three classes in
  ``docs/events.md`` ("What goes on the bus").
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
ADR = REPO / "docs" / "adr" / "0009-bus-only-at-the-reaction-seam.md"
EVENTS_DOC = REPO / "docs" / "events.md"
#: the protocol's implementations (they receive publishes, they are not publishers)
ADAPTERS = REPO / "homelabnext" / "conform" / "adapters"
CLASSES = {"reaction", "record", "decision"}


def _section(text: str, heading: str) -> str:
    m = re.search(rf"^## {re.escape(heading)}\n(.*?)(?=^## |\Z)", text, re.S | re.M)
    assert m, f"no '## {heading}' section"
    return m.group(1)


def _bus_publishers() -> set[str]:
    """Repo-relative paths of modules with a ``<x>.publish(..., msg_id=...)`` call."""
    found: set[str] = set()
    for py in sorted((REPO / "homelabnext").rglob("*.py")):
        if ADAPTERS in py.parents:
            continue
        tree = ast.parse(py.read_text(encoding="utf-8"), filename=str(py))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "publish"
                and any(k.arg == "msg_id" for k in node.keywords)
            ):
                found.add(py.relative_to(REPO).as_posix())
    return found


def test_scan_finds_the_known_bus_publishers():
    # the scan itself works: the broker's relay is a bus publisher
    assert "homelabnext/broker/relay.py" in _bus_publishers()


def test_every_bus_publisher_is_sanctioned_by_adr_0009():
    decision = _section(ADR.read_text(encoding="utf-8"), "Decision")
    named = set(re.findall(r"`(homelabnext/[\w/]+\.py)`", decision))
    unsanctioned = sorted(_bus_publishers() - named)
    assert not unsanctioned, (
        f"publishes through the EventBus protocol but ADR-0009 does not name it: {unsanctioned}"
    )


def test_events_doc_names_the_relay_exception():
    head = EVENTS_DOC.read_text(encoding="utf-8").split("\n## ", 1)[0]
    assert "Publishers never speak the bus" not in head
    assert "hnx broker relay" in head and "ADR-0009" in head


def _classes_table() -> dict[str, str]:
    body = _section(EVENTS_DOC.read_text(encoding="utf-8"), "What goes on the bus")
    rows = re.findall(r"^\| `(homelabnext\.[a-z0-9_.]+)` \| ([a-z]+) \|$", body, re.M)
    table: dict[str, str] = {}
    for etype, cls in rows:
        assert etype not in table, f"{etype} listed twice"
        table[etype] = cls
    return table


def test_every_event_type_has_a_bus_class():
    types = {
        "homelabnext." + p.name.removesuffix(".schema.json")
        for p in (REPO / "schemas" / "events").glob("*.schema.json")
        if p.name != "envelope.schema.json"
    }
    table = _classes_table()
    assert sorted(types - table.keys()) == [], "event types with no class in docs/events.md"
    assert sorted(table.keys() - types) == [], "classes listed for event types that do not exist"
    assert set(table.values()) <= CLASSES, set(table.values()) - CLASSES


def test_adr_0009_names_the_three_classes():
    decision = _section(ADR.read_text(encoding="utf-8"), "Decision")
    for phrase in ("reaction triggers", "per-item business records", "decision events"):
        assert phrase in decision


def test_checklist_t01_is_scoped_to_the_bus_classes():
    text = (REPO / "docs" / "checklist.md").read_text(encoding="utf-8")
    row = next(line for line in text.splitlines() if line.startswith("| T-01 |"))
    assert "All events flow through the event bus" not in row
    assert "docs/events.md" in row


def test_adr_0033_states_where_labels_stop():
    adr = REPO / "docs" / "adr" / "0033-data-carries-tlp-every-reader-has-a-ceiling.md"
    consequences = _section(adr.read_text(encoding="utf-8"), "Consequences")
    assert "The event envelope" in consequences and "carry none" in consequences
