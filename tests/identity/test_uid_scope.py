# SPDX-License-Identifier: Apache-2.0
"""ADR-0019's Scope holds: which record families moved to uids and which keep their own keys.

The decision covers keys that were allocated numbers (lessons, runbooks, strategy records).
The invariant criteria keep their checklist row ids, and the system and capability pages keep
their registry and capability names.  These tests tie that table to the code, so a register
keyed by something other than a uid cannot appear without the ADR saying why, a kept key can
never be mistaken for a legacy code (which the migration would rewrite and validation refuse),
and the migration refuses a kept family by name.
"""

from __future__ import annotations

import json
import pathlib
import re
import shutil

import pytest
import yaml

from homelabnext.identity.migrate import MigrationError, assign_uids
from homelabnext.identity.types import LEGACY_CODE_RE, REGISTER_TYPES, STRATEGY_TYPES
from homelabnext.registers.ids import SPECS

REPO = pathlib.Path(__file__).resolve().parents[2]
ADR = REPO / "docs" / "adr" / "0019-record-uids-computed-numbers.md"
REGISTER = REPO / "examples" / "registers" / "invariants.yml"
RESULTS = REPO / "examples" / "registers" / "invariants.results.json"
_ROW = re.compile(r"^\| (?P<family>[^|]+) \| (?P<key>[^|]+) \| (?P<moves>yes|no)\b[^|]* \|$")


def scope() -> dict[str, list[str]]:
    """The ADR's Scope table: ``yes`` / ``no`` -> the family cells."""
    text = ADR.read_text(encoding="utf-8")
    m = re.search(r"^### Scope\n(?P<body>.*?)^## ", text, re.S | re.M)
    assert m, "ADR-0019 has no Scope section naming the families that keep their own keys"
    out: dict[str, list[str]] = {"yes": [], "no": []}
    for line in m["body"].splitlines():
        if r := _ROW.match(line):
            out[r["moves"]].append(r["family"])
    return out


def test_every_uid_record_type_is_in_scope():
    moved = " ".join(scope()["yes"])
    for t in [*REGISTER_TYPES, *STRATEGY_TYPES]:
        assert re.search(rf"\b{t}\b", moved), f"record type {t} is not listed as moved to uids"


def test_every_register_not_keyed_by_uid_is_named_in_scope():
    kept = " ".join(scope()["no"])
    for kind, spec in SPECS.items():
        if spec.key != "uid":
            assert kind in kept, (
                f"register {kind} keys on {spec.key!r}; ADR-0019 Scope must say why"
            )
    for family in ("invariant", "docs/systems", "docs/capabilities"):
        assert family in kept, f"{family} keeps its own key but ADR-0019 Scope does not say so"


def _criterion_ids() -> set[str]:
    data = yaml.safe_load(REGISTER.read_text(encoding="utf-8"))
    return {c["id"] for c in data["criteria"]} | set(data.get("retired") or {})


def _page_names() -> set[str]:
    services = yaml.safe_load((REPO / "examples" / "services.yml").read_text(encoding="utf-8"))
    pages = {p.stem for d in ("systems", "capabilities") for p in (REPO / "docs" / d).glob("*.md")}
    return set(services["services"]) | pages


@pytest.mark.parametrize("keys", [_criterion_ids, _page_names], ids=["criteria", "pages"])
def test_kept_keys_are_never_legacy_codes(keys):
    """A record may cite ``F-21`` or ``dns``; were either a legacy code, the migration would
    rewrite the citation and the record validator would refuse it."""
    found = sorted(keys())
    assert found
    assert [k for k in found if LEGACY_CODE_RE.search(k)] == []


def test_results_are_keyed_by_criterion_ids():
    spec = SPECS["invariants"]
    results = json.loads(RESULTS.read_text(encoding="utf-8"))["results"]
    live = _criterion_ids()
    for key in results:
        assert re.fullmatch(spec.id_re, key) and key in live, key


@pytest.mark.parametrize(
    ("src", "family"),
    [
        ("examples/registers/invariants.yml", "invariants"),
        ("docs/systems", "system"),
        ("docs/capabilities", "capability"),
    ],
)
def test_migration_refuses_a_kept_family_by_name(tmp_path, src, family):
    origin = REPO / src
    tree = tmp_path / origin.name
    if origin.is_file():
        shutil.copy(origin, tree)
    else:
        shutil.copytree(origin, tree)
    before = {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    with pytest.raises(MigrationError) as ex:
        assign_uids([tree])
    assert any(f"{family} entries keep their own keys" in p for p in ex.value.problems), ex.value
    assert any("ADR-0019, Scope" in p for p in ex.value.problems)
    assert {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()} == before
