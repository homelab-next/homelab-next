# SPDX-License-Identifier: Apache-2.0
"""ATT&CK-id validation for detection rules.

Problem this exists for
-----------------------

A rule can cite a (sub-)technique newer than the target engine's bundled ATT&CK database.
Detection still works - the rule fires on the event - but the engine logs a warning on every
alert because it does not know the id, and the monitoring stack can read that as an ongoing
error on something that is actually healthy. The rule is to tag the PARENT technique the engine
KNOWS (``T1059``), and keep the newer sub-technique (``T1059.999``) in the rule description or
in extra tags that do not cross the ATT&CK boundary.

The pieces
----------

- ``KnownIdSnapshot`` carries one engine's known ATT&CK ids plus the engine's name/version and
  the date and ATT&CK release the snapshot was captured against.
- ``load_snapshot(path)`` reads a snapshot from either ``.yml``/``.yaml`` (structured) or a
  plain-text ``.txt``/``.ids`` file with ``# key: value`` header comments. The engine-neutral
  shape lets any adapter ship its own snapshot without agreeing on a container format.
- ``parent_of(technique_id)`` returns the parent technique id for a sub-technique, or ``None``
  for a bare technique.
- ``validate_rules(rules, known, *, suggest_parent=False)`` compares every rule's
  ``attack_techniques`` against the engine's known set and returns problem strings. With
  ``suggest_parent=True``, an unknown sub-technique whose parent IS known becomes a suggestion
  (``...; parent T1059 is known - tag the parent and keep T1059.999 in the description``)
  instead of a bare "unknown".

Backends may ADVERTISE their known ids by implementing ``Backend.known_technique_ids()`` (see
``homelabnext.detections.adapters.KnownTechniques``). The CLI's ``validate-techniques`` command
and ``lint`` can both consume either a loaded snapshot file or a backend's advertised set.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

# A sub-technique id is ``T<4 digits>.<3 digits>``. A bare technique is ``T<4 digits>``.
# Sigma tags normalise to lower-case (``attack.t1059.001``); the detection layer upper-cases
# the id in ``Rule.attack_techniques`` before anything downstream reads it.
TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
SUBTECHNIQUE_RE = re.compile(r"^T\d{4}\.\d{3}$")


class SnapshotError(ValueError):
    """A known-id snapshot file is malformed or missing a required field."""


@dataclass(frozen=True)
class KnownIdSnapshot:
    """One engine's view of ATT&CK, captured on a day.

    ``engine`` is the backend's ``name`` (``wazuh``, ``generic``, ...). ``engine_version`` and
    ``attack_version`` are strings for display and reproducibility - no comparison is done on
    them, so the format is whatever the engine's own release channel uses. ``snapshot_date`` is
    ISO-8601. ``technique_ids`` is a set of canonical uppercase ids.
    """

    engine: str
    engine_version: str
    attack_version: str
    snapshot_date: str
    technique_ids: frozenset[str]
    source: Path | None = field(default=None)

    def knows(self, technique_id: str) -> bool:
        return technique_id in self.technique_ids


def parent_of(technique_id: str) -> str | None:
    """Return the parent technique id of a sub-technique, else ``None``.

    ``parent_of("T1059.001")`` -> ``"T1059"``;  ``parent_of("T1059")`` -> ``None``.
    """
    if not SUBTECHNIQUE_RE.match(technique_id):
        return None
    return technique_id.split(".", 1)[0]


def _normalise_ids(raw: object, where: str) -> frozenset[str]:
    if not isinstance(raw, (list, tuple, set, frozenset)):
        raise SnapshotError(f"{where}: 'technique_ids' must be a list, got {type(raw).__name__}")
    out = set()
    for i, item in enumerate(raw):
        if not isinstance(item, str):
            raise SnapshotError(f"{where}: technique_ids[{i}] must be a string, got {item!r}")
        canon = item.strip().upper()
        if canon.startswith("ATTACK."):
            canon = canon.split(".", 1)[1]
        if not TECHNIQUE_RE.match(canon):
            raise SnapshotError(
                f"{where}: {item!r} is not a technique id (want T#### or T####.###)"
            )
        out.add(canon)
    return frozenset(out)


def _parse_text_header(text: str, where: str) -> tuple[dict[str, str], list[str]]:
    header: dict[str, str] = {}
    ids: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("#"):
            body = line.lstrip("#").strip()
            if ":" in body:
                k, _, v = body.partition(":")
                header[k.strip().lower().replace(" ", "_")] = v.strip()
            continue
        ids.append(line)
    return header, ids


def load_snapshot(path: Path | str) -> KnownIdSnapshot:
    """Load a known-id snapshot from ``.yml``/``.yaml``/``.json`` (structured) or a plain-text
    ``.txt``/``.ids`` file with header ``# key: value`` comments. Missing fields are rejected
    because reproducibility costs almost nothing to record and a snapshot without a date is a
    rumour.
    """
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    suffix = p.suffix.lower()
    if suffix in (".yml", ".yaml"):
        doc = yaml.safe_load(text) or {}
        if not isinstance(doc, dict):
            raise SnapshotError(f"{p}: top level must be a mapping")
        header = {k: str(v) for k, v in doc.items() if k != "technique_ids"}
        ids_raw = doc.get("technique_ids", [])
    elif suffix == ".json":
        doc = json.loads(text)
        if not isinstance(doc, dict):
            raise SnapshotError(f"{p}: top level must be an object")
        header = {k: str(v) for k, v in doc.items() if k != "technique_ids"}
        ids_raw = doc.get("technique_ids", [])
    else:  # .txt / .ids / plain
        header, ids_list = _parse_text_header(text, str(p))
        ids_raw = ids_list
    required = ("engine", "engine_version", "attack_version", "snapshot_date")
    missing = [k for k in required if not header.get(k)]
    if missing:
        raise SnapshotError(f"{p}: snapshot header missing required fields: {missing}")
    technique_ids = _normalise_ids(ids_raw, str(p))
    if not technique_ids:
        raise SnapshotError(f"{p}: snapshot has no technique ids")
    return KnownIdSnapshot(
        engine=header["engine"],
        engine_version=header["engine_version"],
        attack_version=header["attack_version"],
        snapshot_date=header["snapshot_date"],
        technique_ids=technique_ids,
        source=p,
    )


# ---- validation --------------------------------------------------------------------------

# The known-ids container is lax: callers may pass a loaded ``KnownIdSnapshot`` OR a bare
# iterable of ids (which a backend's ``known_technique_ids()`` returns). The validator
# normalises them to a set, so the detection layer never cares which form it is holding.
KnownIds = "KnownIdSnapshot | frozenset[str] | set[str] | list[str] | tuple[str, ...]"


def _as_set(known) -> frozenset[str]:
    if isinstance(known, KnownIdSnapshot):
        return known.technique_ids
    return frozenset(str(x).upper() for x in known)


@dataclass(frozen=True)
class TechniqueProblem:
    """One rule-cited id that the engine does not know.

    ``parent_known`` is True when the id is a sub-technique whose PARENT is in the known set -
    the parent-tagging fix applies. ``suggested_parent`` is the parent id when ``parent_known``.
    """

    det_id: str
    technique_id: str
    parent_known: bool = False
    suggested_parent: str | None = None

    def message(self, *, suggest_parent: bool) -> str:
        base = f"{self.det_id}: ATT&CK id {self.technique_id} not in the engine's known set"
        if suggest_parent and self.parent_known:
            return (
                f"{base}; parent {self.suggested_parent} IS known - tag the parent and keep "
                f"{self.technique_id} in the description or extra tags"
            )
        return base


def validate_rule(
    rule_det_id: str,
    attack_techniques: list[str] | tuple[str, ...],
    known,
) -> list[TechniqueProblem]:
    """Problems for one rule's ids. ``rule_det_id`` is the logical id (``det:<slug>``)."""
    ks = _as_set(known)
    problems: list[TechniqueProblem] = []
    for raw in attack_techniques:
        t = str(raw).upper()
        if t in ks:
            continue
        parent = parent_of(t)
        problems.append(
            TechniqueProblem(
                det_id=rule_det_id,
                technique_id=t,
                parent_known=parent is not None and parent in ks,
                suggested_parent=parent if (parent is not None and parent in ks) else None,
            )
        )
    return problems


def validate_rules(rules, known, *, suggest_parent: bool = False) -> list[str]:
    """Validate every rule's ``attack_techniques`` against the engine's known set and return a
    flat list of problem strings, one per unknown id. With ``suggest_parent=True``, each
    unknown sub-technique whose parent is known gets a 'tag the parent' suggestion appended to
    its message. Order is stable: rules are iterated in their given order, ids in their given
    order, so a caller can diff two runs cleanly.
    """
    out: list[str] = []
    for r in rules:
        det_id = getattr(r, "det_id", None) or f"det:{getattr(r, 'slug', '?')}"
        for p in validate_rule(det_id, getattr(r, "attack_techniques", []) or [], known):
            out.append(p.message(suggest_parent=suggest_parent))
    return out
