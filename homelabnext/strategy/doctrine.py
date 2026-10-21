# SPDX-License-Identifier: Apache-2.0
"""The doctrine policy: which mechanical measurement rules apply, and how hard.

``<root>/doctrine.yml`` (``schemas/strategy/doctrine.schema.json``) names each rule with
``enforce: error | warn | off``.  A validation rule's finding fails the check (error), is printed
(warn) or is not looked for (off); a computed rule (the self-measured cap, cold start, trends)
applies unless it is off.  A rule the file does not name takes its default from
:data:`DEFAULT_RULES`, the nine-rule MOE/MOP doctrine the project ships with, so another
discipline writes only what it changes.

The rules and where they act (the rest of the doctrine needs judgment; the file lists it under
``judgment`` for reviewers):

======================== ==========================================================================
rule                     effect
======================== ==========================================================================
trend_same_definition    a trend is drawn only between readings of one definition digest (measure)
no_silent_redefinition   a reading under the current definition_version whose digest differs (rules)
self_measured_moe_cap    a MOE measured manually, not at all, or by its objective's owner is capped
activity_never_moe       a measure of an activity ``kind`` must be a MOP (rules)
moe_per_objective        an objective at the listed levels carries at least ``min`` MOEs (rules)
measures_per_owner       at most ``max`` active measures per objective owner (rules; off by default)
cold_start_baseline      the first ``readings`` readings on a definition are a baseline, not a grade
not_measurable_is_finding  source none needs a Not measurable section; a reading without a value
                         carries a finding (rules, and the event schema)
never_fabricate          a not-measurable measure has no values; every reading names evidence
baseline_so              each requirement of ``types`` supports ``exactly`` baseline SOs, and no
                         baseline SO is shared between two of them (rules)
so_supported             an active SO no active requirement supports is an orphan (rules)
======================== ==========================================================================

The model's shape is in the file too, so it is read in one place (and a discipline with another
cascade can say so):

``hierarchy``  each record type's ``parent`` types (``[]``: top level, no parent) and whether
               the parent is ``optional``.  A record's display number is drawn from it
               (``OO 1.2`` is the second OO under SO 1): :data:`DEFAULT_HIERARCHY`.
``links``      each typed link field: per record type that may carry it, the types it may name
               (``serves``: an FFIR names CCIRs, a PIR CCIRs or FFIRs): :data:`DEFAULT_LINKS`.
"""

from __future__ import annotations

import copy
import pathlib
from dataclasses import dataclass, field
from typing import Any

import yaml

from homelabnext.registers.schema import RegisterError

__all__ = ["DEFAULT_HIERARCHY", "DEFAULT_LINKS", "DEFAULT_RULES", "Doctrine", "load_doctrine"]

DEFAULT_RULES: dict[str, dict[str, Any]] = {
    "trend_same_definition": {"enforce": "error"},
    "no_silent_redefinition": {"enforce": "error"},
    "self_measured_moe_cap": {"enforce": "error", "cap": "amber"},
    "activity_never_moe": {"enforce": "error", "kinds": ["activity"]},
    "moe_per_objective": {"enforce": "error", "min": 1, "levels": ["SO", "OO", "TO", "TT"]},
    "measures_per_owner": {"enforce": "off", "max": 8},
    "cold_start_baseline": {"enforce": "error", "readings": 1},
    "not_measurable_is_finding": {"enforce": "error"},
    "never_fabricate": {"enforce": "error"},
    "baseline_so": {"enforce": "error", "types": ["PIR", "FFIR"], "exactly": 1},
    "so_supported": {"enforce": "warn"},
}
_OBJECTIVES = ["SO", "OO", "TO", "TT"]
#: type -> {parent: [types], optional: bool}; a type not listed takes no parent
DEFAULT_HIERARCHY: dict[str, dict[str, Any]] = {
    "SO": {"parent": []},
    "OO": {"parent": ["SO"]},
    "TO": {"parent": ["OO"]},
    "TT": {"parent": ["TO"]},
    "MOE": {"parent": list(_OBJECTIVES)},
    "MOP": {"parent": list(_OBJECTIVES)},
    "CCIR": {"parent": []},
    "FFIR": {"parent": []},
    "PIR": {"parent": ["PIR"], "optional": True},  # a sub-PIR numbers under its PIR (PIR 2.1)
    "RFI": {"parent": []},
}
_SUPPORTABLE = ["SO", "OO", "TO"]
#: link field -> {record type carrying it: [types it may name]}; a type not listed under a field
#: may not carry it (a CCIR serves nothing)
DEFAULT_LINKS: dict[str, dict[str, list[str]]] = {
    "supports": {t: list(_SUPPORTABLE) for t in ("CCIR", "FFIR", "PIR")},
    "serves": {"FFIR": ["CCIR"], "PIR": ["CCIR", "FFIR"]},
    "raised_by": {"RFI": ["MOP", "MOE", "CCIR", "FFIR", "PIR"]},
}


@dataclass
class Doctrine:
    name: str = "defaults"
    rules: dict[str, dict[str, Any]] = field(default_factory=lambda: copy.deepcopy(DEFAULT_RULES))
    rfi_default_ltiov_days: int = 30
    expiring_soon_days: int = 7
    judgment: list[dict[str, str]] = field(default_factory=list)
    hierarchy: dict[str, dict[str, Any]] = field(
        default_factory=lambda: copy.deepcopy(DEFAULT_HIERARCHY)
    )
    links: dict[str, dict[str, list[str]]] = field(
        default_factory=lambda: copy.deepcopy(DEFAULT_LINKS)
    )

    def parents(self, rtype: str) -> list[str]:
        """The types a record of ``rtype`` may name as its parent (``[]``: none)."""
        return list((self.hierarchy.get(rtype) or {}).get("parent") or ())

    def parent_optional(self, rtype: str) -> bool:
        return bool((self.hierarchy.get(rtype) or {}).get("optional"))

    def link_targets(self, field_: str, rtype: str) -> list[str] | None:
        """The types a ``field_`` link of a ``rtype`` record may name; None: it may not carry
        the field at all."""
        allowed = self.links.get(field_) or {}
        return list(allowed[rtype]) if rtype in allowed else None

    def on(self, rule: str) -> bool:
        return self.rules[rule]["enforce"] != "off"

    def level(self, rule: str) -> str:
        return str(self.rules[rule]["enforce"])

    def opt(self, rule: str, key: str) -> Any:
        return self.rules[rule].get(key, DEFAULT_RULES[rule].get(key))


def load_doctrine(root) -> Doctrine:
    """``<root>/doctrine.yml`` merged over the defaults (fatal when it does not validate); the
    defaults alone when the file is absent."""
    from .rules import schema_problems

    p = pathlib.Path(root) / "doctrine.yml"
    if not p.is_file():
        return Doctrine()
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
    except yaml.YAMLError as ex:
        raise RegisterError("doctrine", [f"{p.name}: not YAML ({ex})".replace("\n", " ")]) from None
    problems = schema_problems("doctrine", data, p.name)
    if problems:
        raise RegisterError("doctrine", problems)
    rules = copy.deepcopy(DEFAULT_RULES)
    for name, spec in data["rules"].items():
        rules[name] = {**rules[name], **spec}
    return Doctrine(
        name=data["name"],
        rules=rules,
        rfi_default_ltiov_days=data.get("rfi_default_ltiov_days", 30),
        expiring_soon_days=data.get("expiring_soon_days", 7),
        judgment=list(data.get("judgment") or ()),
        hierarchy={**copy.deepcopy(DEFAULT_HIERARCHY), **(data.get("hierarchy") or {})},
        links={**copy.deepcopy(DEFAULT_LINKS), **(data.get("links") or {})},
    )
