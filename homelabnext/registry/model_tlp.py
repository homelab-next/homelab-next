# SPDX-License-Identifier: Apache-2.0
"""The TLP label of a model request, and whether a model role may receive it (ADR-0033
decisions 10 and 11; docs/llm-gateway.md, "TLP labels on requests").

Every model role has a TLP ceiling (:func:`homelabnext.modules.rules.role_ceiling`): ``red`` for a
role that stays in the lab, ``clear`` for one whose prompts can leave it (``leaves_lab`` on the
role or down its fallback chain), ``green`` only with the provider's terms on record, never
``amber`` or above.  The caller labels each request with the strictest label of everything it
assembled (retrieved rows, broker results, MCP tool output, memory).  The caller asserts that
label, so for a role that leaves the lab the request is taken at the **higher** of the claim and
the sending profile's own TLP ceiling: a profile that may hold ``amber`` cannot send to a cloud
role whatever its request says.  A request with no label is ``red``, and so is a label that is
not one (:func:`homelabnext.tlp.read`).

:func:`admit` is the rule as one function: it returns an :class:`Admission` whose ``reason`` and
:meth:`Admission.record` are what a caller logs, allowed or refused, and it never raises on a
request's label.  What runs it: the gateway is configured for an external product with no
admission code of its own (ADR-0022), so the generator applies the part it can decide without a
request (:mod:`homelabnext.generators.llm_gateway` scopes no key to a role whose ceiling is below
the key's sending ceiling), and a caller in front of the gateway applies :func:`admit` to each
request.  Standard library only.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from homelabnext import tlp
from homelabnext.modules.rules import CLOUD_CEILING, cloud_roles, role_ceiling

__all__ = [
    "ABOVE_CEILING",
    "INVALID_TABLE",
    "UNKNOWN_ROLE",
    "UNLABELLED",
    "WITHIN_CEILING",
    "Admission",
    "admit",
    "data_tier_of",
    "request_label",
    "send_ceiling",
    "tier_disagreement",
]

#: the reasons an :class:`Admission` carries (a closed vocabulary a log can branch on)
WITHIN_CEILING = "within-ceiling"
ABOVE_CEILING = "above-ceiling"
UNLABELLED = "unlabelled"
UNKNOWN_ROLE = "unknown-role"
INVALID_TABLE = "invalid-role-table"

#: the default of a request's label: the request carried none at all
_ABSENT: object = object()


def send_ceiling(tlp_ceiling: object = _ABSENT, data_tier: object = None) -> tlp.Label:
    """A sending profile's TLP ceiling, as the gateway rule reads it (decision 11).

    ``tlp_ceiling`` is the profile's declared ceiling (attested by the ceiling policy, decision
    12), read as data: a value that is not a label is ``red``.  A profile that declares none reads
    from its ``data_tier`` the only ceiling that tier allows: ``cloud-allowed`` is at or below the
    cloud-role ceiling, so ``clear``; anything else (``local-only``, absent, unknown) is ``red``,
    the reading that sends nothing to a role that leaves the lab.
    """
    if tlp_ceiling is not _ABSENT and tlp_ceiling is not None:
        return tlp.read(tlp_ceiling)
    return CLOUD_CEILING if data_tier == "cloud-allowed" else tlp.Label.RED


def data_tier_of(label: tlp.Label) -> str:
    """The ``data_tier`` a TLP label or ceiling derives (decision 12): ``cloud-allowed`` at or
    below the cloud-role ceiling (``clear``), ``local-only`` above it."""
    if type(label) is not tlp.Label:
        raise TypeError(f"label must be a Label, not {type(label).__name__}")
    return "cloud-allowed" if label <= CLOUD_CEILING else "local-only"


def tier_disagreement(data_tier: object, label: tlp.Label, what: str) -> str | None:
    """A problem when ``data_tier`` is not the tier ``label`` derives (decision 12: until
    ``data_tier`` is derived, an entry that states both must agree), else ``None``. ``what`` names
    the label (``tlp_ceiling green``, ``tlp amber``) in the message."""
    want = data_tier_of(label)
    if data_tier == want:
        return None
    side = "at or below" if want == "cloud-allowed" else "above"
    return (
        f"data_tier {data_tier} disagrees with {what}: {label} is {side} the cloud-role ceiling "
        f"({CLOUD_CEILING}), which is data_tier {want} (ADR-0033 decision 12)"
    )


def request_label(claimed: object = _ABSENT, *, leaves_lab: bool, sender: tlp.Label) -> tlp.Label:
    """The label a request is judged at: the claim read as data (no claim is ``red``), raised to
    the sender's ceiling when the role leaves the lab (decision 11)."""
    if type(sender) is not tlp.Label:
        raise TypeError(f"sender must be a Label, not {type(sender).__name__}")
    label = tlp.Label.RED if claimed is _ABSENT else tlp.read(claimed)
    return max(label, sender) if leaves_lab is True else label


@dataclass(frozen=True)
class Admission:
    """Whether one request may go to ``role``, and why (what the caller logs)."""

    allowed: bool
    role: str  # mdl:<role>
    label: tlp.Label  # the label the request was judged at
    ceiling: tlp.Label  # the role's ceiling (red for a role the table does not hold)
    leaves_lab: bool
    reason: str  # WITHIN_CEILING, ABOVE_CEILING, UNLABELLED, UNKNOWN_ROLE or INVALID_TABLE

    def __bool__(self) -> bool:
        return self.allowed

    @property
    def message(self) -> str:
        """One line for a log or an error reply: names and labels only, never request content."""
        if self.reason == UNKNOWN_ROLE:
            return f"{self.role} is not in the role table: the request is refused"
        if self.reason == INVALID_TABLE:
            return (
                f"the role table is malformed (a role, a binding or a fallback that is not the "
                f"shape the schema gives it), so no ceiling of {self.role} can be read: refused"
            )
        where = "can leave the lab" if self.leaves_lab else "stays in the lab"
        verdict = "allowed" if self.allowed else "refused"
        why = {
            WITHIN_CEILING: "at or below",
            ABOVE_CEILING: "above",
            UNLABELLED: "unlabelled, read as red, and above",
        }[self.reason]
        return (
            f"{verdict}: a request labelled {self.label} is {why} the TLP ceiling {self.ceiling} "
            f"of {self.role}, whose prompts {where}"
        )

    def record(self) -> dict[str, Any]:
        """The admission as a flat record a caller logs (allowed or refused)."""
        return {
            "role": self.role,
            "allowed": self.allowed,
            "reason": self.reason,
            "label": str(self.label),
            "ceiling": str(self.ceiling),
            "leaves_lab": self.leaves_lab,
        }


def _sound(roles: Mapping[str, Any]) -> bool:
    """Every role is a mapping whose bindings are mappings and whose fallback is text, so the
    ceiling rules can read the whole table (a malformed entry anywhere could sit on a chain)."""
    for r in roles.values():
        if not isinstance(r, Mapping):
            return False
        bindings = r.get("bindings", [])
        if not isinstance(bindings, list) or not all(isinstance(b, Mapping) for b in bindings):
            return False
        if r.get("fallback") is not None and not isinstance(r.get("fallback"), str):
            return False
    return True


def admit(
    roles: Mapping[str, Any],
    role: str,
    claimed: object = _ABSENT,
    *,
    sender: tlp.Label,
) -> Admission:
    """Whether a request labelled ``claimed`` from a profile whose sending ceiling is ``sender``
    (:func:`send_ceiling`) may go to model role ``role`` of the role table's ``roles``.

    Leave ``claimed`` out (or pass ``None``) when the request carried no label: it is ``red``,
    reason ``unlabelled`` when refused.  A role the table does not hold is refused
    (``unknown-role``), and so is any request while the table has a malformed entry
    (``invalid-role-table``): a ceiling read past one could be wrong.  For a role that leaves the lab the label is the higher
    of the claim and ``sender``; it is refused when above the role's ceiling (``above-ceiling``, or
    ``unlabelled`` when there was no claim at all)."""
    name = role.removeprefix("mdl:")
    rid = "mdl:" + name
    roles = dict(roles)
    if not _sound(roles):
        return Admission(False, rid, tlp.Label.RED, tlp.Label.RED, True, INVALID_TABLE)
    if name not in roles:
        return Admission(False, rid, tlp.Label.RED, tlp.Label.RED, True, UNKNOWN_ROLE)
    if claimed is None:
        claimed = _ABSENT
    leaves = rid in cloud_roles(roles)
    ceiling = role_ceiling(roles, name)
    label = request_label(claimed, leaves_lab=leaves, sender=sender)
    if label <= ceiling:
        return Admission(True, rid, label, ceiling, leaves, WITHIN_CEILING)
    reason = UNLABELLED if claimed is _ABSENT else ABOVE_CEILING
    return Admission(False, rid, label, ceiling, leaves, reason)
