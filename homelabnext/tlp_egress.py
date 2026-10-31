# SPDX-License-Identifier: Apache-2.0
"""Checking a label where data leaves its store (ADR-0033 decision 13).

Every egress point (the publishing gate, the public exports, the bus, notification channels,
webhooks, backups and off-site copies, model requests, enrichment lookups, memory and embedding
stores, generated pages committed to a repository, records and tickets, and logs and error text
that reach a notification) applies the same rule before anything leaves:

* the item's label is the **strictest** of the label it claims, the label recorded for it (the
  lake row's, the derived record's) and every TLP marker in its body: a claim never loosens what
  was recorded, and a marker stricter than both wins;
* the item leaves only when that label is at or below the destination's ceiling.

:func:`egress_label` and :func:`egress_check` are that rule.  Enrichment lookups are egress too:
:func:`job_label` labels a lookup by the records that cause it, raised to the submitter's ceiling,
and :func:`analyzers_for` names the analyzers whose declared maximum admits it.

Standard library only.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from homelabnext import tlp

__all__ = [
    "EgressDecision",
    "analyzers_for",
    "egress_check",
    "egress_label",
    "job_label",
    "markers",
]

#: ``TLP:<word>`` in a body, in any ASCII case, with optional spaces around the colon and the
#: ``+``; the word is read by :func:`markers`, so an unknown one (``TLP:BLACK``) counts as ``red``
_MARKER = re.compile(
    r"(?<![A-Za-z0-9])TLP\s*:\s*([A-Za-z]+(?:\s*\+\s*[A-Za-z]+)?)",
    re.IGNORECASE | re.ASCII,
)
_ABSENT: object = object()


def markers(text: object) -> list[tlp.Label]:
    """Every TLP marker in ``text`` as a label (an unknown word is ``red``); none for a body that
    is not text."""
    if not isinstance(text, str):
        return []
    out = []
    for m in _MARKER.finditer(str.__str__(text)):
        word = re.sub(r"\s+", "", m.group(1)).lower()
        out.append(tlp.read(word))
    return out


def egress_label(claimed: object, recorded: object = _ABSENT, body: object = None) -> tlp.Label:
    """The label an item leaves under: the strictest of its claimed label, its recorded label
    (when there is one) and every marker in ``body``.  Each is read as data, so a missing or
    unreadable claim is ``red``."""
    labels = [tlp.read(claimed), *markers(body)]
    if recorded is not _ABSENT:
        labels.append(tlp.read(recorded))
    return max(labels)


@dataclass(frozen=True)
class EgressDecision:
    """Whether an item may leave, the label it was judged at, and why not when it may not."""

    allowed: bool
    label: tlp.Label
    reason: str | None = None


def egress_check(
    ceiling: tlp.Label, claimed: object, recorded: object = _ABSENT, body: object = None
) -> EgressDecision:
    """The decision for one item leaving to a destination with ``ceiling`` (a parsed label)."""
    label = egress_label(claimed, recorded, body)
    if tlp.allows(ceiling, label):
        return EgressDecision(True, label)
    return EgressDecision(False, label, f"labelled {label}, above the destination's {ceiling}")


def job_label(records: Iterable[object], submitter_ceiling: tlp.Label) -> tlp.Label:
    """The label of an enrichment lookup: the strictest label among the records that cause it
    (none, or an unreadable one, is ``red``), raised to the submitting component's own ceiling,
    so a submitter that may hold ``amber`` cannot send an ``amber`` observable out as ``clear``."""
    if type(submitter_ceiling) is not tlp.Label:
        raise TypeError(
            f"submitter_ceiling must be a Label, not {type(submitter_ceiling).__name__}"
        )
    return max(tlp.strictest(list(records)), submitter_ceiling)


def analyzers_for(job: tlp.Label, maxima: Mapping[str, object]) -> list[str]:
    """The analyzers a lookup labelled ``job`` may be sent to: those whose declared maximum is at
    or above it.  An analyzer with no declared maximum, or one that is not a canonical label, is
    sent nothing."""
    if type(job) is not tlp.Label:
        raise TypeError(f"job must be a Label, not {type(job).__name__}")
    out = []
    for name, maximum in sorted(maxima.items()):
        if type(maximum) is not str or maximum not in tlp.LABELS:
            continue
        if tlp.allows(tlp.parse(maximum), job):
            out.append(name)
    return out
