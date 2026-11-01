# SPDX-License-Identifier: Apache-2.0
"""Checking a label where data leaves its store (ADR-0033 decision 13).

Every egress point (the publishing gate, the public exports, the bus, notification channels,
webhooks, backups and off-site copies, model requests, enrichment lookups, memory and embedding
stores, generated pages committed to a repository, records and tickets, and logs and error text
that reach a notification) is to apply the same rule before anything leaves; docs/modules.md,
"Egress points", lists where it is applied today and which points do not apply it yet:

* the item's label is the **strictest** of the label it claims, the label recorded for it (the
  lake row's, the derived record's) and every TLP marker in its body: a claim never loosens what
  was recorded, and a marker stricter than both wins;
* the item leaves only when that label is at or below the destination's ceiling.

:func:`egress_label` and :func:`egress_check` are that rule; the markers are read by
:func:`homelabnext.tlp.markers` (re-exported here), the one marker grammar.  Enrichment lookups
are egress too:
:func:`job_label` labels a lookup by the records that cause it, raised to the submitter's ceiling,
and :func:`analyzers_for` names the analyzers whose declared maximum admits it (a maximum is a
declaration, so it must be a canonical label: any other value is refused, never skipped; an
analyzer named by anything but a string is skipped).  The notification channels call it
(:class:`homelabnext.notify.CeilingSender`).

Standard library only.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from homelabnext import tlp
from homelabnext.tlp import markers

__all__ = [
    "NO_RECORD",
    "EgressDecision",
    "analyzers_for",
    "egress_check",
    "egress_label",
    "job_label",
    "markers",
]


class _NoRecord:
    def __repr__(self) -> str:
        return "NO_RECORD"


#: pass as ``recorded`` for an item that has no recorded label (never the default: a caller that
#: holds one must pass it)
NO_RECORD = _NoRecord()


def egress_label(claimed: object, *, recorded: object, body: object = None) -> tlp.Label:
    """The label an item leaves under: the strictest of its claimed label, its recorded label and
    every marker in ``body``.  Each is read as data, so a missing or unreadable claim or record is
    ``red``.  ``recorded`` is required: pass :data:`NO_RECORD` for an item that has none, so a
    caller cannot loosen an item by forgetting its record."""
    labels = [tlp.read(claimed), *markers(body)]
    if recorded is not NO_RECORD:
        labels.append(tlp.read(recorded))
    return max(labels)


@dataclass(frozen=True)
class EgressDecision:
    """Whether an item may leave, the label it was judged at, and why not when it may not."""

    allowed: bool
    label: tlp.Label
    reason: str | None = None


def egress_check(
    ceiling: tlp.Label, claimed: object, *, recorded: object, body: object = None
) -> EgressDecision:
    """The decision for one item leaving to a destination with ``ceiling`` (a parsed label)."""
    label = egress_label(claimed, recorded=recorded, body=body)
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
    or above it.  An analyzer with no declared maximum (``None``) is sent nothing; a maximum that
    is declared but is not a canonical label (``AMBER``, ``tlp:green``, a typo) is an authored
    mistake, refused with :class:`ValueError` naming the analyzer instead of silently dropping it
    (stored and declared labels are canonical; the lenient spellings are for labels carried on
    incoming data)."""
    if type(job) is not tlp.Label:
        raise TypeError(f"job must be a Label, not {type(job).__name__}")
    out = []
    named = [(k, v) for k, v in maxima.items() if type(k) is str]
    for name, maximum in sorted(named, key=lambda kv: kv[0]):
        if maximum is None:
            continue
        try:
            ceiling = tlp.parse_stored(maximum)
        except ValueError:
            raise ValueError(
                f"analyzer {name!r}: its maximum {maximum!r} is not one of {', '.join(tlp.LABELS)}"
            ) from None
        if tlp.allows(ceiling, job):
            out.append(name)
    return out
