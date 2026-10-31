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
and :func:`analyzers_for` names the analyzers whose declared maximum admits it (a maximum must
be a canonical label; an analyzer named by anything but a string is skipped).  The notification
channels call it (:class:`homelabnext.notify.CeilingSender`); docs/modules.md, "Egress points",
says which other points do and which do not yet.

Standard library only.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from homelabnext import tlp

__all__ = [
    "NO_RECORD",
    "EgressDecision",
    "analyzers_for",
    "egress_check",
    "egress_label",
    "job_label",
    "markers",
]

#: a marker: ``TLP`` then a colon (``TLP:RED``, ``tlp : amber``), the word read by
#: :func:`_marker_label`; or ``TLP`` then a label word with no colon (``TLP RED``)
_COLON = re.compile(r"TLP\s*:\s*", re.IGNORECASE | re.ASCII)
_BARE = re.compile(r"TLP\s+(?=(?:CLEAR|WHITE|GREEN|AMBER|RED))", re.IGNORECASE | re.ASCII)
_WORD = re.compile(r"[A-Za-z]+", re.ASCII)
_PLUS_WORD = re.compile(r"\s*\+\s*([A-Za-z]+)", re.ASCII)
_PLUS = re.compile(r"\s*\+", re.ASCII)
#: ``strict`` within a few characters of ``amber`` in any other spelling (``amber-strict``,
#: ``amber strict``, ``amber and strict``): not a label, so red (decision 1)
_NEAR_STRICT = re.compile(r"[^A-Za-z]{0,3}(?:[A-Za-z]{1,4}[^A-Za-z]{1,3})?strict", re.I | re.ASCII)
#: a body nested deeper than this is not scanned to the end, so it is red
_MAX_DEPTH = 32


class _NoRecord:
    def __repr__(self) -> str:
        return "NO_RECORD"


#: pass as ``recorded`` for an item that has no recorded label (never the default: a caller that
#: holds one must pass it)
NO_RECORD = _NoRecord()


def _normalised(text: str) -> str:
    """``text`` as a marker reader sees it: compatibility forms folded (fullwidth letters become
    ASCII), format characters (zero-width and the like) removed, every white space a space."""
    folded = unicodedata.normalize("NFKC", str.__str__(text))
    return "".join(" " if ch.isspace() else ch for ch in folded if unicodedata.category(ch) != "Cf")


def _marker_label(rest: str) -> tlp.Label:
    """The label a ``TLP:`` marker gives, ``rest`` being what follows the colon."""
    word = _WORD.match(rest)
    if word is None:
        return tlp.Label.RED  # TLP: and then no ASCII word
    after = rest[word.end() :]
    plus_word = _PLUS_WORD.match(after)
    if plus_word is not None:
        return tlp.read(f"{word.group(0)}+{plus_word.group(1)}")
    if _PLUS.match(after):
        return tlp.Label.RED  # a dangling +
    if word.group(0).lower() == "amber" and _NEAR_STRICT.match(after):
        return tlp.Label.RED  # amber-strict, amber strict: not a label
    return tlp.read(word.group(0))


def _scan(text: str) -> list[tlp.Label]:
    text = _normalised(text)
    out = [_marker_label(text[m.end() :]) for m in _COLON.finditer(text)]
    # a colon-less marker starts with a label word and is read exactly as a colon one
    out += [_marker_label(text[m.end() :]) for m in _BARE.finditer(text)]
    return out


def markers(body: object, _depth: int = 0) -> list[tlp.Label]:
    """Every TLP marker in ``body`` as a label.  Text is read after folding look-alikes; bytes are
    read as UTF-8; a mapping or a list is read leaf by leaf, keys included.  ``None`` holds no
    marker; anything else (a number is fine, an object is not) is read as ``red``, since a body
    that cannot be scanned cannot be shown to hold no stricter marker."""
    if body is None or type(body) in (bool, int, float):
        return []
    if _depth > _MAX_DEPTH:
        return [tlp.Label.RED]
    if isinstance(body, str):
        return _scan(body)
    if isinstance(body, (bytes, bytearray)):
        return _scan(bytes(body).decode("utf-8", errors="replace"))
    if isinstance(body, Mapping):
        out: list[tlp.Label] = []
        for k, v in body.items():
            out += markers(k, _depth + 1) + markers(v, _depth + 1)
        return out
    if isinstance(body, (list, tuple)):
        return [label for item in body for label in markers(item, _depth + 1)]
    return [tlp.Label.RED]


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
    or above it.  An analyzer with no declared maximum, or one that is not a canonical label, is
    sent nothing."""
    if type(job) is not tlp.Label:
        raise TypeError(f"job must be a Label, not {type(job).__name__}")
    out = []
    named = [(k, v) for k, v in maxima.items() if type(k) is str]
    for name, maximum in sorted(named, key=lambda kv: kv[0]):
        if type(maximum) is not str or maximum not in tlp.LABELS:
            continue
        if tlp.allows(tlp.parse(maximum), job):
            out.append(name)
    return out
