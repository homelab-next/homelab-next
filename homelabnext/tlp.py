# SPDX-License-Identifier: Apache-2.0
"""TLP 2.0 labels: the one type every source, record and reader uses (ADR-0033 decision 1).

The five labels, ordered by restriction: ``clear`` < ``green`` < ``amber`` < ``amber+strict`` <
``red``.  A reader with ceiling X receives labels at or below X.

Two readers of a label, with opposite failure directions:

* :func:`read` is for **data**: a label on a record, a sidecar, an event, a stored row.  It never
  raises.  An accepted spelling is the label; anything else (a misspelling, an empty string,
  ``None``, a number) is ``red``, so damaged or missing labels hide data rather than expose it.
* :func:`parse` is for **declarations**: a source's ``tlp``, a reader's ceiling, a role's ceiling.
  It raises on anything but an accepted spelling, so an authored mistake is refused by validation
  instead of silently becoming ``red`` (or, for a ceiling, silently showing less than intended).

Accepted spellings: ``clear``, ``green``, ``amber``, ``amber+strict``, ``red``, each with an
optional ``tlp:`` prefix, in any ASCII case, with surrounding whitespace ignored; TLP 1.0
``white`` is ``clear``.  Nothing else is accepted: ``amber-strict``, ``amber strict``, ``tlp: red``
(a space after the colon) and non-ASCII look-alikes are not labels.

Standard library only.
"""

from __future__ import annotations

from collections.abc import Iterable
from enum import IntEnum

__all__ = ["LABELS", "Label", "allows", "parse", "read", "strictest"]


class Label(IntEnum):
    """A TLP 2.0 label; comparison follows restriction (``Label.CLEAR < Label.RED``)."""

    CLEAR = 0
    GREEN = 1
    AMBER = 2
    AMBER_STRICT = 3
    RED = 4

    def __str__(self) -> str:
        return _CANONICAL[self]


_CANONICAL = {
    Label.CLEAR: "clear",
    Label.GREEN: "green",
    Label.AMBER: "amber",
    Label.AMBER_STRICT: "amber+strict",
    Label.RED: "red",
}

#: the canonical spellings, least to most restrictive: the enum every schema uses
LABELS: tuple[str, ...] = tuple(_CANONICAL[label] for label in Label)

_SPELLINGS = {**{name: label for label, name in _CANONICAL.items()}, "white": Label.CLEAR}
_PREFIX = "tlp:"


def _lookup(value: object) -> Label | None:
    if isinstance(value, Label):
        return value
    if not isinstance(value, str) or not value.isascii():
        return None
    text = value.strip().lower()
    if text.startswith(_PREFIX):
        text = text[len(_PREFIX) :]
    return _SPELLINGS.get(text)


def read(value: object) -> Label:
    """The label of a piece of data: an accepted spelling, else ``red``. Never raises."""
    label = _lookup(value)
    return Label.RED if label is None else label


def parse(value: object) -> Label:
    """The label a declaration states; ``ValueError`` for anything but an accepted spelling."""
    label = _lookup(value)
    if label is None:
        raise ValueError(
            f"not a TLP label: {value!r} (one of {', '.join(LABELS)}, optionally 'tlp:'-prefixed;"
            " 'white' is read as clear)"
        )
    return label


def strictest(labels: Iterable[object]) -> Label:
    """The most restrictive of ``labels``, each read as data (ADR-0033 decision 4).

    Derived data takes its strictest input, so an unreadable input makes the result ``red``. No
    inputs at all is ``red`` too: a derived item whose inputs are unknown is unlabelled (decision 2).
    """
    return max((read(v) for v in labels), default=Label.RED)


def allows(ceiling: Label, label: object) -> bool:
    """Whether a reader with ``ceiling`` may receive data labelled ``label`` (read as data).

    ``ceiling`` must already be a :class:`Label` (from :func:`parse`): a reader without a valid
    ceiling is refused by validation (decision 6), never given a default here.
    """
    if not isinstance(ceiling, Label):
        raise TypeError(f"ceiling must be a Label, not {type(ceiling).__name__}")
    return read(label) <= ceiling
