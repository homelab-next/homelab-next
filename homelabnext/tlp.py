# SPDX-License-Identifier: Apache-2.0
"""TLP 2.0 labels: the one type every source, record and reader uses (ADR-0033 decision 1).

The five labels, ordered by restriction: ``clear`` < ``green`` < ``amber`` < ``amber+strict`` <
``red``.  A reader with ceiling X receives labels at or below X.  :class:`Label` compares only
with another :class:`Label` (never with a number) and is always truthy.

Two readers of a label, with opposite failure directions:

* :func:`read` is for **data**: a label on a record, a sidecar, an event, a stored row.  It never
  raises.  An accepted spelling is the label; anything else (a misspelling, an empty string,
  ``None``, a number, bytes) is ``red``, so damaged or missing labels hide data rather than expose
  it.
* :func:`parse` is for **declarations**: a source's ``tlp``, a reader's ceiling, a role's ceiling.
  It raises on anything but an accepted spelling, so an authored mistake is refused by validation
  instead of silently becoming ``red`` (or, for a ceiling, silently showing less than intended).

Accepted spellings: ``clear``, ``green``, ``amber``, ``amber+strict``, ``red``, each with an
optional ``tlp:`` prefix, in any ASCII case, with surrounding spaces, tabs, carriage returns and
line feeds ignored; TLP 1.0 ``white`` is ``clear``.  Nothing else is accepted: ``amber-strict``,
``amber strict``, ``tlp: red`` (a space after the colon), other control or non-ASCII whitespace
and non-ASCII look-alikes are not labels.  A ``str`` subclass is read through ``str``'s own
methods, so it cannot change how it is read.

Standard library only.
"""

from __future__ import annotations

from collections.abc import Iterable
from enum import Enum
from types import MappingProxyType

__all__ = ["LABELS", "Label", "allows", "parse", "read", "strictest"]


class Label(Enum):
    """A TLP 2.0 label; ``<`` follows restriction (``Label.CLEAR < Label.RED``)."""

    CLEAR = "clear"
    GREEN = "green"
    AMBER = "amber"
    AMBER_STRICT = "amber+strict"
    RED = "red"

    def __str__(self) -> str:
        return self.value

    def __bool__(self) -> bool:
        return True

    @property
    def rank(self) -> int:
        """0 for ``clear`` up to 4 for ``red``."""
        return _RANK[self]

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Label):
            return NotImplemented
        return _RANK[self] < _RANK[other]

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Label):
            return NotImplemented
        return _RANK[self] <= _RANK[other]

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Label):
            return NotImplemented
        return _RANK[self] > _RANK[other]

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Label):
            return NotImplemented
        return _RANK[self] >= _RANK[other]


_RANK = MappingProxyType({label: i for i, label in enumerate(Label)})

#: the canonical spellings, least to most restrictive: the enum every schema uses
LABELS: tuple[str, ...] = tuple(label.value for label in Label)

_SPELLINGS = MappingProxyType({**{label.value: label for label in Label}, "white": Label.CLEAR})
_PREFIX = "tlp:"
_SPACE = " \t\r\n"


def _lookup(value: object) -> Label | None:
    if type(value) is Label:
        return value
    if not isinstance(value, str):
        return None
    # str's own methods: a subclass's overrides never run, and every result is an exact str
    if not str.isascii(value):
        return None
    text = str.lower(str.strip(value, _SPACE))
    if str.startswith(text, _PREFIX):
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
    inputs at all is ``red`` too: a derived item whose inputs are unknown is unlabelled (decision
    2). A single string is one input, not a sequence of characters; anything that is not iterable
    is unreadable.
    """
    if isinstance(labels, (str, bytes, bytearray, Label)):
        return read(labels)
    try:
        inputs = iter(labels)
    except TypeError:
        return Label.RED
    return max((read(v) for v in inputs), default=Label.RED)


def allows(ceiling: Label, label: object) -> bool:
    """Whether a reader with ``ceiling`` may receive data labelled ``label`` (read as data).

    ``ceiling`` must already be a :class:`Label` (from :func:`parse`): a reader without a valid
    ceiling is refused by validation (decision 6), never given a default here.
    """
    if type(ceiling) is not Label:
        raise TypeError(f"ceiling must be a Label, not {type(ceiling).__name__}")
    return read(label) <= ceiling
