# SPDX-License-Identifier: Apache-2.0
"""TLP 2.0 labels: the one type every source, record and reader uses (ADR-0033 decision 1).

The five labels, ordered by restriction: ``clear`` < ``green`` < ``amber`` < ``amber+strict`` <
``red``.  A reader with ceiling X receives labels at or below X.  :class:`Label` compares only
with another :class:`Label` (never with a number) and is always truthy.

This module owns the label grammar: every spelling of a label, and every carrier it arrives in,
is read here and nowhere else.  Readers come in two pairs, with opposite failure directions:

* **incoming** (a label on data as it arrives: a record, a sidecar, an event): :func:`read` never
  raises.  An accepted spelling is the label; anything else (a misspelling, an empty string,
  ``None``, a number, bytes) is ``red``, so damaged or missing labels hide data rather than expose
  it.  :func:`parse` is the same lenient grammar for a hand-written **declaration** (a source's
  ``tlp``, a reader's ceiling, a role's ceiling) and raises on anything else, so an authored
  mistake is refused by validation instead of silently becoming ``red``.
* **stored** (a value this platform wrote: a lake row's ``tlp``, a generated table, a recorded
  maximum): only the five canonical spellings (:data:`LABELS`, exact ``str``) are labels, since a
  writer normalises before it stores.  :func:`read_stored` never raises (anything else is
  ``red``); :func:`parse_stored` raises on anything else.

The carriers: :func:`markers` finds every TLP marker in a body (``TLP:RED``, ``[TLP=AMBER]``,
``TLP_GREEN``...); :func:`tag_label` reads a ``tlp:`` tag with the same marker grammar; and
:func:`stix_marking_label` reads a STIX 2.1 TLP marking-definition id (:data:`STIX_TLP_MARKINGS`).

Accepted spellings: ``clear``, ``green``, ``amber``, ``amber+strict``, ``red``, each with an
optional ``tlp:`` prefix, in any ASCII case, with surrounding spaces, tabs, carriage returns and
line feeds ignored; TLP 1.0 ``white`` is ``clear``.  Nothing else is accepted: ``amber-strict``,
``amber strict``, ``tlp: red`` (a space after the colon), other control or non-ASCII whitespace
and non-ASCII look-alikes are not labels.  A ``str`` subclass is read through ``str``'s own
methods, so it cannot change how it is read.

Standard library only.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable, Mapping
from enum import Enum
from types import MappingProxyType

__all__ = [
    "LABELS",
    "STIX_TLP_MARKINGS",
    "Label",
    "allows",
    "at_or_below",
    "item_label",
    "markers",
    "parse",
    "parse_stored",
    "read",
    "read_stored",
    "row_filter_sql",
    "stix_marking_label",
    "strictest",
    "tag_label",
]


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


def _stored(value: object) -> Label | None:
    if type(value) is str and value in LABELS:
        return _SPELLINGS[value]
    return None


def read_stored(value: object) -> Label:
    """The label of a stored value: a canonical spelling (an exact ``str`` in :data:`LABELS`),
    else ``red``.  Never raises.  A lenient spelling (``white``, ``TLP:RED``, ``Green``) is not a
    stored label: a writer that stored one bypassed normalisation, so the value is not trusted."""
    label = _stored(value)
    return Label.RED if label is None else label


def parse_stored(value: object) -> Label:
    """The label a stored or generated value states; ``ValueError`` for anything but a canonical
    spelling (an exact ``str`` in :data:`LABELS`)."""
    label = _stored(value)
    if label is None:
        raise ValueError(f"not a canonical TLP label: {value!r} (one of {', '.join(LABELS)})")
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


#: the default of :func:`item_label`'s ``item``: the item carried no label at all
_ABSENT: object = object()


def item_label(
    declared: Label, item: object = _ABSENT, *, honour_item_labels: bool = False
) -> Label:
    """The label of one item from a source that declares ``declared`` (ADR-0033 decision 3).

    ``item`` is the label the item carried from the source; leave it out when the item carried
    none (its label field is missing), and only then does the item take the declaration. Anything
    passed is read as data, so ``None`` (a JSON ``null`` in a label field), an empty string or a
    misspelling is ``red``. A carried label is kept when it is stricter than the declaration, and
    when looser only if the source declares ``honour_item_labels`` (a human-approve field); it is
    otherwise raised to the declaration.
    """
    if type(declared) is not Label:
        raise TypeError(f"declared must be a Label, not {type(declared).__name__}")
    if item is _ABSENT:
        return declared
    carried = read(item)
    if carried >= declared or honour_item_labels is True:
        return carried
    return declared


def at_or_below(ceiling: Label) -> tuple[str, ...]:
    """The canonical labels a reader with ``ceiling`` receives, least restrictive first."""
    if type(ceiling) is not Label:
        raise TypeError(f"ceiling must be a Label, not {type(ceiling).__name__}")
    return tuple(label.value for label in Label if label <= ceiling)


def row_filter_sql(ceiling: Label, column: str = "tlp") -> str | None:
    """The SQL predicate a query engine applies for a reader with ``ceiling`` (ADR-0033 decision
    6), or None for ``red``, which receives every row.  A row whose label is missing reads as
    ``red``; one that is not a canonical label matches no listed value, so it is shown only at
    ``red`` too.  ``column`` must be a plain identifier."""
    if not column.isidentifier() or not column.isascii():
        raise ValueError(f"not a plain column name: {column!r}")
    labels = at_or_below(ceiling)
    if ceiling is Label.RED:
        return None
    listed = ", ".join(f"'{v}'" for v in labels)
    return f"coalesce({column}, 'red') IN ({listed})"


# ---------------------------------------------------------------- carriers: markers, tags, STIX
#: a marker: ``TLP`` then a colon (``TLP:RED``, ``tlp : amber``), the word read by
#: :func:`_marker_label`; or ``TLP`` then a label word with no colon, after any run of white space
#: and up to three other characters that are neither a letter nor a digit, or none (``TLP RED``,
#: ``TLP    RED``, ``TLP-AMBER``, ``TLP_RED``, ``TLP/AMBER``, ``[TLP=RED]``, ``TLP--GREEN``,
#: ``TLP  -  RED``, ``TLPRED``): the spellings report headers, column-padded tables, file names
#: and exports use.  White space is never counted against the three, so padding cannot hide one.
_COLON = re.compile(r"TLP\s*:\s*", re.IGNORECASE | re.ASCII)
_BARE = re.compile(
    r"TLP(?!\s*:)\s*(?:[^A-Za-z0-9\s]{1,3}\s*)?(?=(?:CLEAR|WHITE|GREEN|AMBER|RED))",
    re.IGNORECASE | re.ASCII,
)
_WORD = re.compile(r"[A-Za-z]+", re.ASCII)
_PLUS_WORD = re.compile(r"\s*\+\s*([A-Za-z]+)", re.ASCII)
_PLUS = re.compile(r"\s*\+", re.ASCII)
#: ``strict`` within a few characters of ``amber`` in any other spelling (``amber-strict``,
#: ``amber strict``, ``amber and strict``): not a label, so red (decision 1)
_NEAR_STRICT = re.compile(r"[^A-Za-z]{0,3}(?:[A-Za-z]{1,4}[^A-Za-z]{1,3})?strict", re.I | re.ASCII)
#: a body nested deeper than this is not scanned to the end, so it is red
_MAX_DEPTH = 32


def _normalised(text: str) -> str:
    """``text`` as a marker reader sees it: compatibility forms folded (fullwidth letters become
    ASCII), format characters (zero-width and the like) removed, every white space a space."""
    folded = unicodedata.normalize("NFKC", str.__str__(text))
    return "".join(" " if ch.isspace() else ch for ch in folded if unicodedata.category(ch) != "Cf")


def _marker_label(rest: str) -> Label:
    """The label a ``TLP:`` marker gives, ``rest`` being what follows the colon."""
    word = _WORD.match(rest)
    if word is None:
        return Label.RED  # TLP: and then no ASCII word
    after = rest[word.end() :]
    plus_word = _PLUS_WORD.match(after)
    if plus_word is not None:
        return read(f"{word.group(0)}+{plus_word.group(1)}")
    if _PLUS.match(after):
        return Label.RED  # a dangling +
    if word.group(0).lower() == "amber" and _NEAR_STRICT.match(after):
        return Label.RED  # amber-strict, amber strict: not a label
    return read(word.group(0))


def _scan(text: str) -> list[Label]:
    text = _normalised(text)
    out = [_marker_label(text[m.end() :]) for m in _COLON.finditer(text)]
    # a colon-less marker starts with a label word and is read exactly as a colon one
    out += [_marker_label(text[m.end() :]) for m in _BARE.finditer(text)]
    return out


def markers(body: object, _depth: int = 0) -> list[Label]:
    """Every TLP marker in ``body`` as a label.  Text is read after folding look-alikes; bytes are
    read as UTF-8; a mapping or a list is read leaf by leaf, keys included.  ``None`` holds no
    marker; anything else (a number is fine, an object is not) is read as ``red``, since a body
    that cannot be scanned cannot be shown to hold no stricter marker."""
    if body is None or type(body) in (bool, int, float):
        return []
    if _depth > _MAX_DEPTH:
        return [Label.RED]
    if isinstance(body, str):
        return _scan(body)
    if isinstance(body, (bytes, bytearray)):
        return _scan(bytes(body).decode("utf-8", errors="replace"))
    if isinstance(body, Mapping):
        out: list[Label] = []
        for k, v in body.items():
            out += markers(k, _depth + 1) + markers(v, _depth + 1)
        return out
    if isinstance(body, (list, tuple)):
        return [label for item in body for label in markers(item, _depth + 1)]
    return [Label.RED]


def tag_label(tag: object) -> Label | None:
    """The label a tag carries, or ``None`` for a tag that is not a TLP one.  A tag is a TLP tag
    when the marker grammar (:func:`markers`) finds a marker in it, so ``tlp:red``, ``TLP:RED``,
    ``tlp : red`` and its fullwidth look-alike are all ``red``; it gives the strictest marker
    found, and a marker that is not a label (``tlp:amber-strict``, ``tlp:unknown``, ``tlp:``) is
    ``red``.  A tag that is not text holds no label."""
    if not isinstance(tag, str):
        return None
    found = markers(tag)
    return max(found) if found else None


#: the STIX 2.1 marking definitions of TLP: the TLP 2.0 ones (the TLP 2.0 marking extension) and
#: the TLP 1.0 ones the STIX 2.1 specification predefines (``white`` is ``clear``)
STIX_TLP_MARKINGS: Mapping[str, str] = MappingProxyType(
    {
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487": "clear",
        "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb": "green",
        "marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421": "amber",
        "marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003": "amber+strict",
        "marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1": "red",
        "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9": "clear",
        "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da": "green",
        "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82": "amber",
        "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed": "red",
    }
)


def stix_marking_label(ref: object) -> Label | None:
    """The label of a STIX marking reference, or ``None`` for one that is not a TLP marking (a
    statement marking, say).  Case and surrounding white space are ignored."""
    if not isinstance(ref, str):
        return None
    value = STIX_TLP_MARKINGS.get(str.casefold(str.strip(ref)))
    return None if value is None else _SPELLINGS[value]
