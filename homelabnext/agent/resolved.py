# SPDX-License-Identifier: Apache-2.0
"""Platform-issued input uids for a context pack (ADR-0037 decisions 7, 8 and 13).

An input item (a feed item, a lake row, a record) enters a pack under a uid, a digest and a label.
None of the three may come from the item's own content: a poisoned item could claim a good
record's uid (and get it retracted) or a fresh one (and escape a retraction), and could claim a
looser label.  So :func:`~homelabnext.agent.pack.assemble_pack` takes a :class:`ResolvedUids`:
for each uid, the ``digest`` and ``tlp`` the platform stored for it.

:class:`ResolvedUids` is sealed like :class:`~homelabnext.agent.compiler.VerifiedProfile`:
constructing it directly raises ``TypeError``, and it is read-only.  It is made only by
:func:`resolve_input_uids`, which a records or lake reader calls with the rows **it read from its
own store** (never rows a caller or a feed supplied).  Each row is read as stored data:

* ``uid`` must be a canonical UUIDv7 and ``digest`` ``sha256:<64 hex>``;
* ``tlp`` is read with :func:`homelabnext.tlp.read_stored`, so a missing or non-canonical label is
  ``red``;
* a uid listed twice with two digests, or a digest under two uids, is refused.

The type proves that a reader's function built the map, not which reader; what a reader passes
it is that reader's to get right, as a ceiling policy's attestation is its owner's.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator, Mapping
from types import MappingProxyType
from typing import Any

from homelabnext import tlp

from .errors import SpecError

__all__ = ["DIGEST", "UID", "ResolvedUids", "resolve_input_uids"]

#: a canonical record uid (a UUIDv7)
UID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_SEALED = object()


class ResolvedUids(Mapping[str, Mapping[str, str]]):
    """``{uid: {"digest", "tlp"}}`` as a platform reader stored them; made only by
    :func:`resolve_input_uids`.  ``source`` names the reader."""

    __slots__ = ("_map", "source")

    def __init_subclass__(cls, **kwargs: Any) -> None:
        # a subclass could override the reads the assembler relies on, so there is none
        raise TypeError("ResolvedUids is sealed: it cannot be subclassed")

    def __init__(self, entries: Mapping[str, Mapping[str, str]], source: str, token: object = None):
        if token is not _SEALED:
            raise TypeError(
                "ResolvedUids is made only by resolve_input_uids(), called by a records or lake "
                "reader with the rows it read from its own store"
            )
        frozen = {u: MappingProxyType(dict(e)) for u, e in entries.items()}
        object.__setattr__(self, "_map", MappingProxyType(frozen))
        object.__setattr__(self, "source", source)

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("ResolvedUids is read-only")

    def __getitem__(self, uid: str) -> Mapping[str, str]:
        return self._map[uid]

    def __iter__(self) -> Iterator[str]:
        return iter(self._map)

    def __len__(self) -> int:
        return len(self._map)

    def __repr__(self) -> str:
        return f"ResolvedUids({len(self)} uids from {self.source})"


def resolve_input_uids(rows: Iterable[Mapping[str, Any]], *, source: str) -> ResolvedUids:
    """The :class:`ResolvedUids` of ``rows``, each a stored ``{uid, digest, tlp}`` a records or
    lake reader read from its own store; ``source`` names that reader.  Raises
    :class:`~homelabnext.agent.errors.SpecError` for a malformed row and for a uid or a digest
    paired twice."""
    if not isinstance(source, str) or not source:
        raise SpecError("resolve_input_uids: source names the reader")
    out: dict[str, dict[str, str]] = {}
    owner: dict[str, str] = {}
    for n, row in enumerate(rows):
        where = f"{source} row #{n}"
        if not isinstance(row, Mapping):
            raise SpecError(f"{where}: a row is a mapping")
        uid, digest = row.get("uid"), row.get("digest")
        if not isinstance(uid, str) or not UID.fullmatch(uid):
            raise SpecError(f"{where}: uid must be a canonical record uid (a UUIDv7)")
        if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
            raise SpecError(f"{where}: digest must be sha256:<64 hex>")
        label = str(tlp.read_stored(row.get("tlp")))
        if uid in out and out[uid]["digest"] != digest:
            raise SpecError(f"{where}: uid {uid} is stored with two digests")
        if owner.setdefault(digest, uid) != uid:
            raise SpecError(f"{where}: digest {digest} is stored under two uids")
        prev = out.get(uid, {}).get("tlp")
        if prev is not None:
            label = str(tlp.strictest([prev, label]))
        out[uid] = {"digest": digest, "tlp": label}
    return ResolvedUids(out, source, _SEALED)
