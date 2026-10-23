# SPDX-License-Identifier: Apache-2.0
"""Contract for ``records``: the propose -> decide -> complete lifecycle.

Agents can write only into the ``inbox`` lane; only the decision maker moves notes into
``decided/approved|denied|completed``.  A completion request moves every note it names from
approved to completed in one step (all-or-nothing).  A decision is final: ``approve`` and ``deny``
take a note from the inbox only, so a note already approved, denied or completed is refused and
stays where it is.  Subject = :class:`RecordsTarget`, which the
fake builds from ``homelabnext.records`` over a temporary directory.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Protocol, runtime_checkable

__all__ = ["RecordsTarget"]


@runtime_checkable
class RecordsTarget(Protocol):
    def propose(self, note: Mapping[str, Any], body: str = "") -> str:
        """Agent side.  Returns the note name.  Raises ValueError (naming the field) when the
        note is invalid, FileExistsError when the name is taken, PermissionError for a lane
        violation."""

    def completion_request(self, related: Sequence[str], body: str, *, agent: str) -> str: ...

    def list(self, lane: str) -> Sequence[str]: ...

    def read(self, lane: str, name: str) -> tuple[Mapping[str, Any], str]: ...

    # decision-maker side (never given to agents)
    def approve(self, name: str) -> None: ...

    def deny(self, name: str, reason: str | None = None) -> None: ...

    def complete(self, name: str) -> None: ...
