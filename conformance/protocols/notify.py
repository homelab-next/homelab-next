# SPDX-License-Identifier: Apache-2.0
"""Contract for ``notify``: a ``homelabnext.notify.Sender`` plus a way to see what arrived.

The thing proved is the *delivery channel* (ntfy today, anything tomorrow): a ``Sender`` that
delivers each message exactly once, faithfully, and raises ``SendError`` when it cannot.  The
suite then drives the state-diffed ``Notifier`` over that sender, so the paging rules (one page
per state change, one recovery) are proved on the replacement too.

Subject attributes:

``sender``      the ``Sender`` under test
``received()``  messages that reached the far side, in order (a fake lists them; a real adapter
                reads them back from a scratch topic)
``fail_next(n)``  optional feature ``fault-injection``: make the next ``n`` sends fail
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol, runtime_checkable

from homelabnext.notify import Message, Sender, SendError

__all__ = ["Message", "NotifyTarget", "SendError", "Sender"]


@runtime_checkable
class NotifyTarget(Protocol):
    sender: Sender

    def received(self) -> Sequence[Message]: ...
