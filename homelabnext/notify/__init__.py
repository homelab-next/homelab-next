# SPDX-License-Identifier: Apache-2.0
"""One notification interface: state-diffed paging with registered recovery pairs."""

from .core import (
    LEVELS,
    Message,
    Notifier,
    RateLimit,
    Sender,
    SendError,
    UnregisteredProblem,
)
from .senders import FakeSender, NtfySender

__all__ = [
    "LEVELS",
    "FakeSender",
    "Message",
    "Notifier",
    "NtfySender",
    "RateLimit",
    "SendError",
    "Sender",
    "UnregisteredProblem",
]
