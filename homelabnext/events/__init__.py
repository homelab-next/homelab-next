# SPDX-License-Identifier: Apache-2.0
"""Event envelope, validation and an idempotent publisher.

Publishers never speak the event bus directly: they hand a CloudEvents-shaped envelope to a
*forwarder* over HTTP.  The envelope ``id`` is the idempotency key end to end, so a retry after a
lost acknowledgement is accepted once.
"""

from .consumer import Consumer, Delivery, decode_event
from .envelope import (
    EventError,
    build_event,
    derive_event_id,
    event_problems,
    schema_for_type,
    validate_event,
)
from .forwarder import (
    Ack,
    FakeForwarder,
    FakeForwarderServer,
    Forwarder,
    HttpForwarder,
    PermanentError,
    TransientError,
)
from .publisher import Publisher, PublishResult, RetryPolicy

__all__ = [
    "Ack",
    "Consumer",
    "Delivery",
    "EventError",
    "FakeForwarder",
    "FakeForwarderServer",
    "Forwarder",
    "HttpForwarder",
    "PermanentError",
    "PublishResult",
    "Publisher",
    "RetryPolicy",
    "TransientError",
    "build_event",
    "decode_event",
    "derive_event_id",
    "event_problems",
    "schema_for_type",
    "validate_event",
]
