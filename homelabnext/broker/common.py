# SPDX-License-Identifier: Apache-2.0
"""What the broker service's parts share: its refusal reasons, defaults, the audit context
(:data:`TRANSPORT_PEER`, the token being used) and the small error helpers.

The service is :class:`homelabnext.broker.service.BrokerService`; its parts are mixins it is built
from, one per privilege boundary (:mod:`.requests`, :mod:`.approvals`, :mod:`.paging`,
:mod:`.codemode_tokens`).  Every name here is re-exported by :mod:`homelabnext.broker.service`."""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping, Sequence
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from conformance.protocols.broker import (
    ArgSpec,
    BrokerError,
    Denied,
    InvalidArguments,
)
from homelabnext.notify.core_pairs import BROKER_APPROVAL, BROKER_LANE_QUOTA

from .state import (
    StateError,
)

NOT_OWNER = "not-request-owner"
TOO_MANY_PENDING = "too-many-pending"
#: an actor had ``quotas.calls_per_minute`` operations admitted in the last 60 s (manifest 1.9)
CALL_RATE_EXCEEDED = "call-rate-exceeded"
#: an action was not run because its ``started`` record could not be written
AUDIT_UNAVAILABLE = "audit-unavailable"
#: an action ran and its outcome record could not be written (its ``started`` record stands)
AUDIT_INCOMPLETE = "audit-incomplete"
#: what writing an audit record can raise when the trail cannot take it
_AUDIT_FAILURES = (OSError, StateError, BrokerError)
log = logging.getLogger("homelabnext.broker.service")
#: manifest ``quotas`` defaults: requests one actor may have pending at once, and the least time
#: between two of its approval pages (s)
DEFAULT_PENDING_PER_ACTOR = 20
DEFAULT_NOTIFY_WINDOW_S = 300.0
#: manifest 1.9 ``quotas.calls_per_minute`` default, and the window it counts over (s)
DEFAULT_CALLS_PER_MINUTE = 60
CALL_RATE_WINDOW_S = 60.0
#: manifest 1.9 ``retention`` defaults (days): a finished run's directory, an audit record
DEFAULT_RUNS_RETENTION_DAYS = 30
DEFAULT_AUDIT_RETENTION_DAYS = 400
#: the least time between two retention prunes in one process (s)
RETENTION_PRUNE_INTERVAL_S = 3600.0
#: request ids an approval page names before it says "and N more"
_PAGE_IDS = 10
#: how long after a page that could not be sent (a failed send, a spent budget) it is tried again
PAGE_RETRY_S = 60.0
#: the least time between two log lines about failed notifications (s)
NOTIFY_WARN_EVERY_S = 300.0
CALLABLE_HANDLER = "builtin/callable"
EMPTY_MANIFEST = {
    "manifest_id": "in-process",
    "default": "deny",
    "mode": "enforce",
    "actions": [],
    "grants": [],
}
APPROVAL_TITLE, APPROVAL_CLEARED = BROKER_APPROVAL
#: decide()'s reason for a request's latest approval -> the approval_state pending() reports
_APPROVAL_STATES = {
    "approved": "valid",
    "approval-expired": "expired",
    "approval-replayed": "consumed",
    "approval-denied": "denied",
}
#: the operator's notice that an agent's writes into a lane are being refused for its quota
LANE_QUOTA_TITLE, LANE_QUOTA_CLEARED = BROKER_LANE_QUOTA
#: the least time between two lane-quota notices for one actor and lane (s)
LANE_NOTICE_INTERVAL_S = 900.0
_SUMMARY_BYTES = 1024
_SVC_RE = re.compile(r"^svc:[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
#: manifest 1.7 ``codemode`` defaults: the most calls a token may carry, the seconds a token may
#: outlive its run's wall budget, the wall budget of a request that names none, and how many
#: live tokens one actor may hold at once
DEFAULT_CODEMODE_MAX_CALLS = 50
DEFAULT_TOKEN_TTL_MARGIN_S = 10
DEFAULT_CODEMODE_WALL_S = 60
DEFAULT_LIVE_TOKENS_PER_ACTOR = 4
#: how long the tokens of an ended execution are kept, and how often the sweep runs at most
DEFAULT_TOKEN_RETENTION_DAYS = 7
TOKEN_SWEEP_INTERVAL_S = 60.0
#: how a runner may end a token (``spend_token``)
SPEND_OUTCOMES = ("finished", "paused")
NOT_A_RUNNER = "not-a-codemode-runner"
#: refused unknown secrets are audited once per transport peer and this many seconds
COALESCE_WINDOW_S = 60.0
#: token_run of a paused request an approver denied: the request was decided, so the refusal
#: names it (request_id, request_digest), unlike the token refusals
REQUEST_DENIED = "request-denied"
#: the in-process handler kind of ``codemode.execute`` (:meth:`BrokerService.register_runner`)
RUNNER_HANDLER = "builtin/codemode-runner"
#: the caller of a token-authenticated call whose secret names no token
UNKNOWN_TOKEN_CALLER = "token:unknown"
#: the token a call is being made with: every audit record written meanwhile names it
_TOKEN: ContextVar[Mapping[str, Any] | None] = ContextVar("hnx_broker_token", default=None)
#: the authenticated transport peer (``uid:<n>``) of the request being served on this thread, set
#: by :mod:`homelabnext.broker.server`; every audit record written meanwhile carries it as ``via``
TRANSPORT_PEER: ContextVar[str | None] = ContextVar("hnx_broker_transport_peer", default=None)


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _stamp(t: datetime) -> str:
    return t.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class ManifestError(ValueError):
    """The manifest, a handler document or a lane is not usable; ``problems`` lists each."""

    def __init__(self, problems: Sequence[str]) -> None:
        self.problems = list(problems)
        super().__init__("broker manifest invalid:\n  - " + "\n  - ".join(self.problems))


class _Refused(Exception):
    """Internal: a refusal to audit and turn into the contract's exception."""

    def __init__(self, outcome: str, reason: str, message: str) -> None:
        super().__init__(message)
        self.outcome, self.reason = outcome, reason


def _reasoned(message: str, reason: str) -> BrokerError:
    err = BrokerError(message)
    err.reason = reason  # type: ignore[attr-defined]
    return err


def _carry(err: BrokerError, request: Mapping[str, Any]) -> BrokerError:
    """``err`` naming the request it refuses (``request_id``, ``request_digest``): a refusal
    after the request was built says which one, as an answer does."""
    err.request_id = request["request_id"]  # type: ignore[attr-defined]
    err.request_digest = request["digest"]  # type: ignore[attr-defined]
    return err


def _reasoned_invalid(message: str, reason: str) -> InvalidArguments:
    err = InvalidArguments(message)
    err.reason = reason  # type: ignore[attr-defined]
    return err


def _contract_error(exc: _Refused) -> BrokerError:
    if exc.outcome == "denied":
        return Denied(str(exc), reason=exc.reason)
    err: BrokerError = (
        InvalidArguments(str(exc)) if exc.outcome == "invalid" else BrokerError(str(exc))
    )
    err.reason = exc.reason  # type: ignore[attr-defined]
    return err


@dataclass(frozen=True)
class _Action:
    name: str
    kind: str  # callable | exec | lane
    handler: Any = None  # callable, handler document, or Lane
    spec: Mapping[str, ArgSpec] | None = None


def _hidden(spec: Mapping[str, ArgSpec], name: str) -> bool:
    """Whether an argument's value is kept out of the audit trail and keyed in the request digest:
    redaction is the default, so everything but an argument the schema names and does not mark
    secret."""
    return name not in spec or spec[name].secret
