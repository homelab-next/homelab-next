# SPDX-License-Identifier: Apache-2.0
"""Contract for ``broker``: allowlisted commands for named callers, with an audit trail.

Callers never get a shell; they get ``call(caller, command, args)``.  A command exists only if
registered with an argument schema; a caller may run only the commands its allowlist names
(per command: being allowed one command grants nothing else); arguments are validated *before*
the handler runs; every call - allowed, denied, invalid, failed - leaves one audit record;
arguments the schema marks ``secret`` never appear in any audit record, whatever the outcome, nor
in anything ``call`` raises.  Redaction follows the schema's ``secret`` flag, not the argument's
name, and it is the default: an argument the schema does not name (a misspelt name, or any
argument of a command nobody registered) is recorded by name only, its value redacted, because
nothing says it is not a secret - whatever the name looks like - and no error ``call`` or
``submit`` raises (message, attributes, cause) carries its value either.  A handler failure surfaces as ``BrokerError`` naming the command only: the handler's own
exception (message, cause, context) is not passed to the caller.

``ArgSpec`` checks *shape* (presence and type), not *content*.  A value that passed validation is
still untrusted caller input: a ``str`` argument can hold ``../``, ``;``, a newline or a flag.
The handler is the trust boundary - it must treat every argument as hostile (no shell, no string
building of commands or paths without its own allowlist or pattern).

Deferred requests: ``submit(caller, command, args)`` runs the same allowlist and argument checks
as ``call`` and returns a request id instead of running the handler.  Like a call, every submit
leaves one audit record (operation ``submit``), accepted, denied or invalid.  ``submit`` checks
and keeps its own copy of the arguments: changing the mapping it was given afterwards changes
nothing that runs.  Running a request leaves one record of its outcome (operation ``run``).  A
grant cannot be withdrawn (``allow`` only adds), so whether ``run`` re-checks the allowlist is not
part of the contract yet.  A request is bound to the
caller that submitted it: only that caller may ``status`` (read), ``run`` or ``cancel`` it.  Any
other caller gets ``Denied`` with ``reason == "not-request-owner"`` - the same answer as for an id
that does not exist, so a foreign request's existence is not disclosed - the request is left
exactly as it was, and the attempt leaves an audit record (outcome ``denied``, the same reason, the
operation and the request id).  ``status`` returns the request's state (``pending``, ``done``,
``error``, ``cancelled``); ``run`` executes a pending request once; ``cancel`` stops a pending one.

Code Mode capability tokens (feature ``codemode-tokens``, ADR-0031 decisions 2, 6 and 7;
:class:`CodemodeTokens`).  ``codemode.execute`` is a broker action like any other, granted with
``allow`` and admitted by the same checks, whose handler is the *runner*
(``register_runner(runner, handler)``: ``handler`` gets the request, ``{request_id, actor,
params}``, where ``params`` is a ``schemas/codemode/execution_request``).  While that handler runs,
and only then, the runner may ``issue_token(runner, request_id, ...)``: a token for that one run
of that one execution, whose claims (``schemas/codemode/token``) the broker takes from the request
itself - its id, its authenticated actor, the execution id and the code digest
(:func:`code_digest`) - never from the runner.  Only an identity registered as a runner may
issue or spend.  The broker refuses to issue (``Denied``, each with its reason): an action that
``decide`` would not admit for the actor (``token-action-not-admitted``: the token narrows the
actor's grants, never widens them), a ``codemode.*`` action (``token-action-codemode``), more
calls than the broker's cap or the request's own budget (``token-max-calls-exceeded``), a lifetime
past the run's wall budget plus the broker's margin (``token-ttl-exceeded``), a second token for
one request (``request-has-token``), a fresh run of an execution id that already exists
(``execution-exists``), a resume (``params.resume``) of an execution that is unknown, another
actor's, or whose latest token is neither paused nor spent (``execution-not-resumable``, one
answer for all three), a resume with another program (``resume-code-mismatch``) and an actor's
token past its live-token cap (``too-many-live-tokens``).

The sandbox presents the token's ``secret`` (a high-entropy random value the broker keeps only a
digest of; it is in no claim, no audit record and no error) to ``token_call`` and
``token_submit``.  The actor is the token's, never one the caller names.  In order, the broker
refuses with ``Denied`` and an audit record carrying the token and execution ids: a secret it
does not know (``token-invalid``: one answer for an unknown and a wrong secret), a token held by
another sandbox than its own (``token-sandbox-mismatch``, when the caller says which), expired
(``token-expired``), spent (``token-spent``), paused (``token-paused``), an action the token does
not list (``token-action-not-allowed``) and a call past ``max_calls`` (``call-cap-reached``).
Every call that passes those checks counts one towards ``max_calls`` - before ``decide`` runs, so
a call ``decide`` then refuses counts too, and a program cannot probe the allowlist past its cap -
and the count is the broker's, so a program that resets its client gains nothing.  It then takes
the ordinary path for the token's actor: ``decide``, approvals, argument checks, one audit record.
An accepted ``token_submit`` **pauses** the token: the request waits for its owner (an approval,
then ``run``), so the program cannot go on, and every later call on that token is refused
``token-paused``.  ``spend_token`` ends a token (the run finished); a token also ends with its
``codemode.execute``: when the handler returns, a token of that request still live is spent.  A
resume is another ``codemode.execute`` of the same execution id with ``resume: true``, whose
runner is issued a new token, never the old one.

Clock: a target declaring the ``clock-control`` hook offers ``tick(seconds)``, moving the clock
that ``issued_at`` and expiry are judged by.  The feature's checks are the extended suite
``broker-tokens`` (``conformance/suites/broker_tokens.py``), run against the same targets.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

__all__ = [
    "CODEMODE_EXECUTE",
    "TOKEN_REFUSALS",
    "ArgSpec",
    "AuditRecord",
    "Broker",
    "BrokerError",
    "CodemodeTokens",
    "Denied",
    "InvalidArguments",
    "IssuedToken",
    "RequestStatus",
    "arg_problems",
    "code_digest",
]

#: the broker action that runs a program; its handler is the runner (feature ``codemode-tokens``)
CODEMODE_EXECUTE = "codemode.execute"
#: why a token-authenticated call is refused, in the order the broker checks
TOKEN_REFUSALS = (
    "token-invalid",
    "token-sandbox-mismatch",
    "token-expired",
    "token-spent",
    "token-paused",
    "token-action-not-allowed",
    "call-cap-reached",
)


class BrokerError(Exception):
    pass


class Denied(BrokerError):
    """``reason`` is a machine-readable cause, e.g. ``not-request-owner``."""

    def __init__(self, message: str = "", reason: str = "") -> None:
        super().__init__(message)
        self.reason = reason


class InvalidArguments(BrokerError):
    pass


@dataclass(frozen=True)
class ArgSpec:
    type: str  # "str" | "int" | "bool"
    required: bool = True
    secret: bool = False


_ARG_TYPES = {"str": str, "int": int, "bool": bool}


def arg_problems(spec: Mapping[str, ArgSpec], args: Mapping[str, Any]) -> list[str]:
    """Shape problems of ``args`` under ``spec`` (empty = valid): a missing required argument, a
    value of the wrong type (``bool`` is never an ``int``), an argument the spec does not name."""
    problems = []
    for name, a in spec.items():
        if name not in args:
            if a.required:
                problems.append(f"missing {name}")
        elif (isinstance(args[name], bool) and a.type != "bool") or not isinstance(
            args[name], _ARG_TYPES[a.type]
        ):
            problems.append(f"{name}: wrong type")
    return problems + [f"unexpected {k}" for k in args if k not in spec]


@dataclass(frozen=True)
class AuditRecord:
    caller: str
    command: str
    outcome: str  # ok | denied | invalid | error
    args: Mapping[str, Any]  # secret arguments replaced by "<redacted>"
    operation: str = "call"  # call | submit | status | run | cancel
    request_id: str | None = None  # set for operations on a deferred request
    reason: str = ""  # why a denial was denied (e.g. not-request-owner); empty otherwise
    token_id: str | None = None  # codemode-tokens: the token a call was made with
    execution_id: str | None = None  # codemode-tokens: the execution that token belongs to


@dataclass(frozen=True)
class RequestStatus:
    request_id: str
    caller: str  # the owner: the caller that submitted it
    command: str
    state: str  # pending | done | error | cancelled


def code_digest(language: str, code: str) -> str:
    """``sha256:<hex>`` of the canonical JSON of ``{language, code}`` (``schemas/codemode``)."""
    import hashlib
    import json

    text = json.dumps(
        {"language": language, "code": code},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class IssuedToken:
    """A token as the runner receives it: ``secret`` is what the sandbox presents (the broker
    keeps only its digest), ``claims`` the token's claims (``schemas/codemode/token``)."""

    secret: str
    claims: Mapping[str, Any]


@runtime_checkable
class Broker(Protocol):
    def register(
        self,
        command: str,
        handler: Callable[..., Any],
        args: Mapping[str, ArgSpec],
    ) -> None: ...

    def allow(self, caller: str, commands: Sequence[str]) -> None: ...

    def call(self, caller: str, command: str, args: Mapping[str, Any]) -> Any:
        """Raises Denied / InvalidArguments; a handler exception becomes BrokerError."""

    def submit(self, caller: str, command: str, args: Mapping[str, Any]) -> str:
        """Check like ``call`` but defer running; returns the new request's id."""

    def status(self, caller: str, request_id: str) -> RequestStatus:
        """The owner's view of its request; anyone else: Denied(reason="not-request-owner")."""

    def run(self, caller: str, request_id: str) -> Any:
        """Run the owner's pending request once; same errors as ``call`` plus ownership."""

    def cancel(self, caller: str, request_id: str) -> None:
        """Cancel the owner's pending request; anyone else: Denied, request unchanged."""

    def audit(self) -> Sequence[AuditRecord]: ...


@runtime_checkable
class CodemodeTokens(Protocol):
    """Feature ``codemode-tokens``: capability tokens issued, held and enforced by the broker
    (see the module doc).  Every refusal is ``Denied`` with its ``reason``."""

    def register_runner(self, runner: str, handler: Callable[[Mapping[str, Any]], Any]) -> None:
        """``handler`` runs ``codemode.execute``; ``runner`` is the identity that issues and
        spends its tokens."""

    def issue_token(
        self,
        runner: str,
        request_id: str,
        *,
        sandbox_id: str,
        actions: Sequence[str],
        max_calls: int | None = None,
        ttl_s: int | None = None,
    ) -> IssuedToken:
        """A token for the ``codemode.execute`` request ``request_id`` while its handler runs;
        absent ``max_calls`` and ``ttl_s`` take the request's budget within the broker's caps."""

    def token_call(
        self, token: str, command: str, args: Mapping[str, Any], *, sandbox_id: str | None = None
    ) -> Any:
        """``call`` as the token's actor, after the token checks; counts towards the cap."""

    def token_submit(
        self, token: str, command: str, args: Mapping[str, Any], *, sandbox_id: str | None = None
    ) -> str:
        """``submit`` as the token's actor, after the token checks; an accepted one pauses it."""

    def spend_token(self, runner: str, token_id: str) -> None:
        """End the token: every later call on it is refused ``token-spent``."""
