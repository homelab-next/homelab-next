# SPDX-License-Identifier: Apache-2.0
"""Contract for ``codemode-runner``: the handler of ``codemode.execute`` (ADR-0031, CM-5b).

The runner runs one Code Mode program for the agent that asked the broker for it, and every call
the program makes is an ordinary broker request of that agent's, made with the run's capability
token (decision 2 and 6).  The subject is a runner already registered with a broker as
``codemode.execute``'s handler (``broker.register_runner(runner_id, handle)``): the suite asks
the broker, as an agent, to ``call`` ``codemode.execute`` with an execution request
(``schemas/codemode/execution_request``), and judges the execution result the broker hands back,
the broker's own records and the runner's journal.  The rules, one check each:

a. *The result is the schema's.*  ``handle`` returns a ``schemas/codemode/execution_result``:
   the execution id, the enclosing request's actor and the program's code digest
   (:func:`conformance.protocols.broker.code_digest` of its language and code), the status
   (``ok`` with the program's value, ``paused``, ``denied``, ``error``, ``limit``), every broker
   call in step order with the broker's outcome, reason and request ids, and the printed output
   as single lines (``logs``), whatever the program printed.
b. *A denied call is a value.*  A broker refusal reaches the program as ``broker.Denied``
   carrying the broker's reason, which it can catch and go on (the CM-4 program view), and is a
   ``denied`` call in the result with that reason: with its ``request_id`` and
   ``request_digest`` when the broker had built the request, without them for a token refusal
   (``TOKEN_REFUSALS``).  A program that lets a denial escape ends ``denied``.
c. *Every broker call is journalled.*  Each call the broker answered with a request id has a
   ``schemas/codemode/journal_step`` record (``journal(actor, execution_id)``), bound to the
   actor and the code digest, holding the step, the action, the request id and digest and the
   outcome (with the reason when denied or failed, the result when ok); a call refused before
   the broker built a request is not journalled.
d. *A submit pauses the run.*  ``broker.submit`` (and a call whose action needs approval) leaves
   the request pending at the broker and ends the run ``paused``, with ``pending`` naming the
   step, the action, the request id and digest; the program makes no call after it.
e. *A resume does not replay side effects.*  A resume (``resume: true``, the same execution id
   and program) of a paused execution runs the program from the start, answers every journalled
   step from the journal (marked ``replayed``) without sending it to the broker again, runs the
   paused request by its id once it may run (``token_run``; the runner reads ``token_status``
   to decide, never polling ``token_run``), and sends only the calls after it.  A finished
   execution never resumes.
f. *The broker's call cap ends the run.*  A call the broker refuses ``call-cap-reached`` (the
   execution's cap, held by the broker) is a denied call without request ids, and the run ends
   ``limit`` with ``limit: calls`` however the program handled the refusal.

The program's view is the CM-4 executor's (``conformance/protocols/codemode_executor.py``):
``broker.call(action, args)``, ``broker.submit(action, args)``, ``broker.Denied``,
``broker.Error`` and the global ``result``.  The suite registers its commands and grants on the
subject's ``broker`` through the broker contract (``register``, ``allow``), so a target is a
runner over any broker that declares ``codemode-tokens``: the fake broker, or the reference
service in process.  The runner's own transport (an in-process broker, or the broker's socket
as its runner and sandbox peers) is the target's business.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Protocol, runtime_checkable

__all__ = ["CodemodeRunner"]


@runtime_checkable
class CodemodeRunner(Protocol):
    runner_id: str  # the runner identity the broker issues this runner's tokens to
    languages: frozenset[str]  # the program languages its executor runs
    broker: Any  # the broker it is codemode.execute's handler of (Broker + CodemodeTokens)

    def handle(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        """Run one ``codemode.execute`` request, ``{request_id, actor, params}``; returns its
        execution result (``schemas/codemode/execution_result``).  A program's failure, a
        denial and a broker refusal are results, never exceptions."""

    def journal(self, actor: str, execution_id: str) -> Sequence[Mapping[str, Any]]:
        """Every journal record (``schemas/codemode/journal_step``) of ``actor``'s execution,
        in the order they were appended."""
