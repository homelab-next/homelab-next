# SPDX-License-Identifier: Apache-2.0
"""Contract for ``agent-runner``, the ``agent-runtime`` slot (ADR-0051, version 1.0).

The contract is a process contract (decision 1). A provider ships one **runner body**. A
**launcher** starts the body once per attempt and hands it these inputs:
- the run's inputs as files under ``$CREDENTIALS_DIRECTORY``;
- an output directory, ``$HNX_RUN_DIR``;
- the deploy-rendered grants file, ``$HNX_GRANTS_FILE``, pinned by ``$HNX_GRANTS_SHA256``;
- the gateway the deploy pins, ``$HNX_GATEWAY_URL``: the spec's ``target.gateway_url`` must be
  exactly it, or the body makes no call and the session ends ``Internal``.

The body appends one **usage stream** to ``$HNX_RUN_DIR/usage.jsonl``, writes its answer to
``$HNX_RUN_DIR/answer``, and exits. The launcher then decides the attempt's failure class from
how the body ended, the stream and the gateway's own records (decisions 6 and 10).

The subject is a launcher with its body (``start``/``wait``/``cancel``): the suite plays the
controller, the deploy and the world. It builds:
- the session spec (``schemas/runner/session``);
- the run's inputs (``prompt``, ``gateway-key``, ``run-token-gateway``, ``run-token-broker``);
- the grants file and its pin (``schemas/runner/grants``);
- a fake gateway and fake MCP servers.

The subject is always a launcher with a body. A provider's target supplies only its body's argv
and its ``exit_classes`` and runs under the reference launcher (later the controller's
``runner/agent``); a launcher is certified by its own target. ``start`` also takes a suite body
in place of the provider's, so the launcher's own rules (exit statuses, stream bounds, what
reaches the body) are checked on every target, whatever the provider's runtime does. The rules, one or more checks each:

a. *A session answers.* The answer and a valid stream ending in an ``end`` record come back, and
   a clean exit is no class (``None``).
b. *Every model call is a record, sized when the gateway sized it.* ``unsized`` is reported,
   never left out.
c. *Cancel ends the whole session*, every descendant included, a ``setsid`` one too, as
   ``KilledByController``.
d. *No progress is a stall.* ``progress`` liveness counts gateway-corroborated ``call`` records,
   and falls back to ``cpu`` while the gateway's records lag or it dropped some.
e. *Classes come from typed signals.*
   - ``TurnCap`` comes from the ``end`` record.
   - Exit statuses map through the provider's ``exit_classes``; an unmapped one is ``Internal``.
   - A connection refused by the gateway is ``BackendFault``.
   - A self-reported ``ContextExceeded`` needs a gateway record (``error_code``
     ``upstream_rejected``, status 400) later than every successful call of the run, within the
     gateway wait. ``ConcurrencyLimited`` is never corroborated.
   - ``BudgetExhausted`` needs a gateway refusal ``run_budget_exhausted``.
f. *Per-run credential.* Every model call carries the run's profile key and nothing of the run's
   inputs is left after it.
g. *Trace and tag.* Every model call carries the run's ``traceparent`` trace id and
   ``X-HNX-Tag``. ``_meta.traceparent`` goes only to MCP servers whose locality is ``local``.
h. *Tool calls are records*, by server id and tool name, never with arguments.
i. *Servers come from the grants file.* An id it does not list, a command in the spec or a
   grants file that does not match its pin starts nothing.
j. *The stream is bounded.*
   - Past ``max_usage_bytes`` while running is ``ResourceLimit``.
   - A line over 16 KiB, nesting past 8, or a record that does not validate is ``Internal``.
k. *The spec, argv and environment carry no secret.*
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

__all__ = [
    "CLASSES",
    "CONTRACT_VERSION",
    "INPUT_NAMES",
    "AgentRunner",
    "GatewayView",
    "Outcome",
    "RunInputs",
]

CONTRACT_VERSION = "1.0"
#: the seam's failure classes a run can end with (``None`` is success)
CLASSES = (
    "BackendFault",
    "ContextExceeded",
    "ToolCallParse",
    "Stalled",
    "TimeoutCeiling",
    "TurnCap",
    "TurnFailed",
    "KilledByController",
    "KilledExternally",
    "ConcurrencyLimited",
    "BudgetExhausted",
    "ResourceLimit",
    "Internal",
)
#: the credential names a run's inputs use, under both launchers (ADR-0051 decision 8)
INPUT_NAMES = ("spec", "prompt", "gateway-key", "run-token-gateway", "run-token-broker")


@dataclass(frozen=True)
class RunInputs:
    """One attempt's inputs, as the controller and the deploy would make them."""

    spec: Mapping[str, Any]
    #: credential name -> bytes (``prompt``, ``gateway-key``, the run tokens); never in the spec
    inputs: Mapping[str, bytes]
    #: the grants file's exact bytes and the pin the deploy puts in the template
    grants: bytes
    grants_sha256: str
    #: the gateway the deploy pins in the template (``$HNX_GATEWAY_URL``): the only place a body
    #: sends the run's key, tokens and prompt; a spec naming another is refused (ADR-0051
    #: decision 2)
    gateway_url: str = ""


@dataclass(frozen=True)
class Outcome:
    """How an attempt ended, as the launcher decided it."""

    cls: str | None  # one of CLASSES, None for a successful session
    answer: str | None
    records: list[dict[str, Any]] = field(default_factory=list)
    exit_code: int | None = None
    detail: str = ""


class GatewayView(Protocol):
    """What the launcher may read of the gateway's own usage records (ADR-0047 decision 8)."""

    def records(self, tag: str) -> list[dict[str, Any]]: ...

    def dropped(self) -> int: ...

    def watermark(self) -> float: ...


@runtime_checkable
class AgentRunner(Protocol):
    features: frozenset[str]
    #: the provider manifest's exit statuses -> class
    exit_classes: Mapping[int, str]

    def start(
        self,
        run: RunInputs,
        gateway: GatewayView,
        *,
        body: Sequence[str] | None = None,
    ) -> Any: ...

    def wait(self, handle: Any, timeout_s: float) -> Outcome: ...

    def cancel(self, handle: Any) -> None: ...

    def leftovers(self, handle: Any) -> list[str]: ...
