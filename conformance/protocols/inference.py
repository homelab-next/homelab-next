# SPDX-License-Identifier: Apache-2.0
"""Contract for ``inference``: an OpenAI-compatible chat/embeddings endpoint.

Subject = :class:`homelabnext.conform.adapters.openai_compat.OpenAICompat`-shaped client:

    models() -> list[str]
    chat(model, messages, *, max_tokens, temperature) -> ChatResult
    chat_stream(model, messages, *, max_tokens) -> Iterator[str]     feature ``streaming``
    embed(model, texts) -> list[list[float]]                         feature ``embeddings``

A model *gateway* in front of the backends (LiteLLM, Bifrost; docs/llm-gateway.md) declares the
feature ``gateway`` and adds :class:`GatewayClient`'s three methods, so the suite can prove what
the gateway is for: a bad key is a clean 401, a configured limit is a 429, and ``/v1/models`` is
exactly the declared role aliases.

A gateway that keeps a per-call log declares the feature ``turn-records`` as well: it offers a
:class:`TurnSource`, ``turns(start, end, tags)``, that yields the calls (*turns*) started in a
window and tagged with one of ``tags``, each reduced to the neutral turn record
(:data:`TURN_FIELDS`, checked by :func:`turn_problems`).  How a product logs a call, and how it
receives the tag, is its adapter's business; orchestration telemetry
(``docs/orchestration-telemetry.md``) reads only this record.  The subject's
:meth:`TurnRecordsGateway.turn_records` names a window and tags known to hold turns, so the
suite can check them.

Errors are :class:`InferenceError` with ``.status`` set for HTTP errors (and ``.detail``, the
server's own message).  The target config says
which model to probe (``model``); by default the first model ``models()`` lists.
"""

from __future__ import annotations

import math
import re
from collections.abc import Collection, Iterable, Iterator, Mapping, Sequence
from typing import Any, Protocol, runtime_checkable

from homelabnext.conform.adapters.openai_compat import ChatResult, InferenceError
from homelabnext.status.model import parse_iso

__all__ = [
    "TURN_FIELDS",
    "ChatResult",
    "GatewayClient",
    "InferenceClient",
    "InferenceError",
    "TurnRecordsGateway",
    "TurnSource",
    "TurnSourceError",
    "is_name",
    "turn_problems",
]


@runtime_checkable
class InferenceClient(Protocol):
    def models(self) -> list[str]: ...

    def chat(
        self,
        model: str,
        messages: Sequence[dict[str, str]],
        *,
        max_tokens: int = 64,
        temperature: float = 0.0,
    ) -> ChatResult: ...

    def chat_stream(
        self, model: str, messages: Sequence[dict[str, str]], *, max_tokens: int = 64
    ) -> Iterator[str]: ...

    def embed(self, model: str, texts: Sequence[str]) -> list[list[float]]: ...


@runtime_checkable
class GatewayClient(InferenceClient, Protocol):
    """Feature ``gateway``: an inference endpoint that is a gateway with keys and limits."""

    def declared_models(self) -> list[str]:
        """The model names the gateway is configured to serve (the role aliases)."""
        ...

    def with_key(self, token: str | None) -> InferenceClient:
        """The same endpoint called with ``token`` as the bearer key (``None``: no key at all)."""
        ...

    def throttled(self) -> tuple[InferenceClient, str, int]:
        """``(client, model, n)``: calls by ``client`` to ``model`` are limited to ``n`` per window."""
        ...


# --- feature ``turn-records``: a gateway's per-call log as neutral turn records ----------------
#: the neutral turn record, every key always present (``None`` = not reported, never 0):
#:
#: * ``turn_id`` -- the gateway's id of the call (stable: reading a window twice gives the same id)
#: * ``gateway_tag`` -- which of the asked tags the call carried
#: * ``started_at`` -- when the call started, ISO 8601 UTC (``...Z``)
#: * ``duration_ms``, ``ttft_ms`` -- the call's duration and time to its first token
#: * ``model_role`` -- the role alias the caller asked for (ADR-0007), ``model`` -- what served it
#: * ``call_type`` -- the gateway's own name for the kind of call: opaque, per provider, for
#:   display and grouping only (no consumer may branch on its values)
#: * ``status`` -- ``success`` | ``failure``; ``error_code`` -- the HTTP status of a failure
#: * ``input_tokens``, ``output_tokens``, ``cache_read_tokens``, ``cache_hit``, ``cost_usd``
#:
#: Names and numbers only: never a prompt, an answer, a key, a user or a client address.
TURN_FIELDS = (
    "turn_id", "gateway_tag", "started_at", "duration_ms", "ttft_ms", "model_role", "model",
    "call_type", "status", "error_code", "input_tokens", "output_tokens", "cache_read_tokens",
    "cache_hit", "cost_usd",
)  # fmt: skip
#: used with ``fullmatch`` only (a ``$`` would let a trailing newline through)
TURN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
#: what no name holds although its characters allow it, as lookaheads (used in both patterns
#: below, and in ``agent.job.finished``'s ``model``): a URL (a scheme, ``:/``, as in
#: ``https://`` or ``https:/x``), an IPv4 address, a ``host:port/``, or a mail address (``@``
#: then a dotted domain whose last label is letters: ``alice@example.com``).  An ``@`` before
#: a version (``model@v1.2``, ``claude-sonnet@vertex.v2``, ``...-v2@20241022``) is a name, and so
#: is ``alice@corp``: a single label after ``@`` is indistinguishable from a deployment-qualified
#: alias (``sonnet@vertex``), so it is accepted.  Whitespace and control characters are outside
#: both character sets.  A pattern can never refuse every disguise; this refuses the shapes a
#: careless source would emit
NOT_URL_OR_ADDRESS = (
    r"(?!.*:/)"
    r"(?!(?:.*[^0-9])?[0-9]{1,3}(?:\.[0-9]{1,3}){3}(?![0-9]))"
    r"(?!.*:[0-9]{2,5}/)"
    r"(?!.*@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?![A-Za-z0-9._-]))"
)
#: ``model``, what served the call: up to 256 characters; a leading ``/`` (a vLLM model path)
#: and ``//`` (a provider prefix before a path: ``hosted_vllm//models/x``) are allowed, ``@``
#: carries a version, ``:`` a tag (``ollama:llama3``) or an ARN's parts
MODEL_PATTERN = NOT_URL_OR_ADDRESS + r"[A-Za-z0-9/][A-Za-z0-9._:/@+-]{0,255}"
#: ``model_role`` and ``call_type``, an alias or a kind of call: up to 128 characters, starting
#: with a letter or a digit, never ``//``
LABEL_PATTERN = NOT_URL_OR_ADDRESS + r"(?!.*//)[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}"
_NAME_RULES = {
    "model": re.compile(MODEL_PATTERN),
    "model_role": re.compile(LABEL_PATTERN),
    "call_type": re.compile(LABEL_PATTERN),
}


def is_name(key: str, value: Any) -> bool:
    """Whether ``value`` may stand in the turn record's name field ``key`` (``model``,
    ``model_role`` or ``call_type``): the one rule the record and every adapter use, so an
    adapter maps a value the record would refuse to null instead of emitting it."""
    rule = _NAME_RULES.get(key)
    return rule is not None and isinstance(value, str) and rule.fullmatch(value) is not None


ERROR_CODE = re.compile(r"[0-9]{3}")
#: a gateway tag: the pattern of ``agent.job.finished``'s ``gateway_tag`` (never a comma)
TAG = re.compile(r"[A-Za-z0-9._:/-]{0,64}[A-Za-z0-9._:-]{1,128}")
_COUNTS = ("duration_ms", "ttft_ms", "input_tokens", "output_tokens", "cache_read_tokens")
_NAMES = ("model_role", "model", "call_type")


class TurnSourceError(RuntimeError):
    """The turn source could not be read (configuration, transport, refusal, shape)."""


@runtime_checkable
class TurnSource(Protocol):
    def turns(self, start: float, end: float, tags: Collection[str]) -> Iterable[Mapping[str, Any]]:
        """The calls started in ``[start, end]`` (epoch seconds, whole seconds suffice) that carry
        one of ``tags``, as neutral turn records (:data:`TURN_FIELDS`); raises
        :class:`TurnSourceError` when the log cannot be read."""
        ...


@runtime_checkable
class TurnRecordsGateway(Protocol):
    """Feature ``turn-records``: the gateway's per-call log as a :class:`TurnSource`."""

    def turn_records(self) -> tuple[TurnSource, float, float, list[str]]:
        """``(source, start, end, tags)``: a window and tags known to hold at least one turn."""
        ...


def _count(v: Any) -> bool:
    return v is None or (isinstance(v, int) and not isinstance(v, bool) and v >= 0)


def turn_problems(turn: Any) -> list[str]:
    """Why ``turn`` is not a neutral turn record (empty when it is): exactly :data:`TURN_FIELDS`,
    each value of its kind.  A consumer refuses a record with problems, so no source can widen
    what is stored."""
    if not isinstance(turn, Mapping):
        return [f"a turn is an object, not {type(turn).__name__}"]
    probs = []
    extra, missing = sorted(set(turn) - set(TURN_FIELDS)), sorted(set(TURN_FIELDS) - set(turn))
    if extra:
        probs.append(f"fields outside the turn record: {', '.join(map(str, extra))[:200]}")
    if missing:
        probs.append(f"missing fields: {', '.join(missing)}")
    tid, tag, start = turn.get("turn_id"), turn.get("gateway_tag"), turn.get("started_at")
    if not (isinstance(tid, str) and TURN_ID.fullmatch(tid)):
        probs.append("turn_id is not an id")
    if not (isinstance(tag, str) and TAG.fullmatch(tag)):
        probs.append("gateway_tag is not a tag")
    try:
        ok = isinstance(start, str) and start.endswith("Z") and parse_iso(start) is not None
    except (ValueError, OverflowError):
        ok = False
    if not ok:
        probs.append("started_at is not an ISO 8601 UTC time")
    probs += [f"{k} is not a count" for k in _COUNTS if not _count(turn.get(k))]
    probs += [
        f"{k} is not a name" for k in _NAMES if turn.get(k) is not None and not is_name(k, turn[k])
    ]
    if turn.get("status") not in (None, "success", "failure"):
        probs.append("status is not success, failure or null")
    code = turn.get("error_code")
    if code is not None and not (isinstance(code, str) and ERROR_CODE.fullmatch(code)):
        probs.append("error_code is not a three-digit status")
    if turn.get("cache_hit") not in (None, True, False):
        probs.append("cache_hit is not a boolean or null")
    cost = turn.get("cost_usd")
    if cost is not None and not (
        isinstance(cost, int | float)
        and not isinstance(cost, bool)
        and math.isfinite(cost)
        and cost >= 0
    ):
        probs.append("cost_usd is not a non-negative number")
    return probs
