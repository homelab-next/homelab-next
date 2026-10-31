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

A gateway whose keys are scoped by TLP ceiling (ADR-0033 decisions 10 and 11) declares the feature
``tlp-ceiling`` and adds :meth:`TlpCeilingGateway.over_ceiling`: a key whose sending profile's TLP
ceiling is above the ceiling of a role whose prompts leave the lab is refused that role (a 401 or
403 on the chat, never a reply) while it is still served on a role it may call.  The per-request
half of the rule (a request's own label) is the caller's (:func:`homelabnext.registry.model_tlp.admit`):
a gateway with no admission code of its own cannot read it.

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
    "TlpCeilingGateway",
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


@runtime_checkable
class TlpCeilingGateway(GatewayClient, Protocol):
    """Feature ``tlp-ceiling``: the gateway scopes no key to a role whose TLP ceiling is below
    the key's sending ceiling (ADR-0033 decision 11)."""

    def over_ceiling(self) -> tuple[InferenceClient, str, str]:
        """``(client, refused, served)``: ``client`` is a key whose sending TLP ceiling is above
        the ceiling of role ``refused`` (one whose prompts leave the lab), and that may call role
        ``served``."""
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
#: below, and in ``agent.job.finished``'s ``model``): a URL (a scheme, ``:/`` after two or more
#: characters, as in ``https://`` or ``https:/x``; a drive letter, ``C:/models/x``, is a path),
#: an IPv4 address as a token of its own (a dotted quad alone, after ``x:`` or between ``/``;
#: never a four-part version such as ``v1.0.0.1``), a ``host:port/``, or a mail address (``@``
#: then a dotted domain whose last label is letters, a trailing dot or ``_`` in a label
#: included: ``alice@example.com``, ``bob@example.com.``).  An ``@`` before a version
#: (``model@v1.2``, ``claude-sonnet@vertex.v2``, ``...-v2@20241022``) is a name, and so is
#: ``alice@corp``: a single label after ``@`` is indistinguishable from a deployment-qualified
#: alias (``sonnet@vertex``), so it is accepted.  Whitespace, control characters and ``+`` (the
#: separator of ``+``-joined prose and ``user+tag@`` addresses; no model, alias or call type uses
#: it) are outside both character sets.
#:
#: The residual is an identifier-shaped channel: words joined by ``_``, ``.``, ``-`` or ``/``
#: (``the_prompt_was_...``) pass, as they do in ``run_id``, ``gateway_tag`` and ``tools[].name``,
#: since refusing them would refuse real names (``together_ai``, ``Q4_K_M``, dotted versions).
#: The rule stops a careless source (prose with spaces, URLs, addresses), not a hostile one; the
#: producers are the pinned controller and the operator's gateway.  A controller whose model
#: value fails :data:`MODEL_PATTERN` sends ``model: null`` (the record stays, the name is
#: unknown), as an adapter maps such a turn name to null
NOT_URL_OR_ADDRESS = (
    r"(?!.{2,}:/)"
    r"(?!(?:.*[:/@])?[0-9]{1,3}(?:\.[0-9]{1,3}){3}(?:[:/]|$))"
    r"(?!.*:[0-9]{2,5}/)"
    r"(?!.*@(?:[A-Za-z0-9_-]+\.)+[A-Za-z]{2,}\.?(?![A-Za-z0-9.]))"
)
#: the longest ``model``: a served model's path or a cloud ARN can be long
MODEL_MAX = 512
#: ``model``, what served the call: up to :data:`MODEL_MAX` characters; a leading ``/`` (a vLLM
#: model path), ``./`` (llama-server's ``-m ./models/x.gguf``, never ``..``) or a drive letter,
#: and ``//`` (a provider prefix before a path: ``hosted_vllm//models/x``) are allowed, ``@``
#: carries a version, ``:`` a tag (``ollama:llama3``) or an ARN's parts
MODEL_PATTERN = NOT_URL_OR_ADDRESS + rf"(?!\.\.)[A-Za-z0-9/.][A-Za-z0-9._:/@-]{{0,{MODEL_MAX - 1}}}"
#: ``model_role`` and ``call_type``, an alias or a kind of call: up to 128 characters, starting
#: with a letter or a digit, never ``//``
LABEL_PATTERN = NOT_URL_OR_ADDRESS + r"(?!.*//)[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}"
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
