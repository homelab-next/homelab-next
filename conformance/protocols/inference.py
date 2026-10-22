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

Errors are :class:`InferenceError` with ``.status`` set for HTTP errors (and ``.detail``, the
server's own message).  The target config says
which model to probe (``model``); by default the first model ``models()`` lists.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from typing import Protocol, runtime_checkable

from homelabnext.conform.adapters.openai_compat import ChatResult, InferenceError

__all__ = ["ChatResult", "GatewayClient", "InferenceClient", "InferenceError"]


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
