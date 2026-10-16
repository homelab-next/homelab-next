# SPDX-License-Identifier: Apache-2.0
"""Contract for ``inference``: an OpenAI-compatible chat/embeddings endpoint.

Subject = :class:`homelabnext.conform.adapters.openai_compat.OpenAICompat`-shaped client:

    models() -> list[str]
    chat(model, messages, *, max_tokens, temperature) -> ChatResult
    chat_stream(model, messages, *, max_tokens) -> Iterator[str]     feature ``streaming``
    embed(model, texts) -> list[list[float]]                         feature ``embeddings``

Errors are :class:`InferenceError` with ``.status`` set for HTTP errors.  The target config says
which model to probe (``model``); by default the first model ``models()`` lists.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from typing import Protocol, runtime_checkable

from homelabnext.conform.adapters.openai_compat import ChatResult, InferenceError

__all__ = ["ChatResult", "InferenceClient", "InferenceError"]


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
