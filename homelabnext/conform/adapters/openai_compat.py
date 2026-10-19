# SPDX-License-Identifier: Apache-2.0
"""A small stdlib client for OpenAI-compatible servers (the ``inference`` contract).

``OpenAICompat(base_url)`` implements :class:`conformance.protocols.inference.InferenceClient`.
The base URL is always supplied by the caller (a fake's ``.url``, or an endpoint the registry
resolver produced); there is no default.  An optional ``auth`` callable returns an
``Authorization`` header value at request time so a secret is never held in the object.  With
``auth`` set, plain ``http`` to a non-loopback host is refused unless ``allow_plaintext=True``;
redirects are followed only within the same origin; replies are read up to ``max_bytes``.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from typing import Any

from homelabnext._http import (
    DEFAULT_MAX_BYTES,
    ResponseTooLarge,
    check_plaintext,
    read_bounded,
    safe_urlopen,
)

__all__ = ["ChatResult", "InferenceError", "OpenAICompat"]


class InferenceError(Exception):
    """The server answered with an error or something that is not an OpenAI-shaped reply."""

    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class ChatResult:
    content: str
    finish_reason: str
    model: str
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    total_tokens: int | None = None


class OpenAICompat:
    def __init__(
        self,
        base_url: str,
        *,
        auth: Callable[[], str | None] | None = None,
        timeout: float = 10.0,
        features: Sequence[str] = ("embeddings", "streaming"),
        allow_plaintext: bool = False,
        max_bytes: int = 16 * DEFAULT_MAX_BYTES,
    ):
        if not base_url.startswith(("http://", "https://")):
            raise ValueError("base_url must be an http(s) URL supplied by the caller")
        check_plaintext(base_url, credentials=auth is not None, allow_plaintext=allow_plaintext)
        self.max_bytes = max_bytes
        self._base = base_url.rstrip("/")
        self._auth = auth
        self._timeout = timeout
        self.features = tuple(features)
        self.closers: list[Callable[[], None]] = []

    def __repr__(self) -> str:
        return "OpenAICompat(<endpoint>)"

    def close(self) -> None:
        for c in self.closers:
            c()
        self.closers.clear()

    # ------------------------------------------------------------------ transport
    def _request(self, path: str, body: dict[str, Any] | None = None):
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self._auth is not None:
            token = self._auth()
            if token:
                headers["Authorization"] = token
        data = None if body is None else json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            self._base + path, data=data, headers=headers, method="GET" if body is None else "POST"
        )
        try:
            return safe_urlopen(req, timeout=self._timeout)
        except urllib.error.HTTPError as exc:
            raise InferenceError(f"HTTP {exc.code} from {path}", exc.code) from exc
        except (urllib.error.URLError, OSError) as exc:
            raise InferenceError(f"transport error: {type(exc).__name__}") from exc

    def _json(self, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        with self._request(path, body) as resp:
            try:
                raw = read_bounded(resp, self.max_bytes)
            except ResponseTooLarge as exc:
                raise InferenceError(f"{path}: {exc}") from None
        try:
            doc = json.loads(raw)
        except ValueError as exc:
            raise InferenceError(f"{path}: reply is not JSON") from exc
        if not isinstance(doc, dict):
            raise InferenceError(f"{path}: reply is not an object")
        return doc

    # ------------------------------------------------------------------ contract
    def models(self) -> list[str]:
        doc = self._json("/v1/models")
        try:
            return [str(m["id"]) for m in doc["data"]]
        except (KeyError, TypeError) as exc:
            raise InferenceError("/v1/models: unexpected shape") from exc

    def chat(
        self,
        model: str,
        messages: Sequence[dict[str, str]],
        *,
        max_tokens: int = 64,
        temperature: float = 0.0,
    ) -> ChatResult:
        doc = self._json(
            "/v1/chat/completions",
            {
                "model": model,
                "messages": list(messages),
                "max_tokens": max_tokens,
                "temperature": temperature,
            },
        )
        try:
            choice = doc["choices"][0]
            usage = doc.get("usage") or {}
            return ChatResult(
                content=str(choice["message"]["content"]),
                finish_reason=str(choice.get("finish_reason")),
                model=str(doc["model"]),
                prompt_tokens=usage.get("prompt_tokens"),
                completion_tokens=usage.get("completion_tokens"),
                total_tokens=usage.get("total_tokens"),
            )
        except (KeyError, IndexError, TypeError) as exc:
            raise InferenceError("chat completion: unexpected shape") from exc

    def chat_stream(
        self, model: str, messages: Sequence[dict[str, str]], *, max_tokens: int = 64
    ) -> Iterator[str]:
        resp = self._request(
            "/v1/chat/completions",
            {"model": model, "messages": list(messages), "max_tokens": max_tokens, "stream": True},
        )
        with resp:
            done = False
            seen = 0
            while True:
                raw = resp.readline(self.max_bytes + 1)
                if not raw:
                    break
                seen += len(raw)
                if seen > self.max_bytes:
                    raise InferenceError(f"stream: larger than {self.max_bytes} bytes")
                line = raw.decode("utf-8").strip()
                if not line.startswith("data:"):
                    continue
                payload = line[5:].strip()
                if payload == "[DONE]":
                    done = True
                    break
                try:
                    piece = json.loads(payload)["choices"][0]["delta"].get("content")
                except (ValueError, KeyError, IndexError, TypeError) as exc:
                    raise InferenceError("stream: unexpected chunk") from exc
                if piece:
                    yield piece
            if not done:
                raise InferenceError("stream ended without [DONE]")

    def embed(self, model: str, texts: Sequence[str]) -> list[list[float]]:
        doc = self._json("/v1/embeddings", {"model": model, "input": list(texts)})
        try:
            return [list(map(float, d["embedding"])) for d in doc["data"]]
        except (KeyError, TypeError, ValueError) as exc:
            raise InferenceError("embeddings: unexpected shape") from exc
