# SPDX-License-Identifier: Apache-2.0
"""A small stdlib client for OpenAI-compatible servers (the ``inference`` contract).

``OpenAICompat(base_url)`` implements :class:`conformance.protocols.inference.InferenceClient`.
The base URL is always supplied by the caller (a fake's ``.url``, or an endpoint the registry
resolver produced); there is no default.  An optional ``auth`` callable returns an
``Authorization`` header value at request time so a secret is never held in the object.  With
``auth`` set, plain ``http`` to a non-loopback host is refused unless ``allow_plaintext=True``;
redirects are followed only within the same origin; replies are read up to ``max_bytes``.

:meth:`OpenAICompat.chat_fields` sends a chat with extra request header fields, each sent as a
field of its own even when a name repeats (``X-HNX-TLP`` twice is two fields, which ``urllib``
cannot send): that request goes over :mod:`http.client` directly and follows no redirect.
"""

from __future__ import annotations

import http.client
import json
import ssl
import urllib.error
import urllib.parse
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
    """The server answered with an error or something that is not an OpenAI-shaped reply.

    ``status`` is the HTTP status of an error reply; ``detail`` the server's own error message
    (``error.message`` of an OpenAI-shaped error body, else the start of the body), so a check can
    tell an authentication error from, say, a database one; ``path`` the request path that failed
    (``/v1/chat/completions``), so a check can tell which call was refused; ``code`` the error
    envelope's ``error.code`` when it is a string (``tlp_refused``), else ``""``.
    """

    def __init__(
        self,
        message: str,
        status: int | None = None,
        detail: str = "",
        path: str = "",
        code: str = "",
    ):
        super().__init__(message)
        self.status = status
        self.detail = detail
        self.path = path
        self.code = code


def _error_parts(raw: bytes) -> tuple[str, str]:
    """``(detail, code)`` of an error reply body: the server's message (with its ``type`` or
    ``code`` in brackets) and the envelope's ``error.code`` when it is a string."""
    text = raw.decode("utf-8", "replace")
    try:
        doc = json.loads(text)
    except ValueError:
        return text[:300], ""
    err = doc.get("error") if isinstance(doc, dict) else None
    if isinstance(err, dict) and err.get("message"):
        kind = err.get("type") or err.get("code") or ""
        code = err.get("code") if isinstance(err.get("code"), str) else ""
        return f"{err['message']}" + (f" [{kind}]" if kind else ""), code[:64]
    if isinstance(err, str):
        return err[:300], ""
    return text[:300], ""


def _error_detail(exc: urllib.error.HTTPError, limit: int = 4096) -> tuple[str, str]:
    """:func:`_error_parts` of an error reply (at most ``limit`` bytes are read)."""
    try:
        raw = exc.read(limit)
    except OSError:
        return "", ""
    return _error_parts(raw)


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
            detail, code = _error_detail(exc)
            raise InferenceError(
                f"HTTP {exc.code} from {path}" + (f": {detail[:200]}" if detail else ""),
                exc.code,
                detail,
                path,
                code,
            ) from exc
        except (urllib.error.URLError, OSError) as exc:
            raise InferenceError(f"transport error: {type(exc).__name__}", path=path) from exc

    def _json(self, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        with self._request(path, body) as resp:
            try:
                raw = read_bounded(resp, self.max_bytes)
            except ResponseTooLarge as exc:
                raise InferenceError(f"{path}: {exc}") from None
        return _reply_doc(raw, path)

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
        return _chat_result(doc)

    def chat_fields(
        self,
        model: str,
        messages: Sequence[dict[str, str]],
        fields: Sequence[tuple[str, str]],
        *,
        max_tokens: int = 64,
    ) -> ChatResult:
        """A chat completion sent with the extra request header ``fields``, each a field of its
        own (a repeated name is sent as several fields, and an empty value as an empty field)."""
        body = {"model": model, "messages": list(messages), "max_tokens": max_tokens}
        return _chat_result(self._fields_json("/v1/chat/completions", body, fields))

    def _fields_json(
        self, path: str, body: dict[str, Any], fields: Sequence[tuple[str, str]]
    ) -> dict[str, Any]:
        """POST ``body`` to ``path`` over :mod:`http.client` with ``fields`` added as header
        fields; no redirect is followed (a 3xx is an error), the reply is read bounded."""
        parts = urllib.parse.urlsplit(self._base + path)
        for name, value in fields:
            if not (name.isascii() and name.replace("-", "").isalnum()):
                raise ValueError(f"header field name {name!r} is not a token")
            if any(c in value for c in "\r\n\0"):
                raise ValueError(f"header field {name} carries a line break")
        conn: http.client.HTTPConnection
        if parts.scheme == "https":
            conn = http.client.HTTPSConnection(
                parts.hostname or "",
                parts.port,
                timeout=self._timeout,
                context=ssl.create_default_context(),
            )
        else:
            conn = http.client.HTTPConnection(
                parts.hostname or "", parts.port, timeout=self._timeout
            )
        data = json.dumps(body).encode("utf-8")
        try:
            conn.putrequest("POST", parts.path, skip_accept_encoding=True)
            head = [
                ("Content-Type", "application/json"),
                ("Accept", "application/json"),
                ("Content-Length", str(len(data))),
            ]
            token = self._auth() if self._auth is not None else None
            if token:
                head.append(("Authorization", token))
            for name, value in [*head, *fields]:
                conn.putheader(name, value)
            conn.endheaders(data)
            resp = conn.getresponse()
            try:
                raw = read_bounded(resp, self.max_bytes)
            except ResponseTooLarge as exc:
                raise InferenceError(f"{path}: {exc}", path=path) from None
            status = resp.status
        except (http.client.HTTPException, OSError) as exc:
            raise InferenceError(f"transport error: {type(exc).__name__}", path=path) from exc
        finally:
            conn.close()
        if status >= 300:
            detail, code = _error_parts(raw[:4096])
            raise InferenceError(
                f"HTTP {status} from {path}" + (f": {detail[:200]}" if detail else ""),
                status,
                detail,
                path,
                code,
            )
        return _reply_doc(raw, path)

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


def _reply_doc(raw: bytes, path: str) -> dict[str, Any]:
    """A reply body as the JSON object it must be."""
    try:
        doc = json.loads(raw)
    except ValueError as exc:
        raise InferenceError(f"{path}: reply is not JSON") from exc
    if not isinstance(doc, dict):
        raise InferenceError(f"{path}: reply is not an object")
    return doc


def _chat_result(doc: dict[str, Any]) -> ChatResult:
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
