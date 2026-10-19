# SPDX-License-Identifier: Apache-2.0
"""AWS Signature Version 4 (header form), standard library only.

The pieces are separate functions so each can be checked against AWS's published test suite
(``tests/conform/fixtures/sigv4``): :func:`uri_encode`, :func:`canonical_query`,
:func:`canonical_headers`, :func:`canonical_request`, :func:`string_to_sign`,
:func:`signing_key` and :func:`sign`, which returns the headers to add to a request.

S3 rules, which differ from the generic service rules, are the caller's choice and are spelled
out here so nobody has to rediscover them:

* the canonical URI is the request path exactly as sent on the wire: encode each key once with
  ``uri_encode(key, keep_slash=True)`` and sign that same string (no second encoding, no
  ``.``/``..`` normalisation, which would make two keys sign alike);
* the payload hash is the hex SHA-256 of the body and is sent as ``x-amz-content-sha256``
  (``sign(..., content_sha256_header=True)``).

The secret key is used only inside :func:`signing_key`; nothing here stores or logs it.
"""

from __future__ import annotations

import hashlib
import hmac
import string
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime

__all__ = [
    "ALGORITHM",
    "EMPTY_SHA256",
    "canonical_headers",
    "canonical_query",
    "canonical_request",
    "credential_scope",
    "sign",
    "signing_key",
    "string_to_sign",
    "uri_encode",
]

ALGORITHM = "AWS4-HMAC-SHA256"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
_UNRESERVED = frozenset((string.ascii_letters + string.digits + "-._~").encode("ascii"))

Headers = Mapping[str, str] | Iterable[tuple[str, str]]


def uri_encode(text: str, *, keep_slash: bool) -> str:
    """AWS ``UriEncode``: every byte of the UTF-8 form except ``A-Za-z0-9-._~`` (and ``/`` when
    ``keep_slash``) becomes ``%XX`` with upper-case hex.  Space is ``%20``, never ``+``."""
    out = []
    for b in text.encode("utf-8"):
        if b in _UNRESERVED or (keep_slash and b == 0x2F):
            out.append(chr(b))
        else:
            out.append(f"%{b:02X}")
    return "".join(out)


def canonical_query(pairs: Iterable[tuple[str, str]]) -> str:
    """Decoded ``(name, value)`` pairs -> the canonical query string (also valid on the wire)."""
    enc = sorted(
        (uri_encode(k, keep_slash=False), uri_encode(v, keep_slash=False)) for k, v in pairs
    )
    return "&".join(f"{k}={v}" for k, v in enc)


def _pairs(headers: Headers) -> list[tuple[str, str]]:
    return list(headers.items()) if isinstance(headers, Mapping) else list(headers)


def canonical_headers(headers: Headers) -> tuple[str, str]:
    """``(canonical header block, signed header list)``: names lower-cased and sorted, values
    trimmed with inner runs of whitespace collapsed, repeated names joined with ``,`` in order."""
    merged: dict[str, list[str]] = {}
    for name, value in _pairs(headers):
        merged.setdefault(name.strip().lower(), []).append(" ".join(str(value).split()))
    names = sorted(merged)
    block = "".join(f"{n}:{','.join(merged[n])}\n" for n in names)
    return block, ";".join(names)


def canonical_request(
    method: str,
    canonical_uri: str,
    query: Iterable[tuple[str, str]],
    headers: Headers,
    payload_sha256: str,
) -> str:
    block, signed = canonical_headers(headers)
    return "\n".join(
        [
            method.upper(),
            canonical_uri or "/",
            canonical_query(query),
            block,
            signed,
            payload_sha256,
        ]
    )


def credential_scope(when: datetime, region: str, service: str) -> str:
    return f"{_utc(when):%Y%m%d}/{region}/{service}/aws4_request"


def string_to_sign(when: datetime, scope: str, canonical: str) -> str:
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return "\n".join([ALGORITHM, f"{_utc(when):%Y%m%dT%H%M%SZ}", scope, digest])


def signing_key(secret_key: str, when: datetime, region: str, service: str) -> bytes:
    def h(key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

    k = h(("AWS4" + secret_key).encode("utf-8"), f"{_utc(when):%Y%m%d}")
    return h(h(h(k, region), service), "aws4_request")


def sign(
    method: str,
    canonical_uri: str,
    query: Iterable[tuple[str, str]],
    headers: Headers,
    payload_sha256: str,
    *,
    access_key: str,
    secret_key: str,
    region: str,
    service: str,
    when: datetime,
    content_sha256_header: bool = False,
) -> dict[str, str]:
    """Headers to add to the request: ``x-amz-date``, optionally ``x-amz-content-sha256``, and
    ``Authorization``.  ``headers`` must already hold ``host`` (and anything else to sign)."""
    query = list(query)
    add = {"x-amz-date": f"{_utc(when):%Y%m%dT%H%M%SZ}"}
    if content_sha256_header:
        add["x-amz-content-sha256"] = payload_sha256
    signed_input = _pairs(headers) + list(add.items())
    if not any(n.strip().lower() == "host" for n, _ in signed_input):
        raise ValueError("SigV4: the host header must be signed")
    canonical = canonical_request(method, canonical_uri, query, signed_input, payload_sha256)
    scope = credential_scope(when, region, service)
    sts = string_to_sign(when, scope, canonical)
    key = signing_key(secret_key, when, region, service)
    signature = hmac.new(key, sts.encode("utf-8"), hashlib.sha256).hexdigest()
    _, signed = canonical_headers(signed_input)
    add["Authorization"] = (
        f"{ALGORITHM} Credential={access_key}/{scope}, SignedHeaders={signed}, Signature={signature}"
    )
    return add


def _utc(when: datetime) -> datetime:
    if when.tzinfo is None:
        raise ValueError("SigV4 needs an aware datetime (UTC)")
    return when.astimezone(UTC)
