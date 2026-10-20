# SPDX-License-Identifier: Apache-2.0
"""An ``object-store`` adapter for S3-compatible servers (written against Garage v1.0), stdlib only.

``S3ObjectStore`` implements :class:`conformance.protocols.object_store.ObjectStore` over the S3
REST API with path-style addressing and SigV4 header signing (:mod:`.sigv4`):

* ``create_bucket`` PUT /bucket; ``BucketAlreadyOwnedByYou`` counts as success (idempotent);
* ``put``/``get``/``head``/``delete`` on /bucket/key; user metadata travels as ``x-amz-meta-*``;
* ``list`` is ListObjectsV2 (``prefix``, ``max-keys``, ``continuation-token``, ``encoding-type=url``);
  the opaque ``next`` token is the server's ``NextContinuationToken``.

Keys are opaque text: each is percent-encoded once, ``/`` kept, and a path segment that is only
``.`` or ``..`` has its dots encoded as ``%2E`` so no hop between here and the server can resolve
it as a path; the server decodes the key back verbatim.  The signature covers the path exactly as
sent (S3 performs no second encoding and no normalisation).

Errors map to the protocol's types: ``NoSuchBucket``, ``NoSuchKey``, anything else
``ObjectStoreError`` with the HTTP status and the S3 error code, never a credential.  A HEAD has no
body, so a 404 there is disambiguated with a HeadBucket.

Garage specifics the lab relies on: the region is the server's ``s3_region`` (``LAB_S3_REGION``),
and the key must hold the ``createBucket`` permission for the suite's ``create_bucket`` calls
(``compose/lab-in-a-box/fakes/lab_init.py`` grants it).  Logical bucket names get a per-run prefix
(``bucket_prefix="auto"``) so repeated runs against one server never share a bucket.
"""

from __future__ import annotations

import hashlib
import http.client
import re
import ssl
import urllib.parse
import xml.etree.ElementTree as ET
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any

from homelabnext._http import check_plaintext

from . import sigv4
from ._env import env_reader, resolve, run_token

__all__ = ["S3ObjectStore", "make_object_store"]


def _proto() -> Any:
    """The protocol's types.  ``conformance/`` is a checkout directory, not part of the wheel, so
    it is imported on first use (the conformance harness puts the checkout on ``sys.path``)."""
    from conformance.protocols import object_store

    return object_store


_BUCKET = re.compile(r"^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$")
_META = re.compile(r"^[a-z0-9][a-z0-9-]*$")
DEFAULT_MAX_BYTES = 64 << 20


class S3ObjectStore:
    features: tuple[str, ...] = ("metadata",)

    def __init__(
        self,
        base_url: str,
        *,
        credentials: Callable[[], tuple[str, ...]],
        region: str,
        bucket_prefix: str = "",
        allow_plaintext: bool = False,
        timeout: float = 15.0,
        clock: Callable[[], datetime] | None = None,
        max_bytes: int = DEFAULT_MAX_BYTES,
    ):
        parts = urllib.parse.urlsplit(base_url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError("base_url must be an http(s) URL supplied by the caller")
        if parts.path not in ("", "/") or parts.query:
            raise ValueError("base_url must be scheme://host:port only (path-style addressing)")
        check_plaintext(base_url, credentials=True, allow_plaintext=allow_plaintext)
        self._scheme = parts.scheme
        self._host = parts.hostname
        self._port = parts.port
        self._netloc = parts.netloc
        self._creds = credentials
        self._region = region
        self._prefix = bucket_prefix
        self._timeout = timeout
        self._clock = clock or (lambda: datetime.now(UTC))
        self.max_bytes = max_bytes

    def __repr__(self) -> str:
        return "S3ObjectStore(<endpoint>)"

    def close(self) -> None:
        pass

    # ------------------------------------------------------------------ naming
    def _bucket(self, bucket: str) -> str:
        name = self._prefix + bucket
        if not isinstance(bucket, str) or not _BUCKET.fullmatch(name):
            raise ValueError(f"not a valid bucket name: {bucket!r}")
        return name

    @staticmethod
    def _key(key: str) -> str:
        if not isinstance(key, str) or not key:
            raise ValueError("an object key must be a non-empty string")
        segs = []
        for seg in sigv4.uri_encode(key, keep_slash=True).split("/"):
            segs.append(seg.replace(".", "%2E") if seg in (".", "..") else seg)
        return "/".join(segs)

    # ------------------------------------------------------------------ transport
    def _call(
        self,
        method: str,
        bucket: str,
        key: str | None = None,
        *,
        query: list[tuple[str, str]] | None = None,
        body: bytes = b"",
        headers: Mapping[str, str] | None = None,
    ) -> tuple[int, http.client.HTTPMessage, bytes]:
        path = "/" + self._bucket(bucket) + ("" if key is None else "/" + self._key(key))
        query = list(query or [])
        qs = sigv4.canonical_query(query)
        payload = hashlib.sha256(body).hexdigest()
        send = {"host": self._netloc, **dict(headers or {})}
        access, secret = self._creds()[:2]
        send.update(
            sigv4.sign(
                method,
                path,
                query,
                send,
                payload,
                access_key=access,
                secret_key=secret,
                region=self._region,
                service="s3",
                when=self._clock(),
                content_sha256_header=True,
            )
        )
        if self._scheme == "https":
            conn: http.client.HTTPConnection = http.client.HTTPSConnection(
                self._host, self._port, timeout=self._timeout, context=ssl.create_default_context()
            )
        else:
            conn = http.client.HTTPConnection(self._host, self._port, timeout=self._timeout)
        try:
            conn.request(method, path + ("?" + qs if qs else ""), body=body, headers=send)
            resp = conn.getresponse()
            data = resp.read(self.max_bytes + 1)
            if len(data) > self.max_bytes:
                raise _proto().ObjectStoreError(
                    f"{method} reply larger than {self.max_bytes} bytes"
                )
            return resp.status, resp.headers, data
        except (OSError, http.client.HTTPException) as exc:
            raise _proto().ObjectStoreError(
                f"transport error talking to the object store: {type(exc).__name__}"
            ) from None
        finally:
            conn.close()

    @staticmethod
    def _error(status: int, body: bytes, what: str) -> Any:
        code = message = ""
        if body:
            try:
                root = ET.fromstring(body)
                code = (root.findtext("Code") or "").strip()
                message = (root.findtext("Message") or "").strip()
            except ET.ParseError:
                message = body[:200].decode("utf-8", "replace")
        text = f"{what}: HTTP {status} {code or '(no S3 error code)'}"
        if message:
            text += f": {message[:200]}"
        if code == "NoSuchBucket":
            return _proto().NoSuchBucket(text)
        if code == "NoSuchKey":
            return _proto().NoSuchKey(text)
        return _proto().ObjectStoreError(text)

    # ------------------------------------------------------------------ contract
    def create_bucket(self, bucket: str) -> None:
        status, _, body = self._call("PUT", bucket)
        if status in (200, 204):
            return
        err = self._error(status, body, f"create bucket {bucket!r}")
        if "BucketAlreadyOwnedByYou" in str(err):
            return
        raise err

    def put(
        self, bucket: str, key: str, data: bytes, *, metadata: Mapping[str, str] | None = None
    ) -> Any:
        headers = {"content-type": "application/octet-stream"}
        meta = {}
        for name, value in (metadata or {}).items():
            n = str(name).lower()
            v = str(value)
            if not _META.fullmatch(n) or not v.isascii() or any(c in v for c in "\r\n"):
                raise ValueError(f"metadata {name!r}: names [a-z0-9-], values one ASCII line")
            headers[f"x-amz-meta-{n}"] = v
            meta[n] = v
        status, h, body = self._call("PUT", bucket, key, body=bytes(data), headers=headers)
        if status != 200:
            raise self._error(status, body, f"put {key!r}")
        return _proto().ObjectInfo(key, len(data), (h.get("ETag") or "").strip('"'), meta)

    def get(self, bucket: str, key: str) -> bytes:
        status, _, body = self._call("GET", bucket, key)
        if status != 200:
            raise self._error(status, body, f"get {key!r}")
        return body

    def head(self, bucket: str, key: str) -> Any:
        status, h, body = self._call("HEAD", bucket, key)
        if status == 404:
            b_status, _, _ = self._call("HEAD", bucket)
            if b_status == 404:
                raise _proto().NoSuchBucket(f"head {key!r}: no bucket {bucket!r}")
            raise _proto().NoSuchKey(f"head {key!r}: no such key")
        if status != 200:
            raise self._error(status, body, f"head {key!r}")
        meta = {
            k.lower()[len("x-amz-meta-") :]: v
            for k, v in h.items()
            if k.lower().startswith("x-amz-meta-")
        }
        return _proto().ObjectInfo(
            key, int(h.get("Content-Length") or 0), (h.get("ETag") or "").strip('"'), meta
        )

    def delete(self, bucket: str, key: str) -> None:
        status, _, body = self._call("DELETE", bucket, key)
        if status in (200, 204):
            return
        err = self._error(status, body, f"delete {key!r}")
        if isinstance(err, _proto().NoSuchKey):
            return
        raise err

    def list(
        self, bucket: str, prefix: str = "", *, limit: int = 1000, after: str | None = None
    ) -> Any:
        if not 1 <= int(limit) <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        query = [
            ("list-type", "2"),
            ("encoding-type", "url"),
            ("max-keys", str(int(limit))),
            ("prefix", prefix),
        ]
        if after is not None:
            query.append(("continuation-token", after))
        status, _, body = self._call("GET", bucket, query=query)
        if status != 200:
            raise self._error(status, body, f"list {bucket!r}")
        return _parse_list(body)


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _parse_list(body: bytes) -> Any:
    try:
        root = ET.fromstring(body)
    except ET.ParseError as exc:
        raise _proto().ObjectStoreError("list: reply is not XML") from exc
    fields: dict[str, str] = {}
    keys: list[str] = []
    for el in root:
        name = _local(el.tag)
        if name == "Contents":
            for sub in el:
                if _local(sub.tag) == "Key":
                    keys.append(sub.text or "")
        else:
            fields[name] = (el.text or "").strip()
    if fields.get("EncodingType", "").lower() == "url":
        keys = [urllib.parse.unquote_plus(k) for k in keys]  # "+" is a space (AWS, botocore)
    truncated = fields.get("IsTruncated", "false").lower() == "true"
    token = fields.get("NextContinuationToken") or None
    if truncated and not token:
        raise _proto().ObjectStoreError("list: truncated reply without a continuation token")
    return _proto().ListPage(tuple(keys), token if truncated else None)


def make_object_store(
    *,
    domain: str | None = None,
    resolver: Any = None,
    bucket_prefix: str = "auto",
    access_key_env: str = "LAB_S3_ACCESS_KEY",
    secret_key_env: str = "LAB_S3_SECRET_KEY",
    region_env: str = "LAB_S3_REGION",
    allow_plaintext: bool = False,
) -> S3ObjectStore:
    """Target-file factory: endpoint from the resolver, credentials and region from the env."""
    ep = resolve("object-store", resolver=resolver, domain=domain)
    (region,) = env_reader(region_env)()
    prefix = f"hnx-{run_token()}-" if bucket_prefix == "auto" else bucket_prefix
    return S3ObjectStore(
        ep.url,
        credentials=env_reader(access_key_env, secret_key_env),
        region=region,
        bucket_prefix=prefix,
        allow_plaintext=allow_plaintext,
    )
