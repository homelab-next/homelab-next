# SPDX-License-Identifier: Apache-2.0
"""A loopback S3 server shaped like Garage v1.0's path-style API, for the adapter tests.

It checks every request's SigV4 signature the way Garage does (canonical URI = the raw path as
received, payload hash from ``x-amz-content-sha256``) and refuses a bad one with
``SignatureDoesNotMatch``; keys are the percent-decoded remainder of the path, never resolved as
paths.  Buckets, objects, user metadata, ListObjectsV2 with continuation tokens and
``encoding-type=url``, and the S3 error XML (``NoSuchBucket``, ``NoSuchKey``,
``BucketAlreadyOwnedByYou`` is *not* raised: Garage answers 200 for a bucket the key owns).
``list_encoding``: ``"garage"`` percent-encodes listed keys (a space is ``%20``); ``"aws"`` encodes
them the way AWS S3 and MinIO do, form-style (a space is ``+``, a ``+`` is ``%2B``).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import threading
import urllib.parse
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from xml.sax.saxutils import escape

from homelabnext.conform.adapters import sigv4

NS = "http://s3.amazonaws.com/doc/2006-03-01/"

LOOPBACK = "127.0.0.1"  # no-raw-endpoint: allow fake server binds loopback only


class FakeS3:
    def __init__(
        self,
        access: str,
        secret: str,
        region: str,
        *,
        allow_create: bool = True,
        tamper=None,
        list_encoding: str = "garage",
    ):
        self.access, self.secret, self.region = access, secret, region
        self.quote = {"garage": urllib.parse.quote, "aws": urllib.parse.quote_plus}[list_encoding]
        self.allow_create = allow_create
        self.tamper = tamper  # callable(handler) -> None, to break a reply on purpose
        self.buckets: dict[str, dict[str, tuple[bytes, dict[str, str]]]] = {}
        self.requests: list[tuple[str, str]] = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _do(self):
                outer._handle(self)

            do_GET = do_PUT = do_HEAD = do_DELETE = do_POST = _do

        self._srv = ThreadingHTTPServer((LOOPBACK, 0), H)
        self._t = threading.Thread(target=self._srv.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        host, port = self._srv.server_address[:2]
        return f"http://{host}:{port}"

    def __enter__(self):
        self._t.start()
        return self

    def __exit__(self, *exc):
        self._srv.shutdown()
        self._srv.server_close()

    # ---------------------------------------------------------------- helpers
    @staticmethod
    def _send(h, status, body=b"", headers=None):
        h.send_response(status)
        for k, v in (headers or {}).items():
            h.send_header(k, v)
        h.send_header("Content-Length", str(len(body)))
        h.end_headers()
        if h.command != "HEAD":
            h.wfile.write(body)

    def _err(self, h, status, code, msg=""):
        body = f"<?xml version='1.0'?><Error><Code>{code}</Code><Message>{escape(msg)}</Message></Error>"
        self._send(h, status, body.encode(), {"Content-Type": "application/xml"})

    def _verify(self, h, raw_path, raw_query, body) -> bool:
        auth = h.headers.get("Authorization", "")
        try:
            _, rest = auth.split(" ", 1)
            parts = dict(p.strip().split("=", 1) for p in rest.split(","))
            access, _date, region, service, _ = parts["Credential"].split("/")
            signed = parts["SignedHeaders"].split(";")
        except (ValueError, KeyError):
            return False
        sha = h.headers.get("x-amz-content-sha256", "")
        if access != self.access or region != self.region or service != "s3":
            return False
        if sha != hashlib.sha256(body).hexdigest():
            return False
        when = datetime.strptime(h.headers["x-amz-date"] + "+0000", "%Y%m%dT%H%M%SZ%z")
        pairs = [
            (urllib.parse.unquote(k), urllib.parse.unquote(v))
            for k, _, v in (p.partition("=") for p in raw_query.split("&") if p)
        ]
        headers = [(n, h.headers[n]) for n in signed]
        canon = sigv4.canonical_request(h.command, raw_path, pairs, headers, sha)
        sts = sigv4.string_to_sign(when, sigv4.credential_scope(when, region, "s3"), canon)
        key = sigv4.signing_key(self.secret, when, region, "s3")
        want = hmac.new(key, sts.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(want, parts.get("Signature", ""))

    # ---------------------------------------------------------------- dispatch
    def _handle(self, h):
        raw_path, _, raw_query = h.path.partition("?")
        n = int(h.headers.get("Content-Length") or 0)
        body = h.rfile.read(n) if n else b""
        self.requests.append((h.command, h.path))
        if not self._verify(h, raw_path, raw_query, body):
            return self._err(h, 403, "SignatureDoesNotMatch", "bad signature")
        bucket, _, raw_key = raw_path[1:].partition("/")
        key = urllib.parse.unquote(raw_key) if raw_key else None
        q = dict(urllib.parse.parse_qsl(raw_query, keep_blank_values=True))
        if self.tamper is not None and self.tamper(h, self) is True:
            return None
        objs = self.buckets.get(bucket)
        if key is None:
            if h.command == "PUT":
                if objs is None and not self.allow_create:
                    return self._err(h, 403, "AccessDenied", "key may not create buckets")
                self.buckets.setdefault(bucket, {})
                return self._send(h, 200)
            if objs is None:
                return self._err(h, 404, "NoSuchBucket", bucket)
            if h.command == "HEAD":
                return self._send(h, 200)
            if h.command == "GET" and q.get("list-type") == "2":
                return self._list(h, objs, q)
            return self._err(h, 400, "NotImplemented")
        if objs is None:
            return self._err(h, 404, "NoSuchBucket", bucket)
        if h.command == "PUT":
            meta = {
                k.lower(): v for k, v in h.headers.items() if k.lower().startswith("x-amz-meta-")
            }
            objs[key] = (body, meta)
            return self._send(
                h,
                200,
                headers={"ETag": f'"{hashlib.md5(body, usedforsecurity=False).hexdigest()}"'},
            )
        if key not in objs:
            if h.command == "DELETE":
                return self._send(h, 204)
            return self._err(h, 404, "NoSuchKey", "")
        data, meta = objs[key]
        if h.command == "DELETE":
            del objs[key]
            return self._send(h, 204)
        headers = {"ETag": f'"{hashlib.md5(data, usedforsecurity=False).hexdigest()}"', **meta}
        if h.command == "HEAD":
            h.send_response(200)
            for k, v in headers.items():
                h.send_header(k, v)
            h.send_header("Content-Length", str(len(data)))
            h.end_headers()
            return None
        return self._send(h, 200, data, headers)

    def _list(self, h, objs, q):
        prefix = q.get("prefix", "")
        limit = int(q.get("max-keys", "1000"))
        start = ""
        if "continuation-token" in q:
            start = base64.urlsafe_b64decode(q["continuation-token"]).decode()
        keys = sorted(
            (k for k in objs if k.startswith(prefix) and k.encode() > start.encode()),
            key=lambda k: k.encode(),
        )
        page, more = keys[:limit], len(keys) > limit
        url = q.get("encoding-type") == "url"

        def enc(k):
            return self.quote(k, safe="/") if url else escape(k)

        items = "".join(f"<Contents><Key>{enc(k)}</Key></Contents>" for k in page)
        token = ""
        if more:
            token = f"<NextContinuationToken>{base64.urlsafe_b64encode(page[-1].encode()).decode()}</NextContinuationToken>"
        body = (
            f'<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="{NS}">'
            f"<Prefix>{enc(prefix)}</Prefix><KeyCount>{len(page)}</KeyCount>"
            f"{'<EncodingType>url</EncodingType>' if url else ''}"
            f"<IsTruncated>{'true' if more else 'false'}</IsTruncated>{token}{items}"
            "</ListBucketResult>"
        )
        return self._send(h, 200, body.encode(), {"Content-Type": "application/xml"})
