# SPDX-License-Identifier: Apache-2.0
"""Builders shared by the publishing tests (fictional values only)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from homelabnext.publishing import feed as fd
from homelabnext.publishing import gate as gt
from homelabnext.publishing.transport import Request, Response

DENY = "# the site's names\nvault.example.internal\nre:\\b10\\.20\\.\\d{1,3}\\.\\d{1,3}\\b\n!podcasts.example.internal\n"


def make_item(
    root: Path, kind: str, name: str, files: dict[str, bytes | str], tlp: str = "clear"
) -> Path:
    d = root / kind / name
    d.mkdir(parents=True)
    sums = {}
    for rel, data in files.items():
        b = data.encode() if isinstance(data, str) else data
        (d / rel).parent.mkdir(parents=True, exist_ok=True)
        (d / rel).write_bytes(b)
        sums[rel] = hashlib.sha256(b).hexdigest()
    (d / gt.SIDECAR).write_text(json.dumps({"tlp": tlp, "producer": "producer-a", "sha256s": sums}))
    return d


def policy(deny: str = DENY, **kw) -> gt.Policy:
    return gt.Policy(gt.DenyList.parse(deny), **kw)


def build_mp3(title: str = "episode", comment: str = "", pad: int = 0, body: bytes = b"") -> bytes:
    """A minimal MP3: an ID3v2.3 tag (title, optional comment) and a few frame-sync bytes."""
    import struct

    def frame(fid: bytes, payload: bytes) -> bytes:
        return fid + struct.pack(">I", len(payload)) + b"\x00\x00" + payload

    frames = frame(b"TIT2", b"\x00" + title.encode("latin-1"))
    if comment:
        frames += frame(b"COMM", b"\x00eng\x00" + comment.encode("latin-1"))
    frames += b"\x00" * pad
    size = len(frames)
    syncsafe = bytes([(size >> 21) & 0x7F, (size >> 14) & 0x7F, (size >> 7) & 0x7F, size & 0x7F])
    return b"ID3\x03\x00\x00" + syncsafe + frames + b"\xff\xfb\x90\x00" + body


def build_png(text: str = "", tail: bytes = b"") -> bytes:
    """A minimal PNG, with an optional tEXt chunk."""
    import struct
    import zlib

    def chunk(t: bytes, d: bytes) -> bytes:
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d))

    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    out = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr)
    if text:
        out += chunk(b"tEXt", b"Comment\x00" + text.encode("latin-1"))
    return out + chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00")) + chunk(b"IEND", b"") + tail


def episode(
    root: Path,
    name: str = "ep1",
    period: str = "weekly",
    date: str = "2026-01-05",
    mp3: bytes | None = None,
) -> Path:
    mp3 = build_mp3() if mp3 is None else mp3
    meta = json.dumps(
        {"period": period, "date": date, "title": f"{period} {date}", "description": "d & e"}
    )
    return make_item(root, "podcast", name, {"metadata.json": meta, f"{period}_{date}.mp3": mp3})


FEED = fd.FeedConfig(
    "https://cdn.example.test",
    "Example Show",
    "A fictional show.",
    "Example Author",
    "show@example.test",
)


class FakeBucket:
    """An in-memory S3-ish endpoint behind the Transport seam; records every request."""

    def __init__(self, bucket: str = "b") -> None:
        self.bucket = bucket
        self.objects: dict[str, tuple[bytes, dict[str, str]]] = {}
        self.calls: list[Request] = []

    def send(self, req: Request) -> Response:
        self.calls.append(req)
        from urllib.parse import parse_qs, unquote, urlsplit

        u = urlsplit(req.url)
        key = unquote(u.path)[len(f"/{self.bucket}") :].lstrip("/")
        if req.method == "GET" and not key:
            prefix = parse_qs(u.query).get("prefix", [""])[0]
            body = "".join(
                f"<Contents><Key>{k}</Key><Size>{len(v[0])}</Size></Contents>"
                for k, v in sorted(self.objects.items())
                if k.startswith(prefix)
            )
            xml = f'<ListBucketResult xmlns="http://s3.example.test/doc/"><IsTruncated>false</IsTruncated>{body}</ListBucketResult>'
            return Response(200, {}, xml.encode())
        if req.method == "GET":
            if key not in self.objects:
                return Response(404, {}, b"")
            return Response(200, {"etag": self.etag(key)}, self.objects[key][0])
        if req.method == "HEAD":
            if key not in self.objects:
                return Response(404, {}, b"")
            return Response(200, dict(self.objects[key][1].items()), b"")
        if req.method == "PUT":
            if req.headers.get("If-None-Match") == "*" and key in self.objects:
                return Response(412, {}, b"")
            if "If-Match" in req.headers and (
                key not in self.objects or req.headers["If-Match"] != self.etag(key)
            ):
                return Response(412, {}, b"")
            meta = {
                k.lower(): v for k, v in req.headers.items() if k.lower().startswith("x-amz-meta-")
            }
            self.objects[key] = (req.body, meta)
            return Response(200, {}, b"")
        return Response(405, {}, b"")

    def etag(self, key: str) -> str:
        return '"' + hashlib.md5(self.objects[key][0], usedforsecurity=False).hexdigest() + '"'

    def methods(self) -> list[str]:
        return [c.method for c in self.calls]
