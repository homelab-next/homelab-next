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


def episode(
    root: Path,
    name: str = "ep1",
    period: str = "weekly",
    date: str = "2026-01-05",
    mp3: bytes = b"ID3" + b"a" * 30,
) -> Path:
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
            return Response(200, {}, self.objects[key][0])
        if req.method == "HEAD":
            if key not in self.objects:
                return Response(404, {}, b"")
            return Response(200, dict(self.objects[key][1].items()), b"")
        if req.method == "PUT":
            if req.headers.get("If-None-Match") == "*" and key in self.objects:
                return Response(412, {}, b"")
            meta = {
                k.lower(): v for k, v in req.headers.items() if k.lower().startswith("x-amz-meta-")
            }
            self.objects[key] = (req.body, meta)
            return Response(200, {}, b"")
        return Response(405, {}, b"")

    def methods(self) -> list[str]:
        return [c.method for c in self.calls]
