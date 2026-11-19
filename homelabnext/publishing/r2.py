# SPDX-License-Identifier: Apache-2.0
"""The object-store feed adapter: episode uploads and the deterministic ``feed.xml``.

Idempotent and additive.  The client has no delete (there is no method to call), an episode key
that exists is never overwritten (same bytes: nothing to do; different bytes: a conflict, refused),
and the feed is written only when it differs from the remote one and never when it would drop an
episode the remote feed carries.  Requests are signed here (AWS signature version 4, region
``auto``) so nothing beyond the standard library is needed.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import urllib.parse
import xml.etree.ElementTree as ET
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime

from homelabnext.publishing import feed as fd
from homelabnext.publishing import gate
from homelabnext.publishing.gate import Item
from homelabnext.publishing.transport import Request, Response, Transport

FEED_KEY = "feed.xml"
FEED_TYPE = "application/rss+xml; charset=utf-8"


class R2Error(RuntimeError):
    pass


class PreconditionFailed(R2Error):
    """A conditional write lost a race (HTTP 412): the object changed after it was read."""


class FeedBlocked(R2Error):
    """The feed this run would write does not pass the gate (it is gated like any item)."""


class Conflict(R2Error):
    """An episode key already holds different bytes: a published key never changes."""


def _quote(s: str) -> str:
    return urllib.parse.quote(s, safe="-_.~")


def sign(
    method: str,
    url: str,
    headers: dict[str, str],
    payload: bytes,
    *,
    key_id: str,
    secret: str,
    region: str,
    service: str,
    now: datetime,
) -> dict[str, str]:
    """AWS signature v4: the headers (host, x-amz-date, x-amz-content-sha256, authorization) to send."""
    u = urllib.parse.urlsplit(url)
    amz = now.strftime("%Y%m%dT%H%M%SZ")
    day = amz[:8]
    payload_hash = hashlib.sha256(payload).hexdigest()
    hdr = {k.lower(): " ".join(v.split()) for k, v in headers.items()}
    hdr.update({"host": u.netloc, "x-amz-date": amz, "x-amz-content-sha256": payload_hash})
    names = sorted(hdr)
    canon_headers = "".join(f"{n}:{hdr[n]}\n" for n in names)
    query = sorted(
        (_quote(k), _quote(v)) for k, v in urllib.parse.parse_qsl(u.query, keep_blank_values=True)
    )
    canon_query = "&".join(f"{k}={v}" for k, v in query)
    canon_path = "/".join(_quote(urllib.parse.unquote(seg)) for seg in (u.path or "/").split("/"))
    canonical = "\n".join(
        [method, canon_path, canon_query, canon_headers, ";".join(names), payload_hash]
    )
    scope = f"{day}/{region}/{service}/aws4_request"
    to_sign = "\n".join(
        ["AWS4-HMAC-SHA256", amz, scope, hashlib.sha256(canonical.encode()).hexdigest()]
    )

    def mac(k: bytes, msg: str) -> bytes:
        return hmac.new(k, msg.encode(), hashlib.sha256).digest()

    k = mac(("AWS4" + secret).encode(), day)
    for part in (region, service, "aws4_request"):
        k = mac(k, part)
    sig = hmac.new(k, to_sign.encode(), hashlib.sha256).hexdigest()
    out = dict(headers)
    out.update(
        {
            "x-amz-date": amz,
            "x-amz-content-sha256": payload_hash,
            "Authorization": f"AWS4-HMAC-SHA256 Credential={key_id}/{scope}, "
            f"SignedHeaders={';'.join(names)}, Signature={sig}",
        }
    )
    return out


@dataclass
class R2Client:
    """Path-style S3 requests to ``endpoint``/``bucket``.  Reads and PUT only: nothing here deletes."""

    endpoint: str
    bucket: str
    key_id: str = field(repr=False)
    secret: str = field(repr=False)
    transport: Transport = field(repr=False)

    def _call(
        self,
        method: str,
        key: str,
        query: str = "",
        body: bytes = b"",
        headers: dict | None = None,
        now: datetime | None = None,
    ) -> Response:
        path = f"/{self.bucket}" + (f"/{key}" if key else "")
        url = (
            self.endpoint
            + "/".join(_quote(s) if s else "" for s in path.split("/"))
            + (f"?{query}" if query else "")
        )
        h = sign(
            method,
            url,
            dict(headers or {}),
            body,
            key_id=self.key_id,
            secret=self.secret,
            region="auto",
            service="s3",
            now=now or datetime.now(UTC),
        )
        return self.transport.send(Request(method, url, h, body))

    def list(self, prefix: str) -> dict[str, int]:
        """``{key: size}`` under ``prefix`` (every page)."""
        out: dict[str, int] = {}
        token = ""
        while True:
            q = (
                "list-type=2&prefix="
                + _quote(prefix)
                + (f"&continuation-token={_quote(token)}" if token else "")
            )
            r = self._call("GET", "", q)
            if r.status != 200:
                raise R2Error(f"list {prefix!r}: HTTP {r.status}")
            root = ET.fromstring(r.body)
            ns = root.tag[: root.tag.index("}") + 1] if root.tag.startswith("{") else ""
            for c in root.findall(f"{ns}Contents"):
                out[c.findtext(f"{ns}Key") or ""] = int(c.findtext(f"{ns}Size") or 0)
            if (root.findtext(f"{ns}IsTruncated") or "").lower() != "true":
                return out
            token = root.findtext(f"{ns}NextContinuationToken") or ""
            if not token:
                raise R2Error("a truncated listing without a continuation token")

    def get(self, key: str) -> bytes | None:
        r = self._call("GET", key)
        if r.status == 404:
            return None
        if r.status != 200:
            raise R2Error(f"get {key!r}: HTTP {r.status}")
        return r.body

    def get_with_etag(self, key: str) -> tuple[bytes, str] | None:
        r = self._call("GET", key)
        if r.status == 404:
            return None
        if r.status != 200:
            raise R2Error(f"get {key!r}: HTTP {r.status}")
        return r.body, r.headers.get("etag", "")

    def head_sha256(self, key: str) -> str | None:
        """The ``sha256`` metadata this module stamped on the object (None if it has none)."""
        r = self._call("HEAD", key)
        if r.status != 200:
            raise R2Error(f"head {key!r}: HTTP {r.status}")
        return r.headers.get("x-amz-meta-sha256")

    def put_new(self, key: str, body: bytes, content_type: str, sha256: str) -> None:
        """Create ``key``; refuses (a precondition) if it exists, so a race cannot overwrite."""
        self._put(key, body, content_type, sha256, {"If-None-Match": "*"})

    def put_replace(self, key: str, body: bytes, content_type: str, etag: str | None) -> None:
        """Replace the feed (the one object whose key is fixed and whose content moves), only if it
        still is the version that was read (``If-Match``); created only if it still does not exist."""
        cond = {"If-Match": etag} if etag else {"If-None-Match": "*"}
        self._put(key, body, content_type, hashlib.sha256(body).hexdigest(), cond)

    def _put(
        self, key: str, body: bytes, content_type: str, sha256: str, extra: dict[str, str]
    ) -> None:
        h = {"Content-Type": content_type, "x-amz-meta-sha256": sha256, **extra}
        r = self._call("PUT", key, body=body, headers=h)
        if r.status == 412:
            raise PreconditionFailed(f"put {key!r}: the object changed since it was read")
        if r.status not in (200, 201, 204):
            raise R2Error(f"put {key!r}: HTTP {r.status}")


# ----------------------------------------------------------------------------- the plan
@dataclass(frozen=True)
class Upload:
    key: str
    body: bytes = field(repr=False)
    content_type: str = ""
    sha256: str = ""


@dataclass(frozen=True)
class Plan:
    """What publishing an episode would do, computed from reads only."""

    uploads: tuple[Upload, ...]
    unchanged: tuple[str, ...]
    feed_xml: str
    feed_changes: bool
    episodes: int
    feed_etag: str | None = None  # the ETag of the feed the plan read (None: there was none)
    unverified: tuple[str, ...] = ()  # existing keys compared by size only (no sha256 stamp)
    excused: tuple[str, ...] = ()  # legacy metadata whose text a reviewed exception excuses


def episode_files(item: Item) -> tuple[str, str, str, str]:
    """``(stem, date, metadata path, mp3 path)`` of a podcast item; it holds exactly those two."""
    if "metadata.json" not in item.files:
        raise R2Error(f"{item.id}: no metadata.json")
    meta = json.loads(item.path("metadata.json").read_text(encoding="utf-8"))
    stem, date = fd.stem_of(meta)
    if f"{stem}.mp3" not in item.files:
        raise R2Error(f"{item.id}: no {stem}.mp3")
    return stem, date, "metadata.json", f"{stem}.mp3"


def plan_episode(
    client: R2Client,
    item: Item,
    feed_cfg: fd.FeedConfig,
    policy: gate.Policy,
    legacy: Mapping[str, str] | None = None,
) -> Plan:
    """Reads the bucket (listing, metadata, the feed); writes nothing.  ``legacy`` maps the key of
    an already-public metadata object to its sha256: an operator-reviewed exception whose text the
    deny-list and posture rules do not read (TLP markers and secret shapes still do)."""
    legacy = legacy or {}
    excused: set[str] = set()
    stem, _date, meta_rel, mp3_rel = episode_files(item)
    mp3_key, json_key = f"episodes/{stem}.mp3", f"episodes/{stem}.json"
    local = {}
    for key, rel, ctype in (
        (mp3_key, mp3_rel, "audio/mpeg"),
        (json_key, meta_rel, "application/json"),
    ):
        body = item.path(rel).read_bytes()  # the snapshot: private, already hashed and gated
        sha = hashlib.sha256(body).hexdigest()
        if sha != item.sidecar["sha256s"][rel]:
            raise R2Error(f"{item.id}: {rel} no longer matches its sidecar sha256")
        local[key] = (body, ctype, sha)
    listing = client.list("episodes/")
    uploads, unchanged, unverified = [], [], []
    for key, (body, ctype, sha) in local.items():
        if key not in listing:
            uploads.append(Upload(key, body, ctype, sha))
            continue
        remote_sha = client.head_sha256(key)
        if not remote_sha:
            unverified.append(key)  # an episode from before this module: compared by size only
        same = remote_sha == sha if remote_sha else listing[key] == len(body)
        if not same:
            raise Conflict(f"{key} exists with different bytes: a published key never changes")
        unchanged.append(key)

    sizes = dict(listing)
    metas: dict[str, dict] = {}
    for key in sorted(k for k in sizes if k.endswith(".json")):
        raw = client.get(key)
        try:
            doc = json.loads(raw or b"")
            s, _d = fd.stem_of(doc)
        except (ValueError, fd.FeedError):
            continue  # malformed remote metadata is skipped here, as the old builder did
        if key == f"episodes/{s}.json":
            metas[s] = doc
            if legacy.get(key) == hashlib.sha256(raw or b"").hexdigest():
                excused.add(s)
    metas[stem] = json.loads(local[json_key][0])
    sizes[mp3_key] = len(local[mp3_key][0])
    episodes = []
    for s, doc in metas.items():
        if f"episodes/{s}.mp3" not in sizes:
            continue  # metadata without its audio: not an episode (the old builder skipped it too)
        episodes.append(
            fd.Episode(
                s,
                doc["date"],
                str(doc.get("title") or s),
                str(doc.get("description") or ""),
                sizes[f"episodes/{s}.mp3"],
            )
        )
    if not episodes:
        raise R2Error("zero episodes: refusing to publish an empty feed")
    new_xml = fd.build_feed(episodes, feed_cfg)
    names_xml = None
    if excused:
        blanked = [
            fd.Episode(e.stem, e.date, "-", "", e.size) if e.stem in excused else e
            for e in episodes
        ]
        names_xml = fd.build_feed(blanked, feed_cfg)
    verdict = gate.gate_artifact(FEED_KEY, new_xml, policy, names_xml)
    if not verdict.ok:  # the rendered feed is content too: it must pass what the items passed
        rules = sorted({r.rule for r in verdict.reasons})
        raise FeedBlocked(
            f"the feed this run would write is refused by the gate ({', '.join(rules)})"
        )
    got = client.get_with_etag(FEED_KEY)
    old, etag = (got[0], got[1]) if got else (None, None)
    if old is not None:
        dropped = fd.guids(old.decode("utf-8", "replace")) - {e.stem for e in episodes}
        if dropped:
            raise R2Error(
                f"the new feed would drop {len(dropped)} episode(s) the remote feed carries"
            )
    return Plan(
        tuple(uploads),
        tuple(unchanged),
        new_xml,
        old is None or old != new_xml.encode(),
        len(episodes),
        etag or None,
        tuple(unverified),
        tuple(sorted(f"episodes/{e}.json" for e in excused)),
    )


def apply_plan(client: R2Client, plan: Plan) -> list[str]:
    """Write what the plan says; returns the keys written.  Audio and metadata first, the feed last."""
    written = []
    for up in plan.uploads:
        client.put_new(up.key, up.body, up.content_type, up.sha256)
        written.append(up.key)
    if plan.feed_changes:
        client.put_replace(FEED_KEY, plan.feed_xml.encode(), FEED_TYPE, plan.feed_etag)
        written.append(FEED_KEY)
    return written
