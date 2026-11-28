# SPDX-License-Identifier: Apache-2.0
"""A ``documents`` source: the lab's document store, indexed through its REST API, by tag.

The documents stay in the store.  Nothing is exported, mirrored or checked out: every reindex lists
the documents carrying the configured tag(s) (paginated), reads each one's text, title, created
date and id, and hands them to the same index as a git source's files.  The index is incremental by
content (an unchanged document is not embedded again, :meth:`SemanticContextStore.index`) and a
document that was deleted or lost its tag is no longer listed, so the reindex removes it.

* **Ids**: ``<kind>:<source>/<doc id>-<slug of the title>``; the numeric id leads, so it is unique
  and stable; a retitled document gets a new id (the old one is removed).
* **Auth**: ``Authorization: Token <secret>`` (scheme ``token``) or ``Bearer``; the secret is read
  from the environment variable the source names, sent only in that header, never logged, never put
  in an error message.
* **Bounds**: a timeout per request, at most :data:`MAX_PAGES` pages, a response body limit, a text
  limit per document (``max_doc_bytes``: larger is skipped and counted), ``max_documents``.
* **Redirects are never followed** (the token would travel with them): a redirect is an error.
* **TLS** is verified (the system store, or ``ca_file``: the lab CA).  The store may answer only to
  a host name it knows: ``host_header`` sets the ``Host`` header explicitly (with https the URL's
  host is still what the certificate is checked against, so prefer the registry name).
* **TLP**: the source's declared label, raised by any marker in the text (as for a git source).
"""

from __future__ import annotations

import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from typing import Any

from homelabnext import tlp as _tlp
from homelabnext.context.model import Document

from .config import Source
from .sources import Collected, SourceError, _carried, _label

__all__ = ["MAX_PAGES", "MAX_RESPONSE_BYTES", "collect_documents", "slug"]

#: pages read per tag (page_size documents each); more is a misconfiguration, not a store
MAX_PAGES = 2000
#: the most bytes one response may carry (a page of documents with their text)
MAX_RESPONSE_BYTES = 256 * 1024 * 1024

_SLUG_BAD = re.compile(r"[^a-z0-9]+")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a: Any, **k: Any) -> None:  # type: ignore[override]
        return None


def slug(title: str) -> str:
    """A lower-case ``a-z0-9-`` slug of at most 60 characters (``untitled`` when nothing is left)."""
    s = _SLUG_BAD.sub("-", title.lower()).strip("-")[:60].strip("-")
    return s or "untitled"


def _opener(source: Source) -> urllib.request.OpenerDirector:
    handlers: list[Any] = [_NoRedirect()]
    if source.url.startswith("https://"):
        ctx = ssl.create_default_context(cafile=source.ca_file or None)
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    return urllib.request.build_opener(*handlers)


def _headers(source: Source, env: Mapping[str, str]) -> dict[str, str]:
    secret = env.get(source.credential_env, "")
    if not secret or any(c.isspace() for c in secret):
        raise SourceError(f"source {source.name}: its credential is not set")
    word = "Token" if source.credential_scheme == "token" else "Bearer"
    h = {"Authorization": f"{word} {secret}", "Accept": "application/json"}
    if source.host_header:
        h["Host"] = source.host_header
    return h


def _get(source: Source, opener: Any, url: str, headers: Mapping[str, str]) -> dict[str, Any]:
    req = urllib.request.Request(url, headers=dict(headers), method="GET")
    try:
        with opener.open(req, timeout=source.timeout) as r:
            raw = r.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:  # also a redirect that was refused
        raise SourceError(f"source {source.name}: the store answered {exc.code}") from None
    except (OSError, ValueError) as exc:
        raise SourceError(
            f"source {source.name}: the store did not answer ({type(exc).__name__})"
        ) from None
    if len(raw) > MAX_RESPONSE_BYTES:
        raise SourceError(f"source {source.name}: a response over {MAX_RESPONSE_BYTES} bytes")
    try:
        body = json.loads(raw)
    except ValueError:
        raise SourceError(f"source {source.name}: the store's answer is not JSON") from None
    if not isinstance(body, dict) or not isinstance(body.get("results"), list):
        raise SourceError(f"source {source.name}: the store's answer has no results list")
    return body


def _list(
    source: Source, opener: Any, headers: Mapping[str, str], tag: str
) -> list[dict[str, Any]]:
    base = source.url.rstrip("/") + "/api/documents/"
    out: list[dict[str, Any]] = []
    for page in range(1, MAX_PAGES + 1):
        q = urllib.parse.urlencode(
            {
                "tags__name__iexact": tag,
                "page": page,
                "page_size": source.page_size,
                "fields": "id,title,content,created,modified",
            }
        )
        body = _get(source, opener, f"{base}?{q}", headers)
        out.extend(r for r in body["results"] if isinstance(r, dict))
        if len(out) > source.max_documents:
            raise SourceError(f"source {source.name}: more than {source.max_documents} documents")
        if not body.get("next") or not body["results"]:
            return out
    raise SourceError(f"source {source.name}: more than {MAX_PAGES} pages")


def collect_documents(
    source: Source, env: Mapping[str, str], *, opener: Callable[..., Any] | Any = None
) -> Collected:
    """The source's documents (every tag, de-duplicated by the store's id) with their labels;
    ``SourceError`` when the store cannot be read or no document carries the tags (a wrong tag
    name must fail, never empty the index)."""
    headers = _headers(source, env)
    op = opener if opener is not None else _opener(source)
    rows: dict[int, dict[str, Any]] = {}
    for tag in source.tags:
        for r in _list(source, op, headers, tag):
            did = r.get("id")
            if isinstance(did, int) and not isinstance(did, bool) and did >= 0:
                rows.setdefault(did, r)
    out: list[tuple[Document, _tlp.Label]] = []
    skipped = 0
    for did in sorted(rows):
        r = rows[did]
        text = r.get("content")
        title = str(r.get("title") or "").strip()
        if (
            not isinstance(text, str)
            or not text.strip()
            or len(text.encode("utf-8", "replace")) > source.max_doc_bytes
        ):
            skipped += 1
            continue
        created = str(r.get("created") or "")[:10]
        head = f"{title}\n" + (f"created: {created}\n" if created else "") + "\n"
        content = head + text
        doc_id = f"{source.kind}:{source.name}/{did}-{slug(title)}"
        path = f"{source.name}/{did}"
        out.append((Document(doc_id, source.kind, content, title or str(did), path),
                    _label(source, _carried(content))))  # fmt: skip
    if not out:
        raise SourceError(f"source {source.name}: no document carries its tags")
    return Collected(tuple(out), skipped)
