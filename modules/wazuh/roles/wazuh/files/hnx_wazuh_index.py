# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: wazuh-index-export
#   kind: tool
#   purpose: Export the SIEM's hot index (the alerts indices) to one JSON-lines file per index, and load such files back, through the indexer's own API.
#   owner: platform
#   trigger: [role:wazuh]
#   inputs: "export|restore --url URL --ca FILE --dir DIR [--pattern P] [--user U]; the account's password in HNX_INDEXER_PASSWORD"
#   outputs: "one JSON line on stdout, {files: [{key, docs}]} (export) or {indices, docs} (restore); the files under DIR (0600)"
#   exit:
#     "0": exported or restored
#     "1": the indexer refused a call, or the source is not what a restore needs (the reason on stderr)
#     "2": usage error or an unsafe path
"""The wazuh role's hot-index export and restore (modules/wazuh/README.md, "Export and restore").

    HNX_INDEXER_PASSWORD=... python3 -I hnx_wazuh_index.py export  --url https://INDEXER:PORT --ca CA --dir DIR
    HNX_INDEXER_PASSWORD=... python3 -I hnx_wazuh_index.py restore --url https://INDEXER:PORT --ca CA --dir DIR

``export`` reads every index matching the pattern (default the alerts indices) through a scroll and
writes ``DIR/<index>.jsonl``: one ``{"_id", "_source"}`` object per line (the format is the neutral
one; no product file is involved).  Each file is written under a temporary name and renamed, and an
index that returns no documents is still a (possibly empty) file, so the listing is the list of
indices.  ``restore`` bulk-indexes each file back under its own name and ids, so running it twice
changes nothing.  TLS is verified against ``--ca``; the password is read from the environment, never
from an argument; a redirect is never followed.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

DEFAULT_PATTERN = "wazuh-alerts-*"
INDEX_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}\Z")
PAGE = 1000
BULK = 500


class Refused(Exception):
    """The indexer refused a call or the source is not usable (exit 1)."""


class Unsafe(Exception):
    """An unsafe path or an argument that is not usable (exit 2)."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Client:
    def __init__(
        self, url: str, ca: str | None, user: str, password: str, timeout: float = 60.0
    ) -> None:
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            raise Unsafe("--url must be an http(s) URL")
        self._base = f"{parts.scheme}://{parts.netloc}"
        handlers: list = [_NoRedirect, urllib.request.ProxyHandler({})]
        if parts.scheme == "https":
            handlers.append(
                urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=ca))
            )
        self._opener = urllib.request.build_opener(*handlers)
        self._auth = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
        self._timeout = timeout

    def call(
        self, method: str, path: str, body: bytes | None = None, ctype: str = "application/json"
    ) -> dict:
        req = urllib.request.Request(
            self._base + path,
            data=body,
            method=method,
            headers={"Authorization": self._auth, "Content-Type": ctype},
        )
        try:
            with self._opener.open(req, timeout=self._timeout) as resp:
                return json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as exc:
            raise Refused(f"{method} {path.split('?')[0]} answered {exc.code}") from exc
        except (urllib.error.URLError, OSError) as exc:
            raise Refused(f"{method} {path.split('?')[0]} failed ({type(exc).__name__})") from exc


def _safe_dir(p: str) -> Path:
    path = Path(p)
    if not path.is_absolute() or ".." in path.parts or len(path.parts) < 3 or path.is_symlink():
        raise Unsafe(
            f"--dir must be an absolute, canonical, non-symlink path of at least 3 parts: {p}"
        )
    return path


def _publish(tmp: Path, final: Path) -> None:
    os.replace(tmp, final)


def export(client: Client, out: Path, pattern: str) -> dict:
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    rows = client.call(
        "GET", "/_cat/indices/" + urllib.parse.quote(pattern, safe="*,-") + "?format=json&h=index"
    )
    files = []
    for name in sorted(
        r["index"] for r in rows if isinstance(r, dict) and INDEX_NAME.match(r.get("index", ""))
    ):
        tmp = out / f".{name}.jsonl.tmp"
        docs = 0
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            page = client.call(
                "POST",
                f"/{name}/_search?scroll=2m",
                json.dumps({"size": PAGE, "sort": ["_doc"], "query": {"match_all": {}}}).encode(),
            )
            scroll = page.get("_scroll_id")
            while page.get("hits", {}).get("hits"):
                for hit in page["hits"]["hits"]:
                    fh.write(
                        json.dumps({"_id": hit["_id"], "_source": hit["_source"]}, sort_keys=True)
                        + "\n"
                    )
                    docs += 1
                page = client.call(
                    "POST",
                    "/_search/scroll",
                    json.dumps({"scroll": "2m", "scroll_id": scroll}).encode(),
                )
                scroll = page.get("_scroll_id", scroll)
        if scroll:
            with contextlib.suppress(Refused):  # the scroll expires by itself
                client.call("DELETE", "/_search/scroll", json.dumps({"scroll_id": scroll}).encode())
        _publish(tmp, out / f"{name}.jsonl")
        files.append({"key": f"{name}.jsonl", "docs": docs})
    return {"files": files}


def _bulk(client: Client, name: str, lines: list[str]) -> None:
    body = "".join(lines).encode()
    reply = client.call("POST", "/_bulk", body, "application/x-ndjson")
    if reply.get("errors"):
        raise Refused(f"the bulk load into {name} reported errors")


def restore(client: Client, src: Path) -> dict:
    files = sorted(p for p in src.glob("*.jsonl") if p.is_file() and not p.is_symlink())
    if not files:
        raise Refused(
            f"no .jsonl file under {src} (an export with no indices is refused, not restored)"
        )
    total = 0
    for path in files:
        name = path.name[: -len(".jsonl")]
        if not INDEX_NAME.match(name):
            raise Refused(f"{path.name} is not an index file")
        batch: list[str] = []
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                doc = json.loads(line)
                batch.append(json.dumps({"index": {"_index": name, "_id": doc["_id"]}}) + "\n")
                batch.append(json.dumps(doc["_source"], sort_keys=True) + "\n")
                total += 1
                if len(batch) >= BULK * 2:
                    _bulk(client, name, batch)
                    batch = []
        if batch:
            _bulk(client, name, batch)
    return {"indices": len(files), "docs": total}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="hnx_wazuh_index")
    ap.add_argument("cmd", choices=["export", "restore"])
    ap.add_argument("--url", required=True)
    ap.add_argument("--ca")
    ap.add_argument("--dir", required=True)
    ap.add_argument("--pattern", default=DEFAULT_PATTERN)
    ap.add_argument("--user", default="admin")
    args = ap.parse_args(argv)
    password = os.environ.get("HNX_INDEXER_PASSWORD", "")
    if not password:
        print("HNX_INDEXER_PASSWORD is not set", file=sys.stderr)
        return 2
    try:
        d = _safe_dir(args.dir)
        client = Client(args.url, args.ca, args.user, password)
        report = export(client, d, args.pattern) if args.cmd == "export" else restore(client, d)
    except Unsafe as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except Refused as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
