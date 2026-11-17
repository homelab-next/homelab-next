# SPDX-License-Identifier: Apache-2.0
"""The service's commands.

* ``serve``: load the configuration (``CONTEXT_CONFIG``, default :data:`DEFAULT_CONFIG`), start
  the HTTP server, and index in the background: fetch every source, or, when a fetch fails at
  start, index the checkouts already on disk (``/ready`` stays 503 until one index succeeded).
* ``reindex``: ask the running server to fetch and index now (``POST /v1/reindex`` on loopback,
  with the admin token from the environment): what the timer runs inside the container. Exit 0 on
  a successful run, 1 on a failed one, 2 when the server is busy or unreachable.
* ``check``: ask the running server for its self-check (``POST /v1/check``): exit 0 when the
  canned query found its item (and the judge, when on, cleared it), else 1. Prints the JSON answer.
"""

from __future__ import annotations

import json
import os
import signal
import sys
import threading
import urllib.error
import urllib.request
from collections.abc import Mapping, Sequence

from .config import ADMIN_ENV, Config, ConfigError, load

__all__ = ["DEFAULT_CONFIG", "main"]

DEFAULT_CONFIG = "/etc/hnx-context/config.json"


def _post(cfg: Config, path: str, env: Mapping[str, str], timeout: float) -> tuple[int, dict]:
    url = f"http://localhost:{cfg.port}{path}"
    req = urllib.request.Request(
        url,
        data=b"{}",
        headers={
            "Authorization": f"Bearer {env.get(ADMIN_ENV, '')}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read().decode("utf-8"))
        except ValueError:
            return exc.code, {}


def initial_index(service) -> None:
    """Fetch and index; when the fetch fails, index what is already on disk."""
    report = service.reindex(fetch=True)
    if not report.get("ok"):
        service.reindex(fetch=False)


def serve(cfg: Config, env: Mapping[str, str]) -> int:
    from .server import Routes, make_server
    from .service import ContextService

    service = ContextService(cfg, env=env)
    srv = make_server(Routes(service, env), cfg.bind, cfg.port)
    signal.signal(signal.SIGTERM, lambda *_: threading.Thread(target=srv.shutdown).start())
    threading.Thread(target=initial_index, args=(service,), daemon=True).start()
    try:
        srv.serve_forever()
    finally:
        srv.server_close()
    return 0


def main(argv: Sequence[str], env: Mapping[str, str] | None = None) -> int:
    env = dict(os.environ if env is None else env)
    if len(argv) < 1 or argv[0] not in ("serve", "reindex", "check"):
        print("usage: python -m homelabnext.context_service serve | reindex | check",
              file=sys.stderr)  # fmt: skip
        return 2
    try:
        cfg = load(env.get("CONTEXT_CONFIG", DEFAULT_CONFIG))
    except ConfigError as exc:
        print(f"context: {exc}", file=sys.stderr)
        return 2
    if argv[0] == "serve":
        return serve(cfg, env)
    timeout = float(argv[1]) if len(argv) > 1 else 3600.0
    path = "/v1/reindex" if argv[0] == "reindex" else "/v1/check"
    try:
        status, doc = _post(cfg, path, env, timeout)
    except (OSError, ValueError) as exc:
        print(json.dumps({"ok": False, "error": f"unreachable ({type(exc).__name__})"}))
        return 2
    print(json.dumps(doc, sort_keys=True))
    if status == 200 and doc.get("ok"):
        return 0
    return 1 if status in (500, 503) else 2
