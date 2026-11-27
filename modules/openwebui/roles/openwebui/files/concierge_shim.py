# SPDX-License-Identifier: Apache-2.0
"""The concierge shim: a small OpenAI-compatible front for the lab's own gateway.

It sits between Open WebUI and the gateway (the optional sidecar of modules/openwebui) and adds the
three things the gateway does not: named model TIERS mapped to gateway roles, a lab PERSONA (a
system prompt), and bounded conversation MEMORY (history trimmed to a budget, optional retrieval
from the lab's context service). It calls nothing but the gateway (and, when configured, the
context service); standard library only, so it runs from a stock Python image with no install step.

Behaviour that matters (each has a test in tests/modules/test_concierge_shim.py):

* ``GET /v1/models`` lists a tier only while the gateway lists its role, so a tier "flips on" when
  its role exists and is never advertised before. The main tier is always listed.
* A request for a tier whose role is not (yet) live is a 404 naming the live ids: never a silent
  fallback to another tier (a plausible answer from the wrong model is worse than an error).
* The caller's ``X-HNX-TLP`` / ``X-HNX-Tag`` headers pass through to the gateway; when the caller
  sends none, the configured defaults are used. Nothing is ever sent at a label the config does
  not allow (the gateway's key ceiling is the real bound).
* Inbound ``Authorization: Bearer`` must match the shim token (the connection key Open WebUI holds);
  the gateway key is separate and never leaves the shim. Streaming is passed through unchanged.
* Retrieved passages are labelled with their source id and TLP, and are dropped (not sent to the
  model) when their label is above the configured ceiling.

Config: JSON at CONCIERGE_CONFIG. Secrets: env CONCIERGE_GATEWAY_KEY, CONCIERGE_TOKEN and
(optional) CONCIERGE_CONTEXT_TOKEN.
"""

from __future__ import annotations

import hmac
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Mapping
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

TLP_ORDER = ["clear", "green", "amber", "amber+strict", "red"]
MODEL_CACHE_S = 30.0


class ShimError(Exception):
    def __init__(self, status: int, message: str, code: str = "invalid_request_error") -> None:
        super().__init__(message)
        self.status, self.message, self.code = status, message, code


def tlp_rank(label: str) -> int:
    try:
        return TLP_ORDER.index(label)
    except ValueError:
        return len(TLP_ORDER)  # an unknown label is read as the most restrictive


def message_text(content: Any) -> str:
    """A message's text: a string, or the text parts of a list of content parts."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(
            p.get("text", "") for p in content if isinstance(p, dict) and p.get("type") == "text"
        )
    return ""


def trim_history(messages: list[dict], budget_chars: int) -> tuple[list[dict], int]:
    """Keep the system messages and the newest turns that fit the budget; the last message always
    stays. Returns (messages, dropped_count)."""
    system = [m for m in messages if m.get("role") == "system"]
    rest = [m for m in messages if m.get("role") != "system"]
    kept: list[dict] = []
    used = 0
    for m in reversed(rest):
        size = len(message_text(m.get("content")))
        if kept and used + size > budget_chars:
            break
        kept.append(m)
        used += size
    kept.reverse()
    return system + kept, len(rest) - len(kept)


def format_passages(hits: list[dict], ceiling: str, max_chars: int) -> str:
    """The retrieved passages as one block; any above the ceiling are left out."""
    parts: list[str] = []
    for h in hits:
        if tlp_rank(str(h.get("tlp", "red"))) > tlp_rank(ceiling):
            continue
        text = (h.get("content") or h.get("snippet") or "").strip()
        if not text:
            continue
        parts.append(f"[{h.get('id', '?')} | {h.get('tlp', '?')}]\n{text[:max_chars]}")
    return "\n\n".join(parts)


class Shim:
    def __init__(
        self, cfg: Mapping[str, Any], gateway_key: str, token: str, context_token: str = ""
    ) -> None:
        self.cfg = cfg
        self.gateway_url = cfg["gateway_url"].rstrip("/")
        self.gateway_key, self.token, self.context_token = gateway_key, token, context_token
        self.models: dict[str, dict] = {m["id"]: m for m in cfg["models"]}
        self.tiers: Mapping[str, str] = cfg["tiers"]
        self._live: tuple[float, set[str]] = (0.0, set())
        self._lock = threading.Lock()

    # -- the gateway ----------------------------------------------------------------------------
    def _request(self, path: str, body: dict | None, headers: Mapping[str, str], timeout: float):
        h = {
            "Authorization": "Bearer " + self.gateway_key,
            "Content-Type": "application/json",
            **headers,
        }
        data = None if body is None else json.dumps(body).encode()
        return urllib.request.urlopen(
            urllib.request.Request(self.gateway_url + path, data=data, headers=h), timeout=timeout
        )

    def live_roles(self, force: bool = False) -> set[str]:
        with self._lock:
            at, roles = self._live
            if not force and time.monotonic() - at < MODEL_CACHE_S:
                return roles
        try:
            with self._request("/v1/models", None, {}, 10) as r:
                roles = {m["id"] for m in json.loads(r.read())["data"]}
        except (urllib.error.URLError, OSError, ValueError, KeyError):
            return self._live[1]  # keep the last answer: a gateway blip must not empty the list
        with self._lock:
            self._live = (time.monotonic(), roles)
        return roles

    def visible_models(self) -> list[dict]:
        live = self.live_roles()
        out = []
        for m in self.cfg["models"]:
            if self.tiers[m["tier"]] in live or m["tier"] == self.cfg["always_on_tier"]:
                out.append(m)
        return out

    # -- request shaping -------------------------------------------------------------------------
    def authorize(self, auth_header: str | None) -> None:
        supplied = (auth_header or "").removeprefix("Bearer ").strip()
        if not supplied or not hmac.compare_digest(supplied.encode(), self.token.encode()):
            raise ShimError(401, "missing or invalid bearer token", "invalid_api_key")

    def resolve(self, requested: str) -> tuple[dict, str]:
        model = self.models.get(requested)
        live_ids = [m["id"] for m in self.visible_models()]
        if model is None or model["id"] not in live_ids:
            raise ShimError(
                404,
                f"unknown or not-yet-live model {requested!r}; live models: {', '.join(live_ids)}",
                "model_not_found",
            )
        return model, self.tiers[model["tier"]]

    def retrieve(self, query: str) -> str:
        ctx = self.cfg.get("context") or {}
        if not ctx.get("url") or not query.strip():
            return ""
        body = {
            "text": query[:2000],
            "allowed": ctx["allowed"],
            "budget": ctx.get("top_k", 4),
            "ceiling": ctx["ceiling"],
        }
        try:
            req = urllib.request.Request(
                ctx["url"].rstrip("/") + "/v1/query",
                data=json.dumps(body).encode(),
                headers={
                    "Authorization": "Bearer " + self.context_token,
                    "Content-Type": "application/json",
                },
            )
            with urllib.request.urlopen(req, timeout=ctx.get("timeout_s", 8)) as r:
                hits = json.loads(r.read()).get("hits", [])
        except (urllib.error.URLError, OSError, ValueError):
            return ""  # retrieval is an extra: the chat answers without it
        return format_passages(hits, ctx["ceiling"], ctx.get("max_passage_chars", 1500))

    def shape(self, body: dict, model: dict, role: str) -> dict:
        msgs = [dict(m) for m in body.get("messages") or []]
        if (
            not msgs
            or msgs[-1].get("role") != "user"
            or not message_text(msgs[-1].get("content")).strip()
        ):
            raise ShimError(400, "the last message must be a non-empty user message")
        msgs, _ = trim_history(msgs, int(self.cfg["history_chars"]))
        extra: list[dict] = []
        persona = model.get("persona", self.cfg.get("persona", ""))
        if persona:
            extra.append({"role": "system", "content": persona})
        if model.get("context", False):
            passages = self.retrieve(message_text(msgs[-1]["content"]))
            if passages:
                extra.append(
                    {
                        "role": "system",
                        "content": "Passages from the lab's own records (cite the id in brackets when you use one):\n\n"
                        + passages,
                    }
                )
        out = dict(body)
        out["model"] = role
        out["messages"] = extra + msgs
        return out

    def upstream_headers(self, inbound: Mapping[str, str]) -> dict[str, str]:
        tlp = inbound.get("X-HNX-TLP") or self.cfg["default_tlp"]
        if tlp_rank(tlp) > tlp_rank(self.cfg["max_tlp"]):
            raise ShimError(
                400, f"X-HNX-TLP {tlp!r} is above this front's ceiling {self.cfg['max_tlp']!r}"
            )
        return {"X-HNX-TLP": tlp, "X-HNX-Tag": inbound.get("X-HNX-Tag") or self.cfg["default_tag"]}


def make_handler(shim: Shim):
    class Handler(BaseHTTPRequestHandler):
        server_version = "hnx-concierge"
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt: str, *args: Any) -> None:  # no prompt text in the log
            sys.stderr.write("{} {}\n".format(self.command, self.path.split("?")[0]))

        def _json(self, status: int, doc: dict) -> None:
            data = json.dumps(doc).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _error(self, e: ShimError) -> None:
            self._json(
                e.status,
                {"error": {"message": e.message, "type": "invalid_request_error", "code": e.code}},
            )

        def do_GET(self) -> None:
            try:
                if self.path == "/health":
                    return self._json(200, {"status": "ok"})
                shim.authorize(self.headers.get("Authorization"))
                if self.path == "/v1/models":
                    now = int(time.time())
                    return self._json(
                        200,
                        {
                            "object": "list",
                            "data": [
                                {
                                    "id": m["id"],
                                    "object": "model",
                                    "created": now,
                                    "owned_by": "concierge",
                                }
                                for m in shim.visible_models()
                            ],
                        },
                    )
                raise ShimError(404, "not found", "not_found")
            except ShimError as e:
                self._error(e)

        def do_POST(self) -> None:
            try:
                shim.authorize(self.headers.get("Authorization"))
                if self.path != "/v1/chat/completions":
                    raise ShimError(404, "not found", "not_found")
                n = int(self.headers.get("Content-Length") or 0)
                if n <= 0 or n > int(shim.cfg["max_body_bytes"]):
                    raise ShimError(413 if n > 0 else 400, "request body missing or too large")
                try:
                    body = json.loads(self.rfile.read(n))
                except ValueError:
                    raise ShimError(400, "the body is not JSON") from None
                model, role = shim.resolve(str(body.get("model") or ""))
                up_body = shim.shape(body, model, role)
                headers = shim.upstream_headers(
                    {
                        "X-HNX-TLP": self.headers.get("X-HNX-TLP", ""),
                        "X-HNX-Tag": self.headers.get("X-HNX-Tag", ""),
                    }
                )
                self._forward(up_body, headers, bool(body.get("stream")), model["id"])
            except ShimError as e:
                self._error(e)

        def _forward(self, up_body: dict, headers: dict, stream: bool, model_id: str) -> None:
            try:
                resp = shim._request(
                    "/v1/chat/completions", up_body, headers, float(shim.cfg["timeout_s"])
                )
            except urllib.error.HTTPError as e:
                # the gateway's own refusal (a limit, a ceiling, a role) is passed on as it is
                data = e.read()
                self.send_response(e.code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
            except (urllib.error.URLError, OSError):
                raise ShimError(502, "the gateway did not answer", "upstream_unavailable") from None
            with resp:
                if not stream:
                    doc = json.loads(resp.read())
                    doc["model"] = model_id
                    return self._json(200, doc)
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "close")
                self.end_headers()
                for line in resp:  # SSE lines, passed through as they arrive
                    self.wfile.write(line)
                    self.wfile.flush()
                self.close_connection = True

    return Handler


def load(path: str) -> Shim:
    with open(path, encoding="utf-8") as f:
        cfg = json.load(f)
    env = os.environ
    for need in ("CONCIERGE_GATEWAY_KEY", "CONCIERGE_TOKEN"):
        if not env.get(need):
            raise SystemExit(f"concierge: {need} is not set")
    if cfg.get("context", {}).get("url") and not env.get("CONCIERGE_CONTEXT_TOKEN"):
        raise SystemExit(
            "concierge: a context service is configured but CONCIERGE_CONTEXT_TOKEN is not set"
        )
    return Shim(
        cfg,
        env["CONCIERGE_GATEWAY_KEY"],
        env["CONCIERGE_TOKEN"],
        env.get("CONCIERGE_CONTEXT_TOKEN", ""),
    )


def healthcheck(port: int) -> int:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=5) as r:
            return 0 if r.status == 200 else 1
    except OSError:
        return 1


def main(argv: list[str]) -> int:
    path = os.environ.get("CONCIERGE_CONFIG", "/etc/concierge/config.json")
    if "--healthcheck" in argv:
        return healthcheck(int(json.load(open(path))["port"]))
    shim = load(path)
    server = ThreadingHTTPServer(
        (shim.cfg.get("bind", "0.0.0.0"), int(shim.cfg["port"])), make_handler(shim)
    )
    server.daemon_threads = True
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
