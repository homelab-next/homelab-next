#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The agent-runner contract's reference body: a fake runtime (ADR-0051 decision 14).

It runs a session the way the contract asks a runtime to:
- read the spec, the prompt and the gateway key from ``$CREDENTIALS_DIRECTORY``;
- check the grants file ``$HNX_GRANTS_FILE`` against ``$HNX_GRANTS_SHA256`` and start only servers
  whose ids are both in the spec and in the file;
- loop on the gateway's chat completions until it answers, calling an MCP tool whenever a reply
  asks for one;
- append one record per model call and tool call to ``$HNX_RUN_DIR/usage.jsonl``, then an ``end``
  record, and write the answer to ``$HNX_RUN_DIR/answer``.

A tool name is ``<server id>__<tool>``. A ``_meta.traceparent`` goes only to a server whose
locality is ``local``. Every model call carries the bearer key, ``X-HNX-Tag``, a ``traceparent``
with the run's trace id and a fresh span id, and the gateway run token when the spec names one.

Its exit statuses are the ones :data:`EXIT_CLASSES` maps:
- the gateway unreachable is ``BackendFault``;
- a ``429 concurrency_limited`` is ``ConcurrencyLimited``;
- a failure it reports in its ``end`` record is ``TurnFailed``, which that record's class
  overrides;
- a spec or grants file it refuses is 70, which nothing maps (``Internal``).

``--mutant NAME`` makes it one of the suite's deliberately defective bodies (see
``conformance/suites/agent_runner.py``). Standard library only: it runs as ``python3 -I`` under
the launcher, outside the repository's environment.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request
from typing import Any

EXIT_BACKEND = 69
EXIT_CONCURRENCY = 75
EXIT_REPORTED = 1
EXIT_REFUSED = 70
#: the provider manifest's exit_classes for this body
EXIT_CLASSES = {
    EXIT_BACKEND: "BackendFault",
    EXIT_CONCURRENCY: "ConcurrencyLimited",
    EXIT_REPORTED: "TurnFailed",
}
CALL_TIMEOUT_S = 60.0
MUTANTS = (
    "drops-meta",
    "meta-to-non-local",
    "backend-key",
    "other-profile-key",
    "runs-spec-command",
    "starts-unlisted-server",
    "unsized-call-omitted",
)


def _cred(name: str) -> bytes:
    with open(os.path.join(os.environ["CREDENTIALS_DIRECTORY"], name), "rb") as f:
        return f.read()


class Stream:
    def __init__(self, path: str) -> None:
        self.f = open(path, "a", encoding="utf-8")  # noqa: SIM115 - open for the session

    def write(self, rec: dict[str, Any]) -> None:
        self.f.write(json.dumps(rec, separators=(",", ":")) + "\n")
        self.f.flush()


class Stdio:
    """A started stdio MCP server, one JSON-RPC object per line."""

    def __init__(self, server: dict[str, Any]) -> None:
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), **(server.get("env") or {})}
        self.p = subprocess.Popen(
            [server["command"], *(server.get("args") or [])],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            env=env,
            text=True,
        )
        self.n = 0

    def call(self, params: dict[str, Any]) -> dict[str, Any]:
        self.n += 1
        assert self.p.stdin and self.p.stdout
        self.p.stdin.write(
            json.dumps({"jsonrpc": "2.0", "id": self.n, "method": "tools/call", "params": params})
            + "\n"
        )
        self.p.stdin.flush()
        return json.loads(self.p.stdout.readline() or "{}")


def _http_call(url: str, params: dict[str, Any]) -> dict[str, Any]:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params})
    req = urllib.request.Request(
        url, data=body.encode(), method="POST", headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=CALL_TIMEOUT_S) as r:
        return json.loads(r.read() or b"{}")


def main(argv: list[str]) -> int:
    mutant = argv[argv.index("--mutant") + 1] if "--mutant" in argv else ""
    spec = json.loads(_cred("spec"))
    prompt = _cred("prompt").decode("utf-8", "replace")
    key = _cred("gateway-key").decode().strip()
    if mutant == "backend-key":
        key = "key-backend-home"  # what a backend's home held before per-run keys
    elif mutant == "other-profile-key":
        key = "key-another-profile"
    token = None
    if (spec.get("credentials") or {}).get("run_tokens", {}).get("gateway"):
        token = _cred("run-token-gateway").decode().strip()
    out = os.environ["HNX_RUN_DIR"]

    raw = open(os.environ["HNX_GRANTS_FILE"], "rb").read()  # noqa: SIM115
    if "sha256:" + hashlib.sha256(raw).hexdigest() != os.environ.get("HNX_GRANTS_SHA256"):
        print("agent_runner_body: the grants file does not match its pin", file=sys.stderr)
        return EXIT_REFUSED
    grants = json.loads(raw)["servers"]
    wanted = list(spec.get("servers") or [])
    if mutant == "starts-unlisted-server":
        wanted = list(grants)  # every server of the file, whatever the spec names
    elif any(s not in grants for s in wanted):
        print("agent_runner_body: the spec names a server the grants file lacks", file=sys.stderr)
        return EXIT_REFUSED
    if mutant == "runs-spec-command":
        for s in spec.get("servers") or []:
            if isinstance(s, dict) and s.get("command"):
                subprocess.run([s["command"], *(s.get("args") or [])], check=False)
        wanted = [s for s in wanted if isinstance(s, str) and s in grants]
    stdio = {s: Stdio(grants[s]) for s in wanted if grants[s]["transport"] == "stdio"}

    stream = Stream(os.path.join(out, "usage.jsonl"))
    trace_id = spec["trace"].split("-")[1]
    role = spec["target"]["model_role"]
    url = spec["target"]["gateway_url"].rstrip("/") + "/v1/chat/completions"
    messages: list[dict[str, Any]] = [{"role": "user", "content": prompt}]
    max_turns = spec["limits"]["max_turns"]
    turns = 0
    while True:
        if max_turns and turns >= max_turns:
            stream.write({"type": "end", "turns": turns, "class": "TurnCap"})
            return EXIT_REPORTED
        turns += 1
        span = secrets.token_hex(8)
        headers = {
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "X-HNX-Tag": spec["gateway_tag"],
            "traceparent": f"00-{trace_id}-{span}-01",
        }
        if token:
            headers["X-HNX-Run-Token"] = token
        req = urllib.request.Request(
            url,
            method="POST",
            headers=headers,
            data=json.dumps({"model": role, "messages": messages}).encode(),
        )
        try:
            with urllib.request.urlopen(req, timeout=CALL_TIMEOUT_S) as r:
                reply = json.loads(r.read())
        except urllib.error.HTTPError as e:
            doc = json.loads(e.read() or b"{}").get("error") or {}
            code = doc.get("code")
            if code == "concurrency_limited":
                stream.write({"type": "end", "turns": turns, "class": "ConcurrencyLimited"})
                return EXIT_CONCURRENCY
            if code == "run_budget_exhausted":
                stream.write(
                    {
                        "type": "end",
                        "turns": turns,
                        "budget_exhausted": doc.get("budget", "tool_calls"),
                    }
                )
                return EXIT_REPORTED
            if code == "upstream_rejected" and e.code == 400:
                stream.write({"type": "end", "turns": turns, "class": "ContextExceeded"})
                return EXIT_REPORTED
            stream.write({"type": "end", "turns": turns})
            return EXIT_REPORTED
        except (urllib.error.URLError, OSError):
            return EXIT_BACKEND
        usage = reply.get("usage")
        if usage:
            stream.write(
                {
                    "type": "call",
                    "role": role,
                    "sized": True,
                    "input_tokens": usage["prompt_tokens"],
                    "output_tokens": usage["completion_tokens"],
                    "span_id": span,
                }
            )
        elif mutant != "unsized-call-omitted":
            stream.write({"type": "call", "role": role, "sized": False, "span_id": span})
        msg = reply["choices"][0]["message"]
        calls = msg.get("tool_calls") or []
        if not calls:
            with open(os.path.join(out, "answer"), "w", encoding="utf-8") as f:
                f.write(msg.get("content") or "")
            stream.write({"type": "end", "session_id": reply.get("id", "s"), "turns": turns})
            return 0
        messages.append(msg)
        for c in calls:
            server, _, tool = c["function"]["name"].partition("__")
            params: dict[str, Any] = {
                "name": tool,
                "arguments": json.loads(c["function"].get("arguments") or "{}"),
            }
            local = grants.get(server, {}).get("locality") == "local"
            send_meta = local != (mutant == "meta-to-non-local") and mutant != "drops-meta"
            if send_meta:
                params["_meta"] = {"traceparent": f"00-{trace_id}-{secrets.token_hex(8)}-01"}
            started, t0 = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), time.monotonic()
            outcome = "ok"
            try:
                if server not in wanted:
                    outcome, res = "refused", {}
                elif server in stdio:
                    res = stdio[server].call(params)
                else:
                    res = _http_call(grants[server]["url"], params)
                if "error" in res:
                    outcome = "error"
            except (OSError, ValueError):
                outcome, res = "error", {}
            stream.write(
                {
                    "type": "tool_call",
                    "server": server,
                    "tool": tool,
                    "start": started,
                    "duration_ms": int((time.monotonic() - t0) * 1000),
                    "outcome": outcome,
                    "span_id": secrets.token_hex(8),
                }
            )
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": c.get("id", ""),
                    "content": json.dumps(res.get("result", {})),
                }
            )


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
