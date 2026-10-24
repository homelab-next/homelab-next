#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Stands in for ``hermes`` under the LLM orchestrator, for the ``orchestration`` conformance run.

The controller runs every profiled job as ``hermes -z PROMPT [--toolsets T] [--usage-file F]``
(``internal/hermesagent/invoker.go:239-247`` at ``a52a1c4``), where PROMPT starts with the job's
``task_description`` (``internal/hermesagent/prompt.go:153``).  The adapter
(``homelabnext.conform.adapters.llm_orchestrator``) puts one job line into that description:
``hnx-conform-job:<base64url JSON>`` naming its loopback handler host, the job and its parameters.
This script finds the line, asks the handler host to run the job's handler, and answers the way
hermes does.  The job line is controller data (any client of its API can read or write a task
description), so the only URL it ever posts to is ``/run`` on IPv4 loopback (:data:`LOOPBACK`):
a callback with another scheme (``file://`` included), host, userinfo, path or query is refused.

* success: the answer on stdout (``{"hnx_result": ...}``) and exit 0 -- the controller stores
  stdout as ``response_body`` (``internal/queue/scheduler.go:744``);
* failure: the error on stderr and exit 1 -- a non-zero exit is a failed attempt whose stderr
  ends up in ``local_failed_reason`` (``invoker.go:379-382``).

It also writes the ``--usage-file`` the controller reads back (``invoker.go:359-362``).  Install it
for a live run by linking it as ``hermes`` first on the controller's PATH (docs/orchestration-
controller.md).  Standard library only: it runs under the controller's ``python3``, not the
repository's environment.
"""

from __future__ import annotations

import base64
import functools
import json
import sys
import urllib.error
import urllib.request
from collections.abc import Callable, Sequence
from typing import Any
from urllib.parse import urlsplit

#: the job line prefix; homelabnext.conform.adapters.llm_orchestrator.JOB_MARKER is the same
JOB_MARKER = "hnx-conform-job:"
CALL_TIMEOUT_S = 120.0
#: the handler host is always on IPv4 loopback (homelabnext.conform.adapters.llm_orchestrator)
LOOPBACK = "127.0.0.1"  # no-raw-endpoint: allow the handler host is local by design


def run_url(callback: Any) -> str | None:
    """``http://<LOOPBACK>:<port>/run`` for a callback that is exactly the loopback handler host
    (``http://<LOOPBACK>:<port>``, an optional trailing ``/``), else ``None``."""
    if not isinstance(callback, str):
        return None
    try:
        parts = urlsplit(callback)
        port = parts.port
    except ValueError:
        return None
    if (
        parts.scheme != "http"
        or port is None
        or parts.netloc != f"{LOOPBACK}:{port}"  # no userinfo, no other host
        or parts.path not in ("", "/")
        or parts.query
        or parts.fragment
    ):
        return None
    return f"http://{LOOPBACK}:{port}/run"


def decode(prompt: str) -> dict[str, Any] | None:
    """The job the adapter encoded into ``prompt``, or ``None`` when there is no job line."""
    for line in prompt.splitlines():
        line = line.strip()
        if line.startswith(JOB_MARKER):
            raw = line[len(JOB_MARKER) :].strip()
            try:
                doc = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
            except ValueError:
                return None
            return doc if isinstance(doc, dict) else None
    return None


@functools.cache
def _opener() -> urllib.request.OpenerDirector:
    """One proxy-free opener per process: building one loads the CA bundle, and the conformance
    run calls this stand-in in-process for every job."""
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _post(url: str, body: dict[str, Any]) -> dict[str, Any]:
    # the handler host is always loopback; never route it through a proxy from the environment
    opener = _opener()
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with opener.open(req, timeout=CALL_TIMEOUT_S) as resp:
        doc = json.loads(resp.read())
    if not isinstance(doc, dict):
        raise ValueError("handler host answered something other than an object")
    return doc


def run(
    argv: Sequence[str], *, post: Callable[[str, dict[str, Any]], dict[str, Any]] = _post
) -> tuple[int, str, str]:
    """``(exit code, stdout, stderr)`` for one ``hermes`` invocation with arguments ``argv``."""
    prompt, usage_file = None, None
    args = list(argv)
    for i, a in enumerate(args[:-1]):
        if a == "-z":
            prompt = args[i + 1]
        elif a == "--usage-file":
            usage_file = args[i + 1]
    if prompt is None:
        return 2, "", "usage: hermes -z PROMPT [--toolsets T] [--usage-file F]"
    job = decode(prompt)
    if job is None:
        return 1, "", f"no {JOB_MARKER} line in the prompt: not a conformance job"
    url = run_url(job.get("callback"))
    if url is None:
        return 1, "", f"job callback is not http://{LOOPBACK}:<port>: refused"
    body = {k: job.get(k) for k in ("token", "mac", "job", "params")}
    try:
        answer = _call(post, url, body)
    except (OSError, ValueError) as exc:
        return 1, "", f"conformance handler host did not answer: {type(exc).__name__}: {exc}"
    if usage_file:
        try:
            with open(usage_file, "w", encoding="utf-8") as fh:
                json.dump({"session_id": f"hnx-{job.get('token')}", "completed": answer["ok"]}, fh)
        except OSError:
            pass  # the controller treats a missing usage file as "no telemetry", never a failure
    if answer.get("ok"):
        return 0, json.dumps({"hnx_result": answer.get("result")}, ensure_ascii=False) + "\n", ""
    return 1, "", str(answer.get("error") or "handler failed")


def _call(post, url: str, body: dict[str, Any]) -> dict[str, Any]:
    try:
        return post(url, body)
    except urllib.error.HTTPError as exc:
        raise ValueError(f"HTTP {exc.code}") from exc


def main() -> int:  # pragma: no cover - exercised as a subprocess in the live run
    code, out, err = run(sys.argv[1:])
    sys.stdout.write(out)
    if err:
        sys.stderr.write(err + "\n")
    return code


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
