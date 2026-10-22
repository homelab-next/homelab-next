#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Stands in for ``hermes`` under the LLM orchestrator, for the ``orchestration`` conformance run.

The controller runs every profiled job as ``hermes -z PROMPT [--toolsets T] [--usage-file F]``
(``internal/hermesagent/invoker.go:239-247`` at ``a52a1c4``), where PROMPT starts with the job's
``task_description`` (``internal/hermesagent/prompt.go:153``).  The adapter
(``homelabnext.conform.adapters.llm_orchestrator``) puts one job line into that description:
``hnx-conform-job:<base64url JSON>`` naming its loopback handler host, the job and its parameters.
This script finds the line, asks the handler host to run the job's handler, and answers the way
hermes does:

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
import json
import sys
import urllib.error
import urllib.request
from collections.abc import Callable, Sequence
from typing import Any

#: the job line prefix; homelabnext.conform.adapters.llm_orchestrator.JOB_MARKER is the same
JOB_MARKER = "hnx-conform-job:"
CALL_TIMEOUT_S = 120.0


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


def _post(url: str, body: dict[str, Any]) -> dict[str, Any]:
    # the handler host is always loopback; never route it through a proxy from the environment
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
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
    if job is None or not isinstance(job.get("callback"), str):
        return 1, "", f"no {JOB_MARKER} line in the prompt: not a conformance job"
    body = {k: job.get(k) for k in ("secret", "token", "job", "params")}
    try:
        answer = _call(post, job["callback"].rstrip("/") + "/run", body)
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
