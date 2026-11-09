#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""A body the agent-runner suite runs under a launcher in place of the provider's, to check the
launcher's own rules whatever the runtime does.

    agent_runner_probe.py MODE [ARG...]

The modes:
- ``exit N`` exits with status N after an ``end`` record;
- ``dump`` writes what it can see (argv, environment, the spec, the input names) to its answer;
- ``records N`` writes N ``call`` records it never made, then sleeps;
- ``spin`` burns CPU with no model call;
- ``oversize N`` writes N bytes of valid records, then sleeps;
- ``long-line`` writes one 17 KiB record;
- ``deep`` writes a record nested past 8;
- ``spaced N`` makes N model calls 0.15 s apart, each written as a record in JSON with spaces
  (``json.dumps``'s default), then ends cleanly;
- ``plant`` writes a clean-exit record where a launcher might read one (the run's root), then
  exits 3;
- ``claim CLASS`` ends with that class after the calls its following arguments ask for:
  ``ok`` (a call the gateway answers) or ``rejected`` (a call it refuses with 400
  ``upstream_rejected``), in order, then exits 1.

Standard library only (``python3 -I``).
"""

from __future__ import annotations

import contextlib
import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.request


def _cred(name: str) -> bytes:
    with open(os.path.join(os.environ["CREDENTIALS_DIRECTORY"], name), "rb") as f:
        return f.read()


def _write(line: str) -> None:
    with open(os.path.join(os.environ["HNX_RUN_DIR"], "usage.jsonl"), "a", encoding="utf-8") as f:
        f.write(line + "\n")


def _call(spec: dict, key: str, answer: str) -> None:
    url = spec["target"]["gateway_url"].rstrip("/") + "/v1/chat/completions"
    span = secrets.token_hex(8)
    req = urllib.request.Request(
        url,
        method="POST",
        data=json.dumps(
            {
                "model": spec["target"]["model_role"],
                "messages": [{"role": "user", "content": answer}],
            }
        ).encode(),
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "X-HNX-Tag": spec["gateway_tag"],
            "traceparent": f"00-{spec['trace'].split('-')[1]}-{span}-01",
        },
    )
    # a refusal is a call made all the same
    with contextlib.suppress(urllib.error.HTTPError), urllib.request.urlopen(req, timeout=30) as r:
        r.read()
    # json.dumps's default spacing: the launcher must read records however they are spaced
    rec = {"type": "call", "role": spec["target"]["model_role"], "sized": False, "span_id": span}
    _write(json.dumps(rec))


def main(argv: list[str]) -> int:
    mode, args = argv[0], argv[1:]
    spec = json.loads(_cred("spec"))
    if mode == "exit":
        _write(json.dumps({"type": "end", "turns": 0}))
        return int(args[0])
    if mode == "dump":
        seen = {
            "argv": sys.argv,
            "env": dict(os.environ),
            "spec": spec,
            "inputs": sorted(os.listdir(os.environ["CREDENTIALS_DIRECTORY"])),
        }
        with open(os.path.join(os.environ["HNX_RUN_DIR"], "answer"), "w", encoding="utf-8") as f:
            json.dump(seen, f)
        _write(json.dumps({"type": "end", "turns": 0}))
        return 0
    if mode == "records":
        for _ in range(int(args[0])):
            _write(
                json.dumps(
                    {"type": "call", "role": "r", "sized": False, "span_id": secrets.token_hex(8)}
                )
            )
            time.sleep(0.05)
        time.sleep(3600)
    if mode == "spin":
        end = time.monotonic() + 3600
        while time.monotonic() < end:
            pass
    if mode == "oversize":
        rec = json.dumps({"type": "signal", "signal": "backend_absent"})
        for _ in range(int(args[0]) // (len(rec) + 1) + 1):
            _write(rec)
        time.sleep(3600)
    if mode == "long-line":
        _write(json.dumps({"type": "end", "session_id": "s", "turns": 0, "pad": "x" * 17000}))
        return 0
    if mode == "deep":
        deep: dict = {"type": "end", "turns": 0}
        for _ in range(9):
            deep = {"x": deep}
        _write(json.dumps(deep))
        return 0
    if mode == "plant":
        root = os.path.dirname(os.environ["HNX_RUN_DIR"].rstrip("/"))
        planted = os.path.join(root, "exit.json")
        with contextlib.suppress(OSError), open(planted, "w", encoding="ascii") as f:
            json.dump({"stopped": False, "code": 0}, f)
        _write(json.dumps({"type": "end", "turns": 0}))
        return 3
    if mode == "spaced":
        key = _cred("gateway-key").decode().strip()
        for i in range(int(args[0])):
            _call(spec, key, f"ok-{i}")
            time.sleep(0.15)
        _write(json.dumps({"type": "end", "turns": int(args[0])}))
        return 0
    if mode == "claim":
        key = _cred("gateway-key").decode().strip()
        for i, kind in enumerate(args[1:]):
            _call(spec, key, f"{kind}-{i}")
        _write(json.dumps({"type": "end", "turns": len(args) - 1, "class": args[0]}))
        return 1
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
