#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""A stdio MCP server for the agent-runner suite: one JSON-RPC object per line, every
``tools/call`` answered ``ok``.

    runner_mcp_stdio.py [--mark FILE] [--spawn FILE]

``--mark FILE`` appends its pid to FILE when it starts, so the suite can tell which servers ran.
``--spawn FILE`` forks a descendant that calls ``setsid`` (leaving the session's process group),
writes its pid to FILE and sleeps: the shape of a tool that leaves a daemon behind, which a cancel
must end too. Standard library only.
"""

from __future__ import annotations

import json
import os
import sys
import time


def main(argv: list[str]) -> int:
    if "--mark" in argv:
        with open(argv[argv.index("--mark") + 1], "a", encoding="ascii") as f:
            f.write(f"{os.getpid()}\n")
    if "--spawn" in argv:
        path = argv[argv.index("--spawn") + 1]
        if os.fork() == 0:
            os.setsid()
            if os.fork() == 0:
                with open(path, "w", encoding="ascii") as f:  # the reader waits for the newline
                    f.write(f"{os.getpid()}\n")
                time.sleep(3600)
            os._exit(0)
    for line in sys.stdin:
        req = json.loads(line)
        sys.stdout.write(
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": req.get("id"),
                    "result": {"content": [{"type": "text", "text": "ok"}]},
                }
            )
        )
        sys.stdout.write("\n")
        sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
