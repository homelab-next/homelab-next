#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The development launcher's per-run supervisor: what the unit's cgroup is under the unit
launcher (ADR-0051 decisions 7 and 9), for a host with no systemd.

    agent_runner_supervisor.py EXIT_FILE [--group-only] -- BODY [ARG...]

It makes itself a child subreaper (``PR_SET_CHILD_SUBREAPER``), so a descendant that calls
``setsid`` and whose parent exits is re-parented to it, and starts the body in a session of its
own. When the body exits, or on SIGTERM (the launcher's stop), it kills every descendant left,
the re-parented ones included, and reaps them, as a unit's stop ends its whole cgroup. It writes
how the body ended to EXIT_FILE (``{"code": N}`` or ``{"signal": N}``, and ``"stopped": true``
when the launcher stopped it), then exits.

``--group-only`` is the suite's defective launcher: it kills only the body's process group, so a
``setsid`` descendant outlives the session. Linux only; standard library only (``python3 -I``).
"""

from __future__ import annotations

import contextlib
import ctypes
import json
import os
import signal
import subprocess
import sys

PR_SET_CHILD_SUBREAPER = 36


def _descendants(root: int) -> list[int]:
    children: dict[int, list[int]] = {}
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        try:
            with open(f"/proc/{name}/stat", encoding="ascii", errors="replace") as f:
                ppid = int(f.read().rsplit(")", 1)[1].split()[1])
        except (OSError, IndexError, ValueError):
            continue
        children.setdefault(ppid, []).append(int(name))
    out, todo = [], list(children.get(root, []))
    while todo:
        pid = todo.pop()
        out.append(pid)
        todo.extend(children.get(pid, []))
    return out


def _sweep(body: subprocess.Popen, group_only: bool) -> None:
    if group_only:
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(body.pid, signal.SIGKILL)
    else:
        for _ in range(50):  # a fork racing the sweep is caught by the next pass
            pids = _descendants(os.getpid())
            if not pids:
                break
            for pid in pids:
                with contextlib.suppress(ProcessLookupError, PermissionError):
                    os.kill(pid, signal.SIGKILL)
            _reap()
    _reap()


def _reap() -> None:
    while True:
        try:
            pid, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        if pid == 0:
            return


def main(argv: list[str]) -> int:
    exit_file = argv[0]
    group_only = "--group-only" in argv[: argv.index("--")]
    cmd = argv[argv.index("--") + 1 :]
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
        print("agent_runner_supervisor: cannot become a child subreaper", file=sys.stderr)
        return 70
    stopped = {"yes": False}
    body = subprocess.Popen(cmd, start_new_session=True)

    def stop(signum, frame):
        stopped["yes"] = True
        _sweep(body, group_only)

    signal.signal(signal.SIGTERM, stop)
    while True:
        try:
            _, status = os.waitpid(body.pid, 0)
            break
        except ChildProcessError:
            status = 0
            break
        except InterruptedError:
            continue
    _sweep(body, group_only)
    ended: dict[str, object] = {"stopped": stopped["yes"]}
    if os.WIFSIGNALED(status):
        ended["signal"] = os.WTERMSIG(status)
    else:
        ended["code"] = os.WEXITSTATUS(status)
    # read by the launcher only after this process has exited, so a plain write is whole
    with open(exit_file, "w", encoding="ascii") as f:
        json.dump(ended, f)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
