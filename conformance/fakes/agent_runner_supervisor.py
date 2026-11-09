#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The development launcher's per-run supervisor: what the unit's cgroup is under the unit
launcher (ADR-0051 decisions 7 and 9), for a host with no systemd.

    agent_runner_supervisor.py EXIT_FILE [--group-only] -- BODY [ARG...]

It makes itself a child subreaper (``PR_SET_CHILD_SUBREAPER``), so a descendant that calls
``setsid`` and whose parent exits is re-parented to it, and starts the body in a session of its
own. When the body exits, or on SIGTERM (the launcher's stop), it kills every descendant left,
the re-parented ones included, and reaps them, as a unit's stop ends its whole cgroup. It writes
how the body ended to EXIT_FILE, a new file it creates (``{"code": N}`` or ``{"signal": N}``,
``"stopped": true`` when the launcher stopped it, and ``"survivors"`` naming any process still
alive after its sweep), then exits. It keeps the body's status whoever reaps it, and signals a
process only through a pidfd after checking through it that the process is still its
descendant.

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


#: the body's wait status, whoever reaps it: the SIGTERM handler's sweep reaps every child it
#: can, the body included, so the main loop must not take a missing child for a clean exit
BODY: dict[str, int | None] = {"pid": None, "status": None}


def _ppid(pid: int) -> int | None:
    try:
        with open(f"/proc/{pid}/stat", encoding="ascii", errors="replace") as f:
            return int(f.read().rsplit(")", 1)[1].split()[1])
    except (OSError, IndexError, ValueError):
        return None


def _kill(pid: int, ours: set[int]) -> None:
    """SIGKILL ``pid`` through a pidfd, after checking through it that ``pid`` is still one of
    ours (its parent is this supervisor or another of its descendants): a pid freed and reused
    between the scan and the signal is never signalled."""
    try:
        fd = os.pidfd_open(pid)
    except (ProcessLookupError, OSError):
        return
    try:
        if _ppid(pid) in ours:
            with contextlib.suppress(ProcessLookupError):
                signal.pidfd_send_signal(fd, signal.SIGKILL)
    finally:
        os.close(fd)


def _sweep(body: subprocess.Popen, group_only: bool) -> list[int]:
    """Kill and reap what is left of the run; the pids still alive after it (none, normally)."""
    if group_only:
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(body.pid, signal.SIGKILL)
        _reap()
        return []
    me = os.getpid()
    for _ in range(50):  # a fork racing the sweep is caught by the next pass
        pids = _descendants(me)
        if not pids:
            break
        ours = {me, *pids}
        for pid in pids:
            _kill(pid, ours)
        _reap()
    _reap()
    return [p for p in _descendants(me) if _alive(p)]


def _alive(pid: int) -> bool:
    try:
        with open(f"/proc/{pid}/stat", encoding="ascii", errors="replace") as f:
            return f.read().rsplit(")", 1)[1].split()[0] not in ("Z", "X")
    except (OSError, IndexError):
        return False


def _reap() -> None:
    while True:
        try:
            pid, status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        if pid == 0:
            return
        if pid == BODY["pid"]:
            BODY["status"] = status


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
    BODY["pid"] = body.pid
    survivors: list[int] = []

    def stop(signum, frame):
        stopped["yes"] = True
        survivors.extend(_sweep(body, group_only))

    signal.signal(signal.SIGTERM, stop)
    while BODY["status"] is None:
        try:
            _, BODY["status"] = os.waitpid(body.pid, 0)
        except ChildProcessError:
            break  # the handler's sweep reaped it, and kept its status
        except InterruptedError:
            continue
    survivors.extend(_sweep(body, group_only))
    ended: dict[str, object] = {"stopped": stopped["yes"]}
    status = BODY["status"]
    if status is None:
        ended["lost"] = True  # nothing kept the body's status: never a clean exit
    elif os.WIFSIGNALED(status):
        ended["signal"] = os.WTERMSIG(status)
    else:
        ended["code"] = os.WEXITSTATUS(status)
    if survivors:
        ended["survivors"] = sorted(set(survivors))
    # a new file only: never through a link a body planted, never over one that is there
    fd = os.open(exit_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as f:
        json.dump(ended, f)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
