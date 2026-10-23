# SPDX-License-Identifier: Apache-2.0
"""Helpers shared by the suites."""

from __future__ import annotations

import contextlib
import functools
import itertools
import os
import sys
from collections.abc import Callable
from typing import Any

_COUNTER = itertools.count(1)


def nonce() -> str:
    """Run-scoped token that namespaces what checks create.  Set ``HNX_CONFORM_NONCE`` when
    several runs share one real service; the default keeps fake runs deterministic."""
    return os.environ.get("HNX_CONFORM_NONCE", "r0")


def uniq(prefix: str) -> str:
    return f"{prefix}-{nonce()}-{next(_COUNTER)}"


_DOC_NETS = ("192.0.2", "198.51.100", "203.0.113")  # RFC 5737 documentation ranges


def ip(host: int, net: int = 0) -> str:
    """An RFC 5737 documentation address: ``net`` 0 = 192.0.2/24, 1 = 198.51.100/24, 2 = 203.0.113/24."""
    return f"{_DOC_NETS[net]}.{host}"


def raises(fn: Callable[[], Any], what: str, *types: type[BaseException]) -> BaseException:
    """Call ``fn`` and return the exception it raises; fail the check if it does not raise."""
    catch = types or (Exception,)
    try:
        out = fn()
    except catch as exc:
        return exc
    raise AssertionError(f"{what}: expected an error, got {out!r}")


def exc_text(exc: BaseException) -> str:
    """Everything a caller can read off an exception: the formatted traceback, and for every
    exception on the chain (``__cause__`` and ``__context__``, suppressed or not) its ``str``,
    ``repr``, ``args`` and attributes.  Leak checks search this, not just ``str(exc)``."""
    import traceback

    parts = ["".join(traceback.format_exception(exc))]
    seen: set[int] = set()
    todo: list[BaseException | None] = [exc]
    while todo:
        e = todo.pop()
        if e is None or id(e) in seen:
            continue
        seen.add(id(e))
        parts += [str(e), repr(e), repr(e.args)]
        with contextlib.suppress(TypeError):
            parts.append(repr(vars(e)))
        parts += [repr(n) for n in getattr(e, "__notes__", ())]
        todo += [e.__cause__, e.__context__]
    return "\n".join(parts)


def expires(subject: Any, still_valid: Callable[[], bool], ttl: float) -> bool:
    """Let ``ttl`` seconds pass and report whether ``still_valid()`` turned False.

    With the ``clock-control`` hook (a ``tick(seconds)`` method) the clock is advanced; without
    it the check waits in real time (keep ``ttl`` to a second), polling so a precise
    implementation returns quickly and a whole-second one gets one second of grace.  Expiry is a
    MUST either way: not offering the hook only makes the check slower.
    """
    import time

    tick = getattr(subject, "tick", None)
    if callable(tick):
        tick(ttl + 1)
        return not still_valid()
    deadline = time.monotonic() + ttl + 1.5
    time.sleep(ttl)
    while time.monotonic() < deadline:
        if not still_valid():
            return True
        time.sleep(0.05)
    return not still_valid()


# ---- deterministic interleaving: two operations, the first paused at chosen points ---------------


def _lib_dirs() -> tuple[tuple[str, ...], tuple[str, ...]]:
    import sysconfig

    paths = sysconfig.get_paths()
    lib = tuple({os.path.realpath(paths[k]) + os.sep for k in ("stdlib", "platstdlib")})
    site = tuple({os.path.realpath(paths[k]) + os.sep for k in ("purelib", "platlib")})
    return lib, site


class Inconclusive(Exception):
    """The race could not be judged (a thread did not finish): not a pass and not a failure."""


class _Paused:
    """Runs ``fn`` in a thread that stops before its ``at``-th traced line (never, for ``at=0``).

    ``where(filename)`` says whether a frame is traced (None: not traced) and whether it is the
    subject's own package (True) or other source it calls (False).  ``seen`` maps each traced
    line location to the first line number (count) at which it ran, and whether it is own code.

    The thread installs its own ``sys.settrace``: while it runs, a coverage tracer or debugger
    that uses ``settrace`` does not see that thread's lines (``sys.monitoring`` tools do)."""

    def __init__(self, fn: Callable[[], Any], at: int, where: Callable[[str], bool | None]) -> None:
        import threading

        self.fn, self.at, self.where = fn, at, where
        self.lines = 0
        self.seen: dict[tuple[str, int], tuple[int, bool]] = {}
        self.result: tuple[bool, Any] = (False, None)
        self.stopped = threading.Event()  # paused at ``at``, or finished
        self.resume = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _tracer(self, own: bool) -> Callable[..., Any]:
        def line(frame: Any, event: str, arg: Any) -> Any:
            if event == "line":
                self.lines += 1
                self.seen.setdefault((frame.f_code.co_filename, frame.f_lineno), (self.lines, own))
                if self.lines == self.at:
                    self.stopped.set()
                    self.resume.wait()
            return line

        return line

    def _call(self, frame: Any, event: str, arg: Any) -> Any:
        own = self.where(frame.f_code.co_filename)
        return None if own is None else self._tracer(own)

    def _run(self) -> None:
        sys.settrace(self._call)
        try:
            self.result = (True, self.fn())
        except BaseException as exc:  # the subject's error is the outcome being judged
            self.result = (False, exc)
        finally:
            sys.settrace(None)
            self.stopped.set()


def _spread(items: list[int], limit: int) -> list[int]:
    if len(items) <= limit:
        return items
    return [items[(i * (len(items) - 1)) // (limit - 1)] for i in range(limit)]


def interleavings(
    subject: Any,
    setup: Callable[[], tuple[Callable[[], Any], Callable[[], Any], Callable[..., None]]],
    *,
    own_limit: int = 32,
    other_limit: int = 4,
    blocked_after: float = 0.5,
    give_up_after: float = 60.0,
) -> int:
    """Race two operations under a deterministic schedule, never decided by timing.

    ``setup()`` prepares fresh state and returns ``(first, second, judge)``.  ``first`` runs in a
    thread that is stopped before one chosen line; ``second`` then runs to completion, ``first``
    resumes, and ``judge((ok1, out1), (ok2, out2))`` asserts on the outcome (``ok`` False means
    ``out`` is the exception raised).  An unpaused run finds the candidate lines, so the same
    subject is raced at the same places every time:

    * every distinct line of the subject's own top-level package (the package that defines its
      class, wherever it is installed, site-packages included), up to ``own_limit`` spread evenly;
    * ``other_limit`` distinct lines spread over other source it calls that is neither the
      standard library nor site-packages (a library in a checkout, a second top-level module).

    What this can catch is a *single preemption*: a window between a check and an act inside one
    operation, which the other operation, run whole, falls into.  It cannot catch a race that
    needs both operations preempted (a lock file taken by check-then-create, two renames that
    interleave line by line), races on the far side of a network call, or windows in code it
    does not trace (the standard library, other site-packages, C).  A pass is evidence, not
    proof.

    When ``second`` has not finished ``blocked_after`` seconds after ``first`` stopped (it waits
    on a lock the paused ``first`` holds, or it is slow), ``first`` is resumed and the pair is
    judged as it ends; exploration goes on at the next point.  That wait only changes which
    schedule ran, never the verdict, and ``judge`` must accept the outcome a held lock can cause
    (a correct loser timing out).  A thread that is still running ``give_up_after`` seconds after
    the resume raises :class:`Inconclusive`.  Fewer than two candidate lines also raises
    :class:`Inconclusive`: such a run would prove nothing.  Returns the number of schedules run.
    """
    import threading

    lib, site = _lib_dirs()
    pkg = type(subject).__module__.split(".")[0]
    top = sys.modules.get(pkg)
    roots = [os.path.realpath(d) + os.sep for d in getattr(top, "__path__", ())]
    own_files = {os.path.realpath(getattr(top, "__file__", None) or "") if not roots else ""}
    suites = os.path.dirname(os.path.realpath(__file__)) + os.sep

    @functools.cache
    def where(filename: str) -> bool | None:
        if filename.startswith("<"):
            return None
        path = os.path.realpath(filename)
        if path.startswith(suites):
            return None  # the suites are not the subject
        if path in own_files or any(path.startswith(r) for r in roots):
            return True
        if path.startswith(site) or path.startswith(lib):
            return None  # libraries are not the subject's code
        return False

    def race(at: int) -> _Paused:
        first, second, judge = setup()
        a = _Paused(first, at, where)
        a.thread.start()
        if not a.stopped.wait(give_up_after):
            raise Inconclusive(f"the first operation neither paused nor ended in {give_up_after}s")
        out2: list[tuple[bool, Any]] = []

        def run_second() -> None:
            try:
                out2.append((True, second()))
            except BaseException as exc:  # judged below
                out2.append((False, exc))

        b = threading.Thread(target=run_second, daemon=True)
        b.start()
        if a.thread.is_alive():
            b.join(blocked_after)  # a lock the paused first holds: resume it, never wait it out
        a.resume.set()
        a.thread.join(give_up_after)
        b.join(give_up_after)
        if a.thread.is_alive() or b.is_alive():
            raise Inconclusive(f"an operation was still running {give_up_after}s after the resume")
        judge(a.result, out2[0])
        return a

    plain = race(0)
    own = sorted(n for n, is_own in plain.seen.values() if is_own)
    other = sorted(n for n, is_own in plain.seen.values() if not is_own)
    points = sorted({*_spread(own, own_limit), *_spread(other, other_limit)})
    if len(points) < 2:
        raise Inconclusive(f"only {len(points)} traced line(s) of the subject's code to pause at")
    for at in points:
        race(at)
    return 1 + len(points)
