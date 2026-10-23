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


class _Paused:
    """Runs ``fn`` in a thread that stops before its ``at``-th traced line (never, for ``at=0``).

    ``where(filename)`` says whether a frame is traced (None: not traced) and whether it is the
    subject's own module (True) or other code it calls (False); ``own`` lists the numbers of the
    lines that ran in the subject's own module."""

    def __init__(self, fn: Callable[[], Any], at: int, where: Callable[[str], bool | None]) -> None:
        import threading

        self.fn, self.at, self.where = fn, at, where
        self.lines = 0
        self.own: list[int] = []
        self.result: tuple[bool, Any] = (False, None)
        self.stopped = threading.Event()  # paused at ``at``, or finished
        self.resume = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _tracer(self, own: bool) -> Callable[..., Any]:
        def line(frame: Any, event: str, arg: Any) -> Any:
            if event == "line":
                self.lines += 1
                if own:
                    self.own.append(self.lines)
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


def interleavings(
    subject: Any,
    setup: Callable[[], tuple[Callable[[], Any], Callable[[], Any], Callable[..., None]]],
    *,
    own_limit: int = 8,
    other_limit: int = 3,
    blocked_after: float = 1.0,
) -> int:
    """Race two operations under a deterministic schedule, not under timing.

    ``setup()`` prepares fresh state and returns ``(first, second, judge)``.  ``first`` runs in a
    thread that is stopped before one chosen line of the subject's code; ``second`` then runs to
    completion, ``first`` resumes, and ``judge((ok1, out1), (ok2, out2))`` asserts on the outcome
    (``ok`` False means ``out`` is the exception raised).  The subject's code is the module that
    defines its class (where an adapter's check-then-act lives: every one of its lines up to
    ``own_limit`` is a pause point) and any other source outside the standard library and
    site-packages that it calls (``other_limit`` points spread evenly).  The points come from an
    unpaused first run, so the same subject is always raced at the same places.

    A subject that serialises the two (``second`` waits on a lock that the paused ``first``
    holds) cannot be raced this way: when ``second`` has not finished ``blocked_after`` seconds
    after ``first`` stopped, ``first`` is resumed, the pair is judged as it ended and no further
    point is tried.  That wait only ends exploration early; it never decides a verdict.  Returns
    the number of schedules run.
    """
    import threading

    lib, site = _lib_dirs()
    mod = sys.modules.get(type(subject).__module__)
    own_file = os.path.realpath(getattr(mod, "__file__", None) or "") if mod else ""
    suites = os.path.dirname(os.path.realpath(__file__)) + os.sep

    @functools.cache
    def where(filename: str) -> bool | None:
        if filename.startswith("<"):
            return None
        path = os.path.realpath(filename)
        if path == own_file:
            return True
        if path.startswith(suites) or path.startswith(site) or path.startswith(lib):
            return None  # the suites are not the subject; libraries are not its code
        return False

    def race(at: int) -> _Paused | None:
        first, second, judge = setup()
        a = _Paused(first, at, where)
        a.thread.start()
        a.stopped.wait()
        out2: list[tuple[bool, Any]] = []

        def run_second() -> None:
            try:
                out2.append((True, second()))
            except BaseException as exc:  # judged below
                out2.append((False, exc))

        b = threading.Thread(target=run_second, daemon=True)
        b.start()
        b.join(blocked_after if a.thread.is_alive() else None)
        blocked = b.is_alive()
        a.resume.set()
        a.thread.join()
        b.join()
        judge(a.result, out2[0])
        return None if blocked else a

    plain = race(0)  # unpaused: finds the pause points (and judges one sequential schedule)
    assert plain is not None
    total = plain.lines
    points = set(plain.own[:own_limit])
    if total and other_limit:
        step = max(1, total // other_limit)
        points |= set(range(step // 2 + 1, total + 1, step)[:other_limit])
    runs = 1
    for at in sorted(points):
        runs += 1
        if race(at) is None:
            break
    return runs
