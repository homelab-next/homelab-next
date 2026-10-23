# SPDX-License-Identifier: Apache-2.0
"""An append-only journal of a dual writer's parked batches, so a restart does not drop them.

One JSON object per line, appended and ``fsync``-ed as each change happens, so the cost of a
change is one record (one batch at most), never a rewrite of the whole queue:

* ``{"op": "park", "owed_to": "old"|"new", "order": N, "table", "idempotency_key", "source",
  "high_water", "rows"}``: a batch parked for a component;
* ``{"op": "settled", "order": N}``: that batch was replayed or discarded;
* ``{"op": "mark", "on": "old"|"new", "table", "source", "order": N}``: the newest batch of a
  source a component took with its mark (the writer's guard against moving a mark back);
* ``{"op": "old", "down": true|false}``: the old component was stopped or started.

At open the journal is read, compacted (the live records only, written atomically) and then
appended to.  A torn last line (a crash mid-append) is dropped; any other unreadable line refuses
to open, rather than drop parked writes.  The file is ``0600``, and an exclusive ``flock`` on
``<path>.lock`` (opened without following a symlink) is held for the journal's lifetime: a second
backend on the same path is refused, so two writers can never overwrite each other's batches.
``close()`` releases it, and so does a journal that is garbage-collected unclosed (a finalizer).
An append after ``close()`` raises: parked batches are never kept in memory only by mistake.  It is also compacted in place after every
``compact_every`` settled records, so rows parked and settled in one long-lived process do not
pile up.  Stale temp files of a crashed compaction are removed at open.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import weakref
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Any

from homelabnext.lake.errors import LakeError

try:  # POSIX; elsewhere the journal still works, without the cross-process lock
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]

FILE_MODE = 0o600
#: settled records after which the journal is compacted in place (a flapping candidate parks and
#: settles rows all day; without this they stay in the file until the next open)
COMPACT_EVERY = 1000
_TMP = re.compile(r"^\.(?P<name>.+)\.(?P<pid>\d+)\.[0-9a-f]+\.tmp$")


def json_value(v: Any) -> Any:
    """Rows hold timestamps; they are stored as ISO text, which the lake validation reads back."""
    if isinstance(v, datetime | date):
        return v.isoformat()
    raise TypeError(f"cannot store a parked {type(v).__name__}")


@dataclass
class JournalState:
    """What a journal holds once read: the live parked batches, the marks, the old component."""

    parked: list[dict[str, Any]] = field(default_factory=list)  # in order
    marks: dict[tuple[str, str, str], int] = field(default_factory=dict)  # (role, table, source)
    old_down: bool | None = None
    last_order: int = 0


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


class ParkedJournal:
    def __init__(self, path: str | os.PathLike, *, compact_every: int = COMPACT_EVERY):
        self.path = Path(path)
        self.compact_every = max(1, int(compact_every))
        self._settled_since = 0
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            lock_fd = os.open(
                self.path.with_name(self.path.name + ".lock"),
                os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
                FILE_MODE,
            )
        except OSError as exc:  # a symlink planted at the lock path, among others
            raise LakeError(f"cannot open the lock of {self.path}: {exc}") from None
        if fcntl is not None:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                os.close(lock_fd)
                raise LakeError(
                    f"{self.path} is in use by another swap backend; refusing to share it"
                ) from None
        # what to release; the finalizer holds this, not the journal, so it can run at collection
        self._res: dict[str, Any] = {"lock_fd": lock_fd, "fh": None}
        self._finalizer = weakref.finalize(self, _release, self._res)
        self.closed = False
        try:
            self._sweep()
            self.state = self._read()
            self._compact()
            self._res["fh"] = open(self.path, "a", encoding="utf-8")  # noqa: SIM115 - held open
        except BaseException:
            self.close()
            raise

    # ------------------------------------------------------------ open
    def _sweep(self) -> None:
        for tmp in self.path.parent.glob(f".{self.path.name}.*.tmp"):
            m = _TMP.match(tmp.name)
            if m and m.group("name") == self.path.name and not _pid_alive(int(m.group("pid"))):
                with contextlib.suppress(FileNotFoundError):
                    tmp.unlink()

    def _read(self) -> JournalState:
        st = JournalState()
        if not self.path.exists():
            return st
        try:
            text = self.path.read_text(encoding="utf-8")
        except OSError as exc:
            raise LakeError(f"parked batches in {self.path} are unreadable: {exc}") from exc
        lines = text.split("\n")
        live: dict[int, dict[str, Any]] = {}
        for i, line in enumerate(lines):
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
                op = rec["op"]
                if op == "park":
                    live[int(rec["order"])] = rec
                    st.last_order = max(st.last_order, int(rec["order"]))
                elif op == "settled":
                    live.pop(int(rec["order"]), None)
                elif op == "mark":
                    k = (str(rec["on"]), str(rec["table"]), str(rec["source"]))
                    st.marks[k] = max(int(rec["order"]), st.marks.get(k, 0))
                    st.last_order = max(st.last_order, int(rec["order"]))
                elif op == "old":
                    st.old_down = bool(rec["down"])
                else:
                    raise ValueError(f"unknown op {op!r}")
            except (ValueError, KeyError, TypeError) as exc:
                if i == len(lines) - 1:  # a torn last line: the crash came mid-append
                    continue
                raise LakeError(
                    f"parked batches in {self.path} are unreadable (line {i + 1}: {exc})"
                ) from exc
        st.parked = [live[o] for o in sorted(live)]
        return st

    def _compact(self) -> None:
        from homelabnext.state import atomic_write_text

        st = self.state
        recs: list[dict[str, Any]] = []
        recs += [
            {"op": "mark", "on": on, "table": t, "source": src, "order": o}
            for (on, t, src), o in sorted(st.marks.items())
        ]
        if st.old_down is not None:
            recs.append({"op": "old", "down": st.old_down})
        recs += st.parked
        text = "".join(json.dumps(r, sort_keys=True, default=json_value) + "\n" for r in recs)
        atomic_write_text(self.path, text, mode=FILE_MODE)

    # ------------------------------------------------------------ append
    def _append(self, rec: dict[str, Any]) -> None:
        fh = self._res["fh"]
        if self.closed or fh is None:
            raise LakeError(f"the parked-batch journal {self.path} is closed")
        fh.write(json.dumps(rec, sort_keys=True, default=json_value) + "\n")
        fh.flush()
        os.fsync(fh.fileno())

    def park(self, owed_to: str, p: Any) -> None:
        rec = {"op": "park", "owed_to": owed_to, **p.to_dict()}
        self._append(rec)
        st = self.state
        st.parked = [r for r in st.parked if int(r["order"]) != int(p.order)]
        st.parked.append(json.loads(json.dumps(rec, default=json_value)))
        st.parked.sort(key=lambda r: int(r["order"]))
        st.last_order = max(st.last_order, int(p.order))

    def settled(self, order: int) -> None:
        self._append({"op": "settled", "order": int(order)})
        self.state.parked = [r for r in self.state.parked if int(r["order"]) != int(order)]
        self._settled_since += 1
        if self._settled_since >= self.compact_every:
            self.compact()

    def mark(self, on: str, table: str, source: str, order: int) -> None:
        self._append({"op": "mark", "on": on, "table": table, "source": source, "order": order})
        k = (on, table, source)
        self.state.marks[k] = max(order, self.state.marks.get(k, 0))
        self.state.last_order = max(self.state.last_order, int(order))

    def old_down(self, down: bool) -> None:
        self._append({"op": "old", "down": bool(down)})
        self.state.old_down = bool(down)

    def compact(self) -> None:
        """Rewrite the journal as its live records only (atomically) and append from there."""
        if self.closed or self._res["fh"] is None:
            raise LakeError(f"the parked-batch journal {self.path} is closed")
        self._res["fh"].close()
        self._res["fh"] = None
        self._compact()
        self._res["fh"] = open(self.path, "a", encoding="utf-8")  # noqa: SIM115 - held open
        self._settled_since = 0

    def close(self) -> None:
        """Release the file and the lock (idempotent); later appends raise."""
        self.closed = True
        self._finalizer()


def _release(res: dict[str, Any]) -> None:
    fh, res["fh"] = res.get("fh"), None
    if fh is not None:
        with contextlib.suppress(OSError):
            fh.close()
    fd, res["lock_fd"] = res.get("lock_fd"), None
    if fd is not None:
        with contextlib.suppress(OSError):
            os.close(fd)  # closing the descriptor releases the lock


__all__ = ["JournalState", "ParkedJournal", "json_value"]
