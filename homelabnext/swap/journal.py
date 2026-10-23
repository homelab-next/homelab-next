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
``<path>.lock`` is held for the journal's lifetime: a second backend on the same path is refused,
so two writers can never overwrite each other's batches.  Stale temp files of a crashed compaction
are removed at open.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
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
    def __init__(self, path: str | os.PathLike):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock_fd = os.open(self.path.with_name(self.path.name + ".lock"), os.O_RDWR | os.O_CREAT, FILE_MODE)  # fmt: skip
        if fcntl is not None:
            try:
                fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                os.close(self._lock_fd)
                raise LakeError(
                    f"{self.path} is in use by another swap backend; refusing to share it"
                ) from None
        self._fh: Any = None
        try:
            self._sweep()
            self.state = self._read()
            self._compact()
            self._fh = open(self.path, "a", encoding="utf-8")  # noqa: SIM115 - held open
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
        if self._fh is None:
            raise LakeError(f"the parked-batch journal {self.path} is closed")
        self._fh.write(json.dumps(rec, sort_keys=True, default=json_value) + "\n")
        self._fh.flush()
        os.fsync(self._fh.fileno())

    def park(self, owed_to: str, p: Any) -> None:
        self._append({"op": "park", "owed_to": owed_to, **p.to_dict()})

    def settled(self, order: int) -> None:
        self._append({"op": "settled", "order": int(order)})

    def mark(self, on: str, table: str, source: str, order: int) -> None:
        self._append({"op": "mark", "on": on, "table": table, "source": source, "order": order})

    def old_down(self, down: bool) -> None:
        self._append({"op": "old", "down": bool(down)})

    def close(self) -> None:
        if self._fh is not None:
            with contextlib.suppress(OSError):
                self._fh.close()
            self._fh = None
        if self._lock_fd is not None:
            with contextlib.suppress(OSError):
                os.close(self._lock_fd)  # closing the descriptor releases the lock
            self._lock_fd = None  # type: ignore[assignment]


__all__ = ["JournalState", "ParkedJournal", "json_value"]
