# SPDX-License-Identifier: Apache-2.0
"""The record of the pairs a running notifier holds, for the module census.

A process that owns a :class:`~homelabnext.notify.core.Notifier` (``hnx broker serve`` and ``hnx
status collect``) can be given a :class:`PairsRecord`: the notifier then writes every pair it
holds, at construction and after each registration, to ``<dir>/<owner>/pairs.json``
(:data:`OWNERS`, :data:`RECORD_NAME`), replacing the whole file each time.  The ``module_census``
role reads the records at the fixed directory :data:`RECORD_DIR` and ``hnx modules gather`` turns
the fresh ones into the inventory's ``notify_pairs`` (docs/modules.md, "Notify pairs").

The document is ``{"schema_version": 2, "owner", "written_at", "boot_id", "pid", "started",
"pairs": [{"problem", "recovery", "module"?}, ...]}``, the pairs sorted by problem title.
``module`` is present only when the registrant named the module the pair came from
(``register_pair(..., module=...)``); the notifier never guesses one, and a pair without it is
the core's.  ``written_at`` (UTC), ``boot_id`` (the host's, or null where it cannot be read),
``pid`` and ``started`` (the process's start time in clock ticks since boot, or null) let the
census tell a live record from a leftover (:func:`stale`): a broker's record counts only while
its process runs, a status pass's (one per timer run) only while it is at most
:data:`STATUS_MAX_AGE_S` old, and neither across a reboot.  A process that stops leaves its file;
the census, not the file, decides whether it still counts.

**Where it is written.**  ``<dir>`` and ``<dir>/<owner>`` are opened once, never through a
symbolic link at any step, and each must be owned by root or by the writing process's user and
writable by no one else (group or other); ``<dir>/<owner>`` is created when ``<dir>`` lets the
process create it.  Every later step (the ``flock`` on the owner directory itself, the temp
file, the replace, the directory ``fsync``) is relative to that open directory, so a path swapped
after start cannot redirect a write, and there is no lock file to plant.  The record is mode
``0644``: it discloses which pairs (and which module ids) run on the host to its local users.

**Trust:** the file is the owning service's word about its own pairs, as a host's ``systemctl``
output is about its units; a service (or a root) that lies about them is believed, and nothing
read from the host can rule that out.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import json
import os
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from homelabnext.schemas.module_manifest import TITLE_RE

try:  # POSIX only
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]

#: where the census looks: ``<RECORD_DIR>/<owner>/pairs.json``, never a glob
RECORD_DIR = "/var/lib/homelabnext/notify-pairs"
RECORD_NAME = "pairs.json"
#: the processes that own a notifier, and how the census tells whether a record still counts:
#: ``process`` (a long-running service: while its pid runs with the same start time) or ``age``
#: (one pass per timer run: while it is at most :data:`STATUS_MAX_AGE_S` old)
LIVENESS = {"broker": "process", "status": "age"}
OWNERS = tuple(LIVENESS)
#: a status pass rewrites its record every run; 15 minutes outlasts a few missed runs of a timer
#: that fires every few minutes
STATUS_MAX_AGE_S = 900
#: how far a record's ``written_at`` may run ahead of the host's clock (one clock, a rounding)
FUTURE_SLACK_S = 300
SCHEMA_VERSION = 2
RECORD_MODE = 0o644
DIR_MODE = 0o755
MAX_PAIRS = 256
MAX_BYTES = 256 * 1024
BOOT_ID_FILE = "/proc/sys/kernel/random/boot_id"
_BOOT = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_STAMP = "%Y-%m-%dT%H:%M:%SZ"
#: a module id (``platform/module_inventory`` ``$defs.name``)
_MODULE = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*")
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


class RecordError(ValueError):
    """A pairs record that cannot be read."""


def _title(value: Any) -> bool:
    return isinstance(value, str) and 0 < len(value) <= 160 and bool(TITLE_RE.fullmatch(value))


# ------------------------------------------------------------------------------- host facts
def boot_id(path: str = BOOT_ID_FILE) -> str | None:
    """This host's boot id, or None where it cannot be read."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            raw = os.read(fd, 64)
        finally:
            os.close(fd)
    except OSError:
        return None
    text = raw.decode("ascii", "replace").strip()
    return text if _BOOT.fullmatch(text) else None


def process_started(pid: int) -> int | None:
    """When process ``pid`` started (clock ticks since boot, ``/proc/<pid>/stat`` field 22), or
    None where it is not running or cannot be read."""
    try:
        with open(f"/proc/{int(pid)}/stat", "rb") as fh:
            raw = fh.read(4096)
    except (OSError, ValueError):
        return None
    tail = raw.rpartition(b")")[2].split()  # the command name may hold spaces and parentheses
    try:
        return int(tail[19])  # field 22 counts from 1 and includes pid and comm
    except (IndexError, ValueError):
        return None


# ------------------------------------------------------------------------------- the writer
def _open_dir(path: str | os.PathLike) -> int:
    """``path`` opened as a directory with no symbolic link at any step (absolute paths only)."""
    p = Path(path)
    if not p.is_absolute():
        raise ValueError(f"notify pairs record: {p} is not an absolute path")
    fd = os.open("/", _DIR_FLAGS)
    try:
        for part in p.parts[1:]:
            nxt = os.open(part, _DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = nxt
    except OSError as exc:
        os.close(fd)
        raise ValueError(
            f"notify pairs record: {p} is not a directory reached without a link ({exc.strerror})"
        ) from None
    return fd


def _check_owned(fd: int, shown: Any) -> None:
    st = os.fstat(fd)
    if st.st_uid not in (0, os.geteuid()) or st.st_mode & 0o022:
        raise ValueError(
            f"notify pairs record: {shown} must be owned by root or this process's user and "
            "writable by no one else"
        )


class PairsRecord:
    """Where one notifier owner writes the pairs it holds (see the module)."""

    def __init__(
        self, directory: str | os.PathLike, owner: str, *, clock: Callable[[], float] = time.time
    ) -> None:
        if owner not in OWNERS:
            raise ValueError(f"notify pairs record: owner is one of {', '.join(OWNERS)}")
        parent = _open_dir(directory)
        try:
            _check_owned(parent, directory)
            # it exists, or the operator makes it (docs/modules.md, "Notify pairs")
            with contextlib.suppress(FileExistsError, PermissionError):
                os.mkdir(owner, DIR_MODE, dir_fd=parent)
            try:
                fd = os.open(owner, _DIR_FLAGS, dir_fd=parent)
            except OSError as exc:
                raise ValueError(
                    f"notify pairs record: {Path(directory) / owner} is not a directory "
                    f"reached without a link ({exc.strerror})"
                ) from None
        finally:
            os.close(parent)
        try:
            _check_owned(fd, Path(directory) / owner)
        except ValueError:
            os.close(fd)
            raise
        self.owner = owner
        self.path = Path(directory) / owner / RECORD_NAME  # shown only: writes use the open fd
        self._fd = fd
        self._clock = clock

    def close(self) -> None:
        if self._fd >= 0:
            os.close(self._fd)
            self._fd = -1

    def __del__(self) -> None:  # pragma: no cover - best effort at interpreter exit
        with contextlib.suppress(OSError, AttributeError):
            self.close()

    def document(self, pairs: Mapping[str, tuple[str, str | None]]) -> dict[str, Any]:
        rows = []
        for problem in sorted(pairs):
            recovery, module = pairs[problem]
            row = {"problem": problem, "recovery": recovery}
            if module is not None:
                row["module"] = module
            rows.append(row)
        pid = os.getpid()
        return {
            "schema_version": SCHEMA_VERSION,
            "owner": self.owner,
            "written_at": dt.datetime.fromtimestamp(self._clock(), dt.UTC).strftime(_STAMP),
            "boot_id": boot_id(),
            "pid": pid,
            "started": process_started(pid),
            "pairs": rows,
        }

    def write(self, pairs: Mapping[str, tuple[str, str | None]]) -> None:
        """Replace the record with ``pairs`` (problem title -> (recovery title, module or None))."""
        if self._fd < 0:
            raise ValueError("notify pairs record: closed")
        data = (json.dumps(self.document(pairs), indent=1) + "\n").encode("utf-8")
        _check_owned(self._fd, self.path.parent)  # a mode or owner changed since start
        if fcntl is not None:
            fcntl.flock(self._fd, fcntl.LOCK_EX)
        tmp = f".{RECORD_NAME}.{os.getpid()}.{os.urandom(4).hex()}.tmp"
        try:
            t = os.open(
                tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
                dir_fd=self._fd,
            )  # fmt: skip
            try:
                os.fchmod(t, RECORD_MODE)  # not subject to the umask
                os.write(t, data)
                os.fsync(t)
            finally:
                os.close(t)
            os.replace(tmp, RECORD_NAME, src_dir_fd=self._fd, dst_dir_fd=self._fd)
            os.fsync(self._fd)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp, dir_fd=self._fd)
            raise
        finally:
            if fcntl is not None:
                fcntl.flock(self._fd, fcntl.LOCK_UN)


def record_in(directory: str | os.PathLike | None, owner: str) -> PairsRecord | None:
    """The record of ``owner`` under ``directory`` (``--notify-pairs-dir``), or None without one."""
    return PairsRecord(directory, owner) if directory else None


# ------------------------------------------------------------------------------- the reader
@dataclass(frozen=True)
class Record:
    owner: str
    written_at: float  # seconds since the epoch, UTC
    boot_id: str | None
    pid: int
    started: int | None
    pairs: list[dict[str, str]]


def _int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


_KEYS = {"schema_version", "owner", "written_at", "boot_id", "pid", "started", "pairs"}


def parse_record(text: str, owner: str) -> Record:
    """One record, read strictly: anything off the shape is :class:`RecordError`."""
    if len(text.encode("utf-8")) > MAX_BYTES:
        raise RecordError(f"{owner}: over {MAX_BYTES} bytes")
    try:
        doc = json.loads(text)
    except ValueError:
        raise RecordError(f"{owner}: not JSON") from None
    if not isinstance(doc, dict) or set(doc) != _KEYS:
        raise RecordError(f"{owner}: not {{{', '.join(sorted(_KEYS))}}}")
    if doc["schema_version"] != SCHEMA_VERSION or not _int(doc["schema_version"]):
        raise RecordError(f"{owner}: schema_version is not {SCHEMA_VERSION}")
    if doc["owner"] != owner:
        raise RecordError(f"{owner}: written for another owner")
    try:
        when = dt.datetime.strptime(doc["written_at"], _STAMP).replace(tzinfo=dt.UTC)
    except (TypeError, ValueError):
        raise RecordError(f"{owner}: written_at is not a UTC time (YYYY-MM-DDTHH:MM:SSZ)") from None
    if doc["boot_id"] is not None and not (
        isinstance(doc["boot_id"], str) and _BOOT.fullmatch(doc["boot_id"])
    ):
        raise RecordError(f"{owner}: boot_id is not a boot id or null")
    if not _int(doc["pid"]) or doc["pid"] < 1:
        raise RecordError(f"{owner}: pid is not a process id")
    if doc["started"] is not None and (not _int(doc["started"]) or doc["started"] < 0):
        raise RecordError(f"{owner}: started is not a start time or null")
    pairs = doc["pairs"]
    if not isinstance(pairs, list) or len(pairs) > MAX_PAIRS:
        raise RecordError(f"{owner}: pairs is not a list of at most {MAX_PAIRS}")
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for i, p in enumerate(pairs, 1):
        if not isinstance(p, dict) or not (
            set(p) == {"problem", "recovery"} or set(p) == {"problem", "recovery", "module"}
        ):
            raise RecordError(f"{owner}: pair {i} is not {{problem, recovery, module?}}")
        if not _title(p["problem"]) or not _title(p["recovery"]):
            raise RecordError(f"{owner}: pair {i} has a title that is not one line of text")
        if "module" in p and not (
            isinstance(p["module"], str)
            and len(p["module"]) <= 64
            and _MODULE.fullmatch(p["module"])
        ):
            raise RecordError(f"{owner}: pair {i} names a module that is not a module id")
        if p["problem"] in seen:
            raise RecordError(f"{owner}: pair {i} repeats a problem title")
        seen.add(p["problem"])
        out.append(dict(p))
    return Record(
        owner, when.timestamp(), doc["boot_id"], doc["pid"], doc["started"], out
    )  # fmt: skip


def stale(
    record: Record, host_boot_id: str | None, host_now: float, pid_started: int | None
) -> str | None:
    """Why ``record`` no longer says what runs on its host, or None when it still does.

    ``host_boot_id``, ``host_now`` and ``pid_started`` (the start time of the record's ``pid`` on
    the host now, or None where it is not running) are the host's own answers."""
    if record.boot_id is None or host_boot_id is None:
        return "the host's boot cannot be told, so neither can a leftover"
    if record.boot_id != host_boot_id:
        return "written before the host's last boot"
    if record.written_at > host_now + FUTURE_SLACK_S:
        return "written in the future"
    if LIVENESS[record.owner] == "process":
        if record.started is None or pid_started != record.started:
            return f"its process (pid {record.pid}) is not running"
    elif host_now - record.written_at > STATUS_MAX_AGE_S:
        return f"written {int(host_now - record.written_at)}s ago, over {STATUS_MAX_AGE_S}s"
    return None
