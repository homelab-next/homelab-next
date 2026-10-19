# SPDX-License-Identifier: Apache-2.0
"""An atomic, locked, versioned key/value state file.

Guarantees
  * **Atomic replace.**  Every write goes to a temp file in the same directory, is flushed and
    ``fsync``-ed, then ``os.replace``-d over the target (and the directory is fsync-ed).  A
    reader, or the next start after ``kill -9`` mid-write, sees either the whole old file or the
    whole new one, never a torn mix.  Orphaned temp files of dead writers are swept.
  * **Locking.**  A sidecar ``<name>.lock`` is held with ``flock`` around every read-modify-write,
    so two processes updating different keys never lose each other's update.
  * **Schema version.**  The file is ``{"schema_version": N, "data": {...}}``.  Older versions
    are upgraded through the ``migrations`` mapping; a file from a *newer* writer raises
    :class:`StateVersionError` rather than being guessed at.
  * **Corrupt file quarantine.**  Unparseable content is renamed to ``<name>.corrupt-<stamp>``
    and the store starts empty, so one bad file cannot crash a scheduled check forever.  Each
    quarantine is logged (logger ``homelabnext.state``, WARNING) with the reason.  Only decode
    and shape errors quarantine; anything else (permissions, I/O) raises.
  * **Permissions.**  A replaced file keeps the mode of the file it replaces; a new file is
    created ``0600`` (state often holds tokens or cursors that are nobody else's business).

``.json`` is the default; ``.yml``/``.yaml`` use PyYAML (imported lazily).
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import re
import time
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path
from typing import Any

try:  # POSIX only; the fallback keeps the library importable elsewhere (no cross-process lock)
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]

SCHEMA_VERSION = 1
NEW_FILE_MODE = 0o600
log = logging.getLogger("homelabnext.state")
_MISSING = object()
_TMP_RE = re.compile(r"^\.(?P<name>.+)\.(?P<pid>\d+)\.[0-9a-f]+\.tmp$")


class StateError(Exception):
    """Base class for state-file problems."""


class StateVersionError(StateError):
    """The file was written by a newer schema version than this code understands."""


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def quarantined_files(path: str | os.PathLike) -> list[Path]:
    """Quarantined copies of ``path`` (oldest first)."""
    p = Path(path)
    return sorted(p.parent.glob(p.name + ".corrupt-*"))


class StateStore:
    """Dict-like persistent store.  Values must be JSON-serialisable."""

    def __init__(
        self,
        path: str | os.PathLike,
        *,
        schema_version: int = SCHEMA_VERSION,
        migrations: Mapping[int, Callable[[dict[str, Any]], dict[str, Any]]] | None = None,
        clock: Callable[[], float] = time.time,
    ):
        self.path = Path(path)
        self.schema_version = schema_version
        # migrations[n] upgrades data from version n to n + 1
        self.migrations = dict(migrations or {})
        self.clock = clock
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock_path = self.path.with_name(self.path.name + ".lock")

    # ---------------------------------------------------------------- public API
    def get(self, key: str, default: Any = None) -> Any:
        with self._locked():
            return self._load().get(key, default)

    def put(self, key: str, value: Any) -> None:
        with self._locked():
            data = self._load()
            data[key] = value
            self._write(data)

    def delete(self, key: str) -> bool:
        with self._locked():
            data = self._load()
            if key not in data:
                return False
            del data[key]
            self._write(data)
            return True

    def update(self, key: str, fn: Callable[[Any], Any], default: Any = None) -> Any:
        """Atomic read-modify-write of one key under the lock; returns the new value."""
        with self._locked():
            data = self._load()
            new = fn(data.get(key, default))
            data[key] = new
            self._write(data)
            return new

    def keys(self) -> list[str]:
        with self._locked():
            return sorted(self._load())

    def items(self) -> dict[str, Any]:
        with self._locked():
            return dict(self._load())

    def __contains__(self, key: object) -> bool:
        with self._locked():
            return key in self._load()

    # ---------------------------------------------------------------- internals
    @contextlib.contextmanager
    def _locked(self) -> Iterator[None]:
        with open(self._lock_path, "a+b") as fh:
            if fcntl is not None:
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                if fcntl is not None:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_UN)

    @property
    def _is_yaml(self) -> bool:
        return self.path.suffix in (".yml", ".yaml")

    def _decode(self, text: str) -> Any:
        if self._is_yaml:
            import yaml

            return yaml.safe_load(text)
        return json.loads(text)

    def _encode(self, doc: dict[str, Any]) -> str:
        if self._is_yaml:
            import yaml

            return yaml.safe_dump(doc, sort_keys=True)
        return json.dumps(doc, sort_keys=True, indent=1) + "\n"

    def _quarantine(self, reason: str) -> None:
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(self.clock()))
        target = self.path.with_name(f"{self.path.name}.corrupt-{stamp}")
        n = 1
        while target.exists():
            n += 1
            target = self.path.with_name(f"{self.path.name}.corrupt-{stamp}-{n}")
        os.replace(self.path, target)
        log.warning("state file %s is unusable (%s); quarantined as %s", self.path, reason, target)

    def _decode_errors(self) -> tuple[type[BaseException], ...]:
        errs: tuple[type[BaseException], ...] = (ValueError, UnicodeDecodeError)
        if self._is_yaml:
            import yaml

            errs += (yaml.YAMLError,)
        return errs

    def _load(self) -> dict[str, Any]:
        try:
            raw = self.path.read_bytes()
        except FileNotFoundError:
            return {}
        try:
            doc = self._decode(raw.decode("utf-8"))
            if not isinstance(doc, dict) or not isinstance(doc.get("data"), dict):
                raise ValueError("not a state document")
            version = doc.get("schema_version")
            if not isinstance(version, int) or isinstance(version, bool) or version < 1:
                raise ValueError("bad schema_version")
        except self._decode_errors() as exc:  # JSON/YAML/shape errors all mean "unusable file"
            self._quarantine(f"{type(exc).__name__}: {str(exc)[:200]}")
            return {}
        if version > self.schema_version:
            raise StateVersionError(
                f"{self.path}: schema_version {version} is newer than supported "
                f"{self.schema_version}; refusing to read or overwrite it"
            )
        data = doc["data"]
        while version < self.schema_version:
            step = self.migrations.get(version)
            if step is None:
                raise StateVersionError(f"{self.path}: no migration from version {version}")
            data = step(data)
            version += 1
        return data

    def _sweep_orphans(self) -> None:
        for tmp in self.path.parent.glob(f".{self.path.name}.*.tmp"):
            m = _TMP_RE.match(tmp.name)
            if m and m.group("name") == self.path.name and not _pid_alive(int(m.group("pid"))):
                with contextlib.suppress(FileNotFoundError):
                    tmp.unlink()

    def _write(self, data: dict[str, Any]) -> None:
        self._sweep_orphans()
        doc = {"schema_version": self.schema_version, "data": data}
        text = self._encode(doc)
        tmp = self.path.with_name(f".{self.path.name}.{os.getpid()}.{os.urandom(4).hex()}.tmp")
        try:
            mode = self.path.stat().st_mode & 0o7777
        except FileNotFoundError:
            mode = NEW_FILE_MODE
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, NEW_FILE_MODE)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                if hasattr(os, "fchmod"):
                    os.fchmod(fh.fileno(), mode)  # not subject to the umask
                fh.write(text)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.path)
        except BaseException:
            with contextlib.suppress(FileNotFoundError):
                tmp.unlink()
            raise
        self._fsync_dir()

    def _fsync_dir(self) -> None:
        try:
            fd = os.open(self.path.parent, os.O_RDONLY)
        except OSError:  # pragma: no cover - platforms that cannot open a directory
            return
        try:
            os.fsync(fd)
        except OSError:  # pragma: no cover
            pass
        finally:
            os.close(fd)
