# SPDX-License-Identifier: Apache-2.0
"""The one temporary-file writer behind every exclusive or atomic create relative to a directory
file descriptor: the broker's state and lane files (:mod:`homelabnext.broker.state`) and the
records inbox (:mod:`homelabnext.records.inbox`).  Standard library only."""

from __future__ import annotations

import os
import secrets

__all__ = ["write_temp"]


def write_temp(name: str, data: bytes, *, dir_fd: int, mode: int = 0o600) -> str:
    """Write ``data`` to a new temporary file beside ``name`` in the directory ``dir_fd`` and
    fsync it; returns the temporary name.  Callers then link (exclusive) or rename (replace) it
    into place and unlink the temporary name.  ``mode`` is the new file's (less the umask)."""
    tmp = f".{name}.{os.getpid()}.{secrets.token_hex(4)}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=dir_fd)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view) :]
        os.fsync(fd)
    finally:
        os.close(fd)
    return tmp
