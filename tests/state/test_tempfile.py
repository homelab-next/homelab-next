# SPDX-License-Identifier: Apache-2.0
"""write_temp: the one temporary-file writer; a failed write must leave nothing behind."""

from __future__ import annotations

import errno
import os
import stat

import pytest

from homelabnext._tempfile import write_temp


def _dir_fd(path):
    return os.open(path, os.O_RDONLY | os.O_DIRECTORY)


def test_write_temp_writes_and_keeps_its_mode(tmp_path):
    fd = _dir_fd(tmp_path)
    try:
        old = os.umask(0)
        try:
            tmp = write_temp("a.json", b"hello", dir_fd=fd, mode=0o640)
        finally:
            os.umask(old)
    finally:
        os.close(fd)
    p = tmp_path / tmp
    assert p.read_bytes() == b"hello"
    assert stat.S_IMODE(p.stat().st_mode) == 0o640


@pytest.mark.parametrize("failing", ["write", "fsync"])
def test_write_temp_leaves_no_file_after_a_failed_write(tmp_path, monkeypatch, failing):
    def boom(*a, **k):
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(os, failing, boom)
    fd = _dir_fd(tmp_path)
    try:
        with pytest.raises(OSError):
            write_temp("a.json", b"hello", dir_fd=fd)
    finally:
        os.close(fd)
    assert list(tmp_path.iterdir()) == []
