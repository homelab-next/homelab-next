# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: notify-pairs-records
#   kind: tool
#   purpose: Read each notifier owner's notify pairs record on a host, never through a link, with the facts that tell a live record from a leftover.
#   owner: platform
#   trigger: [role:module_census]
#   inputs: the pairs directory, the owners, the largest record read
#   outputs: the host's boot id and clock, and per owner the record's text and whether its process still runs (JSON, as an Ansible module)
#   exit:
#     "0": every record present was read (a missing directory or record is a result, not a failure)
#     "1": a record is not a small regular file, or a directory on the way is a link or writable by others; the census stops
"""Ansible module (role-local): read the notify pairs records (homelabnext.notify.record) in one
step, so nothing can be swapped between a check and a read.

``<dir>`` is opened with no symbolic link at any step and must be writable by no one but its
owner; each ``<dir>/<owner>`` likewise; each ``<dir>/<owner>/<name>`` is opened ``O_NOFOLLOW``
and ``O_NONBLOCK`` (a FIFO never blocks), must be a regular file, and is read to at most
``max_bytes`` plus one byte (one over is refused).  Beside each record it returns the start time
of the process the record names (``/proc/<pid>/stat``), and for the host its boot id and clock:
``hnx modules gather`` decides from them whether the record still counts.  Read-only; supports
check mode.  Standard library plus Ansible's own module_utils.
"""

from __future__ import annotations

import errno
import json
import os
import re
import stat
import time

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r"""
module: notify_pairs_records
short_description: Read each notifier owner's notify pairs record, never through a link
options:
  dir:
    description: The pairs directory (absolute); each record is C(<dir>/<owner>/<name>).
    type: str
    required: true
  owners:
    description: The notifier owners, each its own directory.
    type: list
    elements: str
    required: true
  name:
    description: The record's file name in each owner's directory.
    type: str
    default: pairs.json
  max_bytes:
    description: The largest record read.
    type: int
    required: true
"""

EXAMPLES = r"""
- name: Read the notify pairs records
  notify_pairs_records:
    dir: /var/lib/homelabnext/notify-pairs
    owners: [broker, status]
    max_bytes: 262144
  register: module_census_pairs
"""

RETURN = r"""
boot_id: {description: The host's boot id, or null where it cannot be read., type: str, returned: always}
now: {description: The host's clock (seconds since the epoch)., type: int, returned: always}
records:
  description: Per owner, null where it holds no record, else C(text) and C(pid_started) (the start time of the record's pid now, null where it is not running).
  type: dict
  returned: always
"""

_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")


class Refused(Exception):
    pass


def open_dir(path: str) -> int | None:
    """``path`` opened as a directory with no link at any step; None where it does not exist."""
    if not path.startswith("/"):
        raise Refused(f"{path} is not an absolute path")
    fd = os.open("/", _DIR)
    for part in [p for p in path.split("/") if p]:
        try:
            nxt = os.open(part, _DIR, dir_fd=fd)
        except FileNotFoundError:
            os.close(fd)
            return None
        except OSError as exc:
            os.close(fd)
            raise Refused(
                f"{path} is not a directory reached without a link ({exc.strerror})"
            ) from None
        os.close(fd)
        fd = nxt
    return fd


def open_sub(parent: int, name: str, shown: str) -> int | None:
    try:
        return os.open(name, _DIR, dir_fd=parent)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise Refused(
            f"{shown} is not a directory reached without a link ({exc.strerror})"
        ) from None


def guarded(fd: int, shown: str) -> None:
    if os.fstat(fd).st_mode & 0o022:
        raise Refused(f"{shown} is writable by its group or others")


def read_capped(parent: int, name: str, shown: str, max_bytes: int) -> str | None:
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    try:
        fd = os.open(name, flags, dir_fd=parent)
    except FileNotFoundError:
        return None
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.EMLINK):
            raise Refused(f"{shown} is not a regular file of at most {max_bytes} bytes") from None
        raise
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise Refused(f"{shown} is not a regular file of at most {max_bytes} bytes")
        chunks, size = [], 0
        while size <= max_bytes:
            block = os.read(fd, max_bytes + 1 - size)
            if not block:
                break
            chunks.append(block)
            size += len(block)
    finally:
        os.close(fd)
    if size > max_bytes:
        raise Refused(f"{shown} is not a regular file of at most {max_bytes} bytes")
    return b"".join(chunks).decode("utf-8", "replace")


def host_boot_id() -> str | None:
    try:
        with open("/proc/sys/kernel/random/boot_id", "rb") as fh:
            text = fh.read(64).decode("ascii", "replace").strip()
    except OSError:
        return None
    return text if _UUID.fullmatch(text) else None


def started_of(text: str) -> int | None:
    """The start time now of the pid a record names (``/proc/<pid>/stat`` field 22), or None."""
    try:
        pid = json.loads(text).get("pid")
    except (ValueError, AttributeError):
        return None
    if not isinstance(pid, int) or isinstance(pid, bool) or pid < 1:
        return None
    try:
        with open(f"/proc/{pid}/stat", "rb") as fh:
            fields = fh.read(4096).rpartition(b")")[2].split()
        return int(fields[19])
    except (OSError, IndexError, ValueError):
        return None


def read_records(directory: str, owners: list[str], name: str, max_bytes: int) -> dict:
    records: dict = dict.fromkeys(owners)
    root = open_dir(directory.rstrip("/") or "/")
    if root is not None:
        try:
            guarded(root, directory)
            for owner in owners:
                sub = open_sub(root, owner, f"{directory}/{owner}")
                if sub is None:
                    continue
                try:
                    guarded(sub, f"{directory}/{owner}")
                    text = read_capped(sub, name, f"{directory}/{owner}/{name}", max_bytes)
                finally:
                    os.close(sub)
                if text is not None:
                    records[owner] = {"text": text, "pid_started": started_of(text)}
        finally:
            os.close(root)
    return {"boot_id": host_boot_id(), "now": int(time.time()), "records": records}


def main() -> None:
    module = AnsibleModule(
        argument_spec={
            "dir": {"type": "str", "required": True},
            "owners": {"type": "list", "elements": "str", "required": True},
            "name": {"type": "str", "default": "pairs.json"},
            "max_bytes": {"type": "int", "required": True},
        },
        supports_check_mode=True,
    )
    p = module.params
    plain = re.compile(r"[a-z][a-z0-9_.-]*")
    if not all(plain.fullmatch(x) for x in [*p["owners"], p["name"]]):
        module.fail_json(msg="module_census: a notify pairs owner or file name is not a plain name")
    try:
        out = read_records(p["dir"], p["owners"], p["name"], p["max_bytes"])
    except Refused as exc:
        module.fail_json(msg=f"module_census: a notify pairs record: {exc}")
    except OSError as exc:
        module.fail_json(msg=f"module_census: {exc.filename}: {exc.strerror}")
    module.exit_json(changed=False, **out)


if __name__ == "__main__":
    main()
