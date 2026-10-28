# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: mcp-client-configs
#   kind: tool
#   purpose: Read the MCP client configurations installed on a host (what each client registers when it starts), never through a link, for the module census.
#   owner: platform
#   trigger: [role:module_census]
#   inputs: the configuration files (absolute paths, each with its client), the largest file read
#   outputs: per file its text, or null where it is absent (JSON, as an Ansible module)
#   exit:
#     "0": every file listed was read or is absent (an absent file is a result, not a failure)
#     "1": a file is not a small regular file, or a directory on its way is a link or writable by its group or others; the census stops
"""Ansible module (role-local): read each installed MCP client configuration in one step, so
nothing can be swapped between a check and a read.

Each file is reached from ``/`` one directory at a time, every one opened ``O_NOFOLLOW`` (no
symbolic link at any step) and refused when its group or others may write it (a directory
someone else may write could have had its contents replaced; a root-owned sticky one, ``/tmp``,
lets no one replace an entry they do not own, and passes); the file itself is opened
``O_NOFOLLOW`` and ``O_NONBLOCK`` (a FIFO never blocks), must be a regular file its group and
others may not write, and is read to at most ``max_bytes`` plus one byte (one over is refused).
The text is returned as it is: ``hnx modules gather`` parses it strictly, per client.  Read-only;
supports check mode.  Standard library plus Ansible's own module_utils.
"""

from __future__ import annotations

import errno
import os
import re
import stat

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r"""
module: mcp_client_configs
short_description: Read the installed MCP client configurations, never through a link
options:
  files:
    description: The configurations, each C(path) (absolute) and C(client) (its format).
    type: list
    elements: dict
    required: true
  max_bytes:
    description: The largest file read.
    type: int
    required: true
"""

EXAMPLES = r"""
- name: Read the installed MCP client configurations
  mcp_client_configs:
    files: [{path: /var/lib/agent/.mcp.json, client: claude-code}]
    max_bytes: 1048576
  register: module_census_mcp
"""

RETURN = r"""
configs:
  description: Per file, in order, C(path), C(client) and C(text) (null where the file is absent).
  type: list
  returned: always
"""

_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
#: an absolute path of plain components (``.mcp.json`` is one; ``.`` and ``..`` and an empty
#: step are not)
PATH_RE = re.compile(r"(?:/(?!\.\.?(?:/|$))[A-Za-z0-9._-]+)+")


class Refused(Exception):
    pass


def open_to_others(mode: int, uid: int, directory: bool = True) -> bool:
    """A directory (or, with ``directory`` false, a file) its group or others may write.  A
    root-owned directory with the sticky bit (``/tmp``) is not: in it no one can replace an entry
    they do not own, so what is reached through it is still its owner's."""
    sticky = directory and bool(mode & stat.S_ISVTX) and uid == 0
    return bool(mode & 0o022) and not sticky


def read_one(path: str, max_bytes: int) -> str | None:
    """The text of the regular file at ``path``, or None where it (or a directory on its way)
    does not exist; :class:`Refused` for a link, a directory others may write, or anything that
    is not a small regular file."""
    *dirs, name = path.strip("/").split("/")
    fd = os.open("/", _DIR)
    try:
        for i, part in enumerate(dirs):
            shown = "/" + "/".join(dirs[: i + 1])
            try:
                nxt = os.open(part, _DIR, dir_fd=fd)
            except FileNotFoundError:
                return None
            except OSError as exc:
                raise Refused(f"{shown} is not a directory reached without a link") from exc
            os.close(fd)
            fd = nxt
            st = os.fstat(fd)
            if open_to_others(st.st_mode, st.st_uid):
                raise Refused(f"{shown} is writable by its group or others")
        try:
            f = os.open(name, _FILE, dir_fd=fd)
        except FileNotFoundError:
            return None
        except OSError as exc:
            if exc.errno in (errno.ELOOP, errno.EMLINK):
                raise Refused(f"{path} is not a regular file of at most {max_bytes} bytes") from exc
            raise
    finally:
        os.close(fd)
    try:
        st = os.fstat(f)
        if not stat.S_ISREG(st.st_mode) or open_to_others(st.st_mode, st.st_uid, False):
            raise Refused(f"{path} is not a regular file of at most {max_bytes} bytes")
        data = b""
        while len(data) <= max_bytes and (block := os.read(f, max_bytes + 1 - len(data))):
            data += block
    finally:
        os.close(f)
    if len(data) > max_bytes:
        raise Refused(f"{path} is not a regular file of at most {max_bytes} bytes")
    return data.decode("utf-8", "replace")


def main() -> None:
    module = AnsibleModule(
        argument_spec={
            "files": {"type": "list", "elements": "dict", "required": True},
            "max_bytes": {"type": "int", "required": True},
        },
        supports_check_mode=True,
    )
    p = module.params
    configs = []
    try:
        for entry in p["files"]:
            path, client = entry.get("path"), entry.get("client")
            if not isinstance(path, str) or not PATH_RE.fullmatch(path):
                module.fail_json(msg="module_census: an MCP client configuration path is not plain")
            text = read_one(path, p["max_bytes"])
            configs.append({"path": path, "client": client, "text": text})
    except Refused as exc:
        module.fail_json(msg=f"module_census: an MCP client configuration: {exc}")
    except OSError as exc:
        module.fail_json(msg=f"module_census: {exc.filename}: {exc.strerror}")
    module.exit_json(changed=False, configs=configs)


if __name__ == "__main__":
    main()
