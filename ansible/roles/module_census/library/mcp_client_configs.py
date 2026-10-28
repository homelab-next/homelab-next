# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: mcp-client-configs
#   kind: tool
#   purpose: Read the MCP client configurations installed on a host (what each client registers when it starts), never through a link, and return only the server names each registers, for the module census.
#   owner: platform
#   trigger: [role:module_census]
#   inputs: the configuration files (absolute paths, each with its client), the largest file read
#   outputs: per file whether it is present and the server names it registers, never its text (JSON, as an Ansible module)
#   exit:
#     "0": every file listed was read and parsed, or is absent (an absent file is a result, not a failure)
#     "1": a file is not a small regular file of its client's name, a file or a directory on its way is a link, someone else's or writable by its group or others, or a file does not parse strictly; the census stops
"""Ansible module (role-local): read each installed MCP client configuration in one step, so
nothing can be swapped between a check and a read, and parse it on the host.

A configuration can hold secrets (an ``env`` value, a header), so its text never leaves the host:
the module returns, per file, only whether it is present and the server names it registers.

Each file is reached from ``/`` one directory at a time, every one opened ``O_NOFOLLOW`` (no
symbolic link at any step), owned by root or by this module's user, and refused when its group or
others may write it (a directory someone else may write could have had its contents replaced; a
root-owned sticky one, ``/tmp``, lets no one replace an entry they do not own, and passes, but
what is reached through it must still be root's or this user's).  The file must be named as its
client's configuration (:data:`BASENAMES`), is opened ``O_NOFOLLOW`` and ``O_NONBLOCK`` (a FIFO
never blocks), must be a regular file with a single link, owned by root or this user, that its
group and others may not write, and is read to at most ``max_bytes`` plus one byte (one over is
refused).  It is then parsed strictly for its client: a JSON client file's ``mcpServers`` object
(duplicate keys, ``NaN`` and ``Infinity`` refused), a Hermes YAML file's ``mcp_servers`` mapping
(PyYAML's safe loader with duplicate keys and aliases refused; where PyYAML is not installed on
the host, a Hermes file fails the census rather than its text being returned), and every server
name must be an inventory name.  Read-only; supports check mode.  Standard library plus
Ansible's own module_utils (and PyYAML, only for a Hermes file).
"""

from __future__ import annotations

import collections.abc
import errno
import json
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
  description: >-
    Per file, in order, C(path), C(client), C(present) and C(servers) (the server names it
    registers, sorted; empty where the file is absent).  Never the file's text.
  type: list
  returned: always
"""

_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
#: an absolute path of plain components (``.mcp.json`` is one; ``.`` and ``..`` and an empty
#: step are not)
PATH_RE = re.compile(r"(?:/(?!\.\.?(?:/|$))[A-Za-z0-9._-]+)+")


#: each client's configuration file names (what ``hnx mcp catalog render`` writes for it and the
#: client reads): a file of any other name is refused before it is opened
BASENAMES = {
    "claude-code": re.compile(r"(?:[a-z0-9][a-z0-9-]*)?\.mcp\.json"),
    "generic": re.compile(r"(?:(?:[a-z0-9][a-z0-9-]*)?\.)?mcp\.json"),
    "hermes": re.compile(r"config\.yaml"),
}
#: where each client lists its servers
SERVERS_KEY = {"claude-code": "mcpServers", "generic": "mcpServers", "hermes": "mcp_servers"}
#: an MCP server name as a client registers it (homelabnext.modules.census.MCP_NAME_RE)
MCP_NAME_RE = re.compile(r"[a-z0-9][a-z0-9_-]*")
#: the longest MCP server name (homelabnext.modules.census.MCP_NAME_MAX): a longer one is refused
#: here, never returned, since past this length a name is more likely a pasted secret than a name
MCP_NAME_MAX = 64
#: the most server names one file may register
MAX_SERVERS = 1024


class Refused(Exception):
    pass


def owned(uid: int, euid: int) -> bool:
    """A file or directory root's or this module's user's."""
    return uid in (0, euid)


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
            if not owned(st.st_uid, os.geteuid()):
                raise Refused(f"{shown} is neither root's nor this user's")
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
        if st.st_nlink != 1:
            raise Refused(f"{path} has more than one link")
        if not owned(st.st_uid, os.geteuid()):
            raise Refused(f"{path} is neither root's nor this user's")
        data = b""
        while len(data) <= max_bytes and (block := os.read(f, max_bytes + 1 - len(data))):
            data += block
    finally:
        os.close(f)
    if len(data) > max_bytes:
        raise Refused(f"{path} is not a regular file of at most {max_bytes} bytes")
    return data.decode("utf-8", "replace")


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict:
    out: dict = {}
    for k, v in pairs:
        if k in out:
            raise ValueError(f"a duplicate key {k!r}")
        out[k] = v
    return out


def _no_constant(name: str) -> object:
    raise ValueError(f"{name} is not JSON")


def _yaml_loader():
    """PyYAML's safe loader with duplicate keys and aliases refused, or None where PyYAML is not
    installed on this host."""
    try:
        import yaml
    except ImportError:
        return None, None

    class Strict(yaml.SafeLoader):
        # an alias is how a small file expands into a huge document, and no configuration needs one
        def compose_node(self, parent, index):
            event = self.peek_event()
            if isinstance(event, yaml.AliasEvent):
                raise yaml.composer.ComposerError(
                    "while reading a configuration", None, "aliases are refused", event.start_mark
                )
            return yaml.SafeLoader.compose_node(self, parent, index)

        def construct_mapping(self, node, deep=False):
            seen = set()
            for key_node, _ in node.value:
                key = self.construct_object(key_node, deep=deep)
                if not isinstance(key, collections.abc.Hashable):
                    # a complex key (a sequence or mapping as a key): no configuration has one
                    raise yaml.constructor.ConstructorError(
                        None, None, "a key that is not a scalar", key_node.start_mark
                    )
                if key in seen:
                    raise yaml.constructor.ConstructorError(
                        None, None, f"a duplicate key {key!r}", key_node.start_mark
                    )
                seen.add(key)
            return super().construct_mapping(node, deep=deep)

    return yaml, Strict


def server_names(text: str, client: str, path: str) -> list[str]:
    """The server names a configuration of ``client`` registers, parsed strictly; :class:`Refused`
    for anything else.  The text itself is never part of a message."""
    try:
        if client == "hermes":
            yaml, loader = _yaml_loader()
            if yaml is None:
                raise Refused(f"{path}: PyYAML is not installed on this host to parse it")
            try:
                doc = yaml.load(text, Loader=loader)
            except yaml.YAMLError as exc:
                raise Refused(f"{path} does not parse ({type(exc).__name__})") from None
        else:
            doc = json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_no_constant)
    except (ValueError, RecursionError) as exc:
        why = "nested too deeply" if isinstance(exc, RecursionError) else type(exc).__name__
        raise Refused(f"{path} does not parse ({why})") from None
    key = SERVERS_KEY[client]
    if not isinstance(doc, dict):
        raise Refused(f"{path} is not a {client} configuration")
    servers = doc.get(key, {})
    if not isinstance(servers, dict):
        raise Refused(f"{path}: {key} is not a mapping")
    if len(servers) > MAX_SERVERS:
        raise Refused(f"{path} registers more than {MAX_SERVERS} servers")
    for name in servers:
        if not isinstance(name, str) or len(name) > MCP_NAME_MAX or not MCP_NAME_RE.fullmatch(name):
            raise Refused(f"{path}: a server name is not an inventory name")
    return sorted(servers)


def read_names(path: str, client: str, max_bytes: int) -> dict:
    """One configuration as the census sees it: present or not, and the server names it
    registers; never its text."""
    if not isinstance(client, str) or client not in BASENAMES:
        raise Refused(f"{path}: {client!r} is no known client")
    if not BASENAMES[client].fullmatch(path.rsplit("/", 1)[-1]):
        raise Refused(f"{path} is not named as a {client} configuration")
    text = read_one(path, max_bytes)
    if text is None:
        return {"path": path, "client": client, "present": False, "servers": []}
    return {
        "path": path,
        "client": client,
        "present": True,
        "servers": server_names(text, client, path),
    }


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
            configs.append(read_names(path, client, p["max_bytes"]))
    except Refused as exc:
        module.fail_json(msg=f"module_census: an MCP client configuration: {exc}")
    except OSError as exc:
        module.fail_json(msg=f"module_census: {exc.filename}: {exc.strerror}")
    module.exit_json(changed=False, configs=configs)


if __name__ == "__main__":
    main()
