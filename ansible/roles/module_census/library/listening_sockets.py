# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: listening-sockets
#   kind: tool
#   purpose: List the TCP ports a host listens on and the UDP ports it has bound, from the kernel's own socket tables, for the census of which service rows answer.
#   owner: platform
#   trigger: [role:module_census]
#   inputs: none (the kernel's /proc/net socket tables)
#   outputs: the sockets as proto/port, sorted and listed once (JSON, as an Ansible module)
#   exit:
#     "0": the socket tables were read (an absent IPv6 table is IPv6 being off, not a failure)
#     "1": the IPv4 TCP table cannot be read, or a table is over the size read; the census stops
"""Ansible module (role-local): the sockets a host listens on, for ``hnx modules gather``.

It reads the kernel's socket tables for the host's own network namespace (``/proc/net/tcp``,
``tcp6``, ``udp``, ``udp6``), never a command's output, and returns each listening TCP port
(state ``0A``) and each bound, unconnected UDP port (state ``07``, no remote port) as
``tcp/<port>`` or ``udp/<port>``.  The address a socket is bound to is not reported: a service
that answers only on loopback still listens.  A socket in another network namespace (a
container's own) is not in these tables; a published container port is, through the process that
holds the host side of it, where the runtime keeps one.  Read-only; supports check mode.
Standard library plus Ansible's own module_utils.
"""

from __future__ import annotations

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r"""
module: listening_sockets
short_description: List the TCP ports a host listens on and the UDP ports it has bound
options:
  tables:
    description: The directory of the kernel's socket tables (a test points it at its own).
    type: str
    default: /proc/net
"""

EXAMPLES = r"""
- name: List the listening sockets
  listening_sockets:
    tables: /proc/net
  register: module_census_listening
"""

RETURN = r"""
sockets: {description: Each listening TCP and bound UDP port as proto/port, sorted, once., type: list, elements: str, returned: always}
"""

#: per table, the state a listening socket has in it
TABLES = {"tcp": "0A", "tcp6": "0A", "udp": "07", "udp6": "07"}
#: the largest table read (a busy host's TCP table is a few MiB at most)
MAX_BYTES = 32 * 1024 * 1024


class Refused(Exception):
    pass


def read_table(name: str, root: str = "/proc/net") -> str | None:
    """One socket table's text, or None where the kernel has none (IPv6 off)."""
    try:
        with open(f"{root}/{name}", "rb") as fh:
            data = fh.read(MAX_BYTES + 1)
    except FileNotFoundError:
        return None
    if len(data) > MAX_BYTES:
        raise Refused(f"{root}/{name} is over {MAX_BYTES} bytes")
    return data.decode("ascii", "replace")


def listening(table: str, text: str) -> set[str]:
    """``proto/port`` for every listening socket in one table's text (its header line first)."""
    proto, state = table.rstrip("6"), TABLES[table]
    out = set()
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 4 or fields[3] != state:
            continue
        local, remote = fields[1], fields[2]
        if proto == "udp" and not remote.endswith(":0000"):
            continue  # a connected UDP socket is a client's, not a service's
        port = int(local.rpartition(":")[2], 16)
        if port:
            out.add(f"{proto}/{port}")
    return out


def sockets(root: str = "/proc/net") -> list[str]:
    found: set[str] = set()
    for table in TABLES:
        text = read_table(table, root)
        if text is None:
            if table == "tcp":
                raise Refused(f"{root}/tcp cannot be read")
            continue
        found |= listening(table, text)
    return sorted(found, key=lambda s: (s.split("/")[0], int(s.split("/")[1])))


def main() -> None:
    module = AnsibleModule(
        argument_spec={"tables": {"type": "str", "default": "/proc/net"}},
        supports_check_mode=True,
    )
    root = module.params["tables"]
    if not root.startswith("/") or ".." in root.split("/"):
        module.fail_json(msg="module_census: the socket tables directory is an absolute path")
    try:
        out = sockets(root)
    except Refused as exc:
        module.fail_json(msg=f"module_census: the listening sockets: {exc}")
    except (OSError, ValueError) as exc:
        module.fail_json(msg=f"module_census: the listening sockets: {exc}")
    module.exit_json(changed=False, sockets=out)


if __name__ == "__main__":
    main()
