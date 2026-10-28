# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: listening-sockets
#   kind: tool
#   purpose: List the TCP ports a host listens on and the UDP ports it has bound, from the kernel's own socket tables, for the census of which service rows answer.
#   owner: platform
#   trigger: [role:module_census]
#   inputs: none (the kernel's /proc/net socket tables)
#   outputs: the sockets as proto/port, or proto/port@lo for one bound only to loopback, sorted and listed once (JSON, as an Ansible module)
#   exit:
#     "0": the socket tables were read (an absent IPv6 table is IPv6 being off, not a failure)
#     "1": the IPv4 TCP table cannot be read, a table is over the size read, or the host holds more sockets than the census takes; the census stops
"""Ansible module (role-local): the sockets a host listens on, for ``hnx modules gather``.

It reads the kernel's socket tables for the host's own network namespace (``/proc/net/tcp``,
``tcp6``, ``udp``, ``udp6``), never a command's output, and returns each listening TCP port
(state ``0A``) and each bound, unconnected UDP port (state ``07``, no remote port) as
``tcp/<port>`` or ``udp/<port>``, or with ``@lo`` when it is bound only to a loopback address (a
service other hosts cannot reach).  A line that does not parse (an address or port that is not
the kernel's hex) is skipped.  More than ``MAX_SOCKETS`` distinct sockets fails rather than being
cut short.  A socket in another network namespace (a container's own) is not in these tables; a
published container port is, through the process that holds the host side of it, where the
runtime keeps one.  Read-only; supports check mode.  Standard library plus Ansible's own
module_utils.
"""

from __future__ import annotations

import ipaddress
import re
import sys

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
sockets: {description: "Each listening TCP and bound UDP port as proto/port (proto/port@lo when bound only to loopback), sorted, once.", type: list, elements: str, returned: always}
"""

#: per table, the state a listening socket has in it
TABLES = {"tcp": "0A", "tcp6": "0A", "udp": "07", "udp6": "07"}
#: the largest table read (a busy host's TCP table is a few MiB at most)
MAX_BYTES = 32 * 1024 * 1024
#: the most distinct sockets a host's answer may carry (``hnx modules gather`` takes as many)
MAX_SOCKETS = 16384
#: an address field: the kernel's hex address (IPv4 8 digits, IPv6 32), a colon, a 4-digit port
_ADDR = re.compile(r"(?P<ip>[0-9A-Fa-f]{8}|[0-9A-Fa-f]{32}):(?P<port>[0-9A-Fa-f]{4})")


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


def _address(hexip: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """The kernel's hex address: 32-bit words in host byte order."""
    words = [
        int.from_bytes(bytes.fromhex(hexip[i : i + 8]), sys.byteorder).to_bytes(4, "big")
        for i in range(0, len(hexip), 8)
    ]
    return ipaddress.ip_address(b"".join(words))


def _loopback(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    mapped = getattr(ip, "ipv4_mapped", None)
    return ip.is_loopback or bool(mapped and mapped.is_loopback)


def listening(table: str, text: str) -> set[str]:
    """``proto/port`` (``@lo`` when bound only to loopback) for every listening socket in one
    table's text (its header line first); a line that does not parse is skipped."""
    proto, state = table.rstrip("6"), TABLES[table]
    out = set()
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 4 or fields[3] != state:
            continue
        local, remote = _ADDR.fullmatch(fields[1]), _ADDR.fullmatch(fields[2])
        if local is None or remote is None:
            continue
        if proto == "udp" and remote["port"] != "0000":
            continue  # a connected UDP socket is a client's, not a service's
        port = int(local["port"], 16)
        if not 1 <= port <= 65535:
            continue
        lo = "@lo" if _loopback(_address(local["ip"])) else ""
        out.add(f"{proto}/{port}{lo}")
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
    if len(found) > MAX_SOCKETS:
        raise Refused(
            f"the host holds {len(found)} sockets, over the {MAX_SOCKETS} the census takes"
        )
    return sorted(found, key=_order)


def _order(sock: str) -> tuple[str, int, str]:
    proto, _, rest = sock.partition("/")
    port, _, scope = rest.partition("@")
    return proto, int(port), scope


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
