# SPDX-License-Identifier: Apache-2.0
"""What runs, gathered from the hosts: a ``platform/module_inventory`` built from the census the
``module_census`` role writes (ADR-0027 follow-up 9; docs/modules.md, "What the loader checks").

The role runs two read-only queries on every host of the play, ``systemctl list-unit-files
--state=enabled`` and ``systemctl list-units --state=active`` (both for ``hnx-*`` services and
timers), and the controller writes what each host answered to ``<dir>/<host>.json``
(``{"host": ..., "enabled": [lines], "active": [lines]}``), plus ``<dir>/_hosts.json``, the play's
hosts (every host it targeted, the unreachable ones included).  :func:`gather` reads that
directory and returns the inventory: ``units`` is every ``hnx-<name>.service`` or ``.timer`` some
host reports with an enabled unit file **or** as an active unit, as ``<name>``.  So a unit that
runs without being enabled (``static``, ``enabled-runtime``, linked, or started by another unit
or ``systemd-run`` under a ``hnx-`` name) is counted while it is active; one that is neither
enabled nor active at the moment of the census is not.  Template instances (``hnx-<name>@...``)
are counted and noted, never listed: an instance name is not a unit a manifest declares.

**The census is a union across hosts.**  A unit counts as running when any host reports it, so a
unit enabled on the wrong host satisfies the check for the right one: the inventory carries no
host, and a manifest declares no placement per unit to compare one with.

**No binding is guessed, and none is written.**  A running name is bound to a module by its name
alone (``<id>`` or ``<id>-...``; the loader's :func:`~homelabnext.modules.loader.running_problems`
decides it), the same rule the hand-written inventory followed: the gatherer lists names and
never says whose they are, so nothing a host could write decides the binding.

**Trust.**  The directory is the controller's (the deploy creates it empty), and a host's only
input is its own command output, which arrives as a JSON-encoded list of lines and is parsed
strictly: every line must be one enabled unit of the fleet's shape, so a host that prints
anything else makes the census unreadable (it fails, never passes).  A host that did not answer
leaves its file missing, which fails too: the census must cover every host the play targeted.
What a host reports is believed: a host whose root is compromised can hide a unit or claim one,
and no census read from the host itself can rule that out.

**Agents.**  On a host that runs the broker (the role's ``module_census_broker_socket``), the role
also asks the running broker, as root, which agents it serves (``hnx broker agents``: the
operator's operation, :mod:`homelabnext.broker.server`), and the answer carries ``agents``, one
agent key per line.  ``agents`` is gathered when at least one host answered it (the union of the
keys every broker serves) and stays in ``not_gathered`` otherwise: a lab whose census asked no
broker has not shown which agents run, which is never read as "none".  Each line must be one
inventory name; anything else fails the census, like a unit line.  A broker host's answer is
believed as a unit line is: it is that host's broker answering its root.

**Notify pairs.**  Each answer also carries ``pairs``: the host's boot id and clock, and for
every notifier owner (:data:`homelabnext.notify.record.OWNERS`) the text of its record under the
fixed directory (:data:`~homelabnext.notify.record.RECORD_DIR`) with the start time now of the
process the record names, or null where the host holds none.  Each record is read strictly
(:func:`homelabnext.notify.record.parse_record`), and one that no longer says what runs
(:func:`~homelabnext.notify.record.stale`: written before the host's last boot, a broker whose
process is gone, a status pass older than its window) is noted and not counted: a leftover is
never read as running.  The inventory's ``notify_pairs`` is every pair some counted record holds,
each listed once (two owners holding one pair alike are one; one title held with two recoveries
is listed twice, which the loader refuses).  When no record counts, ``notify_pairs`` is left out
and the pairs are not compared: the census cannot tell "no notifier records its pairs" from "no
pair runs".  A record is the owning service's word about its own pairs, believed as a host's
``systemctl`` output is.

**MCP servers.**  On a host that lists the MCP client configurations it has installed (the role's
``module_census_mcp_configs``: each ``{path, client}``, what ``hnx mcp catalog render`` wrote and
the deploy put in place, trusted overlay input), the role reads each one in one step (no link at
any step, root's or the connection user's, from directories its group and others may not write, a
small regular file with a single link, named as its client's configuration) and parses it on the
host, for its client (:data:`MCP_CLIENTS`: the ``mcpServers`` object of a JSON client file, the
``mcp_servers`` mapping of a Hermes YAML one, both strict).  A configuration can hold secrets, so
its text never leaves the host: the answer carries ``mcp``, per file its client, whether it is
present and the server names it registers.  Every name is one a client registers when it starts:
a record's id, or its instance name (``instance:`` in the catalog record), which the loader
matches back to the record.  An absent file registers nothing.  ``mcp_servers`` is gathered when
at least one host listed a configuration and stays in ``not_gathered`` otherwise.  A server name
that is not a valid MCP server name, or a file that does not parse, fails the census (one host's stray
name fails it for the whole fleet).  The file is what the client reads, so a home that lost an
entry, or one a hand added, shows; what a client did with it after it started (a server that
failed to launch) does not, nor what a client reads from files the host does not list (a user's
or a project's own configuration, a managed policy file).

**Listening sockets.**  Each answer also carries ``listening``: the TCP ports the host listens on
and the UDP ports it has bound, from the kernel's own socket tables (the role's
``listening_sockets`` module), as ``tcp/<port>`` or ``udp/<port>``, with ``@lo`` for a socket
bound only to loopback.  The inventory's
``listening`` is each host's list.  Service rows themselves stay in ``not_gathered``: a socket
names no row.  ``hnx modules check`` judges each selected module's row by whether the host the
site places it on listens on its port (:func:`~homelabnext.modules.loader.listening_problems`),
which is derived, from what the host reports and what the row and the placement declare: a row
whose port is held by another program reads as answering, and a row nobody declared is never
seen.

**Lake tables.**  On the host that runs the lake catalog (the role's
``module_census_catalog_url``, a loopback IP literal, and ``module_census_catalog_warehouse``),
the role runs ``hnx modules catalog-tables`` there (:func:`catalog_tables`): the Iceberg REST
catalog's namespaces and tables, by GET requests only, with the token (when the catalog wants
one) read on that host from a file its reader's alone (:func:`read_token`) and sent to the
loopback address alone; only names come back.  ``tables`` is gathered when at least one host
listed a catalog (the union, as ``table:<namespace>.<name>``) and stays in ``not_gathered``
otherwise; a name that is not ``<namespace>.<name>`` fails the census.  What the catalog lists is
believed, like a unit line.

Kinds the hosts cannot report (service rows by name) are named in the inventory's
``not_gathered``, and the loader notes each as not compared; an inventory that merely leaves a
kind out is refused by its schema, never read as "nothing runs".
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import stat
import time
import urllib.parse
from pathlib import Path
from typing import Any

from homelabnext.modules import loader as ld
from homelabnext.notify import record as nr

HOSTS_FILE = "_hosts.json"
#: an inventory host name as a file name: no path separator, no leading dot, never the host list
HOST_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,252}")
#: one line of ``systemctl list-unit-files --no-legend --plain --state=enabled``: the unit file,
#: its state and (systemd 245 and later) its vendor preset
LINE_RE = re.compile(
    r"hnx-(?P<name>[a-z0-9][a-z0-9-]*)(?P<template>@?)\.(?:service|timer)"
    r"[ \t]+enabled(?:[ \t]+(?:enabled|disabled|ignored|-))?[ \t]*"
)
#: one line of ``systemctl list-units --no-legend --plain --state=active``: the unit, its load
#: state, ``active``, its sub-state and its description (free text from the unit file: printable,
#: never parsed)
ACTIVE_RE = re.compile(
    r"hnx-(?P<name>[a-z0-9][a-z0-9-]*)(?P<instance>@[^\s]*)?\.(?:service|timer)"
    r"[ \t]+loaded[ \t]+active[ \t]+[a-z-]+(?:[ \t]+[^\x00-\x1f\x7f]*)?"
)
#: an inventory name (``platform/module_inventory`` ``$defs.name``)
NAME_RE = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*")
#: an MCP server name as a client registers it: what ``platform/mcp_server`` ``instance`` can expand
#: to (``^[a-z0-9{][a-z0-9_{}-]{0,63}$`` with the placeholders filled), so ``_`` is allowed and the
#: longest is 64.  ``homelabnext.modules.loader.instance_pattern`` matches these back to a record
MCP_NAME_RE = re.compile(r"[a-z0-9][a-z0-9_-]*")
#: the client formats the census reads, and the key of the server map each one holds
MCP_CLIENTS = {
    "claude-code": "mcpServers",
    "generic": "mcpServers",
    "hermes": "mcp_servers",
}
#: one listening socket as the role's ``listening_sockets`` module reports it
SOCKET_RE = re.compile(r"(?:tcp|udp)/[1-9][0-9]{0,4}(?:@lo)?")
MAX_HOSTS = 4096
MAX_LINES = 4096
#: the longest MCP server name a census accepts (the role's reader refuses longer ones on the host):
#: the manifest schema's ``instance`` allows 64 characters, so the loader can produce one that long
#: and the census must not fail the whole fleet on it; past 64 a name is more likely a secret pasted
#: where a name belongs than a name, so it is refused (clipped in the message) and never persisted
MCP_NAME_MAX = 64
MAX_SOCKETS = 16384
#: one lake table as the catalog listing reports it, ``<namespace>.<name>`` (the inventory's
#: ``table:<namespace>.<name>`` without its prefix: ``platform/module_inventory``, at most 129)
TABLE_RE = re.compile(r"[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*")
TABLE_PART_RE = re.compile(r"[a-z][a-z0-9_]*")
TABLE_MAX = 129 - len("table:")
#: a bearer token as the catalog listing sends it (RFC 6750 ``b64token``): one line, no space
TOKEN_RE = re.compile(r"[A-Za-z0-9._~+/=-]{1,4096}")
#: the one directory a catalog token file may sit in (one plain name below it)
TOKEN_DIR = "/etc/homelabnext"
TOKEN_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
#: the longest the catalog listing may take, every request included
CATALOG_DEADLINE = 120.0
#: the longest error the catalog listing reports
ERROR_MAX = 200


class CensusError(ValueError):
    """A census that cannot be read, or that does not cover every host (the gather fails)."""


def _read(path: Path) -> Any:
    try:
        st = path.lstat()
    except OSError as exc:
        raise CensusError(f"{path.name}: cannot be read ({exc.strerror})") from None
    if not stat.S_ISREG(st.st_mode):
        raise CensusError(f"{path.name}: not a regular file")
    try:
        data = ld.read_bytes(path, follow=False)
        return json.loads(data.decode("utf-8"))
    except ld.Unreadable as exc:
        raise CensusError(f"{path.name}: {exc}") from None
    except (UnicodeDecodeError, ValueError) as exc:
        raise CensusError(f"{path.name}: not JSON ({exc.__class__.__name__})") from None


def parse_units(lines: Any, host: str, active: bool = False) -> tuple[set[str], int]:
    """The fleet unit names one host reports enabled (or, with ``active``, active), and how many
    template units or instances it listed (``hnx-<name>@...``: left out, see the module)."""
    what = "active" if active else "enabled"
    if not isinstance(lines, list) or not all(isinstance(x, str) for x in lines):
        raise CensusError(f"{host}: the {what} units are not a list of lines")
    if len(lines) > MAX_LINES:
        raise CensusError(f"{host}: over {MAX_LINES} {what} lines")
    names: set[str] = set()
    templates = 0
    for i, line in enumerate(lines, 1):
        m = (ACTIVE_RE if active else LINE_RE).fullmatch(line)
        if m is None:
            raise CensusError(
                f"{host}: {what} line {i} is not an {what} hnx- unit: {ld._shown(line)}"
            )
        if m["instance" if active else "template"]:
            templates += 1
            continue
        name = m["name"]
        if len(name) > 64 or not NAME_RE.fullmatch(name):
            raise CensusError(
                f"{host}: {what} line {i}: {ld._shown(name)} is not a valid MCP server name"
            )
        names.add(name)
    return names, templates


def parse_agents(lines: Any, host: str) -> set[str]:
    """The agent keys one host's broker serves: one inventory name per line, nothing else."""
    if not isinstance(lines, list) or not all(isinstance(x, str) for x in lines):
        raise CensusError(f"{host}: the agents are not a list of lines")
    if len(lines) > MAX_LINES:
        raise CensusError(f"{host}: over {MAX_LINES} agent lines")
    keys: set[str] = set()
    for i, line in enumerate(lines, 1):
        if len(line) > 64 or not NAME_RE.fullmatch(line):
            raise CensusError(f"{host}: agent line {i} is not an agent key: {ld._shown(line)}")
        keys.add(line)
    return keys


def parse_mcp(configs: Any, host: str) -> tuple[set[str], list[str]]:
    """The MCP server names one host's installed client configurations register, and a note for
    each configuration that is absent (it registers nothing).  The host parsed each file for its
    client and sent only the names (a configuration can hold secrets); here the shape and every
    name are checked again."""
    if not isinstance(configs, list) or not configs or len(configs) > MAX_LINES:
        raise CensusError(f"{host}: the MCP client configurations are not a non-empty list")
    names: set[str] = set()
    notes: list[str] = []
    for i, entry in enumerate(configs, 1):
        if not isinstance(entry, dict) or set(entry) != {"path", "client", "present", "servers"}:
            raise CensusError(
                f"{host}: MCP client configuration {i} is not {{path, client, present, servers}}"
            )
        path, client = entry["path"], entry["client"]
        present, servers = entry["present"], entry["servers"]
        if not isinstance(path, str) or client not in MCP_CLIENTS:
            raise CensusError(f"{host}: MCP client configuration {i} names no known client")
        if not isinstance(present, bool) or not isinstance(servers, list):
            raise CensusError(f"{host}: {ld._shown(path)}: present or servers is malformed")
        if not present:
            if servers:
                raise CensusError(f"{host}: {ld._shown(path)} is absent yet registers servers")
            notes.append(f"{host}: {ld._shown(path)} is absent: {client} registers nothing from it")
            continue
        if len(servers) > MAX_LINES or len(set(map(str, servers))) != len(servers):
            raise CensusError(f"{host}: {ld._shown(path)}: the server names are not a set")
        for name in servers:
            if (
                not isinstance(name, str)
                or len(name) > MCP_NAME_MAX
                or not MCP_NAME_RE.fullmatch(name)
            ):
                raise CensusError(
                    f"{host}: {ld._shown(path)}: server {ld._clipped(name)} is not a valid MCP server name"
                )
            names.add(name)
    return names, notes


def parse_tables(found: Any, host: str) -> tuple[set[str], int]:
    """The lake tables one host's catalog listing reports, as ``table:<namespace>.<name>``, and
    how many names it left out (:func:`catalog_tables`)."""
    if not isinstance(found, dict) or set(found) != {"tables", "left_out"}:
        raise CensusError(f"{host}: the lake tables are not {{tables, left_out}}")
    tables, left = found["tables"], found["left_out"]
    if not isinstance(tables, list) or not all(isinstance(x, str) for x in tables):
        raise CensusError(f"{host}: the lake tables are not a list of text")
    if len(tables) > MAX_LINES:
        raise CensusError(f"{host}: over {MAX_LINES} lake tables")
    if not isinstance(left, int) or isinstance(left, bool) or left < 0:
        raise CensusError(f"{host}: the lake tables' left_out is not a count")
    out: set[str] = set()
    for i, name in enumerate(tables, 1):
        if len(name) > TABLE_MAX or not TABLE_RE.fullmatch(name):
            raise CensusError(
                f"{host}: lake table {i} is not <namespace>.<name>: {ld._shown(name)}"
            )
        out.add(f"table:{name}")
    return out, left


def read_token(path: str | Path) -> str:
    """The bearer token in ``path``, read in one step: never through a link, a regular file with
    a single link, owned by this process's user, which its group and others may neither read nor
    write, one line of :data:`TOKEN_RE`.  The token is never part of an error."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError as exc:
        raise CensusError(f"token file: cannot be opened ({exc.strerror})") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise CensusError("token file: not a regular file with a single link")
        if st.st_uid != os.geteuid() or st.st_mode & 0o077:
            raise CensusError("token file: not this user's alone (owner only, no group or other)")
        if st.st_size > 4097:
            raise CensusError("token file: larger than a token")
        raw = os.read(fd, 4098)
    finally:
        os.close(fd)
    text = raw.decode("ascii", "replace")
    text = text[:-1] if text.endswith("\n") else text
    if not TOKEN_RE.fullmatch(text):
        raise CensusError("token file: not one line of token characters")
    return text


class _Deadline:
    """An opener that refuses a request once ``deadline`` seconds have passed on ``clock`` since
    it was made, and gives no request longer than what is left."""

    def __init__(self, opener: Any, deadline: float, clock: Any) -> None:
        self._opener = opener
        self._clock = clock
        self._end = clock() + deadline

    def open(self, req: Any, timeout: float | None = None) -> Any:
        left = self._end - self._clock()
        if left <= 0:
            raise CensusError("the catalog listing ran past its deadline")
        return self._opener.open(req, timeout=min(timeout, left) if timeout else left)


def _plain(text: str, token: str | None) -> str:
    """``text`` fit to report: the token replaced, control characters dropped, short."""
    if token:
        text = text.replace(token, "<token>")
    return re.sub(r"[^ -~]", "", text)[:ERROR_MAX]


def catalog_tables(
    url: str,
    warehouse: str,
    *,
    token_file: str | Path | None = None,
    api_root: str = "/catalog",
    timeout: float = 15.0,
    deadline: float = CATALOG_DEADLINE,
    clock: Any = time.monotonic,
) -> dict[str, Any]:
    """The lake tables the Iceberg REST catalog at ``url`` (the lake-catalog slot's contract,
    :class:`homelabnext.lake.rest_catalog.RestCatalog`) lists in ``warehouse``: GET requests
    only, over plain http to a loopback IP literal (the census runs on the catalog's own host),
    with the token in ``token_file`` (a plain name in :data:`TOKEN_DIR`, :func:`read_token`) sent
    to that address alone (no redirect followed, no proxy), all of it within ``deadline`` seconds.
    ``{"tables": ["<namespace>.<name>", ...], "left_out": n}``: a namespace or a table whose name
    is not of the inventory's shape is left out and counted (no module's table can have such a
    name), as is each namespace directly under a listed one (its tables are not listed) and a
    namespace that is gone by the time its tables are asked for.  More than :data:`MAX_LINES`
    namespaces or tables fails.  An error names the request and its HTTP status, never what the
    catalog answered."""
    from homelabnext._http import credential_opener
    from homelabnext.lake import LakeError
    from homelabnext.lake.errors import UnknownTable
    from homelabnext.lake.rest_catalog import RestCatalog

    try:
        parts = urllib.parse.urlsplit(url)
        local = (
            parts.scheme == "http"
            and parts.username is None
            and ipaddress.ip_address(parts.hostname or "").is_loopback
        )
    except ValueError:
        local = False
    if not local:
        raise CensusError("the catalog URL is not http on a loopback address (an IP literal)")
    token = None
    if token_file is not None:
        where = Path(token_file)
        if where.parent != Path(TOKEN_DIR) or not TOKEN_NAME_RE.fullmatch(where.name):
            raise CensusError(f"token file: not a plain name in {TOKEN_DIR}")
        token = read_token(where)
    catalog = RestCatalog(
        url,
        warehouse=warehouse,
        api_root=api_root,
        auth=(lambda: f"Bearer {token}") if token else None,
        timeout=timeout,
        max_bytes=1 << 20,
        opener=_Deadline(credential_opener(), deadline, clock),
    )
    tables: list[str] = []
    left = 0
    try:
        for ns in catalog.list_namespaces(limit=MAX_LINES):
            if len(ns) != 1 or not TABLE_PART_RE.fullmatch(ns[0]):
                left += 1
                continue
            try:
                children = catalog.list_namespaces(limit=MAX_LINES, parent=ns)
                names = catalog.list_tables(ns[0], limit=MAX_LINES)
            except UnknownTable:
                # listed a moment ago and gone now: nothing of it to count but itself
                left += 1
                continue
            for child in children:
                if len(child) != 2 or child[0] != ns[0]:
                    raise CensusError(f"the catalog lists a namespace not under {ns[0]!r}")
            left += len(children)
            for name in names:
                full = f"{ns[0]}.{name}"
                if len(full) > TABLE_MAX or not TABLE_RE.fullmatch(full):
                    left += 1
                    continue
                tables.append(full)
                if len(tables) > MAX_LINES:
                    raise CensusError(f"the catalog lists over {MAX_LINES} tables")
    except LakeError as exc:
        raise CensusError(_plain(getattr(exc, "bare", None) or str(exc), token)) from None
    return {"tables": sorted(set(tables)), "left_out": left}


def parse_listening(found: Any, host: str) -> list[str]:
    """The sockets one host listens on: each ``tcp/<port>`` or ``udp/<port>``, a port 1 to
    65535, with ``@lo`` when bound only to loopback, listed once."""
    if not isinstance(found, list) or not all(isinstance(x, str) for x in found):
        raise CensusError(f"{host}: the listening sockets are not a list of text")
    if len(found) > MAX_SOCKETS:
        raise CensusError(f"{host}: over {MAX_SOCKETS} listening sockets")
    out: set[str] = set()
    for i, sock in enumerate(found, 1):
        if not SOCKET_RE.fullmatch(sock) or int(sock.split("/")[1].split("@")[0]) > 65535:
            raise CensusError(f"{host}: listening socket {i} is not proto/port: {ld._shown(sock)}")
        out.add(sock)
    return sorted(out, key=_socket_order)


def _socket_order(sock: str) -> tuple[str, int, str]:
    proto, _, rest = sock.partition("/")
    port, _, scope = rest.partition("@")
    return proto, int(port), scope


def gather(directory: str | Path) -> tuple[dict[str, Any], list[str]]:
    """The inventory the census in ``directory`` describes, and notes on what it does not cover.

    Fails (:class:`CensusError`) when the directory is not a plain directory, the host list is
    missing or malformed, a listed host wrote no answer, an entry is not a listed host's answer,
    or an answer does not parse."""
    root = Path(directory)
    if root.is_symlink() or not root.is_dir():
        raise CensusError(f"{root}: not a directory")
    hosts = _read(root / HOSTS_FILE)
    if (
        not isinstance(hosts, list)
        or not hosts
        or len(hosts) > MAX_HOSTS
        or not all(isinstance(h, str) and HOST_RE.fullmatch(h) for h in hosts)
        or len(set(hosts)) != len(hosts)
    ):
        raise CensusError(f"{HOSTS_FILE}: not a non-empty list of distinct host names")
    expected = {f"{h}.json": h for h in hosts}
    present = {p.name for p in root.iterdir()} - {HOSTS_FILE}
    stray = sorted(present - set(expected))
    if stray:
        raise CensusError(f"not a listed host's answer: {', '.join(map(ld._shown, stray))}")
    missing = sorted(h for f, h in expected.items() if f not in present)
    if missing:
        raise CensusError(f"no answer from {', '.join(map(ld._shown, missing))}")
    units: set[str] = set()
    agents: set[str] = set()
    brokers = 0
    templates = 0
    pairs: set[tuple[str, str, str | None]] = set()
    records = 0
    stale_notes: list[str] = []
    mcp: set[str] = set()
    mcp_hosts = 0
    listening: list[dict[str, Any]] = []
    tables: set[str] = set()
    catalogs = 0
    tables_left = 0
    base = {"host", "enabled", "active", "pairs", "listening"}
    for file, host in sorted(expected.items()):
        doc = _read(root / file)
        if not isinstance(doc, dict) or not base <= set(doc) <= base | {"agents", "mcp", "tables"}:
            raise CensusError(
                f"{file}: not {{host, enabled, active, pairs, listening}} (and agents on a "
                "broker host, mcp where MCP client configurations are installed, tables on a "
                "lake catalog host)"
            )
        if doc["host"] != host:
            raise CensusError(f"{file}: written for {ld._shown(doc['host'])}")
        for active in (False, True):
            names, t = parse_units(doc["active" if active else "enabled"], host, active)
            units |= names
            templates += t
        listening.append({"host": host, "sockets": parse_listening(doc["listening"], host)})
        found, left = parse_pairs(doc["pairs"], host)
        stale_notes += left
        records += len(found)
        for held in found:
            pairs |= {(p["problem"], p["recovery"], p.get("module")) for p in held}
        if "agents" in doc:
            agents |= parse_agents(doc["agents"], host)
            brokers += 1
        if "mcp" in doc:
            found_mcp, absent = parse_mcp(doc["mcp"], host)
            mcp |= found_mcp
            stale_notes += absent
            mcp_hosts += 1
        if "tables" in doc:
            found_tables, left = parse_tables(doc["tables"], host)
            tables |= found_tables
            tables_left += left
            catalogs += 1
            if len(tables) > MAX_LINES:
                raise CensusError(f"the lake catalogs list over {MAX_LINES} tables")
    notes = [
        f"gathered from {len(hosts)} host(s): {len(units)} fleet unit(s) enabled or active",
        "the census is a union across hosts: a unit is not checked against the host it runs on",
        "service rows are not gathered by name: each selected module's row is judged by whether "
        "its placed host listens on its port (derived from the hosts' sockets)",
    ]
    if brokers:
        notes.append(f"asked {brokers} broker(s): {len(agents)} agent(s) served")
    else:
        notes.append(
            "no host's census asked a broker (module_census_broker_socket): agents not gathered"
        )
    if mcp_hosts:
        notes.append(
            f"read the MCP client configurations of {mcp_hosts} host(s): {len(mcp)} server "
            "name(s) registered"
        )
    else:
        notes.append(
            "no host lists an installed MCP client configuration (module_census_mcp_configs): "
            "MCP servers not gathered"
        )
    if catalogs:
        notes.append(f"listed {catalogs} lake catalog(s): {len(tables)} table(s)")
        if tables_left:
            notes.append(
                f"{tables_left} catalog namespace(s) or table(s) not of the inventory's shape "
                "(<namespace>.<name>, lowercase) left out: no module's table has such a name"
            )
    else:
        notes.append(
            "no host's census listed a lake catalog (module_census_catalog_url): tables not "
            "gathered"
        )
    if templates:
        notes.append(
            f"{templates} template unit(s) or instance(s) (hnx-<name>@...) left out: an instance "
            "is not a unit a manifest declares"
        )
    gathered = (
        {"units"}
        | ({"agents"} if brokers else set())
        | ({"mcp_servers"} if mcp_hosts else set())
        | ({"tables"} if catalogs else set())
    )
    inventory: dict[str, Any] = {"schema_version": "1.0", "units": sorted(units)}
    if mcp_hosts:
        inventory["mcp_servers"] = sorted(mcp)
    if brokers:
        inventory["agents"] = sorted(agents)
    if catalogs:
        inventory["tables"] = sorted(tables)
    inventory["not_gathered"] = [k for k in ld.INVENTORY_KINDS if k not in gathered]
    inventory["listening"] = listening
    if records:
        inventory["notify_pairs"] = [
            {"problem": t, "recovery": r, **({"module": m} if m is not None else {})}
            for t, r, m in sorted(pairs, key=lambda x: (x[0], x[1], x[2] or ""))
        ]
        notes.insert(2, f"{len(pairs)} notify pair(s) from {records} pairs record(s)")
    else:
        notes.insert(
            2,
            "no host holds a notify pairs record that counts: the recovery pairs were not "
            "compared (a notifier records them with --notify-pairs-dir)",
        )
    return inventory, notes + stale_notes


_PAIRS_KEYS = {"boot_id", "now", "records"}


def parse_pairs(found: Any, host: str) -> tuple[list[list[dict[str, str]]], list[str]]:
    """The pairs records one host answered that still count, each read strictly, and a note for
    each that does not (:func:`homelabnext.notify.record.stale`)."""
    if not isinstance(found, dict) or set(found) != _PAIRS_KEYS:
        raise CensusError(f"{host}: the pairs are not {{boot_id, now, records}}")
    boot, now, records = found["boot_id"], found["now"], found["records"]
    if boot is not None and not (isinstance(boot, str) and len(boot) <= 64):
        raise CensusError(f"{host}: the host's boot id is not text or null")
    if not isinstance(now, int) or isinstance(now, bool) or now < 0:
        raise CensusError(f"{host}: the host's clock is not a time")
    if not isinstance(records, dict) or set(records) != set(nr.OWNERS):
        raise CensusError(
            f"{host}: the records are not one entry per owner ({', '.join(nr.OWNERS)})"
        )
    out, notes = [], []
    for owner in nr.OWNERS:
        entry = records[owner]
        if entry is None:
            continue
        if not isinstance(entry, dict) or set(entry) != {"text", "pid_started"}:
            raise CensusError(f"{host}: the {owner} pairs record is not {{text, pid_started}}")
        text, started = entry["text"], entry["pid_started"]
        if not isinstance(text, str):
            raise CensusError(f"{host}: the {owner} pairs record is not text")
        if started is not None and (not isinstance(started, int) or isinstance(started, bool)):
            raise CensusError(f"{host}: the {owner} record's process start time is not a number")
        try:
            record = nr.parse_record(text, owner)
        except nr.RecordError as exc:
            raise CensusError(f"{host}: pairs record {exc}") from None
        why = nr.stale(record, boot, now, started)
        if why is not None:
            notes.append(f"{host}: the {owner} pairs record does not count ({why})")
            continue
        out.append(record.pairs)
    return out, notes
