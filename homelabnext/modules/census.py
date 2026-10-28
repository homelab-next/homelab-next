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

Kinds the hosts cannot report (service rows that answer, MCP servers, tables) are named in the
inventory's ``not_gathered``, and the loader notes each as not compared; an inventory that merely
leaves a kind out is refused by its schema, never read as "nothing runs".
"""

from __future__ import annotations

import json
import re
import stat
from pathlib import Path
from typing import Any

from homelabnext.modules import loader as ld

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
MAX_HOSTS = 4096
MAX_LINES = 4096


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
                f"{host}: {what} line {i}: {ld._shown(name)} is not an inventory name"
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
    base = {"host", "enabled", "active"}
    for file, host in sorted(expected.items()):
        doc = _read(root / file)
        if not isinstance(doc, dict) or set(doc) not in (base, base | {"agents"}):
            raise CensusError(
                f"{file}: not {{host, enabled, active}} (and agents on a broker host)"
            )
        if doc["host"] != host:
            raise CensusError(f"{file}: written for {ld._shown(doc['host'])}")
        for active in (False, True):
            names, t = parse_units(doc["active" if active else "enabled"], host, active)
            units |= names
            templates += t
        if "agents" in doc:
            agents |= parse_agents(doc["agents"], host)
            brokers += 1
    notes = [
        f"gathered from {len(hosts)} host(s): {len(units)} fleet unit(s) enabled or active",
        "the census is a union across hosts: a unit is not checked against the host it runs on",
    ]
    if brokers:
        notes.append(f"asked {brokers} broker(s): {len(agents)} agent(s) served")
    else:
        notes.append(
            "no host's census asked a broker (module_census_broker_socket): agents not gathered"
        )
    if templates:
        notes.append(
            f"{templates} template unit(s) or instance(s) (hnx-<name>@...) left out: an instance "
            "is not a unit a manifest declares"
        )
    gathered = {"units", "agents"} if brokers else {"units"}
    inventory: dict[str, Any] = {"schema_version": "1.0", "units": sorted(units)}
    if brokers:
        inventory["agents"] = sorted(agents)
    inventory["not_gathered"] = [k for k in ld.INVENTORY_KINDS if k not in gathered]
    return inventory, notes
