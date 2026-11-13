# SPDX-License-Identifier: Apache-2.0
"""Selection hosts that reference guest records (``hosts.<name>.guest``, ADR-0027 decision 9).

A site selection's host is either a stand-in that declares ``kind`` and ``capacity`` (and
``addresses``) itself, or a reference to the ``platform/guest`` record it is:
``hosts.<name>: {guest: guest:<id>}``.  The guest records are read the way ``hnx guests`` reads
them (:func:`homelabnext.compute.loader.load_guests`, with the guests' baseline set when the
directory holds one), never parsed again here.

:func:`resolve` turns each reference into the stand-in shape every other rule and generator
already reads (``kind`` from the guest, ``capacity`` from its ``resources``, ``addresses`` from
``network.ip`` and ``extra_addresses``), so the footprint sum, the slices and the egress policy
judge the guest's real size and addresses.  It refuses a reference it cannot resolve: no guest
records read, an unknown guest, one whose file has problems, one without ``resources``, a retired
one, and a guest two hosts name.  :func:`placement_problems` then judges each placed host role
against the guest under it: the role's ``kind``, its footprint (times its count) against the
guest's vCPUs, memory (less the host's headroom) and disk, and the role's ``guest`` requirements
(the guest's ``capability`` is one of those listed; every listed baseline is among the guest's).
Each mismatch names the module, the role, the host, the guest and what is missing.

The selection names no hypervisor node, so a guest's ``placement.node`` is not judged here.
"""

from __future__ import annotations

import copy
import ipaddress
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from homelabnext.modules.rules import _placed

Doc = dict[str, Any]

#: the guest directory under an overlay's ``lab/`` (``hnx guests`` reads the same one)
GUESTS_DIR = "guests"
#: the guest statuses a placement may land on (``retired`` is kept for the record but gone)
PLACEABLE = ("live", "planned")
#: the role kinds a guest kind must equal (``any`` takes every kind; ``external`` is never a guest)
GUEST_KINDS = ("vm", "lxc", "host")
#: at most this many guest files are read for one selection (a lab has tens)
MAX_GUEST_FILES = 2000


class GuestsUnreadable(Exception):
    """The guest directory itself cannot be read (not a directory, an unreadable baseline set)."""


@dataclass(frozen=True)
class GuestHost:
    """What a selection host takes from one schema-valid guest record."""

    id: str
    kind: str
    status: str
    capability: str
    #: the guest's baselines, with every baseline they extend when the baseline set was read
    baselines: frozenset[str]
    #: ``{cpu, memory_mb, disk_gb}`` from ``resources``; None when the guest declares none
    capacity: Mapping[str, int] | None
    addresses: tuple[str, ...]


@dataclass(frozen=True)
class Guests:
    """The guest records read for a selection: ``hosts`` by guest id, ``invalid`` the guest ids
    whose file failed the guest schema (id -> its first problem)."""

    hosts: Mapping[str, GuestHost] = field(default_factory=dict)
    invalid: Mapping[str, str] = field(default_factory=dict)
    #: the baseline set was read, so a role's baseline is met by one the guest's baselines extend
    baselines_read: bool = False


def _capacity(raw: Mapping[str, Any]) -> dict[str, int] | None:
    res = raw.get("resources")
    if not isinstance(res, Mapping):
        return None
    return {
        "cpu": res["cpu"]["cores"],
        "memory_mb": res["memory"]["size_mb"],
        "disk_gb": sum(d["size_gb"] for d in res["disks"]),
    }


def read(directory: str | Path) -> Guests:
    """Read a guest directory with the guest loader (``hnx guests``'s own).  Raises
    :class:`GuestsUnreadable` when the directory or its baseline set cannot be read at all."""
    from homelabnext.compute.baselines import BASELINES_FILE, load_baselines
    from homelabnext.compute.loader import guest_files, load_guests
    from homelabnext.compute.model import ComputeError

    d = Path(directory)
    if not d.is_dir():
        raise GuestsUnreadable(f"not a directory: {d}")
    # a guest file is the directory's own: a symbolic link could read (and echo, in a parse
    # error) a file outside it
    files = guest_files(d)
    linked = [f.name for f in files if f.is_symlink()]
    if linked:
        raise GuestsUnreadable(f"{d}: guest file(s) are symbolic links: {', '.join(linked[:5])}")
    if len(files) > MAX_GUEST_FILES:
        raise GuestsUnreadable(f"{d}: {len(files)} guest files, more than {MAX_GUEST_FILES}")
    try:
        found, problems = load_guests(d)
        bs = None
        if (d / BASELINES_FILE).is_file():
            bs, bad = load_baselines(d / BASELINES_FILE)
            if bad:
                raise GuestsUnreadable(f"{d / BASELINES_FILE}: {bad[0].message}")
    except ComputeError as exc:
        raise GuestsUnreadable(str(exc)) from None
    invalid: dict[str, str] = {}
    for p in problems:
        # the guests loader refuses a file whose name is not its id, so the file name is the id
        gid = "guest:" + Path(p.where).stem
        invalid.setdefault(gid, p.message)
    hosts: dict[str, GuestHost] = {}
    for g in found:
        if g.id in hosts or g.id in invalid:  # data-1.yml beside data-1.yaml: neither is trusted
            hosts.pop(g.id, None)
            invalid.setdefault(g.id, "two guest files carry this id")
            continue
        names = list(g.baseline.get("names", []))
        if bs is not None:
            names = bs.expand(names)[0] + names  # expand skips an unknown name; keep it as named
        hosts[g.id] = GuestHost(
            id=g.id,
            kind=g.kind,
            status=g.raw.get("status", "live"),
            capability=g.capability,
            baselines=frozenset(names),
            capacity=_capacity(g.raw),
            addresses=g.addresses,
        )
    return Guests(hosts, invalid, bs is not None)


def references(site: Doc) -> dict[str, str]:
    """Site host name -> the guest id it references (stand-in hosts left out)."""
    hosts = site.get("hosts")
    if not isinstance(hosts, Mapping):
        return {}
    return {
        str(n): h["guest"]
        for n, h in hosts.items()
        if isinstance(h, Mapping) and isinstance(h.get("guest"), str)
    }


def resolve(site: Doc, guests: Guests | None) -> tuple[Doc, list[str]]:
    """A copy of ``site`` whose guest-referencing hosts carry ``kind``, ``capacity`` and
    ``addresses`` from their guest records, and the references it refuses.  A host whose guest
    cannot be resolved keeps no capacity, so the footprint rules skip it (its problem is here)."""
    refs = references(site)
    if not refs:
        return site, []
    out = copy.deepcopy(site)
    problems: list[str] = []
    by_guest: dict[str, list[str]] = {}
    for name, gid in sorted(refs.items()):
        by_guest.setdefault(gid, []).append(name)
        where = f"hosts.{name}"
        if guests is None:
            problems.append(
                f"{where}: references {gid}, but no guest records were read "
                "(--guests DIR, or --overlay with lab/guests/)"
            )
            continue
        if gid in guests.invalid:
            problems.append(
                f"{where}: {gid}'s guest file has problems (hnx guests validate): "
                f"{guests.invalid[gid]}"
            )
            continue
        g = guests.hosts.get(gid)
        if g is None:
            problems.append(f"{where}: unknown guest {gid} (no such guest record)")
            continue
        if g.status not in PLACEABLE:
            problems.append(
                f"{where}: {gid} is {g.status}; only a live or planned guest takes a placement"
            )
        if g.capacity is None:
            problems.append(f"{where}: {gid} declares no resources, so its capacity is unknown")
            continue
        h = out["hosts"][name]
        h["kind"] = g.kind
        h["capacity"] = dict(g.capacity)
        h["addresses"] = list(g.addresses)
    for gid, names in sorted(by_guest.items()):
        if len(names) > 1:
            problems.append(
                f"hosts: {', '.join(names)} all reference {gid} (one guest is one host; "
                "its capacity would count once per name)"
            )
    return out, problems


def _lab_networks(site: Doc) -> list[Any]:
    """Where a lab host's own address may lie: never the internet, or the site's trusted nets."""
    from homelabnext.modules.egress import NOT_INTERNET

    nets: list[Any] = list(NOT_INTERNET)
    trusted = site.get("scope", {}).get("trusted", {}) if isinstance(site, Mapping) else {}
    for n in trusted.get("nets", []) if isinstance(trusted, Mapping) else []:
        try:
            nets.append(ipaddress.ip_network(n, strict=False))
        except (TypeError, ValueError):
            continue  # the selection schema refuses it
    return nets


def address_problems(site: Doc) -> list[str]:
    """A lab host's own address (a guest's, as :func:`resolve` copied it, or a stand-in's) is
    private or in the site's ``scope.trusted.nets``: the egress policy lets a role reach it and
    counts it as never the internet, so a public one would open a path out.  An ``external``
    host runs outside the lab and is not judged."""
    hosts = site.get("hosts")
    if not isinstance(hosts, Mapping):
        return []
    nets = _lab_networks(site)
    out: list[str] = []
    for name, h in sorted(hosts.items()):
        if not isinstance(h, Mapping) or h.get("kind") == "external":
            continue
        for a in h.get("addresses", []):
            try:
                addr = ipaddress.ip_network(a, strict=True).network_address
            except (TypeError, ValueError):
                continue  # the egress generator refuses it by name
            if not any(addr.version == n.version and addr in n for n in nets):
                src = f" (from {h['guest']})" if "guest" in h else ""
                out.append(
                    f"hosts.{name}: address {a}{src} is neither private nor in "
                    "scope.trusted.nets; a lab host's own address is never the internet"
                )
    return out


def placement_problems(site: Doc, sel: Mapping[str, Doc], guests: Guests | None) -> list[str]:
    """Each placed host role against the guest under it (``site`` as :func:`resolve` returns
    it): the role's kind, its footprint times its count, and its ``guest`` requirements."""
    if guests is None:
        return []
    out: list[str] = []
    for mod, inst, role, h, host in _placed(site, sel):
        sh = site["hosts"].get(host)
        if h is None or not isinstance(sh, Mapping) or "guest" not in sh:
            continue
        g = guests.hosts.get(sh["guest"])
        if g is None or g.capacity is None:
            continue  # resolve() reported it
        who = f"{mod}/{role}" if inst is None or inst == mod else f"{mod} ({inst})/{role}"
        at = f"host {host} ({g.id})"
        if h["kind"] in GUEST_KINDS and h["kind"] != g.kind:
            out.append(f"{who}: a {h['kind']} role, but {at} is a {g.kind}")
        n = h.get("count", 1)
        fp = h["footprint"]
        have = dict(g.capacity)
        have["memory_mb"] -= sh.get("headroom", {}).get("memory_mb", 0)
        for dim, label in (("cpu", "vCPU"), ("memory_mb", "memory_mb"), ("disk_gb", "disk_gb")):
            need = n * fp.get(dim, 0)
            if need > have[dim]:
                left = " (less headroom)" if dim == "memory_mb" and "headroom" in sh else ""
                out.append(f"{who}: needs {label} {need:g}, {at} has {have[dim]:g}{left}")
        if fp.get("gpu_memory_mb", 0) > 0:
            out.append(
                f"{who}: a GPU footprint cannot be judged against a guest record yet "
                f"({at} declares no GPU memory); place it on a stand-in host"
            )
        want = h.get("guest", {})
        caps = want.get("capability", [])
        if caps and g.capability not in caps:
            out.append(
                f"{who}: needs a guest whose capability is {' or '.join(caps)}; "
                f"{at} provides {g.capability}"
            )
        missing = sorted(set(want.get("baselines", [])) - g.baselines)
        if missing:
            carried = ", ".join(sorted(g.baselines)) or "none"
            out.append(
                f"{who}: needs baseline {', '.join(missing)}; {at} carries {carried}"
                + ("" if guests.baselines_read else " (no baseline set read: extends not followed)")
            )
    return out


def unchecked(site: Doc, sel: Mapping[str, Doc]) -> list[str]:
    """``module/role on host`` for each placed role with ``guest`` requirements on a stand-in
    host, where nothing can judge them."""
    out = []
    for mod, _inst, role, h, host in _placed(site, sel):
        sh = site["hosts"].get(host)
        if h is not None and h.get("guest") and isinstance(sh, Mapping) and "guest" not in sh:
            out.append(f"{mod}/{role} on {host}")
    return sorted(set(out))
