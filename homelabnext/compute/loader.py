# SPDX-License-Identifier: Apache-2.0
"""Load a directory of guest files, validate each against ``guest.schema.json``."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from fractions import Fraction
from pathlib import Path
from typing import Any

import yaml

from homelabnext import paths, sops
from homelabnext._schema_text import safe_message
from homelabnext._yaml import UniqueKeyStrDateLoader
from homelabnext.generators.safe import control_char_paths

from .baselines import BASELINES_FILE, load_baselines
from .model import ComputeError, ComputeUnreadable, Fleet, Guest, Problem, ZoneFlow, ZoneLookup

POLICIES_FILE = "_backup_policies.yml"
NODES_FILE = "_nodes.yml"
#: the problem text of a guest file that does not parse (bad input, see ComputeUnreadable)
UNREADABLE = "unreadable YAML"


# refuses duplicate keys; timestamps stay strings
_UniqueKeyLoader = UniqueKeyStrDateLoader


def schema() -> dict:
    return json.loads(
        paths.schema_file("platform", "guest.schema.json").read_text(encoding="utf-8")
    )


def schema_problems(doc: Any, where: str) -> list[Problem]:
    import jsonschema

    validator = jsonschema.Draft202012Validator(schema())
    out = []
    for err in sorted(validator.iter_errors(doc), key=lambda e: [str(p) for p in e.absolute_path]):
        path = "/".join(str(p) for p in err.absolute_path) or "<root>"
        out.append(Problem(where, f"schema: {path}: {safe_message(err)}"))
    return out


def guest_files(directory: Path) -> list[Path]:
    """``*.yml``/``*.yaml`` files that are guests (names starting with ``_`` are support files)."""
    return sorted(
        p
        for p in directory.iterdir()
        if p.suffix in (".yml", ".yaml") and not p.name.startswith("_") and p.is_file()
    )


def load_guests(directory: str | Path) -> tuple[list[Guest], list[Problem]]:
    """Parse every guest file.  Returns the guests that passed the schema and all problems."""
    d = Path(directory)
    if not d.is_dir():
        raise ComputeUnreadable(f"not a directory: {d}")
    guests: list[Guest] = []
    problems: list[Problem] = []
    for path in guest_files(d):
        where = path.name
        try:
            doc = yaml.load(sops.read_text(path), Loader=_UniqueKeyLoader)
        except (OSError, yaml.YAMLError, sops.SopsError) as exc:
            problems.append(Problem(where, f"{UNREADABLE}: {exc}"))
            continue
        # Python's re lets a schema pattern's "$" match before a trailing newline, and every
        # target writes line-oriented text: refuse control characters in any key or value first
        errs = [Problem(where, f"unsafe: {m}") for m in control_char_paths(doc)]
        errs += schema_problems(doc, where)
        if errs:
            problems += errs
            continue
        g = Guest(doc, source=where)
        if path.stem != g.name:
            problems.append(Problem(where, f"file name must be {g.name}.yml to match id {g.id}"))
            continue
        guests.append(g)
    return guests, problems


def load_policies(path: str | Path) -> dict[str, Mapping[str, Any]]:
    """Read ``{policies: {name: {...}}}``; ``none`` is always implicitly defined."""
    p = Path(path)
    try:
        doc = yaml.load(sops.read_text(p), Loader=_UniqueKeyLoader)
    except (OSError, yaml.YAMLError, sops.SopsError) as exc:
        raise ComputeUnreadable(f"cannot read backup policies {p}: {exc}") from exc
    pol = (doc or {}).get("policies") if isinstance(doc, dict) else None
    if not isinstance(pol, dict):
        raise ComputeError(f"{p}: expected a mapping with a 'policies' mapping")
    return {str(k): (v or {}) for k, v in pol.items()}


def load_nodes(path: str | Path) -> dict[str, Mapping[str, Any]]:
    """Read ``{nodes: {name: {firewall: enabled|disabled, power: {...}, capacity: {...},
    pools: {...}, mirror: {...}}}}``: what each hypervisor enforces, what feeds it (``power``,
    checked against the site by :func:`homelabnext.power.fleet_problems`), what it holds
    (``capacity`` and ``pools``, checked against its guests by
    :func:`homelabnext.compute.validate.validate`), and where it copies its guests' traffic for a
    network sensor (``mirror``, rendered by the ``node-mirror`` target)."""
    p = Path(path)
    try:
        doc = yaml.load(sops.read_text(p), Loader=_UniqueKeyLoader)
    except (OSError, yaml.YAMLError, sops.SopsError) as exc:
        raise ComputeUnreadable(f"cannot read nodes {p}: {exc}") from exc
    nodes = (doc or {}).get("nodes") if isinstance(doc, dict) else None
    if not isinstance(nodes, dict):
        raise ComputeError(f"{p}: expected a mapping with a 'nodes' mapping")
    out: dict[str, Mapping[str, Any]] = {}
    for name, spec in nodes.items():
        spec = spec or {}
        fw = spec.get("firewall", "enabled") if isinstance(spec, dict) else None
        if fw not in ("enabled", "disabled"):
            raise ComputeError(f"{p}: node {name!r}: firewall must be 'enabled' or 'disabled'")
        out[str(name)] = {"firewall": fw}
        if isinstance(spec, dict) and "power" in spec:
            out[str(name)]["power"] = spec["power"]
        if isinstance(spec, dict) and "capacity" in spec:
            out[str(name)]["capacity"] = _capacity(p, name, spec["capacity"])
        if isinstance(spec, dict) and "pools" in spec:
            out[str(name)]["pools"] = _pools(p, name, spec["pools"])
        if isinstance(spec, dict) and "mirror" in spec:
            out[str(name)]["mirror"] = _mirror(p, name, spec["mirror"])
    return out


def _count(v: Any, *, low: int = 1) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= low


def _capacity(p: Path, name: Any, raw: Any) -> dict[str, Any]:
    """``{threads, memory_mb, reserve: {threads, memory_mb}, cpu_overcommit}``: the logical CPUs
    and memory the hypervisor schedules, what it keeps for itself (the hypervisor, a ZFS ARC),
    and how many guest vCPUs it may place on each thread it gives out (default 1.0)."""
    where = f"{p}: node {name!r}: capacity"
    if not isinstance(raw, dict) or set(raw) - {
        "threads",
        "memory_mb",
        "reserve",
        "cpu_overcommit",
    }:
        raise ComputeError(f"{where} takes threads, memory_mb, reserve and cpu_overcommit")
    if not (_count(raw.get("threads")) and _count(raw.get("memory_mb"))):
        raise ComputeError(f"{where}: threads and memory_mb are positive whole numbers")
    reserve = raw.get("reserve", {})
    if (
        not isinstance(reserve, dict)
        or set(reserve) - {"threads", "memory_mb"}
        or not all(_count(v, low=0) for v in reserve.values())
    ):
        raise ComputeError(f"{where}.reserve: threads and memory_mb, whole numbers >= 0")
    ratio = raw.get("cpu_overcommit", 1.0)
    if isinstance(ratio, bool) or not isinstance(ratio, (int, float)) or not 1 <= ratio <= 16:
        raise ComputeError(f"{where}.cpu_overcommit: a number from 1 to 16")
    left = {
        "threads": raw["threads"] - reserve.get("threads", 0),
        "memory_mb": raw["memory_mb"] - reserve.get("memory_mb", 0),
    }
    if left["threads"] < 1 or left["memory_mb"] < 1:
        raise ComputeError(f"{where}: the reserve leaves no threads or memory for guests")
    # the vCPU budget, once: an exact ratio (1.15 is 23/20, not 1.149999...), floored
    left["vcpus"] = int(Fraction(str(ratio)) * left["threads"])
    return {**raw, "reserve": reserve, "cpu_overcommit": float(ratio), "for_guests": left}


def _pools(p: Path, name: Any, raw: Any) -> dict[str, dict[str, Any]]:
    """``{pool: {size_gb, media}}``: the storage pools a guest's disks may name on this node."""
    where = f"{p}: node {name!r}: pools"
    if not isinstance(raw, dict) or not raw:
        raise ComputeError(f"{where}: a mapping of pool name to {{size_gb, media}}")
    out = {}
    for pool, spec in raw.items():
        # the names a guest's disk may use (guest schema: disks[].pool)
        if not isinstance(pool, str) or not _POOL_RE.match(pool):
            raise ComputeError(f"{where}: pool name {pool!r} is not one a disk can name")
        if not isinstance(spec, dict) or set(spec) - {"size_gb", "media"}:
            raise ComputeError(f"{where}.{pool}: takes size_gb and media")
        if not _count(spec.get("size_gb")):
            raise ComputeError(f"{where}.{pool}: size_gb is a positive whole number")
        if spec.get("media", "ssd") not in ("nvme", "ssd", "hdd"):
            raise ComputeError(f"{where}.{pool}: media is nvme, ssd or hdd")
        out[pool] = dict(spec)
    return out


_POOL_RE = re.compile(r"^[a-z][a-z0-9_-]*\Z")
# a Linux interface name: at most 15 bytes (IFNAMSIZ less the NUL), and a word a shell script can
# carry without quoting surprises
_IFNAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,14}\Z")


def _mirror(p: Path, name: Any, raw: Any) -> dict[str, Any]:
    """``{to: <nic>, bridges: [<bridge>, ...]}``: copy every frame the node's guests send into
    these bridges to ``to``, a NIC cabled to the sensor's capture port and carrying nothing else.
    A switch mirror never sees traffic between two guests of one node; this does."""
    where = f"{p}: node {name!r}: mirror"
    if not isinstance(raw, dict) or set(raw) != {"to", "bridges"}:
        raise ComputeError(f"{where}: takes to (a NIC) and bridges (a list), both required")
    to, bridges = raw["to"], raw["bridges"]
    if not isinstance(to, str) or not _IFNAME_RE.match(to):
        raise ComputeError(f"{where}.to: {to!r} is not an interface name")
    if not isinstance(bridges, list) or not bridges:
        raise ComputeError(f"{where}.bridges: a non-empty list of bridge names")
    for br in bridges:
        if not isinstance(br, str) or not _IFNAME_RE.match(br):
            raise ComputeError(f"{where}.bridges: {br!r} is not an interface name")
    if len(set(bridges)) != len(bridges):
        raise ComputeError(f"{where}.bridges: a bridge is listed twice")
    if to in bridges:
        raise ComputeError(f"{where}: to {to!r} is one of the bridges it copies")
    if to == "lo":
        raise ComputeError(f"{where}.to: the loopback interface cannot carry a mirror")
    return {"to": to, "bridges": list(bridges)}


def load_keys(path: str | Path) -> dict[str, str]:
    """Read ``{keys: {name: public-key-line}}`` (public keys only; never private material)."""
    p = Path(path)
    try:
        doc = yaml.safe_load(sops.read_text(p))
    except (OSError, yaml.YAMLError, sops.SopsError) as exc:
        raise ComputeUnreadable(f"cannot read keys {p}: {exc}") from exc
    keys = (doc or {}).get("keys") if isinstance(doc, dict) else None
    if not isinstance(keys, dict):
        raise ComputeError(f"{p}: expected a mapping with a 'keys' mapping")
    return {str(k): str(v) for k, v in keys.items()}


def load_fleet(
    directory: str | Path,
    zones: ZoneLookup,
    *,
    domain: str = "example.internal",
    policies_path: str | Path | None = None,
    keys_path: str | Path | None = None,
    nodes_path: str | Path | None = None,
    baselines_path: str | Path | None = None,
    require_baselines: bool = True,
    flows: tuple[ZoneFlow, ...] = (),
    power: Mapping[str, Any] | None = None,
    deploy: Mapping[str, Any] | None = None,
    site_addresses: Mapping[str, tuple[str, ...]] | None = None,
    delegated6: Any = None,
) -> Fleet:
    """Load, schema- and semantically validate; raise ComputeError listing every problem.

    ``baselines_path`` defaults to ``DIRECTORY/_baselines.yml``; without that file there is no
    baseline set and no guest needs a baseline.  ``require_baselines=False`` tolerates guests
    that declare none (for the coverage report, which lists them).  ``flows``: the zone-to-zone
    flows the site allows (:func:`homelabnext.compute.zones.site_flows`), for the targets that
    follow them (``tailscale-acl``).  ``power``: the site's power facts
    (:func:`homelabnext.compute.zones.site_power`); with them, every hypervisor and physical
    host must say what feeds it.  ``deploy``: the deploy's tailnet access
    (:func:`homelabnext.compute.zones.site_deploy`), for ``tailscale-acl``.  ``site_addresses``:
    the addresses the site names something other than a guest
    (:func:`homelabnext.compute.zones.site_addresses`), which no extra address may claim.
    ``delegated6``: the site's ``delegated_prefixes6`` as read
    (:func:`homelabnext.compute.zones.site_delegated6`), the global IPv6 prefixes it declares its
    own."""
    from .validate import validate

    d = Path(directory)
    guests, problems = load_guests(d)
    unreadable = [p for p in problems if p.message.startswith(UNREADABLE + ":")]
    if unreadable:  # a file that does not parse is bad input, not a guest that fails validation
        raise ComputeUnreadable(f"unreadable guest files in {d}", unreadable)
    pol_path = Path(policies_path) if policies_path else d / POLICIES_FILE
    policies = load_policies(pol_path) if pol_path.is_file() else {}
    nodes_file = Path(nodes_path) if nodes_path else d / NODES_FILE
    bl_file = Path(baselines_path) if baselines_path else d / BASELINES_FILE
    baselines = None
    if baselines_path or bl_file.is_file():
        baselines, bl_problems = load_baselines(bl_file)
        if baselines is None:  # never read an unusable set as "no set": stop here
            raise ComputeError(f"invalid guest set in {d}", problems + bl_problems)
    fleet = Fleet(
        tuple(guests),
        zones,
        domain=domain,
        keys=load_keys(keys_path) if keys_path else {},
        policies=policies,
        nodes=load_nodes(nodes_file) if nodes_file.is_file() else {},
        baselines=baselines,
        flows=tuple(flows),
        power=power,
        deploy=deploy,
        site_addresses=dict(site_addresses or {}),
        delegated6=delegated6,
    )
    problems += validate(fleet, require_baselines=require_baselines)
    if problems:
        raise ComputeError(f"invalid guest set in {d}", problems)
    return fleet
