# SPDX-License-Identifier: Apache-2.0
"""Load a directory of guest files, validate each against ``guest.schema.json``."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml

from homelabnext import paths, sops
from homelabnext._schema_text import safe_message
from homelabnext._yaml import UniqueKeyStrDateLoader
from homelabnext.generators.safe import control_char_paths

from .baselines import BASELINES_FILE, load_baselines
from .model import ComputeError, Fleet, Guest, Problem, ZoneFlow, ZoneLookup

POLICIES_FILE = "_backup_policies.yml"
NODES_FILE = "_nodes.yml"


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
        raise ComputeError(f"not a directory: {d}")
    guests: list[Guest] = []
    problems: list[Problem] = []
    for path in guest_files(d):
        where = path.name
        try:
            doc = yaml.load(sops.read_text(path), Loader=_UniqueKeyLoader)
        except (OSError, yaml.YAMLError, sops.SopsError) as exc:
            problems.append(Problem(where, f"unreadable YAML: {exc}"))
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
        raise ComputeError(f"cannot read backup policies {p}: {exc}") from exc
    pol = (doc or {}).get("policies") if isinstance(doc, dict) else None
    if not isinstance(pol, dict):
        raise ComputeError(f"{p}: expected a mapping with a 'policies' mapping")
    return {str(k): (v or {}) for k, v in pol.items()}


def load_nodes(path: str | Path) -> dict[str, Mapping[str, Any]]:
    """Read ``{nodes: {name: {firewall: enabled|disabled, power: {...}}}}``: what each hypervisor
    enforces, and what feeds it (``power``, checked against the site by
    :func:`homelabnext.power.fleet_problems`)."""
    p = Path(path)
    try:
        doc = yaml.load(sops.read_text(p), Loader=_UniqueKeyLoader)
    except (OSError, yaml.YAMLError, sops.SopsError) as exc:
        raise ComputeError(f"cannot read nodes {p}: {exc}") from exc
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
    return out


def load_keys(path: str | Path) -> dict[str, str]:
    """Read ``{keys: {name: public-key-line}}`` (public keys only; never private material)."""
    p = Path(path)
    try:
        doc = yaml.safe_load(sops.read_text(p))
    except (OSError, yaml.YAMLError, sops.SopsError) as exc:
        raise ComputeError(f"cannot read keys {p}: {exc}") from exc
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
) -> Fleet:
    """Load, schema- and semantically validate; raise ComputeError listing every problem.

    ``baselines_path`` defaults to ``DIRECTORY/_baselines.yml``; without that file there is no
    baseline set and no guest needs a baseline.  ``require_baselines=False`` tolerates guests
    that declare none (for the coverage report, which lists them).  ``flows``: the zone-to-zone
    flows the site allows (:func:`homelabnext.compute.zones.site_flows`), for the targets that
    follow them (``tailscale-acl``).  ``power``: the site's power facts
    (:func:`homelabnext.compute.zones.site_power`); with them, every hypervisor and physical
    host must say what feeds it.  ``deploy``: the deploy's tailnet access
    (:func:`homelabnext.compute.zones.site_deploy`), for ``tailscale-acl``."""
    from .validate import validate

    d = Path(directory)
    guests, problems = load_guests(d)
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
    )
    problems += validate(fleet, require_baselines=require_baselines)
    if problems:
        raise ComputeError(f"invalid guest set in {d}", problems)
    return fleet
