# SPDX-License-Identifier: Apache-2.0
"""Load a directory of guest files, validate each against ``guest.schema.json``."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml

from homelabnext import paths

from .model import ComputeError, Fleet, Guest, Problem, ZoneLookup

POLICIES_FILE = "_backup_policies.yml"


class _UniqueKeyLoader(yaml.SafeLoader):
    """SafeLoader refusing duplicate keys; timestamps stay strings."""


_UniqueKeyLoader.yaml_implicit_resolvers = {
    k: [(tag, rx) for tag, rx in v if tag != "tag:yaml.org,2002:timestamp"]
    for k, v in yaml.SafeLoader.yaml_implicit_resolvers.items()
}


def _construct_mapping(loader: _UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False):
    seen: set[Any] = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in seen:
            raise yaml.constructor.ConstructorError(
                None, None, f"duplicate key {key!r}", key_node.start_mark
            )
        seen.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep)


_UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


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
        out.append(Problem(where, f"schema: {path}: {err.message}"))
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
            doc = yaml.load(path.read_text(encoding="utf-8"), Loader=_UniqueKeyLoader)
        except (OSError, yaml.YAMLError) as exc:
            problems.append(Problem(where, f"unreadable YAML: {exc}"))
            continue
        errs = schema_problems(doc, where)
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
        doc = yaml.load(p.read_text(encoding="utf-8"), Loader=_UniqueKeyLoader)
    except (OSError, yaml.YAMLError) as exc:
        raise ComputeError(f"cannot read backup policies {p}: {exc}") from exc
    pol = (doc or {}).get("policies") if isinstance(doc, dict) else None
    if not isinstance(pol, dict):
        raise ComputeError(f"{p}: expected a mapping with a 'policies' mapping")
    return {str(k): (v or {}) for k, v in pol.items()}


def load_keys(path: str | Path) -> dict[str, str]:
    """Read ``{keys: {name: public-key-line}}`` (public keys only; never private material)."""
    p = Path(path)
    try:
        doc = yaml.safe_load(p.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
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
) -> Fleet:
    """Load, schema- and semantically validate; raise ComputeError listing every problem."""
    from .validate import validate

    d = Path(directory)
    guests, problems = load_guests(d)
    pol_path = Path(policies_path) if policies_path else d / POLICIES_FILE
    policies = load_policies(pol_path) if pol_path.is_file() else {}
    fleet = Fleet(
        tuple(guests),
        zones,
        domain=domain,
        keys=load_keys(keys_path) if keys_path else {},
        policies=policies,
    )
    problems += validate(fleet)
    if problems:
        raise ComputeError(f"invalid guest set in {d}", problems)
    return fleet
