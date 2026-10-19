# SPDX-License-Identifier: Apache-2.0
"""Find and load customization files.

Two sources, never merged silently:

* ``profiles/`` in the repository: shipped OPTIONAL profiles (``origin: public``), inert until a
  deployment enables them.
* The deployment's own directory (``origin: local``), found through ``--dir``, the environment
  variable ``HNX_CUSTOMIZATIONS_DIR`` (several directories separated by ``os.pathsep``) or a
  config file (``--config`` / ``HNX_CUSTOMIZATIONS_CONFIG``)::

      customizations_dir: /path/to/my-overlay/customizations   # string or list
      enable:                                                  # optional shipped profiles
        - id: custom:example-id
          hosts: [some-host]                                   # optional narrowing

A file is a customization if it is named ``customization.{yml,yaml,json}`` or
``*.customization.{yml,yaml,json}``. One document per file. Loading never executes anything.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from homelabnext import paths
from homelabnext._yaml import UniqueKeyStrDateLoader

from .model import Customization, Finding

__all__ = [
    "ENV_CONFIG",
    "ENV_DIR",
    "Settings",
    "load_file",
    "load_tree",
    "resolve_settings",
    "schema_path",
    "validate_doc",
]

ENV_DIR = "HNX_CUSTOMIZATIONS_DIR"
ENV_CONFIG = "HNX_CUSTOMIZATIONS_CONFIG"
# A directory laid out as <root>/schemas, <root>/profiles, <root>/examples: the checkout for a
# source tree, homelabnext/_data for an installed wheel (homelabnext.paths decides).
try:
    REPO_ROOT = paths.data_root()
except paths.ResourceNotFound:  # reported with the full list of places when the data is needed
    REPO_ROOT = paths.source_root()
_SUFFIXES = (".yml", ".yaml", ".json")


# leaves ISO dates as strings (the schema types them as strings) and refuses duplicate mapping
# keys (a silent override is exactly the bug this module exists to prevent)
_StrLoader = UniqueKeyStrDateLoader


def read_document(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".json":
        return json.loads(text)
    return yaml.load(text, Loader=_StrLoader)


# ---- schema ------------------------------------------------------------------------------------


def schema_path() -> Path:
    return paths.schema_file("platform", "customization.schema.json")


_VALIDATOR = None


def _validator():
    """Build (once) a validator that can resolve the logical-id ``$ref``. jsonschema is imported
    lazily so ``hnx --help`` works on a bare install."""
    global _VALIDATOR
    if _VALIDATOR is None:
        from jsonschema import Draft202012Validator
        from referencing import Registry, Resource
        from referencing.jsonschema import DRAFT202012

        reg: Registry = Registry()
        for p in sorted(paths.schemas_dir().rglob("*.json")):
            if "_frozen" in p.parts:
                continue
            doc = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(doc, dict) and "$id" in doc:
                reg = reg.with_resource(
                    doc["$id"], Resource.from_contents(doc, default_specification=DRAFT202012)
                )
        schema = json.loads(schema_path().read_text(encoding="utf-8"))
        _VALIDATOR = Draft202012Validator(schema, registry=reg)
    return _VALIDATOR


def validate_doc(doc: Any) -> list[str]:
    """Schema errors for one document (empty list = valid)."""
    if not isinstance(doc, dict):
        return ["$: a customization must be a mapping"]
    out = []
    for err in sorted(_validator().iter_errors(doc), key=lambda e: [str(p) for p in e.path]):
        where = "/".join(str(p) for p in err.absolute_path) or "$"
        if err.validator == "anyOf" and err.context:
            # name the missing field instead of dumping the whole instance
            detail = "; ".join(sorted({c.message for c in err.context if "required" in c.message}))
            out.append(
                f"{where}: {detail} (review_by is required unless maintained_upstream is true)"
            )
        else:
            out.append(f"{where}: {err.message}")
    return out


# ---- files -------------------------------------------------------------------------------------


def is_customization_file(p: Path) -> bool:
    if p.suffix not in _SUFFIXES:
        return False
    return p.stem == "customization" or p.stem.endswith(".customization")


def load_file(path: Path, origin: str) -> Customization | Finding:
    try:
        doc = read_document(path)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        return Finding("CU012", "error", str(path), f"cannot read: {exc}")
    return Customization(doc if isinstance(doc, dict) else {}, path, origin, validate_doc(doc))


def load_tree(root: Path, origin: str) -> tuple[list[Customization], list[Finding]]:
    """Load every customization file under ``root`` in sorted path order."""
    items: list[Customization] = []
    problems: list[Finding] = []
    if not root.is_dir():
        return items, problems
    for p in sorted(root.rglob("*")):
        if p.is_file() and not p.is_symlink() and is_customization_file(p):
            got = load_file(p, origin)
            (items if isinstance(got, Customization) else problems).append(got)  # type: ignore[arg-type]
    return items, problems


# ---- settings ----------------------------------------------------------------------------------


@dataclass
class Settings:
    """Where to look and what is enabled. Built by :func:`resolve_settings`."""

    public_dir: Path
    local_dirs: list[Path] = field(default_factory=list)
    #: optional shipped profile id -> hosts it is enabled for (empty list = every scoped host)
    enabled: dict[str, list[str]] = field(default_factory=dict)


def resolve_settings(
    dirs: list[str] | None = None,
    config: str | None = None,
    enable: list[str] | None = None,
    env: dict[str, str] | None = None,
    public_dir: Path | None = None,
) -> Settings:
    env = dict(os.environ) if env is None else env
    s = Settings(public_dir=public_dir or paths.profiles_dir())
    cfg_file = config or env.get(ENV_CONFIG)
    if cfg_file:
        cfg = yaml.load(Path(cfg_file).read_text(encoding="utf-8"), Loader=_StrLoader) or {}
        cd = cfg.get("customizations_dir", [])
        for d in [cd] if isinstance(cd, str) else cd:
            s.local_dirs.append(Path(d))
        for e in cfg.get("enable", []) or []:
            s.enabled.setdefault(str(e["id"]), []).extend(e.get("hosts") or [])
    for d in dirs or []:
        s.local_dirs.append(Path(d))
    for d in filter(None, env.get(ENV_DIR, "").split(os.pathsep)):
        s.local_dirs.append(Path(d))
    for item in enable or []:
        cid, _, hosts = item.partition("=")
        s.enabled.setdefault(cid, []).extend(h for h in hosts.split(",") if h)
    seen: list[Path] = []
    for d in s.local_dirs:  # de-duplicate, keep first-seen order (deterministic)
        if d not in seen:
            seen.append(d)
    s.local_dirs = seen
    return s


def load_all(settings: Settings) -> tuple[list[Customization], list[Finding]]:
    items, problems = load_tree(settings.public_dir, "public")
    for d in settings.local_dirs:
        i, p = load_tree(d, "local")
        items += i
        problems += p
    return items, problems
