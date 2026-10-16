# SPDX-License-Identifier: Apache-2.0
"""Read a site document and the service registry it resolves against."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from homelabnext import paths


class SiteError(Exception):
    """The site document is unreadable, malformed or inconsistent."""

    def __init__(self, message: str, problems: list[str] | None = None):
        self.problems = list(problems or [])
        detail = "".join(f"\n  - {p}" for p in self.problems)
        super().__init__(message + detail)


def _yaml():
    try:
        import yaml
    except ModuleNotFoundError as exc:  # surfaced by `hnx` as "install the matching extra"
        raise ModuleNotFoundError("yaml", name="yaml") from exc
    return yaml


def _unique_loader():
    yaml = _yaml()

    class UniqueKeyLoader(yaml.SafeLoader):
        """Safe loader that refuses duplicate mapping keys (a silent override is a bug)."""

    def construct(loader, node, deep=False):
        seen: set[Any] = set()
        for key_node, _ in node.value:
            key = loader.construct_object(key_node, deep=deep)
            if key in seen:
                raise yaml.constructor.ConstructorError(
                    None, None, f"duplicate key {key!r}", key_node.start_mark
                )
            seen.add(key)
        return yaml.SafeLoader.construct_mapping(loader, node, deep)

    UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct)
    return UniqueKeyLoader


def parse_document(text: str, *, name: str = "<site>") -> Any:
    """Parse YAML or JSON text; duplicate keys are an error."""
    if text.lstrip().startswith("{"):
        try:
            return json.loads(text)
        except ValueError as exc:
            raise SiteError(f"{name}: not valid JSON: {exc}") from exc
    yaml = _yaml()
    try:
        return yaml.load(text, Loader=_unique_loader())
    except yaml.YAMLError as exc:
        raise SiteError(f"{name}: not valid YAML: {exc}") from exc


def load_site(path: str | Path) -> dict:
    """Return the parsed (unvalidated) site document."""
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise SiteError(f"cannot read site file {p}: {exc}") from exc
    doc = parse_document(text, name=str(p))
    if not isinstance(doc, dict):
        raise SiteError(f"{p}: site root must be a mapping")
    return doc


@dataclass(frozen=True)
class Loaded:
    """A site document with the registry it resolves against."""

    doc: dict
    registry: Any  # homelabnext.registry.model.Registry


def load_registry(path: str | Path):
    from homelabnext.registry import model

    try:
        return model.load(path)
    except model.RegistryError as exc:
        raise SiteError(f"registry {path} is invalid", exc.problems or [str(exc)]) from exc


def schema() -> dict:
    return json.loads(paths.schema_file("platform", "site.schema.json").read_text(encoding="utf-8"))
