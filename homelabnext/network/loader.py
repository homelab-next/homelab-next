# SPDX-License-Identifier: Apache-2.0
"""Read a site document and the service registry it resolves against."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from homelabnext import paths, sops


class SiteError(Exception):
    """The site document is unreadable, malformed or inconsistent."""

    def __init__(self, message: str, problems: list[str] | None = None):
        self.problems = list(problems or [])
        detail = "".join(f"\n  - {p}" for p in self.problems)
        super().__init__(message + detail)


class SiteUnreadable(SiteError):
    """A site or registry file cannot be read, decrypted or parsed: bad input, not an invalid site."""


def _yaml():
    try:
        import yaml
    except ModuleNotFoundError as exc:  # surfaced by `hnx` as "install the matching extra"
        raise ModuleNotFoundError("yaml", name="yaml") from exc
    return yaml


def _unique_loader():
    _yaml()  # PyYAML stays optional here: import the shared loader only when a document needs it
    from homelabnext._yaml import UniqueKeyLoader

    return UniqueKeyLoader


def parse_document(text: str, *, name: str = "<site>") -> Any:
    """Parse YAML or JSON text; duplicate keys are an error."""
    if text.lstrip().startswith("{"):
        try:
            return json.loads(text)
        except ValueError as exc:
            raise SiteUnreadable(f"{name}: not valid JSON: {exc}") from exc
    yaml = _yaml()
    try:
        return yaml.load(text, Loader=_unique_loader())
    except yaml.YAMLError as exc:
        raise SiteUnreadable(f"{name}: not valid YAML: {exc}") from exc


def load_site(path: str | Path) -> dict:
    """Return the parsed (unvalidated) site document."""
    p = Path(path)
    try:
        text = sops.read_text(p)
    except OSError as exc:
        raise SiteUnreadable(f"cannot read site file {p}: {exc}") from exc
    except sops.SopsError as exc:
        raise SiteUnreadable(str(exc)) from exc
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
    except model.RegistryUnreadable as exc:
        raise SiteUnreadable(f"registry {path}: {exc}") from exc
    except model.RegistryError as exc:
        raise SiteError(f"registry {path} is invalid", exc.problems or [str(exc)]) from exc


def schema() -> dict:
    return json.loads(paths.schema_file("platform", "site.schema.json").read_text(encoding="utf-8"))
