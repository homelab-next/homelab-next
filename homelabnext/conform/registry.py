# SPDX-License-Identifier: Apache-2.0
"""The capability list and suite discovery.

The eighteen names are the contract in ``docs/interfaces.md`` section 3 (``hnx conform list``
prints exactly these).  Suites live in ``conformance/suites/<name_with_underscores>.py`` of a
source checkout; the harness core in this package works without them and says so clearly when
they are missing.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path
from types import ModuleType

from ..paths import checkout_root
from .core import Suite

__all__ = [
    "CAPABILITIES",
    "EXTENDED",
    "ConformError",
    "default_root",
    "find_root",
    "load_module",
    "load_suite",
    "names",
]

CAPABILITIES: tuple[str, ...] = (
    "lake-query",
    "lake-catalog",
    "object-store",
    "inference",
    "fast-classifier",
    "notify",
    "cases",
    "events",
    "orchestration",
    "broker",
    "secrets",
    "idp",
    "records",
    "detections",
    "context",
    "projects",
    "codemode-executor",
    "codemode-runner",
)
#: additional suites that ship with the harness but are not among the eighteen
EXTENDED: tuple[str, ...] = (
    "backup",
    "dns",
    "edge",
    "broker-tokens",
    "orchestration-features",
    "migration",
    "log-pipeline",
)


class ConformError(Exception):
    """Misconfiguration: unknown capability, missing suites, bad target.  CLI exit code 2."""


def default_root() -> Path:
    return Path(__file__).resolve().parents[2]


def find_root(root: str | Path | None) -> Path:
    r = Path(root) if root else default_root()
    return r.resolve()


def _ensure_importable(root: Path) -> None:
    s = str(root)
    if s not in sys.path:
        sys.path.insert(0, s)


def names(include_extended: bool = False) -> list[str]:
    return [*CAPABILITIES, *(EXTENDED if include_extended else ())]


def module_name(capability: str) -> str:
    return "conformance.suites." + capability.replace("-", "_")


def load_module(capability: str, root: str | Path | None = None) -> ModuleType:
    """Import the suite for ``capability`` from ``root`` (default: this package's checkout).

    Suites are executed, so without ``--root`` they are only loaded when this package was imported
    from a verified checkout: from a wheel, a ``conformance`` package that some other
    distribution put on ``sys.path`` is never imported.
    """
    if capability not in (*CAPABILITIES, *EXTENDED):
        raise ConformError(f"unknown capability {capability!r}; known: {', '.join(names(True))}")
    r = find_root(root)
    missing = ConformError(
        f"suite for {capability!r} not found: hnx conform needs a source checkout "
        f"(conformance/suites/ under {r}); use --root to point at one"
    )
    if root is None and checkout_root() is None:
        raise missing
    _ensure_importable(r)
    try:
        return importlib.import_module(module_name(capability))
    except ModuleNotFoundError as exc:
        if exc.name and exc.name.startswith("conformance"):
            raise missing from exc
        raise


def load_suite(capability: str, root: str | Path | None = None) -> Suite:
    suite = load_module(capability, root).SUITE
    if not isinstance(suite, Suite):
        raise ConformError(f"{module_name(capability)}.SUITE is not a Suite")
    return suite
