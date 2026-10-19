# SPDX-License-Identifier: Apache-2.0
"""Where the repo-level data (schemas, profiles, examples) lives, for every install shape.

One module answers every "where is ``schemas/``?" question so no other module guesses from
``__file__``.  Lookup order for a kind (``schemas``, ``profiles``, ``examples``), first hit wins:

1. **explicit override**: ``HNX_SCHEMAS_DIR`` / ``HNX_PROFILES_DIR`` / ``HNX_EXAMPLES_DIR`` for
   that kind (``HNX_SCHEMA_DIR`` is the older spelling of the first and still honoured), then
   ``HNX_DATA_DIR`` for a whole tree laid out as ``<root>/schemas``, ``<root>/profiles``, ...;
2. **installed package data**: ``homelabnext/_data/<kind>`` (what the wheel carries, copied there at
   build time from the repository-level directories by ``setup.py``);
3. **source tree**: ``<checkout>/<kind>`` (editable installs and plain checkouts), used only when
   the directory above the package is verifiably this project's checkout (:func:`checkout_root`:
   a ``pyproject.toml`` naming the ``homelabnext`` project).  In a wheel install that directory is
   ``site-packages``, which other distributions share, so it is never searched or executed from.

Results are cached.  Tests inject roots instead of patching the environment: every function takes
``env=``, ``package_root=`` and ``source_root=`` keyword arguments, and a call that injects any of
them bypasses the cache.  When nothing is found :class:`ResourceNotFound` lists every place tried.
"""

from __future__ import annotations

import importlib.resources
import os
import tomllib
from collections.abc import Mapping, Sequence
from functools import cache
from pathlib import Path

KINDS = ("schemas", "profiles", "examples")
DATA_ENV = "HNX_DATA_DIR"
KIND_ENV: dict[str, tuple[str, ...]] = {
    "schemas": ("HNX_SCHEMAS_DIR", "HNX_SCHEMA_DIR"),
    "profiles": ("HNX_PROFILES_DIR",),
    "examples": ("HNX_EXAMPLES_DIR",),
}
PACKAGE_DATA = "_data"

_PACKAGE_ROOT_DEFAULT = None  # sentinel: ask importlib.resources
_SOURCE_ROOT = Path(__file__).resolve().parents[1]


class NotACheckout(RuntimeError):
    """A feature needs this project's source checkout and the package is not running from one."""


@cache
def checkout_root() -> Path | None:
    """The source checkout this package was imported from, or ``None``.

    Verified, not assumed: the parent of the package directory must hold a ``pyproject.toml``
    whose ``[project] name`` is ``homelabnext``, next to a ``homelabnext/`` that is this package.
    """
    root = _SOURCE_ROOT
    try:
        meta = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if (meta.get("project") or {}).get("name") != "homelabnext":
        return None
    if (root / "homelabnext" / "paths.py").resolve() != Path(__file__).resolve():
        return None
    return root


def checkout_tool(name: str, *, feature: str) -> Path:
    """``<checkout>/tools/<name>``, for code that runs a repository tool in-process.

    Raises :class:`NotACheckout` (naming ``feature``) unless :func:`checkout_root` verified the
    checkout and the file exists.  The tools are executed, so they are never looked up anywhere
    else, in particular not in a ``site-packages/tools`` some other distribution installed.
    """
    root = checkout_root()
    if root is None:
        raise NotACheckout(
            f"{feature} needs a homelabnext source checkout (tools/{name}); this install is not "
            f"one ({_SOURCE_ROOT} has no pyproject.toml for the homelabnext project)"
        )
    path = root / "tools" / name
    if not path.is_file():
        raise NotACheckout(f"{feature} needs tools/{name}, which is missing from {root}")
    return path


class ResourceNotFound(FileNotFoundError):
    """A data directory or file was not found; ``tried`` lists every place that was looked at."""

    def __init__(self, what: str, tried: Sequence[str]):
        self.what = what
        self.tried = list(tried)
        lines = "".join(f"\n  - {t}" for t in self.tried)
        super().__init__(
            f"{what} not found. Places tried, in order:{lines}\n"
            "Install the wheel (it carries the data), run from a source checkout, or point "
            f"{DATA_ENV} / {KIND_ENV.get(what.split()[0], ('HNX_*_DIR',))[0]} at a directory."
        )


def _package_data_root() -> Path | None:
    """The on-disk ``homelabnext/_data`` directory, or ``None`` when it is not installed."""
    try:
        node = importlib.resources.files("homelabnext") / PACKAGE_DATA
        if not node.is_dir():
            return None
        with importlib.resources.as_file(node) as p:  # a real path for ordinary installs
            return Path(p)
    except (ModuleNotFoundError, FileNotFoundError, NotADirectoryError):
        return None


def candidates(
    kind: str,
    *,
    env: Mapping[str, str] | None = None,
    package_root: Path | str | None = _PACKAGE_ROOT_DEFAULT,
    source_root: Path | str | None = None,
) -> list[tuple[str, Path | None]]:
    """The ordered ``(label, path)`` candidates for ``kind``; ``path`` is ``None`` if N/A."""
    if kind not in KINDS:
        raise ValueError(f"unknown data kind {kind!r}; expected one of {KINDS}")
    e = os.environ if env is None else env
    out: list[tuple[str, Path | None]] = []
    for name in KIND_ENV[kind]:
        v = e.get(name)
        out.append((f"${name}", Path(v) if v else None))
    d = e.get(DATA_ENV)
    out.append((f"${DATA_ENV}/{kind}", Path(d) / kind if d else None))
    pkg = Path(package_root) if package_root is not None else _package_data_root()
    out.append((f"package data (homelabnext/{PACKAGE_DATA}/{kind})", pkg / kind if pkg else None))
    src = Path(source_root) if source_root is not None else checkout_root()
    if src is None:
        out.append((f"source tree ({_SOURCE_ROOT} is not a homelabnext checkout)", None))
    else:
        out.append((f"source tree ({src}/{kind})", src / kind))
    return out


def _resolve(kind: str, env, package_root, source_root) -> Path:
    tried: list[str] = []
    for label, path in candidates(
        kind, env=env, package_root=package_root, source_root=source_root
    ):
        if path is None:
            tried.append(f"{label}: not set / not installed")
        elif path.is_dir():
            return path
        else:
            tried.append(f"{label}: {path} (no such directory)")
    raise ResourceNotFound(f"{kind} directory", tried)


@cache
def _cached(kind: str) -> Path:
    return _resolve(kind, None, _PACKAGE_ROOT_DEFAULT, None)


def clear_cache() -> None:
    """Forget cached lookups (after changing the environment or installing data)."""
    _cached.cache_clear()
    checkout_root.cache_clear()


def resource_dir(
    kind: str,
    *,
    env: Mapping[str, str] | None = None,
    package_root: Path | str | None = None,
    source_root: Path | str | None = None,
) -> Path:
    """The directory for ``kind``.  Injecting any root bypasses the cache."""
    if kind not in KINDS:
        raise ValueError(f"unknown data kind {kind!r}; expected one of {KINDS}")
    if env is None and package_root is None and source_root is None:
        return _cached(kind)
    return _resolve(kind, env, package_root, source_root)


def resource_file(kind: str, *parts: str, **inject) -> Path:
    """A file under the ``kind`` directory; raises :class:`ResourceNotFound` if absent."""
    base = resource_dir(kind, **inject)
    p = base.joinpath(*parts)
    if not p.is_file():
        raise ResourceNotFound(
            f"{kind} file {'/'.join(parts)}", [f"{base} (directory found, but {p} is missing)"]
        )
    return p


def schemas_dir(**inject) -> Path:
    return resource_dir("schemas", **inject)


def schema_file(*parts: str, **inject) -> Path:
    """e.g. ``schema_file("platform", "site.schema.json")``."""
    return resource_file("schemas", *parts, **inject)


def ocsf_dir(**inject) -> Path:
    """The OCSF subsets.  ``HNX_SCHEMAS_DIR`` may name either the schemas root or ``ocsf`` itself."""
    base = schemas_dir(**inject)
    return base / "ocsf" if (base / "ocsf").is_dir() else base


def profiles_dir(**inject) -> Path:
    return resource_dir("profiles", **inject)


def examples_dir(**inject) -> Path:
    return resource_dir("examples", **inject)


def example_file(*parts: str, **inject) -> Path:
    return resource_file("examples", *parts, **inject)


def source_root() -> Path:
    """The directory above the package (the repository root when running from a checkout).

    Unverified: in a wheel install this is ``site-packages``.  Use :func:`checkout_root` before
    reading from it, and :func:`checkout_tool` before executing anything in it.
    """
    return _SOURCE_ROOT


def data_root(**inject) -> Path:
    """A directory laid out as ``<root>/schemas``, ``<root>/profiles``, ``<root>/examples``.

    The parent of the located ``schemas`` directory: ``homelabnext/_data`` for an installed wheel,
    the checkout for a source tree.  Used as the default ``--root`` of ``hnx custom``.
    """
    s = schemas_dir(**inject)
    return s.parent if s.name == "schemas" else s
