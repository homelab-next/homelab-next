# SPDX-License-Identifier: Apache-2.0
"""The repository's endpoint gate, ``tools/no_raw_endpoints.py``, for package code that reuses its
detection (the customization lint, the agent home check of invariant A-14), so a check in the
package never drifts from what CI refuses.

The gate is a checkout tool, executed in-process: it is loaded only from a verified checkout
(:func:`homelabnext.paths.checkout_tool`), once, under one module name.  Outside a checkout
:func:`load` returns None and each caller falls back to its own, reduced, detection and says so.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

__all__ = ["MODULE", "gate_path", "load"]

#: the name the gate is registered under in ``sys.modules`` (its dataclasses need one)
MODULE = "hnx_no_raw_endpoints"


def gate_path(feature: str) -> Path | None:
    """``tools/no_raw_endpoints.py`` of a verified checkout, else None."""
    from homelabnext import paths

    try:
        return paths.checkout_tool("no_raw_endpoints.py", feature=feature)
    except paths.NotACheckout:
        return None


def load(feature: str) -> ModuleType | None:
    """The gate module (loaded once per process), or None outside a checkout."""
    mod = sys.modules.get(MODULE)
    if mod is not None:
        return mod
    path = gate_path(feature)
    if path is None:
        return None
    spec = importlib.util.spec_from_file_location(MODULE, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[MODULE] = mod
    try:
        spec.loader.exec_module(mod)
    except BaseException:
        sys.modules.pop(MODULE, None)
        raise
    return mod
