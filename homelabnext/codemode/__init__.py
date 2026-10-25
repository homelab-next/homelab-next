# SPDX-License-Identifier: Apache-2.0
"""Code Mode (ADR-0031): the generated, per-profile namespaces a sandboxed program calls.

CM-3 of the build plan (``docs/codemode.md``) is the generator, ``hnx codemode gen [--check]``:
from a broker manifest and its handler documents it writes, for every profile the manifest
grants actions to, the typed stubs of the program's namespaces (``types.d.ts`` and
``stubs.pyi``, one namespace per action prefix) and the search index ``codemode_search`` will
read (``search.json``).  :mod:`.model` decides what a profile may see, :mod:`.render` writes the
three files from that one model, :mod:`.cli` is the command.  CM-5b adds the runner
(:mod:`.runner`, ``codemode.execute``'s handler), its step journal (:mod:`.journal`) and the
search and describe tools (:mod:`.mcp_tools`, the ``hnx-codemode`` server); the executor
contract is CM-4's (``conformance/protocols/codemode_executor.py``).
"""

from __future__ import annotations

from .model import CodemodeError, Method, ProfileModel, build_models
from .render import DEFAULT_MANIFEST, DEFAULT_OUT, render, render_files

__all__ = [
    "DEFAULT_MANIFEST",
    "DEFAULT_OUT",
    "CodemodeError",
    "Method",
    "ProfileModel",
    "build_models",
    "render",
    "render_files",
]
