# SPDX-License-Identifier: Apache-2.0
"""The fictional example lab with the real publishing module in it.

``examples/modules/`` holds the fictional stand-ins; the publishing module is real (``modules/publishing``),
and a module may not be defined under both roots, so the example lab does not carry a copy.  Tests that load
the example lab on its own (``discover(fixtures=...)``, the site selections that name ``publishing``) read this
merged copy instead: the same tree plus ``publishing``, built once per process under a temporary directory.
"""

from __future__ import annotations

import atexit
import shutil
import tempfile
from functools import cache
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


@cache
def examples_with_publishing() -> Path:
    base = Path(tempfile.mkdtemp(prefix="hnx-examples-"))
    atexit.register(shutil.rmtree, base, ignore_errors=True)
    dest = base / "modules"
    shutil.copytree(ROOT / "examples" / "modules", dest)
    shutil.copytree(ROOT / "modules" / "publishing", dest / "publishing")
    return dest
