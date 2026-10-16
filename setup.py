# SPDX-License-Identifier: Apache-2.0
"""Build hook: copy the repo-level data trees into the package at build time.

``schemas/``, ``profiles/`` and ``examples/`` at the repository root stay the single source of
truth (``tools/schema_check.py`` and the frozen-baseline workflow work on them in place).  A wheel
cannot reach outside the package directory, so ``build_py`` copies those trees into
``homelabnext/_data/`` *inside the build directory only*; nothing is written into the source
tree and nothing can diverge.  ``tests/packaging/test_package_data.py`` fails if the packaged copy
ever differs from the source of truth.  Runtime lookup lives in ``homelabnext/paths.py``.

Everything else is declared in ``pyproject.toml``.
"""

import shutil
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py

HERE = Path(__file__).resolve().parent
DATA_TREES = ("schemas", "profiles", "examples")  # keep in sync with homelabnext/paths.py KINDS
IGNORE = shutil.ignore_patterns("__pycache__", "*.pyc")


class BuildPyWithData(build_py):
    def run(self):
        super().run()
        dest = Path(self.build_lib) / "homelabnext" / "_data"
        if dest.exists():
            shutil.rmtree(dest)
        missing = [t for t in DATA_TREES if not (HERE / t).is_dir()]
        if missing:
            raise SystemExit(
                f"cannot package data: {', '.join(missing)} missing next to setup.py "
                "(build from a source checkout or an sdist, not from a copy of homelabnext/ alone)"
            )
        for tree in DATA_TREES:
            shutil.copytree(HERE / tree, dest / tree, ignore=IGNORE)
            self.announce(f"packaged {tree}/ -> homelabnext/_data/{tree}", level=2)


setup(cmdclass={"build_py": BuildPyWithData})
