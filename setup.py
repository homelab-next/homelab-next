# SPDX-License-Identifier: Apache-2.0
"""Build hook: package only reviewed files, and copy the repo-level data trees into the package.

``schemas/``, ``profiles/`` and ``examples/`` at the repository root stay the single source of
truth (``tools/schema_check.py`` and the frozen-baseline workflow work on them in place).  A wheel
cannot reach outside the package directory, so ``build_py`` copies those trees into
``homelabnext/_data/`` *inside the build directory only*; nothing is written into the source
tree and nothing can diverge.  ``tests/packaging/test_wheel_install.py`` fails if the packaged copy
ever differs from the source of truth.  Runtime lookup lives in ``homelabnext/paths.py``.

What may be packaged is decided by one list, never by what happens to be on disk:

* in a git checkout, the files git tracks (``git ls-files``), so an untracked ``.env``, a scratch
  file or a stray build artefact can never reach a wheel or an sdist;
* in an unpacked sdist (no ``.git``), the sdist's own manifest (``*.egg-info/SOURCES.txt``), which
  was produced from the tracked list when the sdist was built.

A symbolic link is refused outright: following it could package a file from outside the tree.

Everything else is declared in ``pyproject.toml``.
"""

import os
import shutil
import subprocess
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py
from setuptools.command.sdist import sdist

HERE = Path(__file__).resolve().parent
DATA_TREES = ("schemas", "profiles", "examples")  # keep in sync with homelabnext/paths.py KINDS
SKIP_PARTS = {"__pycache__"}
#: tracked paths under the data trees that hnx never reads at run time, so they are not packaged
#: (keep in sync with tests/packaging/test_wheel_install.py)
NOT_PACKAGED = (
    # a template for a separate private repository: dotfiles, a client script, workflows
    "examples/private-overlay/",
)


def _source_files() -> set[str]:
    """Relative POSIX paths that may be packaged (see the module docstring)."""
    if (HERE / ".git").exists():
        try:
            out = subprocess.run(
                ["git", "-C", str(HERE), "ls-files", "-z"],
                capture_output=True,
                check=True,
            ).stdout
        except (OSError, subprocess.CalledProcessError) as exc:
            raise SystemExit(f"cannot list tracked files with git: {exc}") from exc
        return {n for n in out.decode("utf-8", "surrogateescape").split("\0") if n}
    manifests = sorted(HERE.glob("*.egg-info/SOURCES.txt"))
    if (HERE / "PKG-INFO").is_file() and manifests:
        return {ln.strip() for ln in manifests[0].read_text("utf-8").splitlines() if ln.strip()}
    raise SystemExit(
        "refusing to build: no .git and no sdist manifest next to setup.py, so there is no reviewed "
        "list of files to package (build from a git checkout or from an sdist)"
    )


def _check_not_symlink(rel: str) -> None:
    if os.path.islink(HERE / rel):
        raise SystemExit(f"refusing to package a symbolic link: {rel}")


def _allowed(path: str | os.PathLike, files: set[str]) -> bool:
    try:
        rel = Path(path).resolve().relative_to(HERE).as_posix()
    except ValueError:
        return False
    return rel in files


class BuildPyFromTracked(build_py):
    _tracked: set[str] | None = None

    def tracked(self) -> set[str]:
        if self._tracked is None:
            self._tracked = _source_files()
        return self._tracked

    def run(self):
        super().run()
        if getattr(self, "editable_mode", False):
            return  # an editable install reads the source tree in place
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
            chosen = sorted(
                f
                for f in self.tracked()
                if f.startswith(tree + "/")
                and not f.startswith(NOT_PACKAGED)
                and not SKIP_PARTS & set(f.split("/"))
            )
            for rel in chosen:
                _check_not_symlink(rel)
                target = dest / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(HERE / rel, target, follow_symlinks=False)
            self.announce(f"packaged {len(chosen)} files of {tree}/ -> homelabnext/_data", level=2)

    def find_package_modules(self, package, package_dir):
        modules = super().find_package_modules(package, package_dir)
        kept = [m for m in modules if _allowed(m[2], self.tracked())]
        for m in kept:
            _check_not_symlink(Path(m[2]).resolve().relative_to(HERE).as_posix())
        return kept

    def find_data_files(self, package, src_dir):
        found = super().find_data_files(package, src_dir)
        kept = [f for f in found if _allowed(f, self.tracked())]
        for f in kept:
            _check_not_symlink(Path(f).resolve().relative_to(HERE).as_posix())
        return kept


class SdistFromTracked(sdist):
    """The sdist carries MANIFEST.in's selection, narrowed to tracked files; never a symlink."""

    def make_release_tree(self, base_dir, files):
        tracked = _source_files()
        kept = []
        for f in files:
            rel = Path(f).as_posix()
            generated = rel == "PKG-INFO" or rel == "setup.cfg" or ".egg-info/" in rel
            if not generated and rel not in tracked:
                continue
            if not generated:
                _check_not_symlink(rel)
            kept.append(f)
        super().make_release_tree(base_dir, kept)


setup(cmdclass={"build_py": BuildPyFromTracked, "sdist": SdistFromTracked})
