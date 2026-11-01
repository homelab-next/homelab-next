# SPDX-License-Identifier: Apache-2.0
"""ADR-0012 decision 4: the guest model's render targets (``homelabnext/compute/gen/``, where the
hypervisor-specific text is written) are reached only through the compute package. No contract,
library or other generator outside ``homelabnext/compute/`` imports one, apart from the reviewed
exceptions below, so a hypervisor never becomes a seam the rest of the core leans on."""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PKG = ROOT / "homelabnext"
GEN = "homelabnext.compute.gen"

#: (importing file, target module) pairs allowed outside the compute package, each with its reason
ALLOWED = {
    # core_units reads the node mirror's unit name, the one constant the loader needs
    ("homelabnext/modules/loader.py", f"{GEN}.node_mirror"): "reads UNIT only",
}


def _targets(tree: ast.AST) -> set[str]:
    """Every ``homelabnext.compute.gen[.x]`` module a file imports, absolute imports only (a
    relative import cannot reach the compute package from outside it)."""
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out |= {a.name for a in node.names if a.name == GEN or a.name.startswith(GEN + ".")}
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            mod = node.module
            if mod == GEN:
                out |= {f"{GEN}.{a.name}" for a in node.names}
            elif mod == "homelabnext.compute" and any(a.name == "gen" for a in node.names):
                out.add(GEN)
            elif mod.startswith(GEN + "."):
                out.add(mod)
    return out


def imports_outside_compute(pkg: Path = PKG) -> set[tuple[str, str]]:
    found = set()
    for path in pkg.rglob("*.py"):
        rel = path.relative_to(ROOT).as_posix()
        if rel.startswith("homelabnext/compute/"):
            continue
        for mod in _targets(ast.parse(path.read_text(encoding="utf-8"), filename=rel)):
            found.add((rel, mod))
    return found


def test_render_targets_are_imported_only_by_the_compute_package():
    stray = imports_outside_compute() - set(ALLOWED)
    assert not stray, f"a render target imported outside homelabnext/compute/: {sorted(stray)}"


def test_every_allowed_exception_is_still_used():
    assert set(ALLOWED) <= imports_outside_compute(), "drop an ALLOWED entry nothing needs"


def test_the_scan_sees_each_import_form():
    src = (
        "import homelabnext.compute.gen.cloudinit\n"
        "from homelabnext.compute.gen import inventory\n"
        "from homelabnext.compute.gen.backup_jobs import render\n"
        "from homelabnext.compute import model\n"
        "from homelabnext.compute import gen\n"
    )
    assert _targets(ast.parse(src)) == {
        GEN,
        f"{GEN}.cloudinit",
        f"{GEN}.inventory",
        f"{GEN}.backup_jobs",
    }
