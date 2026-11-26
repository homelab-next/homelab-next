# SPDX-License-Identifier: Apache-2.0
"""What CI runs, as text, for the tests that hold a gate to CI.

CI's first job, ``precheck``, runs ``make precheck`` (tools/precheck.sh, the Makefile's
``precheck-run`` target in parallel), so most gates no longer appear in ``ci.yml`` itself:
:func:`ci_text` is the workflow's text followed by the commands ``make precheck`` runs, as make
itself prints them (``make -n``, with a stand-in base so the ratchets print too).
"""

from __future__ import annotations

import functools
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CI = ROOT / ".github" / "workflows" / "ci.yml"
#: a stand-in base: ``make -n`` only prints the ratchets' commands, it never runs them
BASE = "0123456789abcdef0123456789abcdef01234567"


@functools.cache
def precheck_commands(root: Path = ROOT) -> str:
    """The commands ``make precheck`` runs (``make -n precheck-run``), one per line."""
    r = subprocess.run(
        ["make", "-n", "--no-print-directory", "precheck-run", "PY=python", f"BASE={BASE}"],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    )
    return r.stdout


def precheck_targets(root: Path = ROOT) -> list[str]:
    """The Makefile targets ``make precheck`` builds: the prerequisites of ``precheck-run``."""
    out = []
    for line in (root / "Makefile").read_text(encoding="utf-8").splitlines():
        if line.startswith("precheck-run:"):
            out += line.split(":", 1)[1].split("#")[0].split()
    return out


def ci_text(root: Path = ROOT) -> str:
    """ci.yml's text, then what its precheck job's ``make precheck`` runs: a ``make <target>``
    line per target, and the targets' commands."""
    text = (root / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    if "make precheck" in text:
        text += "\n" + "\n".join(f"make {t}" for t in precheck_targets(root))
        text += "\n" + precheck_commands(root)
    return text
