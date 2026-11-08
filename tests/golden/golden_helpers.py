# SPDX-License-Identifier: Apache-2.0
"""Constants and rule sets the golden-runner tests share.

They live here, not in ``conftest.py``: no test directory has an ``__init__.py``, so every
``conftest.py`` is imported as the module ``conftest`` and ``from conftest import ...`` gets
whichever directory's conftest pytest loaded last (``pytest tests/golden tests/status`` handed the
golden runner tests the status hub's).  A helper module with a name of its own does not clash.
"""

from __future__ import annotations

from pathlib import Path

from conformance.fakes.openai_server import label_rule

ROOT = Path(__file__).resolve().parents[2]
SUITE = ROOT / "homelabnext" / "golden" / "examples" / "classifier_smoke.yml"


def good_rules():
    return [
        label_rule("revert the commit", "accept", 0.97),
        label_rule("NO-ROLLBACK", "reject", 0.91),
    ]
