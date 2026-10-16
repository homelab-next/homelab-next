# SPDX-License-Identifier: Apache-2.0
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
for p in (_ROOT, _ROOT / "tests" / "lake" / "fixtures"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))
