# SPDX-License-Identifier: Apache-2.0
"""The package-scan unit keeps the scanner's temporary files on disk. /tmp is a memory-backed tmpfs on the
guests, and an image scan unpacks layers under TMPDIR; leftovers of 1.8-3.5 GB in /tmp starved a 4 GB guest
into a web-app restart loop (2026-11-28)."""

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
UNIT = ROOT / "ansible" / "roles" / "trivy" / "templates" / "scan.service.j2"


@pytest.mark.static
def test_scan_unit_sets_tmpdir_off_tmpfs():
    text = UNIT.read_text(encoding="utf-8")
    m = re.search(r"^Environment=TMPDIR=(\S+)$", text, re.M)
    assert m, "the scan unit must set TMPDIR"
    assert not m.group(1).startswith(("/tmp", "/run", "/dev/shm")), m.group(1)
