# SPDX-License-Identifier: Apache-2.0
"""The schema-layout example for service.json must not drift from the canonical example lab."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_schema_example_is_the_canonical_example_lab():
    canonical = (ROOT / "examples" / "services.yml").read_text(encoding="utf-8")
    copy = (ROOT / "schemas" / "platform" / "examples" / "service.valid.yml").read_text(
        encoding="utf-8"
    )
    assert canonical == copy
