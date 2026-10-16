# SPDX-License-Identifier: Apache-2.0
from pathlib import Path

import yaml

from homelabnext.generators import GENERATORS, generate
from homelabnext.registry import load

ROOT = Path(__file__).resolve().parents[2]


def test_manifest_matches_registered_generators():
    generate(load(ROOT / "examples" / "services.yml"))
    manifest = yaml.safe_load((ROOT / "generators" / "manifest.yml").read_text())["generators"]
    assert set(manifest) == set(GENERATORS)
    for name, g in GENERATORS.items():
        assert manifest[name]["description"] == g.description
        assert manifest[name]["target"] == g.target
