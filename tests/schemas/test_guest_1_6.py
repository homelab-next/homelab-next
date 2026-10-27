# SPDX-License-Identifier: Apache-2.0
"""platform/guest 1.6 (additive): ``network.extra_addresses``, the other addresses a guest sends
from, which the log pipeline's runtime table labels like ``network.ip`` (docs/log-pipeline.md).
The schema holds the shape; validation (``homelabnext.compute.validate``) holds the rest.  1.6-only
documents live in ``fixtures/``."""

import json
from pathlib import Path

import pytest
import schema_check as sc
import yaml

ROOT = Path(__file__).resolve().parents[2]
REG = sc.build_registry(ROOT)
CURRENT = json.loads((ROOT / "schemas/platform/guest.schema.json").read_text())
FROZEN_15 = json.loads((ROOT / "schemas/_frozen/1.5/platform/guest.schema.json").read_text())
FROZEN_16 = json.loads((ROOT / "schemas/_frozen/1.6/platform/guest.schema.json").read_text())
FIXTURES = sorted((Path(__file__).parent / "fixtures").glob("guest.1_6.*.yml"))


def test_version_is_1_6_and_frozen():
    """Validates exactly what the frozen 1.6 does; a description may be reworded (site 1.4 gave
    zones an IPv6 prefix, which extra_addresses' description now names) without a new version."""
    from test_schema_evolution import _validation_only

    assert CURRENT["$id"].endswith("/platform/guest/1.6")
    assert _validation_only(CURRENT) == _validation_only(FROZEN_16)
    assert sc.is_additive(FROZEN_15, CURRENT) == []


def test_fixtures_exist():
    assert FIXTURES


@pytest.mark.parametrize("path", FIXTURES, ids=lambda p: p.name)
def test_1_6_documents_validate_against_1_6_only(path):
    doc = yaml.safe_load(path.read_text())
    assert sc.errors_for(CURRENT, doc, REG) == []
    assert sc.errors_for(FROZEN_15, doc, REG) != []


def _with(entry):
    doc = yaml.safe_load(FIXTURES[0].read_text())
    doc["network"]["extra_addresses"] = [entry]
    return doc


@pytest.mark.parametrize(
    "address",
    [
        "2001:db8::8c/64",
        "198.51.100.200/32",  # no-raw-endpoint: allow a shape the schema refuses
        "fe80::1%eth0",  # scrub-allow: a zone-scoped link-local shape the schema refuses
        "2001:DB8::8C",
        "198.51.100.256",
        "[2001:db8::8c]",
        "198.51.100.200:443",  # no-raw-endpoint: allow a shape the schema refuses
        "infer-box.example",
        "",
        7,
    ],
    ids=[
        "v6-prefix",
        "v4-prefix",
        "zone-id",
        "upper-case",
        "octet",
        "bracketed",
        "port",
        "name",
        "empty",
        "not-string",
    ],
)
def test_an_address_that_is_not_a_bare_address_is_refused(address):
    assert sc.errors_for(CURRENT, _with({"address": address, "why": "a second NIC"}), REG) != []


@pytest.mark.parametrize(
    "entry",
    [
        {"address": "2001:db8::8c"},
        {"address": "2001:db8::8c", "why": "nic"},
        {"address": "2001:db8::8c", "why": "a second NIC", "zone": "compute"},
    ],
    ids=["no-why", "short-why", "extra-key"],
)
def test_an_entry_needs_its_why_and_nothing_else(entry):
    assert sc.errors_for(CURRENT, _with(entry), REG) != []


def test_at_most_sixteen():
    doc = yaml.safe_load(FIXTURES[0].read_text())
    doc["network"]["extra_addresses"] = [
        {"address": f"2001:db8::{i:x}", "why": "a container address"} for i in range(1, 18)
    ]
    assert sc.errors_for(CURRENT, doc, REG) != []
