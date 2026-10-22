# SPDX-License-Identifier: Apache-2.0
"""The site schema accepts the example and rejects each negative for the intended reason."""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from homelabnext.network.loader import load_site, schema
from homelabnext.network.validate import schema_problems

NEG = Path(__file__).resolve().parents[2] / "schemas" / "platform" / "negative"
EXPECT = {
    "default-action-allow": "default_action",
    "mgmt-endpoint-is-url": "mgmt_endpoint",
    "secret-ref-is-literal": "secret_ref",
    "vlan-out-of-range": "vlan_id",
    "subnet-not-cidr": "subnet",
    "extra-field": "wifi_password",
    "no-router": "router",
    "no-zones": "zones",
    "exception-from-not-zone-ref": "service_exceptions",
    "exception-to-is-endpoint": "service_exceptions",
    "access-port-without-vlan": "vlan",
    "timezone-local": "timezone",
    "power-none-without-reason": "reason",
    "edge-kind-unknown": "kind",
    "ups-mac-malformed": "mac",
    "deploy-wildcard-zone": "tailnet/deploy/zones",
    "deploy-exception-without-reason": "reason",
}


def test_schema_is_valid_draft_2020_12():
    jsonschema.Draft202012Validator.check_schema(schema())


def test_example_site_validates(site_path):
    assert schema_problems(load_site(site_path)) == []


def test_every_negative_has_an_expectation():
    on_disk = {p.name[len("site.") : -len(".yml")] for p in NEG.glob("site.*.yml")}
    assert on_disk == set(EXPECT)


@pytest.mark.parametrize("label", sorted(EXPECT))
def test_negative_is_rejected_for_the_intended_reason(label):
    problems = schema_problems(load_site(NEG / f"site.{label}.yml"))
    assert problems, f"{label} was accepted"
    assert any(EXPECT[label] in p for p in problems), problems


def test_schema_id_and_version():
    s = schema()
    assert s["$id"].endswith("/platform/site/1.2")
    assert json.dumps(s)  # serialisable
