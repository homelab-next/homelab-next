# SPDX-License-Identifier: Apache-2.0
"""The metrics generator's listener scheme and secret-referenced scrape authentication (2.11)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from homelabnext.generators import generate
from homelabnext.registry import load
from homelabnext.registry.model import build_registry

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "examples" / "services.yml"
REG = load(EXAMPLE)


@pytest.mark.static
def test_scheme_and_basic_auth_render_file_paths_never_values():
    out = generate(REG, ["prometheus"])
    prom = yaml.safe_load(out["prometheus"]["prometheus/scrape_configs.yml"])
    query = next(j for j in prom["scrape_configs"] if j["job_name"] == "lake-query")
    assert (
        next(j for j in prom["scrape_configs"] if j["job_name"] == "lake-catalog")["scheme"]
        == "http"
    )
    assert (
        next(j for j in prom["scrape_configs"] if j["job_name"] == "object-store")["scheme"]
        == "https"
    )
    assert query["basic_auth"] == {
        "username": "prometheus-scraper",
        "password_file": "/etc/hnx/scrape-credentials/lake/trino-scraper-password.credentials",
    }
    cred = json.loads(out["prometheus"]["prometheus/credentials.json"])
    assert cred["credentials"] == [
        {
            "secret": "secret:lake/trino-scraper-password",
            "path": "/etc/hnx/scrape-credentials/lake/trino-scraper-password.credentials",
            "mode": "0600",
        }
    ]


@pytest.mark.static
def test_prometheus_bearer_auth_uses_a_credentials_file():
    doc = yaml.safe_load(EXAMPLE.read_text())
    doc["services"]["lake-query"]["metrics"]["auth"] = {
        "kind": "bearer",
        "secret": "secret:lake/trino-scraper-token",
    }
    output = generate(build_registry(doc), ["prometheus"])["prometheus"]
    prom = yaml.safe_load(output["prometheus/scrape_configs.yml"])
    query = next(j for j in prom["scrape_configs"] if j["job_name"] == "lake-query")
    assert query["authorization"] == {
        "type": "Bearer",
        "credentials_file": "/etc/hnx/scrape-credentials/lake/trino-scraper-token.credentials",
    }
