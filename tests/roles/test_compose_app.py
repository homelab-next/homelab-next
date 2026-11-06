# SPDX-License-Identifier: Apache-2.0
"""The compose_app health hook against a fake ``docker compose ps`` (one ansible-playbook run)."""

import json
import os

import pytest
from rolerun import fake, first_run, run_cases

pytestmark = pytest.mark.requires_tool("ansible-playbook")

SPEC = {"services": {"web": {}, "db": {}}}


def row(service, state="running", health=""):
    return {"Service": service, "State": state, "Health": health}


def ndjson(*rows):
    return "".join(json.dumps(r) + "\n" for r in rows)


GOOD = [row("web", health="healthy"), row("db")]
CASES = {
    "ndjson, all up": (ndjson(*GOOD), False, ""),
    "older compose, one array": (json.dumps(GOOD), False, ""),
    "empty output (no containers)": ("", True, "no container for"),
    "empty array": ("[]", True, "no container for"),
    "a service has no container": (ndjson(row("web")), True, "no container for db"),
    "a container is down": (ndjson(row("web"), row("db", "exited")), True, "items failed"),
    "a container is unhealthy": (
        ndjson(row("web", health="unhealthy"), row("db")),
        True,
        "items failed",
    ),
}


def _first(tmp_path):
    # the fake reads <dir>/ps.out for the compose file it is given (-f <dir>/docker-compose.yml)
    bindir = tmp_path / "bin"
    bindir.mkdir()
    fake(
        bindir / "docker",
        "import sys\n"
        "from pathlib import Path\n"
        "sys.stdout.write((Path(sys.argv[sys.argv.index('-f') + 1]).parent / 'ps.out').read_text())\n",
    )
    overrides = []
    for i, (out, _, _) in enumerate(CASES.values()):
        d = tmp_path / f"case{i}"
        d.mkdir()
        (d / "ps.out").write_text(out)
        overrides.append({"compose_app_dir": str(d)})
    return {
        "runner": run_cases,
        "role": "compose_app",
        "tasks_from": "health",
        "base_vars": {"compose_app_name": "demo-app", "compose_app_spec": SPEC},
        "overrides": overrides,
        "env": {"PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}"},
    }


@first_run(_first)
def test_compose_app_health_needs_every_service_running_and_healthy(first):
    results, _ = first
    for (name, (_, fails, msg)), (failed, got) in zip(CASES.items(), results, strict=True):
        assert failed is fails, name
        assert msg in got, (name, got)
