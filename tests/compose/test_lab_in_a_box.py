# SPDX-License-Identifier: Apache-2.0
"""The lab-in-a-box stack: static contract tests (no docker needed), a real ``docker compose
config`` validation when docker is present, and the smoke checks against the project's own fakes.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "compose" / "lab-in-a-box"
COMPOSE = LAB / "docker-compose.yml"
ENV_EXAMPLE = LAB / ".env.example"
WORKFLOW = ROOT / ".github" / "workflows" / "nightly.yml"
ONE_SHOT = {"catalog-migrate", "lab-init"}  # run to completion; health is their exit code
LOOPBACK = "127.0.0.1"  # no-raw-endpoint: allow test servers bind loopback only
RAM_BUDGET_MB = 3584  # 4 GB runner minus headroom for the OS and the docker daemon


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def compose() -> dict:
    return yaml.safe_load(COMPOSE.read_text())


@pytest.fixture(scope="module")
def env_vars() -> dict[str, str]:
    out = {}
    for line in ENV_EXAMPLE.read_text().splitlines():
        if line.strip() and not line.startswith("#"):
            key, _, value = line.partition("=")
            out[key] = value.split("  #")[0]
    return out


def mem_mb(value: str) -> int:
    m = re.fullmatch(r"(\d+)([mMgG])", str(value))
    assert m, f"unparsable mem_limit {value!r}"
    return int(m[1]) * (1024 if m[2] in "gG" else 1)


# --- static contract ---------------------------------------------------------------------------


def test_every_long_running_service_has_a_healthcheck(compose):
    for name, svc in compose["services"].items():
        if name in ONE_SHOT:
            continue
        assert "healthcheck" in svc, f"{name} has no healthcheck"
        assert svc["healthcheck"]["test"], name


def test_one_shots_are_waited_on_by_completion(compose):
    deps = compose["services"]["lake-query"]["depends_on"]
    assert deps["lab-init"]["condition"] == "service_completed_successfully"
    assert (
        compose["services"]["lake-catalog"]["depends_on"]["catalog-migrate"]["condition"]
        == "service_completed_successfully"
    )


def test_third_party_images_are_pinned_by_tag_and_digest(compose):
    for name, svc in compose["services"].items():
        if "build" in svc:
            continue
        image = svc["image"]
        assert re.fullmatch(r"[\w./-]+:[\w.-]+@sha256:[0-9a-f]{64}", image), f"{name}: {image}"
        assert ":latest" not in image


def test_dockerfile_base_is_pinned_by_digest():
    froms = [
        line
        for line in (LAB / "fakes" / "Dockerfile").read_text().splitlines()
        if line.startswith("FROM ")
    ]
    assert froms
    for line in froms:
        assert re.search(r"@sha256:[0-9a-f]{64}$", line), line


def test_memory_budget_fits_four_gigabytes(compose):
    total = 0
    for name, svc in compose["services"].items():
        assert "mem_limit" in svc, f"{name} has no mem_limit"
        total += mem_mb(svc["mem_limit"])
    assert total <= RAM_BUDGET_MB, f"sum of mem_limit is {total} MB"


def test_trino_heap_is_tiny():
    heap = re.search(r"^-Xmx(\d+)M$", (LAB / "config/trino/jvm.config").read_text(), re.M)
    assert heap and int(heap[1]) <= 1024


def test_every_capability_has_a_registry_style_alias(compose):
    aliases = {
        a
        for svc in compose["services"].values()
        for net in (svc["networks"].values() if isinstance(svc.get("networks"), dict) else [])
        if isinstance(net, dict)
        for a in net.get("aliases", [])
    }
    for cap in (
        "object-store",
        "lake-catalog",
        "lake-query",
        "events",
        "secrets",
        "notify",
        "authz",
        "inference",
        "cases",
    ):
        assert f"{cap}.svc.example.internal" in aliases, cap


def test_ports_bind_through_a_variable_never_all_interfaces(compose):
    for name, svc in compose["services"].items():
        for port in svc.get("ports", []):
            assert str(port).startswith("${LAB_BIND:-"), f"{name}: {port}"


def test_all_referenced_variables_are_documented(compose, env_vars):
    text = COMPOSE.read_text()
    used = set(re.findall(r"\$\{(LAB_[A-Z0-9_]+)", text))
    used |= set(
        re.findall(
            r"\$\{ENV:(LAB_[A-Z0-9_]+)\}",
            (LAB / "config/trino/catalog/iceberg.properties").read_text(),
        )
    )
    assert used, "no variables found"
    assert used <= set(env_vars), f"undocumented: {sorted(used - set(env_vars))}"


def test_required_credentials_have_no_default_in_the_compose_file():
    text = COMPOSE.read_text()
    for var in ("LAB_POSTGRES_PASSWORD", "LAB_S3_SECRET_KEY", "LAB_SECRETS_DEV_TOKEN"):
        assert f"${{{var}:-" not in text, f"{var} must not have an inline default"


def test_example_credentials_are_obviously_fake(env_vars):
    for key, value in env_vars.items():
        if re.search(r"PASSWORD|SECRET|TOKEN|KEY", key) and not key.startswith("LAB_PORT"):
            assert "fake" in value.lower() or "fade" in value or set(value) <= {"0"}, (
                f"{key} looks real"
            )


def test_addresses_are_documentation_ranges_or_loopback(env_vars):
    for key, value in env_vars.items():
        for ip in re.findall(r"\b\d+\.\d+\.\d+\.\d+\b", value):
            assert ip == LOOPBACK or ip.startswith(("192.0.2.", "198.51.100.", "203.0.113.")), (
                key,
                ip,
            )


def test_negative_a_service_without_a_healthcheck_would_be_caught(compose):
    broken = json.loads(json.dumps(compose))
    del broken["services"]["events"]["healthcheck"]
    missing = [
        n for n, s in broken["services"].items() if n not in ONE_SHOT and "healthcheck" not in s
    ]
    assert missing == ["events"]


# --- docker compose config (skipped cleanly without docker) -----------------------------------


def docker_compose_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return (
            subprocess.run(
                ["docker", "compose", "version"], capture_output=True, timeout=30
            ).returncode
            == 0
        )
    except (OSError, subprocess.TimeoutExpired):
        return False


needs_docker = pytest.mark.skipif(
    not docker_compose_available(), reason="docker with the compose plugin is not available"
)


@needs_docker
def test_docker_compose_config_is_valid():
    proc = subprocess.run(
        [
            "docker",
            "compose",
            "--env-file",
            str(ENV_EXAMPLE),
            "-f",
            str(COMPOSE),
            "config",
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    rendered = json.loads(proc.stdout)
    assert {"object-store", "lake-catalog", "lake-query", "events", "secrets", "notify"} <= set(
        rendered["services"]
    )


@needs_docker
def test_docker_compose_config_rejects_a_missing_required_variable(tmp_path):
    empty = tmp_path / "empty.env"
    empty.write_text("")
    proc = subprocess.run(
        ["docker", "compose", "--env-file", str(empty), "-f", str(COMPOSE), "config", "--quiet"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode != 0
    assert "see .env.example" in proc.stderr


# --- smoke script --------------------------------------------------------------------------------


def test_smoke_script_syntax_and_executable_bit():
    smoke = LAB / "smoke.sh"
    assert os.access(smoke, os.X_OK)
    assert subprocess.run(["bash", "-n", str(smoke)]).returncode == 0


def test_smoke_script_exits_3_without_docker(tmp_path):
    bash = shutil.which("bash")
    assert bash
    # a PATH that holds bash's own dir only under a name that is not "docker"
    stub = tmp_path / "bin"
    stub.mkdir()
    for tool in ("dirname", "mkdir"):
        found = shutil.which(tool)
        assert found
        (stub / tool).symlink_to(found)
    proc = subprocess.run(
        [bash, str(LAB / "smoke.sh"), "--report-dir", str(tmp_path / "r")],
        env={"PATH": str(stub)},
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 3
    assert "docker" in proc.stderr


# --- smoke checks against the project's own fakes ----------------------------------------------


@pytest.fixture(scope="module")
def checks():
    return load_module("smoke_checks", LAB / "smoke_checks.py")


@pytest.fixture
def fake_servers():
    from conformance.fakes.openai_server import FakeOpenAIServer

    fake_cases = load_module("fake_cases", LAB / "fakes" / "fake_cases.py")
    httpd = ThreadingHTTPServer((LOOPBACK, 0), fake_cases.make_handler(fake_cases.CaseStore()))
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    with FakeOpenAIServer(models=["example-4b"]) as inference:
        yield {
            "inference": inference.url,
            "cases": f"http://{LOOPBACK}:{httpd.server_address[1]}",
        }
    httpd.shutdown()
    httpd.server_close()


def test_inference_and_cases_checks_pass_against_the_fakes(checks, fake_servers):
    results = checks.run_checks(fake_servers, only=["inference", "cases"], retries=1)
    assert [r["status"] for r in results] == ["pass", "pass"], results


def test_a_check_fails_when_nothing_is_listening(checks):
    dead = {"cases": f"http://{LOOPBACK}:9"}
    (result,) = checks.run_checks(dead, only=["cases"], retries=1)
    assert result["status"] == "fail"


def test_a_missing_endpoint_is_a_failure_not_a_skip(checks):
    results = checks.run_checks({}, retries=1)
    assert results and all(r["status"] == "fail" for r in results)


def test_bases_come_from_the_documented_env_names(checks, env_vars):
    bases = checks.bases_from_env(env_vars)
    assert bases["lake-query"] == f"http://{LOOPBACK}:8080"
    assert bases["warehouse"] == env_vars["LAB_WAREHOUSE"]


# --- nightly workflow ----------------------------------------------------------------------------


def test_nightly_is_scheduled_and_never_runs_on_pull_requests():
    doc = yaml.safe_load(WORKFLOW.read_text())
    triggers = doc.get("on") or doc.get(True)
    assert "schedule" in triggers and "workflow_dispatch" in triggers
    assert "pull_request" not in triggers and "push" not in triggers


def test_nightly_pins_every_action_by_full_sha():
    uses = re.findall(r"uses:\s*(\S+)", WORKFLOW.read_text())
    assert uses
    for ref in uses:
        if ref.startswith("./.github/actions/"):  # a local action is pinned by this commit
            action = ROOT / ref / "action.yml"
            uses += re.findall(r"uses:\s*(\S+)", action.read_text())
            continue
        assert re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", ref), ref
