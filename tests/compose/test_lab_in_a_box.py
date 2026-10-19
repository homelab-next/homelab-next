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


# --- hardening and the bind guard ---------------------------------------------------------------
HARDENED_EXCEPTIONS = {"secrets"}  # OpenBao's entrypoint needs its default capabilities


def test_containers_drop_capabilities_and_forbid_new_privileges(compose):
    for name, svc in compose["services"].items():
        if name in HARDENED_EXCEPTIONS:
            continue
        assert svc.get("security_opt") == ["no-new-privileges:true"], name
        assert svc.get("cap_drop") == ["ALL"], name
        assert "privileged" not in svc, name
        for v in svc.get("volumes", []):
            assert "docker.sock" not in str(v), name


def test_the_secrets_exception_is_explained_above_the_service():
    text = COMPOSE.read_text()
    banner = text[text.index("# --- secrets:") : text.index("  secrets:\n")]
    for words in ("DEV MODE", "no persistence", "no TLS", "known root token", "Production"):
        assert words in banner, words


GUARD = LAB / "bind_guard.sh"
OTHER_LOOPBACK = "127.0.0.2"  # no-raw-endpoint: allow the whole 127/8 block is loopback
ROUTABLE = "192.0.2.10"  # no-raw-endpoint: allow a documentation address the guard must refuse
CREDENTIALS = (
    "LAB_POSTGRES_PASSWORD",
    "LAB_S3_ACCESS_KEY",
    "LAB_S3_SECRET_KEY",
    "LAB_OBJECT_STORE_RPC_SECRET",
    "LAB_OBJECT_STORE_ADMIN_TOKEN",
    "LAB_CATALOG_ENCRYPTION_KEY",
    "LAB_SECRETS_DEV_TOKEN",
)


@pytest.fixture
def lab_copy(tmp_path):
    """A copy of the lab directory, so a test can add a .env without touching the checkout."""
    dst = tmp_path / "lab"
    dst.mkdir()
    for f in (".env.example", "bind_guard.sh", "smoke.sh", "docker-compose.yml"):
        shutil.copy2(LAB / f, dst / f)
    return dst


def stub_path(tmp_path, tools=("dirname", "mkdir")):
    """A PATH with only the named tools: in particular no docker."""
    stub = tmp_path / "bin"
    stub.mkdir(exist_ok=True)
    for tool in tools:
        found = shutil.which(tool)
        assert found
        if not (stub / tool).exists():
            (stub / tool).symlink_to(found)
    return str(stub)


def guard(lab, tmp_path, **env):
    return subprocess.run(
        [shutil.which("bash"), str(lab / "bind_guard.sh")],
        env={"PATH": stub_path(tmp_path), **env},
        capture_output=True,
        text=True,
    )


def real_credentials():
    return {k: f"changed-{k.lower()}" for k in CREDENTIALS}


@pytest.mark.parametrize("bind", [LOOPBACK, OTHER_LOOPBACK, "::1", "[::1]", ""])
def test_guard_allows_loopback(lab_copy, tmp_path, bind):
    assert guard(lab_copy, tmp_path, LAB_BIND=bind).returncode == 0


def test_guard_allows_the_shipped_defaults(lab_copy, tmp_path):
    assert guard(lab_copy, tmp_path).returncode == 0


@pytest.mark.parametrize("bind", ["0.0.0.0", ROUTABLE, LOOPBACK + ".5", "::", "localhost"])
def test_guard_refuses_a_non_loopback_bind_without_the_acknowledgement(lab_copy, tmp_path, bind):
    r = guard(lab_copy, tmp_path, LAB_BIND=bind, **real_credentials())
    assert r.returncode == 4
    assert "LAB_I_UNDERSTAND_UNAUTHENTICATED=1" in r.stderr


def test_guard_refuses_while_any_credential_is_the_placeholder(lab_copy, tmp_path):
    creds = real_credentials()
    del creds["LAB_SECRETS_DEV_TOKEN"]  # still the .env.example value
    r = guard(lab_copy, tmp_path, LAB_BIND="0.0.0.0", LAB_I_UNDERSTAND_UNAUTHENTICATED="1", **creds)
    assert r.returncode == 4
    assert "LAB_SECRETS_DEV_TOKEN" in r.stderr and "LAB_POSTGRES_PASSWORD" not in r.stderr


def test_guard_allows_a_non_loopback_bind_once_acknowledged_and_changed(lab_copy, tmp_path):
    r = guard(
        lab_copy,
        tmp_path,
        LAB_BIND="0.0.0.0",
        LAB_I_UNDERSTAND_UNAUTHENTICATED="1",
        **real_credentials(),
    )
    assert r.returncode == 0, r.stderr
    assert "WARNING" in r.stderr


def test_guard_reads_dot_env_and_the_environment_wins_over_it(lab_copy, tmp_path):
    lines = [f"{k}={v}" for k, v in real_credentials().items()]
    (lab_copy / ".env").write_text(
        "LAB_BIND=0.0.0.0  # all interfaces\nLAB_I_UNDERSTAND_UNAUTHENTICATED=1\n"
        + "\n".join(lines)
        + "\n"
    )
    assert guard(lab_copy, tmp_path).returncode == 0
    # .env sets a routable bind but keeps one placeholder: refused
    env_example_token = dict(
        line.split("=", 1)
        for line in ENV_EXAMPLE.read_text().splitlines()
        if line.startswith("LAB_SECRETS_DEV_TOKEN=")
    )["LAB_SECRETS_DEV_TOKEN"]
    (lab_copy / ".env").write_text(
        (lab_copy / ".env").read_text() + f"LAB_SECRETS_DEV_TOKEN={env_example_token}\n"
    )
    r = guard(lab_copy, tmp_path)
    assert r.returncode == 4 and "LAB_SECRETS_DEV_TOKEN" in r.stderr
    # the environment overrides .env, exactly as docker compose interpolation does
    assert guard(lab_copy, tmp_path, LAB_BIND=LOOPBACK).returncode == 0


def test_smoke_script_runs_the_guard_before_looking_for_docker(lab_copy, tmp_path):
    bash = shutil.which("bash")
    env = {"PATH": stub_path(tmp_path), "LAB_BIND": "0.0.0.0"}
    r = subprocess.run(
        [bash, str(lab_copy / "smoke.sh"), "--report-dir", str(tmp_path / "r")],
        env=env,
        capture_output=True,
        text=True,
    )
    assert r.returncode == 4, r.stderr
    assert "refusing LAB_BIND=0.0.0.0" in r.stderr
    assert not (tmp_path / "r").exists()  # nothing was run


def test_smoke_script_keeps_the_environment_over_the_env_files(lab_copy, tmp_path):
    # a routable bind in .env but a loopback LAB_BIND in the environment: the guard passes, so
    # smoke.sh must not then re-read .env over the environment and publish on all interfaces
    lines = [f"{k}={v}" for k, v in real_credentials().items()]
    (lab_copy / ".env").write_text("LAB_BIND=0.0.0.0\n" + "\n".join(lines) + "\n")
    text = (lab_copy / "smoke.sh").read_text()
    probe = text.replace('eval "$from_env"', 'eval "$from_env"\necho "bind=$LAB_BIND"; exit 0', 1)
    probe = probe.replace(
        "  exit 3\n", "  :  # no docker here; this probe stops before using it\n", 1
    )
    (lab_copy / "probe.sh").write_text(probe)
    r = subprocess.run(
        [shutil.which("bash"), str(lab_copy / "probe.sh"), "--report-dir", str(tmp_path / "r")],
        env={"PATH": stub_path(tmp_path), "LAB_BIND": LOOPBACK},
        capture_output=True,
        text=True,
    )
    assert r.returncode == 0, r.stderr
    assert f"bind={LOOPBACK}" in r.stdout


@pytest.mark.skipif(shutil.which("make") is None, reason="make not installed")
def test_make_lab_up_runs_the_guard_first(tmp_path):
    path = stub_path(tmp_path, tools=("dirname", "mkdir", "bash", "sh"))
    r = subprocess.run(
        [shutil.which("make"), "-s", "-C", str(ROOT), "lab-up"],
        env={"PATH": path, "LAB_BIND": "0.0.0.0"},
        capture_output=True,
        text=True,
    )
    assert r.returncode != 0
    assert "refusing LAB_BIND=0.0.0.0" in r.stderr
    assert "docker" not in r.stderr.replace("docker's", "")  # never reached docker compose
