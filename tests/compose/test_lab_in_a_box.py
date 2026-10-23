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
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "compose" / "lab-in-a-box"
COMPOSE = LAB / "docker-compose.yml"
ENV_EXAMPLE = LAB / ".env.example"
WORKFLOW = ROOT / ".github" / "workflows" / "nightly.yml"
ONE_SHOT = {"catalog-migrate", "lab-init", "llm-gateway-keys"}  # health is their exit code
LOOPBACK = "127.0.0.1"  # no-raw-endpoint: allow test servers bind loopback only
RAM_BUDGET_MB = 3584  # 4 GB runner minus headroom for the OS and the docker daemon
STATUS_FIXTURES = ROOT / "tests" / "status" / "fixtures"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


NATS_CONF = LAB / "config" / "nats" / "nats.conf"
_NATS_VAR = re.compile(r"(?<![\w\"])\$([A-Z][A-Z0-9_]*)")


def _nats_body(text: str) -> str:
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def nats_vars(text: str) -> set[str]:
    """The ``$VAR`` references of a NATS config (outside comments and strings)."""
    return set(_NATS_VAR.findall(_nats_body(text)))


def parse_nats_conf(text: str):
    """The lab's NATS config (the JSON subset of its syntax, ``$VAR`` references and ``#``
    comment lines): what the server reads, for the tests (``nats-server -t`` agrees, see
    tests/compose/test_lab_in_a_box.py's live test)."""
    return json.loads(_NATS_VAR.sub(r'"$\1"', _nats_body(text)))


def nats_users() -> dict[str, dict]:
    """Every NATS user of the lab by name, with its ``account``."""
    conf = parse_nats_conf(NATS_CONF.read_text())
    return {
        u["user"]: {**u, "account": name}
        for name, account in conf["accounts"].items()
        for u in account.get("users", [])
    }


def nats_allowed(user: dict, direction: str, subject: str) -> bool:
    """Does ``user`` (a :func:`nats_users` entry) may ``direction`` (publish / subscribe) on
    ``subject``: allow-list semantics, deny wins; a user with no permissions may do anything in
    its own account."""
    from conformance.fakes.jetstream_wire import subject_matches

    perms = (user.get("permissions") or {}).get(direction)
    if perms is None:
        return "permissions" not in user
    if any(subject_matches(p, subject) for p in perms.get("deny", [])):
        return False
    return any(subject_matches(p, subject) for p in perms.get("allow", []))


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
    dockerfiles = sorted(LAB.glob("*/Dockerfile"))
    assert {d.parent.name for d in dockerfiles} >= {"fakes", "broker"}
    for dockerfile in dockerfiles:
        froms = [line for line in dockerfile.read_text().splitlines() if line.startswith("FROM ")]
        assert froms, dockerfile
        for line in froms:
            assert re.search(r"@sha256:[0-9a-f]{64}$", line), (dockerfile, line)


def mem_total(compose, profiled: bool = False) -> int:
    """The mem_limit sum of the default stack, or (``profiled``) of the optional profiles.

    A service under ``profiles:`` is not started by ``docker compose up`` (or smoke.sh, or the
    nightly), so it does not count against the 4 GB default budget; it has its own total."""
    total = 0
    for name, svc in compose["services"].items():
        assert "mem_limit" in svc, f"{name} has no mem_limit"
        if bool(svc.get("profiles")) == profiled:
            total += mem_mb(svc["mem_limit"])
    return total


def test_memory_budget_fits_four_gigabytes(compose):
    total = mem_total(compose)
    assert total <= RAM_BUDGET_MB, f"sum of mem_limit is {total} MB"


def test_the_documented_memory_total_is_the_real_one(compose):
    # the header states the sum, so a reader sees the headroom left; keep it true
    stated = re.search(r"mem_limit values sum to (\d+) MB of the (\d+) MB", COMPOSE.read_text())
    assert stated, "docker-compose.yml no longer states its memory total"
    assert (int(stated[1]), int(stated[2])) == (mem_total(compose), RAM_BUDGET_MB)
    broken = json.loads(json.dumps(compose))
    broken["services"]["metrics"]["mem_limit"] = "1g"  # what a silent bump would look like
    assert mem_total(broken) != int(stated[1])


GATEWAY_PROFILES = {"gateway", "gateway-bifrost"}


def test_only_the_gateway_services_are_optional(compose):
    # a profile is how a service leaves the default budget: only the documented ones may
    profiled = {n: set(s["profiles"]) for n, s in compose["services"].items() if s.get("profiles")}
    assert profiled, "the gateway profiles are gone"
    for name, profiles in profiled.items():
        assert profiles <= GATEWAY_PROFILES, f"{name}: undocumented profile(s) {profiles}"
        assert name.startswith("llm-gateway"), f"{name} left the default budget via a profile"


def test_the_documented_gateway_memory_total_is_the_real_one(compose):
    stated = re.search(r"gateway profiles' mem_limit values sum to (\d+) MB", COMPOSE.read_text())
    assert stated, "docker-compose.yml no longer states the gateway profiles' memory total"
    assert int(stated[1]) == mem_total(compose, profiled=True)


GATEWAY_DOC = ROOT / "docs" / "llm-gateway.md"
RUNNER_MB = 4096  # the 4 GB runner the gateway-only path is documented to fit


def started(compose, names) -> set[str]:
    """What `docker compose up NAMES` starts: the named services and their depends_on closure."""
    todo, seen = list(names), set()
    while todo:
        name = todo.pop()
        if name in seen:
            continue
        seen.add(name)
        deps = compose["services"][name].get("depends_on") or {}
        todo += list(deps if isinstance(deps, dict | list) else [])
    return seen


def documented_gateway_path() -> tuple[list[str], int]:
    text = GATEWAY_DOC.read_text()
    up = re.search(r"--profile gateway up -d --build --wait ([\w -]+)\n", text)
    total = re.search(r"what it depends on \(postgres, the fake inference\): (\d+) MB", text)
    assert up and total, "docs/llm-gateway.md no longer shows the gateway-only command and total"
    return up[1].split(), int(total[1])


def test_the_documented_gateway_only_path_fits_the_runner(compose):
    names, stated = documented_gateway_path()
    assert names == ["llm-gateway", "llm-gateway-keys"]
    closure = started(compose, names)
    assert closure == {"llm-gateway", "llm-gateway-keys", "postgres", "inference"}
    total = sum(mem_mb(compose["services"][n]["mem_limit"]) for n in closure)
    assert total == stated, f"docs say {stated} MB, the closure's mem_limit sum is {total} MB"
    assert total <= RUNNER_MB


def test_negative_a_new_gateway_dependency_is_counted(compose):
    broken = json.loads(json.dumps(compose))
    broken["services"]["llm-gateway"]["depends_on"]["lake-query"] = {"condition": "service_healthy"}
    closure = started(broken, ["llm-gateway", "llm-gateway-keys"])
    assert {"lake-query", "lab-init", "object-store"} <= closure  # pulled in transitively
    _, stated = documented_gateway_path()
    assert sum(mem_mb(broken["services"][n]["mem_limit"]) for n in closure) != stated


def test_negative_an_unprofiled_service_counts_against_the_default_budget(compose):
    # moving a gateway service out of its profile must show up in the 4 GB budget
    broken = json.loads(json.dumps(compose))
    del broken["services"]["llm-gateway"]["profiles"]
    assert mem_total(broken) == mem_total(compose) + mem_mb(
        compose["services"]["llm-gateway"]["mem_limit"]
    )
    assert mem_total(broken) > RAM_BUDGET_MB


PG_INIT = LAB / "config" / "postgres" / "init" / "10-litellm.sh"


def gateway_db_problems(compose, init_sql: str) -> list[str]:
    """LiteLLM must reach postgres as its own role, owning only its own schema, never as ``lab``
    (the superuser that owns the lake catalog's tables)."""
    problems = []
    url = compose["services"]["llm-gateway"]["environment"]["HNX_SECRET_LLM_GATEWAY_DATABASE_URL"]
    m = re.match(r"postgresql://([^:]+):\$\{([A-Z_]+)[:?].*@[^/]+/catalog\?schema=(\w+)$", url)
    if not m:
        return [f"unexpected database URL shape: {url}"]
    user, var, schema = m.groups()
    if user != "litellm" or schema != "litellm":
        problems.append(f"LiteLLM connects as {user!r} to schema {schema!r}, not litellm/litellm")
    if var == "LAB_POSTGRES_PASSWORD":
        problems.append("LiteLLM uses the lab superuser's password")
    pg = compose["services"]["postgres"]
    if var not in pg.get("environment", {}):
        problems.append(f"postgres does not get {var}, so the init script cannot set it")
    if "./config/postgres/init:/docker-entrypoint-initdb.d:ro" not in pg.get("volumes", []):
        problems.append("postgres does not mount the init scripts")
    for words in (
        "CREATE ROLE litellm LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE",
        "CREATE SCHEMA litellm AUTHORIZATION litellm",
        "REVOKE CREATE ON SCHEMA public FROM litellm",
        f'"${var}"',
    ):
        if words not in init_sql:
            problems.append(f"the init script lacks {words!r}")
    return problems


def test_the_gateway_has_its_own_database_role(compose):
    assert gateway_db_problems(compose, PG_INIT.read_text()) == []
    assert PG_INIT.stat().st_mode & 0o111, "the postgres entrypoint runs only executable .sh files"


def test_negative_the_gateway_on_the_lab_superuser_is_caught(compose):
    broken = json.loads(json.dumps(compose))
    env = broken["services"]["llm-gateway"]["environment"]
    env["HNX_SECRET_LLM_GATEWAY_DATABASE_URL"] = (
        "postgresql://lab:${LAB_POSTGRES_PASSWORD:?x}@postgres.svc.example.internal:5432"
        "/catalog?schema=litellm"
    )
    problems = gateway_db_problems(broken, PG_INIT.read_text())
    assert "LiteLLM connects as 'lab' to schema 'litellm', not litellm/litellm" in problems
    assert "LiteLLM uses the lab superuser's password" in problems
    assert gateway_db_problems(compose, "") != []  # an init script that creates nothing


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
        "inference",
        "cases",
        "metrics",
        "uptime",
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
    assert {
        "object-store", "lake-catalog", "lake-query", "events", "secrets", "notify", "metrics",
        "uptime", "uptime-init",
    } <= set(rendered["services"])  # fmt: skip


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


# a fake Uptime Kuma 1.23 behind provision.js's client interface: the socket.io events it uses
# (needSetup, setup, login, add, addStatusPage, saveStatusPage) and the lists Kuma sends after a
# login; addStatusPage refuses a slug that exists, as Kuma's unique index does
_FAKE_KUMA = r"""
const { provision } = require(process.argv[1]);
const state = { setup: true, monitors: {}, pages: {}, next: 1, calls: [] };
const kuma = {
    async call(event, ...args) {
        state.calls.push(event);
        switch (event) {
        case "needSetup": return state.setup;
        case "setup": state.setup = false; return { ok: true };
        case "login": return { ok: !state.setup };
        case "add": {
            const id = state.next++;
            state.monitors[id] = { id, name: args[0].name, url: args[0].url };
            return { ok: true, monitorID: id };
        }
        case "addStatusPage":
            if (Object.values(state.pages).some((p) => p.slug === args[1])) {
                return { ok: false, msg: "slug already exists" };
            }
            state.pages[state.next] = { id: state.next++, slug: args[1], title: args[0] };
            return { ok: true };
        case "saveStatusPage": return { ok: true };
        default: return { ok: false, msg: `unknown event ${event}` };
        }
    },
    async lists() { return JSON.parse(JSON.stringify({ monitors: state.monitors, pages: state.pages })); },
    async waitBeats() {},
};
const opts = { username: "lab", password: "fake-kuma-password", slug: "lab",
    upURL: "http://up.example.invalid/-/healthy",
    downURL: "http://down.example.invalid/" };
(async () => {
    const runs = [];
    for (let i = 0; i < 2; i++) {
        state.calls = [];
        const out = await provision(kuma, opts);
        runs.push({ calls: state.calls, out });
    }
    console.log(JSON.stringify({ runs, monitors: Object.keys(state.monitors).length,
        pages: Object.keys(state.pages).length }));
})().catch((e) => { console.error(e.message); process.exit(1); });
"""


@pytest.mark.skipif(shutil.which("node") is None, reason="needs node")
def test_uptime_kuma_provisioning_is_idempotent():
    """Regression: a re-run on a persisted volume added both monitors again and failed on the
    existing status-page slug.  Run twice against a fake Kuma, the second run creates nothing.
    (The real socket.io API -- that Kuma sends monitorList and statusPageList after a login --
    is only exercised by the nightly lab smoke.)"""
    script = str(LAB / "config" / "uptime-kuma" / "provision.js")
    res = subprocess.run(
        ["node", "-e", _FAKE_KUMA, script], capture_output=True, text=True, timeout=60, check=False
    )
    assert res.returncode == 0, res.stderr
    out = json.loads(res.stdout)
    first, second = out["runs"]
    assert first["calls"].count("add") == 2 and "addStatusPage" in first["calls"]
    assert "add" not in second["calls"] and "addStatusPage" not in second["calls"]
    assert second["calls"][-1] == "saveStatusPage" and second["out"]["created"] == []
    assert second["out"]["monitors"] == first["out"]["monitors"]
    assert (out["monitors"], out["pages"]) == (2, 1)


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


class FixtureHandler(BaseHTTPRequestHandler):
    """Serves the status hub's recorded Prometheus and Uptime Kuma responses by path."""

    ROUTES: ClassVar[dict[str, str]] = {
        "/api/v1/alerts": "prometheus-alerts",
        "/api/v1/query": "prometheus-query-up",
        "/api/status-page/lab": "uptime-kuma-status-page",
        "/api/status-page/heartbeat/lab": "uptime-kuma-heartbeat",
    }

    def do_GET(self):
        name = self.ROUTES.get(self.path.split("?", 1)[0])
        body = (STATUS_FIXTURES / f"{name}.json").read_bytes() if name else b""
        self.send_response(200 if name else 404)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def product_server():
    httpd = ThreadingHTTPServer((LOOPBACK, 0), FixtureHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://{LOOPBACK}:{httpd.server_address[1]}"
    httpd.shutdown()
    httpd.server_close()


def test_metrics_and_uptime_checks_poll_through_the_real_collectors(checks, product_server):
    bases = {"metrics": product_server, "uptime": product_server}
    results = checks.run_checks(bases, only=["metrics", "uptime"], retries=1)
    assert [r["status"] for r in results] == ["pass", "pass"], results
    assert "collector" in results[0]["detail"] and "collector" in results[1]["detail"]


def test_metrics_and_uptime_checks_fail_on_the_wrong_reading(checks, product_server, monkeypatch):
    # the down monitor reads ok and a critical alert is gone: both checks must notice
    monkeypatch.setitem(
        FixtureHandler.ROUTES, "/api/status-page/heartbeat/lab", "uptime-kuma-heartbeat-all-up"
    )
    monkeypatch.setitem(FixtureHandler.ROUTES, "/api/v1/alerts", "prometheus-query-error")
    bases = {"metrics": product_server, "uptime": product_server}
    results = checks.run_checks(bases, only=["metrics", "uptime"], retries=1)
    assert [r["status"] for r in results] == ["fail", "fail"], results
    dead = checks.run_checks({"uptime": f"http://{LOOPBACK}:9"}, only=["uptime"], retries=1)
    assert dead[0]["status"] == "fail" and "Connection refused" in dead[0]["detail"]


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


def _report_cmd(doc: dict, rc: int = 0) -> str:
    """A stand-in for the docker exec: prints ``doc`` as the scenario's JSON report."""
    code = f"import json, sys; print(json.dumps({doc!r})); sys.exit({rc})"
    return json.dumps([sys.executable, "-c", code])


def test_broker_check_passes_only_when_every_scenario_step_did(checks):
    good = {"ok": True, "steps": [{"step": "mcp-tools", "ok": True, "detail": "x"},
                                  {"step": "audit", "ok": True, "detail": "y"}]}  # fmt: skip
    (result,) = checks.run_checks({"broker-e2e": _report_cmd(good)}, only=["broker"], retries=1)
    assert result["status"] == "pass", result
    assert result["detail"] == "2 steps passed: mcp-tools, audit"
    bad = {"ok": False, "steps": [{"step": "mcp-tools", "ok": True, "detail": "x"},
                                  {"step": "hub-approve", "ok": False, "detail": "HTTP 403"}]}  # fmt: skip
    (result,) = checks.run_checks({"broker-e2e": _report_cmd(bad, 1)}, only=["broker"], retries=1)
    assert result["status"] == "fail"
    assert "step hub-approve: HTTP 403 (passed: mcp-tools)" in result["detail"]
    for broken in (json.dumps([sys.executable, "-c", "print('not json')"]), _report_cmd(good, 1)):
        (result,) = checks.run_checks({"broker-e2e": broken}, only=["broker"], retries=1)
        assert result["status"] == "fail", broken
    (result,) = checks.run_checks({}, only=["broker"], retries=1)
    assert result["status"] == "fail" and "broker-e2e" in result["detail"]


def test_smoke_script_runs_the_broker_scenario_in_the_edge_container():
    text = (LAB / "smoke.sh").read_text()
    exported = text.index("export LAB_BROKER_E2E")
    assert "exec -T broker-edge" in text[:exported]
    assert "broker_e2e.py run --json" in text[:exported]
    assert exported < text.index('smoke_checks.py" --report')


def test_broker_services_are_three_users_on_one_socket(compose, env_vars):
    e2e = load_module("broker_e2e", LAB / "broker_e2e.py")
    svc = compose["services"]
    broker, hub, edge = svc["broker"], svc["status-hub"], svc["broker-edge"]
    # the broker: its own user, no network at all, nothing published anywhere
    assert broker["user"] == "10010:10010" and broker["network_mode"] == "none"
    assert str(e2e.LAB_CLIENTS_GID) in broker["group_add"]
    assert "manifest.production.yml" in " ".join(broker["command"])
    for s in (broker, hub, edge):
        assert "ports" not in s
        assert "broker-run:/run/hnx-broker" in s["volumes"]
    # the hub is the manifest's relay user, the edge reaches it by its alias
    assert hub["user"] == f"{e2e.LAB_UIDS['relay']}:{e2e.LAB_UIDS['relay']}"
    assert "status-hub.svc.example.internal" in hub["networks"]["lab"]["aliases"]
    assert e2e.LAB_HUB.startswith("http://status-hub.svc.example.internal:")
    # the edge: root with only what it needs to start peers as their uids; the data root read-only
    assert edge["user"] == "0:0" and sorted(edge["cap_add"]) == ["SETGID", "SETUID"]
    assert "broker-data:/srv/agents:ro" in edge["volumes"]
    assert edge["networks"]["lab"]["ipv4_address"] == "${LAB_BROKER_EDGE_ADDRESS:?see .env.example}"
    import ipaddress

    edge_ip = ipaddress.ip_address(env_vars["LAB_BROKER_EDGE_ADDRESS"])
    assert edge_ip in ipaddress.ip_network(env_vars["LAB_SUBNET"])
    # the uids the scenario expects are the users the image creates and the manifest maps
    dockerfile = (LAB / "broker" / "Dockerfile").read_text()
    manifest = yaml.safe_load((ROOT / "examples/broker/manifest.production.yml").read_text())
    users = {"agent": "hnx-agent-triage", "relay": "hnx-hub"}
    for role, user in users.items():
        assert f"--uid {e2e.LAB_UIDS[role]} " in dockerfile and dockerfile.count(user) >= 1
    assert f"--uid {e2e.LAB_UIDS['stranger']} " not in dockerfile  # nobody's uid
    assert {"user": users["agent"], "profile": "profile:triage"} in manifest["callers"]
    assert {"user": users["relay"], "issuer": "sso"} in manifest["approval_relays"]


def test_the_broker_relay_publishes_from_the_edge_as_its_own_user(compose):
    """The bus-relay step: the broker keeps no network; the edge runs ``hnx broker relay`` as the
    relay's own uid, which sees the broker's outbox read-only and its own relay directory, never
    the rest of the broker's state, against the events service, with nats-py."""
    e2e = load_module("broker_e2e", LAB / "broker_e2e.py")
    from homelabnext.broker.relay import BROKER_SOURCE

    svc = compose["services"]
    broker, edge = svc["broker"], svc["broker-edge"]
    state_mount = f"broker-state:{Path(e2e.LAB_STATE).parent}"
    outbox, relay_dir = f"{e2e.LAB_STATE}/outbox", f"{e2e.LAB_STATE}/relay"
    assert broker["network_mode"] == "none" and state_mount in broker["volumes"]
    assert f"broker-outbox:{outbox}" in broker["volumes"]
    assert any(v.startswith(f"broker-relay:{relay_dir}:ro") for v in broker["volumes"])
    # the edge (root, SETUID) holds no handle on approvals/, claims/, audit/ or the digest key
    assert not any(v.startswith("broker-state:") for v in edge["volumes"])
    assert f"broker-outbox:{outbox}:ro" in edge["volumes"]
    assert f"broker-relay:{relay_dir}" in edge["volumes"]
    assert {"broker-state", "broker-outbox", "broker-relay"} <= set(compose["volumes"])
    assert e2e.LAB_RELAY_UID != e2e.LAB_BROKER_UID
    assert e2e.relay_launch()[-3:] == ["as", f"{e2e.LAB_RELAY_UID}:{e2e.LAB_RELAY_UID}", "--"]
    env = edge["environment"]
    assert env["HNX_ENDPOINT_EVENTS"].startswith("nats://events.svc.example.internal:")
    assert "events.svc.example.internal" in svc["events"]["networks"]["lab"]["aliases"]
    assert edge["depends_on"]["events"]["condition"] == "service_healthy"
    target = env["LAB_BROKER_EVENTS_TARGET"]
    assert target == e2e.LAB_EVENTS_TARGET
    local = ROOT / target.removeprefix("/src/")
    binding = yaml.safe_load(local.read_text())["capabilities"]["events"]
    assert binding["adapter"] == "homelabnext.conform.adapters.nats_jetstream:make"
    # the relay connects as the broker's NATS user, with only that password in its process
    from homelabnext.registry.model import secret_env_name

    assert binding["config"]["user"] == "hnx-broker"
    var = secret_env_name(binding["config"]["password_secret"])
    assert e2e.LAB_BUS_USERS["hnx-broker"] == var and var in env
    assert e2e.Relay("s", "t", "S", "p").secrets == (var,)
    assert set(e2e.LAB_BUS_USERS.values()) <= set(env)
    dockerfile = (LAB / "broker" / "Dockerfile").read_text()
    assert f"COPY {local.relative_to(ROOT)} {target}" in dockerfile
    assert "x['nats']" in dockerfile and f"--uid {e2e.LAB_BROKER_UID} " in dockerfile
    assert f"--uid {e2e.LAB_BROKER_UID} --gid {e2e.LAB_BROKER_UID} --no-create-home hnx-broker" in (
        dockerfile
    )
    assert broker["user"] == f"{e2e.LAB_BROKER_UID}:{e2e.LAB_BROKER_UID}"
    assert e2e.BROKER_SOURCE == BROKER_SOURCE


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
    "LAB_UPTIME_PASSWORD",
    "LAB_HUB_FRONT_DOOR_SECRET",
    "LAB_BROKER_DEMO_TOKEN",
    "LAB_GATEWAY_MASTER_KEY",
    "LAB_GATEWAY_DB_PASSWORD",
    "LAB_GATEWAY_SALT_KEY",
    "LAB_GATEWAY_KEY_READER",
    "LAB_GATEWAY_KEY_RESPONDER",
    "LAB_GATEWAY_KEY_THROTTLE",
    "LAB_GATEWAY_BIFROST_ADMIN_PASSWORD",
    "LAB_EVENTS_BROKER_PASSWORD",
    "LAB_EVENTS_ST2_BRIDGE_PASSWORD",
    "LAB_EVENTS_ADMIN_PASSWORD",
    "LAB_EVENTS_CONFORMANCE_PASSWORD",
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


def guard(lab, tmp_path, docker=False, **env):
    """Run the guard with a PATH of only dirname and mkdir, or (``docker=True``) with docker and
    python3 too, so its second pass can resolve the compose configuration."""
    tools = ("dirname", "mkdir", "docker", "python3") if docker else ("dirname", "mkdir")
    base = {"PATH": stub_path(tmp_path, tools)}
    if docker and "HOME" in os.environ:
        base["HOME"] = os.environ["HOME"]  # the docker CLI looks for its plugins there
    return subprocess.run(
        [shutil.which("bash"), str(lab / "bind_guard.sh")],
        env={**base, **env},
        capture_output=True,
        text=True,
    )


def real_credentials():
    return {k: f"changed-{k.lower()}" for k in CREDENTIALS}


@needs_docker
@pytest.mark.parametrize("bind", [LOOPBACK, OTHER_LOOPBACK, "::1", "[::1]", ""])
def test_guard_allows_loopback(lab_copy, tmp_path, bind):
    r = guard(lab_copy, tmp_path, docker=True, LAB_BIND=bind)
    assert r.returncode == 0, r.stderr


@needs_docker
def test_guard_allows_the_shipped_defaults(lab_copy, tmp_path):
    r = guard(lab_copy, tmp_path, docker=True)
    assert r.returncode == 0, r.stderr


def test_guard_fails_closed_when_it_cannot_resolve_the_configuration(lab_copy, tmp_path):
    # the first pass is happy (loopback), but without docker compose the resolved configuration
    # cannot be judged: exit 3, never a pass
    r = guard(lab_copy, tmp_path)
    assert r.returncode == 3, r.stderr
    assert "cannot resolve the compose configuration" in r.stderr


@pytest.mark.parametrize(
    "line",
    [
        "export LAB_BIND=0.0.0.0",
        "LAB_BIND = 0.0.0.0",
        "LAB_BIND =0.0.0.0",
        "  LAB_BIND=0.0.0.0",
        "\tLAB_BIND=0.0.0.0",
        "LAB_BIND: 0.0.0.0",
    ],
)
def test_guard_refuses_a_dotenv_line_it_cannot_read(lab_copy, tmp_path, line):
    # docker compose applies every one of these forms; a guard that skipped them fell back to the
    # .env.example default (loopback) while compose published on all interfaces
    (lab_copy / ".env").write_text(f"# a comment\n\n{line}\n")
    r = guard(lab_copy, tmp_path)
    assert r.returncode == 4, r.stderr
    assert "line 3 is not a plain KEY=value line" in r.stderr


@needs_docker
@pytest.mark.parametrize(
    "line",
    ["export LAB_BIND=0.0.0.0", "LAB_BIND = 0.0.0.0", "  LAB_BIND=0.0.0.0", "LAB_BIND: 0.0.0.0"],
)
def test_docker_compose_applies_the_lines_the_guard_refuses(lab_copy, line):
    """Why the first pass refuses them: compose resolves each to a published 0.0.0.0."""
    (lab_copy / ".env").write_text(line + "\n")
    proc = subprocess.run(
        ["docker", "compose", "--env-file", str(lab_copy / ".env.example"), "--env-file",
         str(lab_copy / ".env"), "-f", str(lab_copy / "docker-compose.yml"), "config",
         "--format", "json"],
        capture_output=True, text=True, timeout=120,
        env={k: v for k, v in os.environ.items() if not k.startswith("LAB_")},
    )  # fmt: skip
    assert proc.returncode == 0, proc.stderr
    ips = {p.get("host_ip") for s in json.loads(proc.stdout)["services"].values()
           for p in s.get("ports", [])}  # fmt: skip
    assert "0.0.0.0" in ips


@needs_docker
def test_guard_judges_the_ports_compose_resolves(lab_copy, tmp_path):
    # LAB_BIND stays on loopback, but the compose file publishes one port on every interface
    compose = lab_copy / "docker-compose.yml"
    text = compose.read_text()
    port = '"${LAB_BIND:-' + LOOPBACK + "}:${LAB_PORT_SECRETS"
    assert port in text
    compose.write_text(text.replace(port, '"0.0.0.0:${LAB_PORT_SECRETS', 1))
    r = guard(lab_copy, tmp_path, docker=True)
    assert r.returncode == 4, r.stderr
    assert "secrets 0.0.0.0:" in r.stderr and "LAB_I_UNDERSTAND_UNAUTHENTICATED" in r.stderr


@needs_docker
def test_guard_judges_the_credentials_compose_resolves(lab_copy, tmp_path):
    # every credential looks changed in .env, but one interpolates to its placeholder
    placeholder = dict(
        line.split("=", 1)
        for line in ENV_EXAMPLE.read_text().splitlines()
        if line.startswith("LAB_SECRETS_DEV_TOKEN=")
    )["LAB_SECRETS_DEV_TOKEN"].split()[0]
    creds = real_credentials()
    creds["LAB_SECRETS_DEV_TOKEN"] = "${HNX_TEST_TOKEN_SOURCE}"
    lines = [f"{k}={v}" for k, v in creds.items()]
    (lab_copy / ".env").write_text(
        "LAB_BIND=0.0.0.0\nLAB_I_UNDERSTAND_UNAUTHENTICATED=1\n" + "\n".join(lines) + "\n"
    )
    r = guard(lab_copy, tmp_path, docker=True, HNX_TEST_TOKEN_SOURCE=placeholder)
    assert r.returncode == 4, r.stderr
    assert "resolve to their .env.example placeholder: LAB_SECRETS_DEV_TOKEN" in r.stderr
    r = guard(lab_copy, tmp_path, docker=True, HNX_TEST_TOKEN_SOURCE="changed-token")
    assert r.returncode == 0, r.stderr


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


@needs_docker
def test_guard_allows_a_non_loopback_bind_once_acknowledged_and_changed(lab_copy, tmp_path):
    r = guard(
        lab_copy,
        tmp_path,
        docker=True,
        LAB_BIND="0.0.0.0",
        LAB_I_UNDERSTAND_UNAUTHENTICATED="1",
        **real_credentials(),
    )
    assert r.returncode == 0, r.stderr
    assert "WARNING" in r.stderr


@needs_docker
def test_guard_reads_dot_env_and_the_environment_wins_over_it(lab_copy, tmp_path):
    lines = [f"{k}={v}" for k, v in real_credentials().items()]
    (lab_copy / ".env").write_text(
        "LAB_BIND=0.0.0.0  # all interfaces\nLAB_I_UNDERSTAND_UNAUTHENTICATED=1\n"
        + "\n".join(lines)
        + "\n"
    )
    assert guard(lab_copy, tmp_path, docker=True).returncode == 0
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
    assert guard(lab_copy, tmp_path, docker=True, LAB_BIND=LOOPBACK).returncode == 0


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
    # no docker here: the guard's first pass only (its second pass would exit 3 without docker)
    assert probe.count("lab_bind_guard\n") == 1
    probe = probe.replace("lab_bind_guard\n", "_lab_bind_guard_values\n", 1)
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


def test_the_relays_user_and_directories_keep_the_broker_state_private():
    """The image's modes: the relay may traverse the state directory and read outbox/ through its
    group, owns relay/; nothing else of the broker's state is open to it."""
    e2e = load_module("broker_e2e", LAB / "broker_e2e.py")
    dockerfile = (LAB / "broker" / "Dockerfile").read_text()
    uid = e2e.LAB_RELAY_UID
    assert f"--uid {uid} --gid {uid} --no-create-home hnx-broker-relay" in dockerfile
    state = e2e.LAB_STATE
    want = {
        "/var/lib/hnx-broker": "-o hnx-broker -g hnx-broker-relay -m 0710",
        state: "-o hnx-broker -g hnx-broker-relay -m 0710",
        f"{state}/outbox": "-o hnx-broker -g hnx-broker-relay -m 2750",
        f"{state}/relay": "-o hnx-broker-relay -g hnx-broker -m 2750",
    }
    for path, flags in want.items():
        assert f"install -d {flags} {path} " in dockerfile, path
    assert dockerfile.count("hnx-broker-relay -m") == 3  # nothing else is the relay's group's


# ---------------------------------------------------------------- the events service's ACL
def test_the_events_service_requires_a_user_and_reads_the_lab_config(compose, env_vars):
    events = compose["services"]["events"]
    assert events["command"] == ["-c", "/etc/nats/nats.conf"]
    assert "./config/nats/nats.conf:/etc/nats/nats.conf:ro" in events["volumes"]
    conf = parse_nats_conf(NATS_CONF.read_text())
    assert "authorization" not in conf and "no_auth_user" not in str(conf)  # no anonymous user
    variables = nats_vars(NATS_CONF.read_text())
    assert variables == set(events["environment"])
    for var in variables:
        assert events["environment"][var] == f"${{{var}:?see .env.example}}"
        assert "fake" in env_vars[var]
    users = nats_users()
    assert {u: v["account"] for u, v in users.items()} == {
        "hnx-broker": "HNX",
        "hnx-st2-bridge": "HNX",
        "hnx-lab-admin": "HNX",
        "hnx-conformance": "CONFORM",
    }


@pytest.mark.parametrize("kind", ["decision.returned", "decision.requested", "proposal.created"])
def test_only_the_broker_may_publish_the_brokers_subjects(kind):
    e2e = load_module("broker_e2e", LAB / "broker_e2e.py")
    subject = f"{e2e.LAB_EVENTS_PREFIX}.homelabnext.{kind}"
    hnx = {n: u for n, u in nats_users().items() if u["account"] == "HNX"}
    assert [n for n, u in hnx.items() if nats_allowed(u, "publish", subject)] == ["hnx-broker"]
    broker = hnx["hnx-broker"]
    other = f"{e2e.LAB_EVENTS_PREFIX}.homelabnext.agent.job.failed"
    assert not nats_allowed(broker, "publish", other)


def test_nobody_but_the_controller_may_publish_agent_job_events():
    """SEC6: agent.job.failed is what A02 resubmits on; only the orchestration controller's user
    may publish it, and the lab runs no controller, so no lab user may."""
    e2e = load_module("broker_e2e", LAB / "broker_e2e.py")
    for kind in ("failed", "other"):
        subject = f"{e2e.LAB_EVENTS_PREFIX}.homelabnext.agent.job.{kind}"
        allowed = [n for n, u in nats_users().items()
                   if u["account"] == "HNX" and nats_allowed(u, "publish", subject)]  # fmt: skip
        assert allowed == [], subject


def test_the_conformance_account_has_its_own_jetstream_limits():
    """SEC7: CONFORM's scratch streams are bounded by account limits, below the server's store,
    so leftovers of failed conformance runs cannot starve the HNX account."""
    conf = parse_nats_conf(NATS_CONF.read_text())
    server = conf["jetstream"]
    limits = conf["accounts"]["CONFORM"]["jetstream"]
    assert isinstance(limits, dict), "CONFORM's jetstream is 'enabled' with no limits"
    assert 0 < limits["max_mem"] < server["max_memory_store"]
    assert 0 < limits["max_file"] < server["max_file_store"]
    assert limits["max_streams"] > 0 and limits["max_consumers"] > 0


def test_no_user_may_purge_rewrite_or_read_another_users_inbox():
    e2e = load_module("broker_e2e", LAB / "broker_e2e.py")
    stream = e2e.LAB_EVENTS_STREAM
    hnx = {n: u for n, u in nats_users().items() if u["account"] == "HNX"}
    for name, user in hnx.items():
        assert "permissions" in user, name  # an allow-list for everyone in HNX
        for what in ("STREAM.PURGE", "STREAM.UPDATE", "STREAM.DELETE", "STREAM.MSG.DELETE",
                     "CONSUMER.DELETE"):  # fmt: skip
            assert not nats_allowed(user, "publish", f"$JS.API.{what}.{stream}"), (name, what)
        subs = user["permissions"]["subscribe"]["allow"]
        assert subs == [f"_INBOX.{name}.>"], name
        for other in hnx:
            if other != name:
                assert not nats_allowed(user, "subscribe", f"_INBOX.{other}.x.y"), (name, other)
    # the bridge reads its own durables only, and creates no stream
    bridge = hnx["hnx-st2-bridge"]
    bridge_json = json.loads((ROOT / "workflows" / "stackstorm" / "bridge.json").read_text())
    prefix = e2e.LAB_EVENTS_PREFIX
    for sub in bridge_json["subscriptions"]:
        d = sub["durable"]
        for what in ("INFO", "MSG.NEXT"):
            assert nats_allowed(bridge, "publish", f"$JS.API.CONSUMER.{what}.{stream}.{d}")
        # only the filtered create (nats 2.9+): the server holds the request to that filter
        create = f"$JS.API.CONSUMER.CREATE.{stream}.{d}"
        assert nats_allowed(bridge, "publish", f"{create}.{prefix}.{sub['subject']}")
        assert not nats_allowed(bridge, "publish", create)  # any filter, any shape
        assert not nats_allowed(bridge, "publish", f"{create}.{prefix}.homelabnext.other")
        assert nats_allowed(bridge, "publish", f"$JS.ACK.{stream}.{d}.1.2.3.4.5")
    assert not nats_allowed(bridge, "publish", f"$JS.API.CONSUMER.CREATE.{stream}.other")
    assert not nats_allowed(bridge, "publish", f"$JS.API.STREAM.CREATE.{stream}")
    assert not nats_allowed(hnx["hnx-broker"], "publish", f"$JS.API.STREAM.CREATE.{stream}")


def test_negative_a_wildcard_grant_would_be_caught():
    broken = {"user": "x", "permissions": {"publish": {"allow": ["$JS.API.>", "hnxlab.>"]},
                                           "subscribe": {"allow": ["_INBOX.>"]}}}  # fmt: skip
    assert nats_allowed(broken, "publish", "$JS.API.STREAM.PURGE.HNXLAB_BROKER")
    assert nats_allowed(broken, "publish", "hnxlab.homelabnext.decision.returned")
    assert nats_allowed(broken, "subscribe", "_INBOX.hnx-broker.x.y")


def _doc_excerpts(path: Path) -> list:
    """The ```text blocks of ``path`` that quote the lab's nats.conf (a JSON list of users)."""
    blocks = re.findall(r"```text\n(# compose/lab-in-a-box/config/nats/nats\.conf.*?)```",
                        path.read_text(), re.S)  # fmt: skip
    return [parse_nats_conf(b) for b in blocks]


@pytest.mark.parametrize("doc", ["broker.md", "stackstorm.md"])
def test_the_docs_acl_excerpts_are_exactly_what_the_lab_enforces(doc):
    [excerpt] = _doc_excerpts(ROOT / "docs" / doc)
    users = nats_users()
    assert excerpt and all(u == {k: v for k, v in users[u["user"]].items() if k != "account"}
                           for u in excerpt)  # fmt: skip
    if doc == "broker.md":
        assert {u["user"] for u in excerpt} == {"hnx-broker", "hnx-st2-bridge"}
    else:
        assert {u["user"] for u in excerpt} == {"hnx-st2-bridge"}


@pytest.mark.skipif(not shutil.which("nats-server"), reason="nats-server is not installed")
def test_nats_server_accepts_the_lab_config(tmp_path, env_vars):
    conf = tmp_path / "nats.conf"
    conf.write_text(NATS_CONF.read_text().replace('"/data"', json.dumps(str(tmp_path))))
    env = {**os.environ, **{v: env_vars[v] for v in nats_vars(conf.read_text())}}
    proc = subprocess.run(["nats-server", "-c", str(conf), "-t"], env=env, capture_output=True,
                          text=True, timeout=30)  # fmt: skip
    assert proc.returncode == 0, proc.stderr
