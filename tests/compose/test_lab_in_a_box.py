# SPDX-License-Identifier: Apache-2.0
"""The lab-in-a-box stack: static contract tests (no docker needed), a real ``docker compose
config`` validation when docker is present, and the smoke checks against the project's own fakes.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import shutil
import string
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar

import pytest
import yaml

from tests.suite_policy import require_tool

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


GATEWAY_PROFILES = {"gateway"}


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


UP_GATEWAY = r"up -d --build --wait (?:--wait-timeout \d+ )?([\w -]+)\n"
RUN_KEYS = r"run --rm --build (?:-T )?([\w -]+)\n"


def documented_gateway_path() -> tuple[list[str], list[str], int]:
    """The documented gateway-only path: what `up --wait` starts, what `run` runs in the foreground
    afterwards (the one-shot, whose exit code `up --wait` does not report), and the stated total."""
    text = GATEWAY_DOC.read_text()
    up = re.search(r"--profile gateway " + UP_GATEWAY, text)
    run = re.search(r"--profile gateway " + RUN_KEYS, text)
    total = re.search(r"then its keys one-shot:\n# (\d+) MB of mem_limit in all", text)
    assert up and run and total, "docs/llm-gateway.md no longer shows the gateway-only path"
    return up[1].split(), run[1].split(), int(total[1])


def test_the_documented_gateway_only_path_fits_the_runner(compose):
    up, run, stated = documented_gateway_path()
    assert up == ["llm-gateway"] and run == ["llm-gateway-keys"]
    closure = started(compose, up + run)
    assert closure == {"llm-gateway", "llm-gateway-keys", "postgres", "inference"}
    total = sum(mem_mb(compose["services"][n]["mem_limit"]) for n in closure)
    assert total == stated, f"docs say {stated} MB, the closure's mem_limit sum is {total} MB"
    assert total <= RUNNER_MB


GATEWAY_TARGET = "compose/lab-in-a-box/targets/inference-gateway.yml"
GATEWAY_CHECKS = (
    "gateway-rejects-bad-key",
    "gateway-limit-throttles",
    "gateway-models-match-roles",
)


def gateway_job() -> dict:
    return yaml.safe_load((WORKFLOW.parent / "ci.yml").read_text())["jobs"]["lab-gateway"]


def gateway_step(name_part: str) -> dict:
    (step,) = [s for s in gateway_job()["steps"] if name_part in s.get("name", "")]
    return step


def test_pull_requests_run_the_documented_gateway_only_path():
    """ci.yml's lab-gateway job brings up exactly the documented gateway-only path (so the 1280 MB
    it is budgeted at is what runs), provisions the keys in the foreground (their exit code fails
    the job), runs the inference suite against the gateway target, and always collects, tears down
    and uploads."""
    job = gateway_job()
    assert job["permissions"] == {"contents": "read"}
    assert job["defaults"] == {"run": {"shell": "bash"}}  # bash -eo pipefail, not bash -e
    assert job["env"] == {
        "COMPOSE_FILE": "compose/lab-in-a-box/docker-compose.yml",
        "COMPOSE_ENV_FILES": "compose/lab-in-a-box/.env.example",  # throwaway values, no secret
        "COMPOSE_PROFILES": "gateway",
    }
    steps = job["steps"]
    assert not any("shell" in s or "continue-on-error" in s for s in steps)
    runs = [s.get("run", "") for s in steps]
    up_doc, run_doc, _ = documented_gateway_path()
    (up_i,) = [i for i, r in enumerate(runs) if "docker compose up " in r]
    m = re.search(r"docker compose " + UP_GATEWAY, runs[up_i])
    assert m and m[1].split() == up_doc, runs[up_i]
    # the one-shot runs in the foreground as the whole step, so its exit code is the step's
    (keys_i,) = [i for i, r in enumerate(runs) if "llm-gateway-keys" in r]
    m = re.fullmatch(r"docker compose " + RUN_KEYS, runs[keys_i] + "\n")
    assert m and m[1].split() == run_doc, runs[keys_i]
    assert "if" not in steps[keys_i]
    (conform_i,) = [i for i, r in enumerate(runs) if "conform run inference" in r]
    assert f"--target {GATEWAY_TARGET}" in runs[conform_i]
    assert "HNX_SECRET_LLM_GATEWAY_KEY_CONFORMANCE_THROTTLE" in runs[conform_i]
    (verdict_i,) = [i for i, r in enumerate(runs) if all(c in r for c in GATEWAY_CHECKS)]
    assert up_i < keys_i < conform_i < verdict_i
    for i in (up_i, keys_i, conform_i, verdict_i):
        assert "if" not in steps[i], steps[i]["name"]
    suite = (ROOT / "conformance" / "suites" / "inference.py").read_text()
    assert all(f'"{c}"' in suite for c in GATEWAY_CHECKS)  # the names CI asserts are the suite's
    target = yaml.safe_load((ROOT / GATEWAY_TARGET).read_text())
    assert "gateway" in target["capabilities"]["inference"]["features"]
    # after the checks, whatever happened: collect, tear down (with volumes), upload
    collect = gateway_step("collect")
    down = gateway_step("tear")
    upload = gateway_step("upload")
    for step in (collect, down, upload):
        assert step["if"] == "always()", step["name"]
    assert "docker compose down --volumes" in down["run"]
    assert upload["with"]["path"] == "build/lab-gateway/"
    assert verdict_i < steps.index(collect) < steps.index(down) < steps.index(upload)


def _run_step(step: dict, tmp_path: Path, env: dict[str, str]) -> int:
    """Run a lab-gateway step's script the way the runner does under `shell: bash`."""
    summary = tmp_path / "summary.md"
    full = {**os.environ, **env, "GITHUB_STEP_SUMMARY": str(summary)}
    return subprocess.run(
        ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", step["run"]],
        cwd=tmp_path,
        env=full,
        capture_output=True,
        check=False,
    ).returncode


def _python_on_path(tmp_path: Path, script: str | None = None) -> dict[str, str]:
    """A PATH whose `python` is this interpreter (or a stand-in script)."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    py = bin_dir / "python"
    py.write_text(script or f'#!/bin/sh\nexec "{sys.executable}" "$@"\n')
    py.chmod(0o755)
    return {"PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}"}


def _result(**over) -> dict:
    run = {
        "verdict": "pass",
        "counts": {"executed": 12, "skipped": 5},
        "results": [{"check": c, "status": "pass"} for c in GATEWAY_CHECKS]
        + [{"check": "turn-records-are-neutral", "status": "skip"}],
    }
    run.update(over)
    return {"runs": [run]}


def _skipped(check: str) -> dict:
    res = _result()
    for r in res["runs"][0]["results"]:
        if r["check"] == check:
            r["status"] = "skip"
    return res


def _missing(check: str) -> dict:
    res = _result()
    res["runs"][0]["results"] = [r for r in res["runs"][0]["results"] if r["check"] != check]
    return res


def _renamed() -> dict:
    res = _result()
    res["runs"][0]["checks"] = res["runs"][0].pop("results")
    return res


@pytest.mark.parametrize(
    ("doc", "ok"),
    [
        (_result(), True),
        (_skipped("gateway-limit-throttles"), False),
        (_skipped("gateway-rejects-bad-key"), False),
        (_missing("gateway-models-match-roles"), False),
        (_result(verdict="fail"), False),
        ({"runs": [_result()["runs"][0], _result()["runs"][0]]}, False),  # two runs
        ({"runs": []}, False),
        (_renamed(), False),  # a renamed `results` key is no result, not a pass
        (None, False),  # no result file at all
    ],
)
def test_the_gateway_verdict_step_fails_unless_the_gateway_checks_passed(tmp_path, doc, ok):
    out = tmp_path / "build" / "lab-gateway"
    out.mkdir(parents=True)
    if doc is not None:
        (out / "conform-inference.json").write_text(json.dumps(doc))
    step = gateway_step("the gateway's own checks")
    assert (_run_step(step, tmp_path, _python_on_path(tmp_path)) == 0) is ok
    # the verdict (or the error) reaches the job summary either way
    assert (tmp_path / "summary.md").read_text().strip()


@pytest.mark.parametrize(("rc", "ok"), [(0, True), (1, False), (100, False)])
def test_the_gateway_conform_step_carries_the_suite_s_exit_code(tmp_path, rc, ok):
    (tmp_path / "build" / "lab-gateway").mkdir(parents=True)
    env_file = tmp_path / "compose" / "lab-in-a-box" / ".env.example"
    env_file.parent.mkdir(parents=True)
    env_file.write_text(ENV_EXAMPLE.read_text())
    stand_in = f"#!/bin/sh\necho 'a stand-in suite'\nexit {rc}\n"
    step = gateway_step("inference conformance")
    assert (_run_step(step, tmp_path, _python_on_path(tmp_path, stand_in)) == 0) is ok
    assert "stand-in suite" in (tmp_path / "build/lab-gateway/conform-inference.log").read_text()


def test_negative_a_new_gateway_dependency_is_counted(compose):
    broken = json.loads(json.dumps(compose))
    broken["services"]["llm-gateway"]["depends_on"]["lake-query"] = {"condition": "service_healthy"}
    closure = started(broken, ["llm-gateway", "llm-gateway-keys"])
    assert {"lake-query", "lab-init", "object-store"} <= closure  # pulled in transitively
    _, _, stated = documented_gateway_path()
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


def postgres_data_problems(compose) -> list[str]:
    """From 18 the official image keeps PGDATA at ``/var/lib/postgresql/<major>/docker`` and its
    VOLUME at ``/var/lib/postgresql``; its entrypoint refuses to start over a mount at the old
    ``/var/lib/postgresql/data``, and a volume there would leave the data in an anonymous one."""
    pg = compose["services"]["postgres"]
    m = re.match(r"postgres:(\d+)\.\d+-alpine@sha256:[0-9a-f]{64}$", pg["image"])
    if not m:
        return [f"unexpected postgres image: {pg['image']}"]
    major = int(m.group(1))
    data = [v for v in pg.get("volumes", []) if v.startswith("postgres-data:")]
    want = (
        "postgres-data:/var/lib/postgresql"
        if major >= 18
        else "postgres-data:/var/lib/postgresql/data"
    )
    if data != [want]:
        return [f"postgres {major} mounts its data volume as {data}, not [{want!r}]"]
    if major >= 18 and pg.get("environment", {}).get("PGDATA"):
        return ["PGDATA is overridden; the 18 image's default keeps pg_upgrade --link possible"]
    return []


def test_postgres_data_volume_matches_the_image_major(compose):
    assert postgres_data_problems(compose) == []


def test_negative_postgres_18_on_the_old_data_mount_is_caught(compose):
    broken = json.loads(json.dumps(compose))
    vols = broken["services"]["postgres"]["volumes"]
    vols[vols.index("postgres-data:/var/lib/postgresql")] = "postgres-data:/var/lib/postgresql/data"
    assert postgres_data_problems(broken) == [
        "postgres 18 mounts its data volume as ['postgres-data:/var/lib/postgresql/data'], "
        "not ['postgres-data:/var/lib/postgresql']"
    ]


def test_negative_postgres_18_with_pgdata_overridden_is_caught(compose):
    broken = json.loads(json.dumps(compose))
    broken["services"]["postgres"]["environment"]["PGDATA"] = "/var/lib/postgresql/data/pgdata"
    assert postgres_data_problems(broken) == [
        "PGDATA is overridden; the 18 image's default keeps pg_upgrade --link possible"
    ]


def test_postgres_is_healthy_only_over_tcp(compose):
    """The entrypoint's temporary init server listens on the unix socket only; a socket probe
    would mark postgres healthy (and start its dependants) while the init scripts still run."""
    test = compose["services"]["postgres"]["healthcheck"]["test"]
    assert test[0] == "CMD-SHELL" and f"pg_isready -h {LOOPBACK} " in test[1], test


def off_lab_network(compose) -> list[str]:
    """Services that would land on compose's implicit default network, where no lab alias
    (``*.svc.example.internal``) resolves: each joins ``lab`` or has no network at all."""
    return sorted(
        name
        for name, svc in compose["services"].items()
        if svc.get("network_mode") != "none" and "lab" not in (svc.get("networks") or [])
    )


def test_every_service_is_on_the_lab_network(compose):
    assert off_lab_network(compose) == []


def test_negative_a_service_without_networks_is_caught(compose):
    broken = json.loads(json.dumps(compose))
    del broken["services"]["llm-gateway-keys"]["networks"]
    assert off_lab_network(broken) == ["llm-gateway-keys"]


def test_trino_heap_is_tiny():
    heap = re.search(r"^-Xmx(\d+)M$", (LAB / "config/trino/jvm.config").read_text(), re.M)
    assert heap and int(heap[1]) <= 1024


# flags the metrics product's 3.0 removed and ones a later 3.x deprecated, whether given as
# `--flag=value` or as `--flag value`.  `--enable-feature` itself stays: 3.x still uses it (e.g.
# promql-experimental-functions for double_exponential_smoothing), so only its gone names count.
METRICS_GONE_FLAGS = {
    "--storage.tsdb.retention",
    "--storage.tsdb.retention.time",
    "--storage.tsdb.retention.size",
    "--storage.tsdb.allow-overlapping-blocks",
    "--alertmanager.timeout",
    "--log.level",
}
# --enable-feature names 2.55.1 read and 3.15.1 does not (3.0 made them defaults, dedicated
# flags or removed them), and ones a later 3.x made a no-op
METRICS_GONE_FEATURES = {
    "agent",
    "auto-gomaxprocs",
    "auto-gomemlimit",
    "expand-external-labels",
    "new-service-discovery-manager",
    "no-default-scrape-port",
    "otlp-write-receiver",
    "promql-at-modifier",
    "promql-negative-offset",
    "remote-write-receiver",
    "utf8-names",
    "native-histograms",  # no-op since 3.9
    "ooo-native-histograms",  # no-op
    "promql-duration-expr",  # no-op since 3.14
}
# an integer le/quantile matcher (normalised to 1.0 on ingest), in any PromQL quoting ("", '',
# ``) and as YAML writes a double-quoted one inside a double-quoted string (\"1\")
INTEGER_BUCKET_MATCHER = re.compile(r"""\b(?:le|quantile)\s*(?:=~|!~|!=|=)\s*(\\?"|'|`)[0-9]+\1""")


def gone_metrics_args(command: list[str]) -> list[str]:
    """The removed or deprecated flags and feature names in a metrics service's command."""
    out = []
    for i, arg in enumerate(command):
        name, eq, value = arg.partition("=")
        if name in METRICS_GONE_FLAGS:
            out.append(f"flag {name}")
        elif name == "--enable-feature":
            if not eq:
                value = command[i + 1] if i + 1 < len(command) else ""
            out += [f"feature {f}" for f in value.split(",") if f.strip() in METRICS_GONE_FEATURES]
    return out


def metrics_mounts(service: dict) -> dict[str, Path]:
    """The metrics service's mounted config files, by in-container name (``rules.yml``, ...)."""
    out = {}
    for v in service.get("volumes", []):
        src, dst = v.split(":")[:2]
        out[Path(dst).name] = LAB / src
    return out


def metrics_v3_problems(service: dict, config: dict, rules: str) -> list[str]:
    """What in the lab's metrics service would not run, or would read differently, on the 3.x
    line it pins (the upstream migration guide, docs/migration.md)."""
    out = []
    tag = service.get("image", "").partition(":")[2]
    if not tag.startswith("v3."):
        out.append(f"the image tag {tag!r} is not the 3.x line")
    out += gone_metrics_args(service.get("command", []))
    if not config.get("storage", {}).get("tsdb", {}).get("retention", {}).get("time"):
        out.append("no storage.tsdb.retention.time in the config file")
    for job in config.get("scrape_configs", []):
        if "scrape_classic_histograms" in job:  # renamed always_scrape_classic_histograms
            out.append(f"job {job.get('job_name')}: scrape_classic_histograms")
    for am in config.get("alerting", {}).get("alertmanagers", []):
        if am.get("api_version") == "v1":
            out.append("an Alertmanager on the v1 API")
    if "holt_winters" in rules:  # double_exponential_smoothing, behind a feature flag
        out.append("holt_winters in the rules")
    if INTEGER_BUCKET_MATCHER.search(rules):
        out.append("an integer le/quantile matcher in the rules")
    return out


def test_the_metrics_service_is_configured_for_its_3_x_line(compose):
    service = compose["services"]["metrics"]
    files = metrics_mounts(service)
    config = yaml.safe_load(files[Path(service["command"][0].partition("=")[2]).name].read_text())
    rules = "".join(files[Path(r).name].read_text() for r in config["rule_files"])
    assert metrics_v3_problems(service, config, rules) == []


def test_negative_2_x_metrics_settings_are_caught(compose):
    service = {**compose["services"]["metrics"]}
    service["image"] = service["image"].split(":")[0] + ":v2.55.1"
    service["command"] = [*service["command"], "--storage.tsdb.retention.time=2h"]
    config = {
        "scrape_configs": [{"job_name": "j", "scrape_classic_histograms": True}],
        "alerting": {"alertmanagers": [{"api_version": "v1"}]},
    }
    rules = 'expr: holt_winters(x[5m], 0.5, 0.5) > 1 or h_bucket{le="1"} > 0'
    assert len(metrics_v3_problems(service, config, rules)) == 7


@pytest.mark.parametrize(
    "command, want",
    [
        (["--storage.tsdb.retention=15d"], ["flag --storage.tsdb.retention"]),
        (["--storage.tsdb.retention", "15d"], ["flag --storage.tsdb.retention"]),
        (["--storage.tsdb.retention.size", "1GB"], ["flag --storage.tsdb.retention.size"]),
        (["--log.level=debug"], ["flag --log.level"]),
        (["--enable-feature=promql-experimental-functions"], []),
        (["--enable-feature", "exemplar-storage"], []),
        (["--enable-feature=agent,promql-experimental-functions"], ["feature agent"]),
        (
            ["--enable-feature", "utf8-names,native-histograms"],
            ["feature utf8-names", "feature native-histograms"],
        ),
        (["--storage.tsdb.path=/data", "--web.enable-lifecycle"], []),
    ],
)
def test_gone_metrics_args_reads_both_flag_forms(command, want):
    assert gone_metrics_args(command) == want


@pytest.mark.parametrize(
    "rules, hit",
    [
        ('h_bucket{le="1"}', True),
        ("h_bucket{le='1'}", True),
        ("h_bucket{le=`1`}", True),
        ('expr: "h_bucket{le=\\"1\\"} > 0"', True),  # YAML double-quoted: le=\"1\"
        ('s{quantile = "1"}', True),
        ('h_bucket{le!="1"}', True),
        ('h_bucket{le=~"1"}', True),
        ('h_bucket{le!~"1"}', True),
        ('h_bucket{le="1.0"}', False),
        ('h_bucket{le="+Inf"}', False),
        ("h_bucket{le='1\"}", False),  # mismatched quotes are no matcher
        ('handle="1"', False),
    ],
)
def test_the_integer_bucket_matcher_reads_every_quoting(rules, hit):
    assert bool(INTEGER_BUCKET_MATCHER.search(rules)) is hit


def _query_etc(compose) -> Path:
    """The host directory the lake-query engine reads as its etc directory (one bind mount)."""
    (src,) = [
        v.split(":")[0] for v in compose["services"]["lake-query"]["volumes"] if v.startswith("./")
    ]
    return LAB / src


def _properties(path: Path) -> dict[str, str]:
    out = {}
    for line in path.read_text().splitlines():
        if line.strip() and not line.lstrip().startswith("#"):
            key, _, value = line.partition("=")
            out[key.strip()] = value.strip()
    return out


def test_lake_query_healthcheck_is_the_images_own_check(compose):
    # since 484 the engine's image (a hardened runtime) has no grep, so a `curl | grep` shell check
    # never passes and lake-query, with everything that waits for it, never becomes healthy
    test = compose["services"]["lake-query"]["healthcheck"]["test"]
    assert test[0] == "CMD" and len(test) == 2 and test[1].endswith("/bin/health-check"), test


def test_lake_query_node_id_is_the_container_hostname(compose):
    # 484 removed the image's wrapper script that passed -Dnode.id=$HOSTNAME when the mounted
    # node.properties named none
    node = _properties(_query_etc(compose) / "node.properties")
    assert node.get("node.id") == "${ENV:HOSTNAME}"


def test_lake_query_etc_holds_only_the_expected_files(compose):
    # the directory is mounted as the whole /etc/trino, so any file in it is read: a stray
    # secrets.toml, for one, replaces Airlift's environment-variable secrets resolver, and every
    # ${ENV:...} the catalog and node.properties use stops resolving
    etc = _query_etc(compose)
    found = {p.relative_to(etc).as_posix() for p in etc.rglob("*") if p.is_file()}
    catalogs = {f for f in found if f.startswith("catalog/")}
    assert catalogs and all(f.count("/") == 1 and f.endswith(".properties") for f in catalogs), (
        catalogs
    )
    assert found - catalogs == {"config.properties", "jvm.config", "node.properties"}, found


def test_lake_query_http_port_is_the_one_the_health_check_reads(compose):
    # the image's health check reads the literal `http-server.http.port=<n>` line of
    # config.properties (bash prefix match: no spaces around `=`), defaulting to 8080
    etc = _query_etc(compose)
    lines = [
        ln
        for ln in (etc / "config.properties").read_text().splitlines()
        if ln.strip().startswith("http-server.http")
    ]
    assert lines == ["http-server.http.port=8080"], lines
    targets = {str(p).rsplit(":", 1)[-1] for p in compose["services"]["lake-query"]["ports"]}
    assert targets == {"8080"}, targets


def test_lake_query_config_names_no_removed_property(compose):
    # properties releases 471-484 removed or made defunct (a defunct one stops the server at
    # start), the legacy S3 file system removed in 481 (hive.s3.*), and fs.hadoop.enabled, which
    # still exists in 484 but only for HDFS: unwanted in a lab with object storage only
    removed = re.compile(
        r"^(task\.statistics-cpu-timer-enabled|enable-large-dynamic-filters"
        r"|dynamic-filtering\.(small|large-broadcast)|fs\.cache\.(directories|max-sizes"
        r"|max-disk-usage-percentages|ttl|page-size)|fs\.hadoop\.enabled|hive\.s3\."
        r"|[a-z]+\.extended-statistics\.enabled|[a-z]+\.equality-deletes-blocks-hash-enabled"
        r"|s3\.use-web-identity-token-credentials-provider)"
    )
    etc = _query_etc(compose)
    catalogs = sorted((etc / "catalog").glob("*.properties"))
    assert catalogs, "no catalog"
    for path in [etc / "config.properties", etc / "node.properties", *catalogs]:
        props = _properties(path)
        bad = [k for k in props if removed.match(k)]
        assert bad == [], f"{path.name}: {bad}"
    for path in catalogs:
        props = _properties(path)
        # the native S3 file system by its current name (fs.native-s3.enabled is a legacy alias)
        assert props.get("fs.s3.enabled") == "true", path.name
        assert not [k for k in props if k.startswith("fs.native-")], path.name


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


@pytest.fixture
def docker_compose():
    """docker with the compose plugin (skips, or fails where HNX_REQUIRE_TOOLS names docker)."""
    return require_tool("docker", docker_compose_available)


needs_docker = pytest.mark.usefixtures("docker_compose")


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


# a fake Uptime Kuma 2.x behind provision.js's client interface: the socket.io events it uses
# (needSetup, setup, login, add, addStatusPage, saveStatusPage) and the lists Kuma sends after a
# login; addStatusPage refuses a slug that exists, as Kuma's unique index does, and add and
# saveStatusPage refuse what a real 2.5.6 refused when the 1.23 provisioning ran against it
# (monitor.conditions is NOT NULL; an analyticsType that is not null or a known type)
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
            if (!Array.isArray(args[0].conditions) || !Array.isArray(args[0].rabbitmqNodes)) {
                return { ok: false, msg: "NOT NULL constraint failed: monitor.conditions" };
            }
            if (!args[0].accepted_statuscodes.every((c) => typeof c === "string")) {
                return { ok: false, msg: "Accepted status codes are not all strings" };
            }
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
        case "saveStatusPage": {
            const c = args[1];
            if (c.analyticsType !== null && !["google", "umami", "plausible", "matomo", "rybbit"].includes(c.analyticsType)) {
                return { ok: false, msg: "Invalid analytics type" };
            }
            if (typeof c.showOnlyLastHeartbeat !== "boolean" || !Array.isArray(c.domainNameList)) {
                return { ok: false, msg: "NOT NULL constraint failed: status_page.show_only_last_heartbeat" };
            }
            return { ok: true };
        }
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


@pytest.mark.requires_tool("node")
def test_uptime_provisioning_is_idempotent():
    """Regression: a re-run on a persisted volume added both monitors again and failed on the
    existing status-page slug.  Run twice against a fake Kuma, the second run creates nothing.
    (The real socket.io API -- that Kuma sends monitorList and statusPageList after a login --
    is only exercised by the nightly lab smoke.)"""
    script = str(LAB / "config" / "uptime" / "provision.js")
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


@pytest.mark.parametrize(
    "ps, hint",
    [
        ("running healthy\n", False),
        ("", False),  # never created: nothing to say
        ("running unhealthy\n", True),
        ("restarting starting\n", True),
        ("exited \n", True),
    ],
)
def test_smoke_hints_at_a_kept_root_owned_volume_when_uptime_is_unhealthy(ps, hint):
    m = re.search(r"^uptime_hint\(\) \{\n.*?^\}\n", (LAB / "smoke.sh").read_text(), re.M | re.S)
    assert m, "smoke.sh defines uptime_hint"
    fake_dc = (
        'dc() { [ "$*" = "ps -a --format {{.State}} {{.Health}} uptime" ] && printf "$PS"; }\n'
    )
    p = subprocess.run(
        [shutil.which("bash"), "-c", fake_dc + m.group(0) + "uptime_hint\n"],
        capture_output=True,
        text=True,
        check=True,
        env={"PATH": "/usr/bin:/bin", "PS": ps},
    )
    assert p.stdout == ""
    lines = p.stderr.splitlines()
    if hint:
        assert len(lines) == 1 and "make lab-down (docker compose down -v)" in lines[0]
        assert lines[0].startswith(f"smoke.sh: hint: uptime is not healthy ({ps.rstrip(chr(10))})")
    else:
        assert lines == []


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
        "/api/status-page/lab": "kuma-2-status-page",  # the lab runs Uptime Kuma 2.x
        "/api/status-page/heartbeat/lab": "kuma-2-heartbeat",
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


def test_pull_requests_run_the_nightly_s_smoke_unchanged():
    """ci.yml's lab-in-a-box job (on the pull requests tools/lab_paths.py picks) is the nightly's
    job step for step, so a pull request's green lab means what a green nightly means."""
    nightly = yaml.safe_load(WORKFLOW.read_text())["jobs"]["lab-in-a-box"]
    ci = yaml.safe_load((WORKFLOW.parent / "ci.yml").read_text())["jobs"]["lab-in-a-box"]
    for key in ("runs-on", "permissions", "timeout-minutes", "steps"):
        assert ci[key] == nightly[key], key
    assert set(ci) - set(nightly) == {"needs", "if"}
    assert set(nightly) - set(ci) == set()  # nothing of the nightly's job is dropped
    assert any("smoke.sh" in s.get("run", "") for s in ci["steps"])


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
HARDENED_EXCEPTIONS: set[str] = set()  # none: OpenBao (2.6+) starts as its own user


def test_the_secrets_service_adds_no_capability_back(compose):
    # OpenBao dropped mlock in 2.0 and starts as its own user since 2.6: IPC_LOCK must not return.
    assert "cap_add" not in compose["services"]["secrets"]


def test_the_uptime_service_runs_its_rootless_image_and_adds_no_capability_back(compose):
    # 1.x's entrypoint chowned /app/data and switched user (CHOWN, SETGID, SETUID); 2.x's
    # *-slim-rootless image starts as `node` (uid 1000), which owns /app/data in the image
    images = set()
    for name in ("uptime", "uptime-init"):
        svc = compose["services"][name]
        assert "cap_add" not in svc and "user" not in svc, name
        images.add(svc["image"])
    (image,) = images  # one pin for both
    assert re.fullmatch(r"[\w/-]+:2\.\d+\.\d+-slim-rootless@sha256:[0-9a-f]{64}", image), image
    # SQLite by its environment variable, not the first-run "setup database" page (unauthenticated)
    assert compose["services"]["uptime"]["environment"]["UPTIME_KUMA_DB_TYPE"] == "sqlite"


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


def guard_pass1(lab, tmp_path, **env):
    """Run only the guard's first pass (dotenv syntax and the values as written), which needs no
    docker, with a PATH of only dirname and mkdir."""
    return subprocess.run(
        [shutil.which("bash"), "-c", '. "$1" && lab_bind_guard_pass1', "guard", str(lab / "bind_guard.sh")],
        env={"PATH": stub_path(tmp_path), **env},
        capture_output=True,
        text=True,
    )  # fmt: skip


# the first pass's allow path, with no docker anywhere (the full guard then needs docker)
@pytest.mark.parametrize("bind", [LOOPBACK, OTHER_LOOPBACK, "::1", "[::1]", ""])
def test_pass1_allows_loopback(lab_copy, tmp_path, bind):
    r = guard_pass1(lab_copy, tmp_path, LAB_BIND=bind)
    assert r.returncode == 0, r.stderr


def test_pass1_allows_the_shipped_defaults(lab_copy, tmp_path):
    assert guard_pass1(lab_copy, tmp_path).returncode == 0


def test_pass1_allows_a_non_loopback_bind_once_acknowledged_and_changed(lab_copy, tmp_path):
    env = {"LAB_BIND": "0.0.0.0", "LAB_I_UNDERSTAND_UNAUTHENTICATED": "1", **real_credentials()}
    assert guard_pass1(lab_copy, tmp_path, **env).returncode == 0
    del env["LAB_I_UNDERSTAND_UNAUTHENTICATED"]
    assert guard_pass1(lab_copy, tmp_path, **env).returncode == 4


def test_pass1_reads_dot_env_and_the_environment_wins_over_it(lab_copy, tmp_path):
    lines = [f"{k}={v}" for k, v in real_credentials().items()]
    (lab_copy / ".env").write_text(
        "LAB_BIND=0.0.0.0  # all interfaces\nLAB_I_UNDERSTAND_UNAUTHENTICATED=1\n"
        + "\n".join(lines)
        + "\nLAB_SECRETS_DEV_TOKEN=fake-dev-root-token-0000\n"  # scrub-allow: the placeholder
    )
    r = guard_pass1(lab_copy, tmp_path)
    assert r.returncode == 4 and "LAB_SECRETS_DEV_TOKEN" in r.stderr
    assert guard_pass1(lab_copy, tmp_path, LAB_BIND=LOOPBACK).returncode == 0


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


@pytest.mark.requires_tool("make")
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
    assert variables == set(events["environment"]) - {"GOMEMLIMIT"}
    # the Go runtime's soft limit sits below the container's, so the server's caches (2.12+)
    # are freed under GC pressure before the kernel kills it
    soft = int(events["environment"]["GOMEMLIMIT"].removesuffix("MiB"))
    assert 0 < soft < int(events["mem_limit"].removesuffix("m"))
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
    # the bus-acl step reads and acks through the bridge's own durable on decision.returned
    by_subject = {s["subject"]: s["durable"] for s in bridge_json["subscriptions"]}
    assert by_subject["homelabnext.decision.returned"] == e2e.LAB_NOT_BROKER_DURABLE
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
    assert not nats_allowed(bridge, "publish", f"$JS.ACK.{stream}.other.1.2.3.4.5")
    assert not nats_allowed(bridge, "publish", f"$JS.API.CONSUMER.CREATE.{stream}.other")
    assert not nats_allowed(bridge, "publish", f"$JS.API.STREAM.CREATE.{stream}")
    assert not nats_allowed(hnx["hnx-broker"], "publish", f"$JS.API.STREAM.CREATE.{stream}")


def nats_account_hash(account: str) -> str:
    """The account hash in a v2 ack subject, as nats-server computes it (``server/events.go``
    ``getHash``/``getHashSize`` at v2.15.1, digits from ``server/accounts.go``): each of the first
    8 bytes of sha256(name), mod 62, as a character of ``0-9A-Za-z``."""
    digits = string.digits + string.ascii_uppercase + string.ascii_lowercase  # 0-9A-Za-z
    return "".join(digits[b % 62] for b in hashlib.sha256(account.encode()).digest()[:8])


def test_the_account_hash_is_the_servers():
    # read off a 2.15.1 server with js_ack_fc_v2 on: $JS.ACK._.hKkTAyOX.HNXLAB_BROKER.<durable>...
    assert nats_account_hash("HNX") == "hKkTAyOX"


def test_acks_are_granted_token_exact_in_both_reply_subject_forms():
    """ADR-15: v1 ``$JS.ACK.<stream>.<consumer>.<5 numbers>`` (what 2.15.1 sends) and v2
    ``$JS.ACK.<domain>.<account hash>.<stream>.<consumer>.<5 numbers>[...]`` (upstream main
    enables it in 2.16 and removes the flag in 2.17).  Each ack grant is exactly the consumer's
    own subscription: no wildcard over the stream or consumer (``$JS.ACK.*.*.<s>.<d>.>`` would
    also match another consumer's 9-token v1 subject, which takes ``+NXT``) and no ``>`` on v1."""
    conf = parse_nats_conf(NATS_CONF.read_text())
    # no JetStream domain anywhere, so the v2 domain token is the server's "_"
    assert "domain" not in conf["jetstream"] and '"domain"' not in json.dumps(conf)
    assert "js_ack_fc_v2" not in json.dumps(conf.get("feature_flags", {}))  # upstream's default
    e2e = load_module("broker_e2e", LAB / "broker_e2e.py")
    stream = e2e.LAB_EVENTS_STREAM
    ackers = 0
    for user in nats_users().values():
        allow = (user.get("permissions") or {}).get("publish", {}).get("allow", [])
        acks = [s for s in allow if s.startswith("$JS.ACK.")]
        if not acks:
            continue
        ackers += 1  # the bridge: the one user granted acks on the standing stream
        h = nats_account_hash(user["account"])
        durables = {s.split(".")[3] for s in acks if s.split(".")[2] == stream}
        assert durables
        assert sorted(acks) == sorted(
            [f"$JS.ACK.{stream}.{d}.*.*.*.*.*" for d in durables]
            + [f"$JS.ACK._.{h}.{stream}.{d}.*.*.*.*.>" for d in durables]
        )
        for d in durables:
            v1, v2 = f"$JS.ACK.{stream}.{d}.1.2.3.4.5", f"$JS.ACK._.{h}.{stream}.{d}.1.2.3.4.5"
            assert nats_allowed(user, "publish", v1) and nats_allowed(user, "publish", v2)
            refused = [
                f"$JS.ACK.Other.other.{stream}.{d}.1.2.3",  # another consumer's v1 subject
                f"$JS.ACK.{stream}.other.1.2.3.4.5",  # another durable, v1
                f"$JS.ACK._.{h}.{stream}.other.1.2.3.4.5",  # another durable, v2
                f"$JS.ACK.dom.{h}.{stream}.{d}.1.2.3.4.5",  # another domain
                f"$JS.ACK._.AAAAAAAA.{stream}.{d}.1.2.3.4.5",  # another account's hash
                f"$JS.ACK.{stream}.{d}.1.2.3.4.5.6.7",  # v1 with extra tokens
                f"$JS.ACK.{stream}.{d}.1.2.3.4",  # v1 short of a token
            ]
            for subject in refused:
                assert not nats_allowed(user, "publish", subject), subject
    assert ackers == 1


def test_negative_a_wildcard_ack_grant_matches_another_consumers_v1_subject():
    loose = {"user": "x", "permissions": {"publish": {"allow": ["$JS.ACK.*.*.S.d.>"]}}}
    assert nats_allowed(loose, "publish", "$JS.ACK.Other.other.S.d.1.2.3")


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


def test_nats_server_accepts_the_lab_config(tmp_path, env_vars):
    require_tool("nats-server")
    conf = tmp_path / "nats.conf"
    conf.write_text(NATS_CONF.read_text().replace('"/data"', json.dumps(str(tmp_path))))
    env = {**os.environ, **{v: env_vars[v] for v in nats_vars(conf.read_text())}}
    proc = subprocess.run(["nats-server", "-c", str(conf), "-t"], env=env, capture_output=True,
                          text=True, timeout=30)  # fmt: skip
    assert proc.returncode == 0, proc.stderr
