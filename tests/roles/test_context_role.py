# SPDX-License-Identifier: Apache-2.0
"""Role ``context`` (modules/context/roles/context), run on localhost against fakes (CI is
unprivileged): main renders the context container through compose_app (the configuration read-only,
the data root the only writable path), a configuration holding each caller's token digest and never
a token, the secrets in the owner-only env file, a reindex timer whose service writes its last-run
record; a second run is ``changed=0``. The judge is on only with a gateway id, its URL from the
registry. Malformed sources, callers, canned queries, images and missing or malformed credentials are
refused before anything is written. Health proves /health, /ready, the self-check inside the
container and the timer; upgrade refuses an unpinned target; backup names no path."""

from __future__ import annotations

import hashlib
import json
import os
import pwd
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import yaml
from rolerun import fake, last_run_vars, logging_fake, run_cases, run_role

ROOT = Path(__file__).resolve().parents[2]
ROLE = str(ROOT / "modules" / "context" / "roles" / "context")
USER = pwd.getpwuid(os.getuid()).pw_name
REPO = "localhost/hnx-context"
DIGEST = "sha256:" + "c" * 64
IMAGE = f"{REPO}:0.1.0-abc123def456@{DIGEST}"
GUEST = yaml.safe_load((ROOT / "examples" / "services.yml").read_text())["hosts"]["dns-core"][
    "address"
]
LOOP = ".".join(["127", "0", "0", "1"])  # the loopback a stand-in listens on
needs_ansible = pytest.mark.requires_tool("ansible-playbook")

# short, obviously fake values (built at run time: nothing here looks like a key)
ADMIN = "a" * 40
AGENTS = "b" * 40
AUTOMATION = "d" * 40
SOURCE = "s" * 20
GATEWAY = "g" * 20
SECRETS = {
    "HNX_SECRET_CONTEXT_ADMIN_TOKEN": ADMIN,
    "HNX_SECRET_CONTEXT_AGENTS_TOKEN": AGENTS,
    "HNX_SECRET_CONTEXT_AUTOMATION_TOKEN": AUTOMATION,
    "HNX_SECRET_CONTEXT_SOURCES_REGISTERS": SOURCE,
    "HNX_SECRET_CONTEXT_GATEWAY_KEY": GATEWAY,
}
SOURCES = [
    {"name": "lessons", "url": "https://git.example.internal/ops/registers.git", "ref": "main",
     "kind": "lesson", "tlp": "amber", "format": "yaml-records", "records_key": "lessons",
     "paths": ["dev/lessons.yml"], "credential": "secret:context/sources/registers"},
    {"name": "adr", "url": "https://git.example.internal/platform/core.git", "ref": "c" * 40,
     "kind": "doc", "tlp": "clear", "paths": ["docs/adr/*.md"]},
]  # fmt: skip
CALLERS = [
    {"name": "agents", "secret": "secret:context/agents-token", "ceiling": "amber",
     "scopes": ["query"]},
    {"name": "automation", "secret": "secret:context/automation-token", "ceiling": "clear",
     "scopes": ["reindex"]},
]  # fmt: skip
HEALTH = {"text": "the dashboard is blank", "expect": "lesson:lessons/LL-003", "ceiling": "amber"}


def context_vars(tmp_path: Path, **kw) -> dict:
    v = {
        "context_logical_id": "context",
        "context_image": IMAGE,
        "ansible_host": GUEST,
        "context_dir": str(tmp_path / "app"),
        "context_data_root": str(tmp_path / "data"),
        "context_owner": USER,
        "context_uid": os.getuid(),
        "context_gid": os.getgid(),
        "context_sources": SOURCES,
        "context_callers": CALLERS,
        "context_health_query": HEALTH,
        "context_start": False,
        "context_validate_with_docker": False,
        "context_unit_dir": str(tmp_path / "units"),
        "context_systemctl_cli": logging_fake(tmp_path, "systemctl", "enabled\n"),
        **last_run_vars(tmp_path, "context"),
    }
    (tmp_path / "units").mkdir(exist_ok=True)
    v.update(kw)
    return v


def compose(tmp_path: Path) -> dict:
    return yaml.safe_load((tmp_path / "app" / "docker-compose.yml").read_text())["services"][
        "context"
    ]


def _sha(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


@needs_ansible
def test_main_renders_the_service_its_configuration_secrets_and_timer(tmp_path):
    v = context_vars(tmp_path)
    r = run_role(tmp_path, ROLE, "main", v, env=SECRETS)
    assert r.returncode == 0, r.stdout + r.stderr
    svc = compose(tmp_path)
    assert svc["image"] == IMAGE and svc["user"] == f"{os.getuid()}:{os.getgid()}"
    assert svc["cap_drop"] == ["ALL"] and svc["security_opt"] == ["no-new-privileges:true"]
    assert svc["ports"] == [GUEST + ":8094:8094"]
    assert svc["volumes"] == [
        f"{tmp_path}/app/config.json:/etc/hnx-context/config.json:ro",
        f"{tmp_path}/data:/data",
    ]
    assert svc["environment"]["CONTEXT_CONFIG"] == "/etc/hnx-context/config.json"
    assert len(svc["environment"]["CONTEXT_CONFIG_SHA"]) == 64
    cfg = json.loads((tmp_path / "app" / "config.json").read_text())
    assert cfg["port"] == 8094 and cfg["data_dir"] == "/data" and cfg["judge"] is None
    assert cfg["model_dir"] == "/opt/hnx-context/model"
    lessons, adr = cfg["sources"]
    assert lessons["credential_env"] == "CONTEXT_SOURCE_LESSONS" and "credential" not in lessons
    assert adr["ref"] == "c" * 40 and "credential_env" not in adr
    assert cfg["callers"] == [
        {"name": "agents", "sha256": _sha(AGENTS), "ceiling": "amber", "scopes": ["query"]},
        {"name": "automation", "sha256": _sha(AUTOMATION), "ceiling": "clear",
         "scopes": ["reindex"]},
    ]  # fmt: skip
    assert cfg["health"] == HEALTH
    text = (tmp_path / "app" / "config.json").read_text()
    assert all(s not in text for s in (ADMIN, AGENTS, AUTOMATION, SOURCE))
    env = (tmp_path / "app" / "secrets" / "context.env").read_text()
    assert f"CONTEXT_ADMIN_TOKEN='{ADMIN}'" in env and f"CONTEXT_SOURCE_LESSONS='{SOURCE}'" in env
    assert "GATEWAY" not in env and AGENTS not in env
    assert oct((tmp_path / "app" / "secrets" / "context.env").stat().st_mode & 0o777) == "0o600"
    assert oct((tmp_path / "data").stat().st_mode & 0o777) == "0o750"
    unit = (tmp_path / "units" / "hnx-context-reindex.service").read_text()
    assert "exec -T context python -m homelabnext.context_service reindex 1800" in unit
    assert "--job timer:context/reindex" in unit and "ExecStopPost=-" in unit
    timer = (tmp_path / "units" / "hnx-context-reindex.timer").read_text()
    assert "OnCalendar=*-*-* *:20:00 UTC" in timer
    again = run_role(tmp_path, ROLE, "main", v, env=SECRETS)
    assert again.returncode == 0 and "changed=0" in again.stdout, again.stdout


@needs_ansible
def test_the_judge_is_on_with_a_gateway_found_in_the_registry(tmp_path):
    v = context_vars(tmp_path, context_gateway_id="llm-gateway", context_judge_ceiling="green")
    r = run_role(tmp_path, ROLE, "main", v, env=SECRETS)
    assert r.returncode == 0, r.stdout + r.stderr
    judge = json.loads((tmp_path / "app" / "config.json").read_text())["judge"]
    assert judge["url"].startswith("https://gateway-01.example.internal")
    assert judge["key_env"] == "CONTEXT_GATEWAY_KEY" and judge["role"] == "fast-classifier"
    assert judge["threshold"] == 0.1 and judge["workers"] == 2 and judge["top_k"] == 5
    assert judge["ceiling"] == "green" and judge["on_error"] == "fallback"
    assert judge["allow_plaintext"] is False
    env = (tmp_path / "app" / "secrets" / "context.env").read_text()
    assert f"CONTEXT_GATEWAY_KEY='{GATEWAY}'" in env
    assert GATEWAY not in (tmp_path / "app" / "config.json").read_text()


def _src(**kw):
    return [{**SOURCES[0], **kw}, SOURCES[1]]


@needs_ansible
def test_malformed_settings_are_refused_before_anything_is_written(tmp_path):
    base = context_vars(tmp_path)
    cases = [
        {"context_sources": _src(url="http://git.example.internal/r.git")},  # plain http
        {"context_sources": _src(url="https://u:p@git.example.internal/r.git")},  # a credential
        {"context_sources": _src(ref="../main")},
        {"context_sources": _src(tlp="TLP:BLUE")},
        {"context_sources": _src(paths=["/etc/*"])},
        {"context_sources": _src(paths=["a/../../b"])},
        {"context_sources": _src(format="json")},
        {"context_sources": _src(credential="secret:other/x")},
        {"context_sources": _src(surprise=1)},
        {"context_sources": []},
        {"context_sources": [SOURCES[0], SOURCES[0]]},
        {"context_callers": [{**CALLERS[0], "scopes": ["health"]}]},
        {"context_callers": [{**CALLERS[0], "name": "admin"}]},
        {"context_callers": [{**CALLERS[0], "secret": "secret:context/admin-token"}]},
        {"context_callers": [{**CALLERS[0], "ceiling": "blue"}]},
        {"context_callers": [CALLERS[0], {**CALLERS[1], "secret": CALLERS[0]["secret"]}]},
        {"context_health_query": {}},
        {"context_health_query": {**HEALTH, "expect": "lesson:nowhere/x"}},
        {"context_image": f"docker.io/someone/else:1@{DIGEST}"},
        {"context_image": f"{REPO}:latest@{DIGEST}"},
        {"context_bind": "0.0.0.0"},
        {"context_judge_ceiling": "blue"},
        {"context_judge_threshold": 2},
        {"context_judge_on_error": "guess"},
        {"context_admin_ref": "secret:other/admin"},
    ]
    results = run_cases(tmp_path, ROLE, "main", base, cases, env=SECRETS, parallel=True)
    assert all(failed for failed, _ in results), [
        (c, m) for c, (f, m) in zip(cases, results, strict=True) if not f
    ]
    assert not (tmp_path / "app" / "config.json").exists()


@needs_ansible
@pytest.mark.parametrize(
    "drop,patch",
    [
        ("HNX_SECRET_CONTEXT_ADMIN_TOKEN", {}),
        ("HNX_SECRET_CONTEXT_SOURCES_REGISTERS", {}),
        (None, {"HNX_SECRET_CONTEXT_AGENTS_TOKEN": "short"}),
        (None, {"HNX_SECRET_CONTEXT_AGENTS_TOKEN": ADMIN}),  # two callers share a token
    ],
)
def test_a_missing_or_malformed_credential_is_refused_before_a_file_is_written(
    tmp_path, drop, patch
):
    env = {k: val for k, val in SECRETS.items() if k != drop} | patch
    r = run_role(tmp_path, ROLE, "main", context_vars(tmp_path), env=env)
    assert r.returncode != 0
    assert not (tmp_path / "app" / "config.json").exists()
    assert all(s not in r.stdout for s in (ADMIN, AGENTS, SOURCE))


@needs_ansible
def test_the_gateway_key_is_needed_only_with_the_judge_on(tmp_path):
    env = {k: val for k, val in SECRETS.items() if k != "HNX_SECRET_CONTEXT_GATEWAY_KEY"}
    assert run_role(tmp_path, ROLE, "main", context_vars(tmp_path), env=env).returncode == 0
    other = tmp_path / "judged"
    other.mkdir()
    r = run_role(
        other, ROLE, "main", context_vars(other, context_gateway_id="llm-gateway"), env=env
    )
    assert r.returncode != 0 and "gateway key" in r.stdout


# ----------------------------------------------------------------------------- health


class _Front:
    """/health and /ready as the service answers them."""

    def __init__(self, ready=True, judge=False):
        doc = {"ready": ready, "documents": 7 if ready else 0, "judge": judge,
               "last_reindex": {"ok": ready}}  # fmt: skip
        self.paths: list[str] = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                return

            def do_GET(self):
                outer.paths.append(f"GET {self.path}")
                body = json.dumps({"status": "ok"} if self.path == "/health" else doc).encode()
                self.send_response(200 if self.path == "/health" or ready else 503)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.srv = ThreadingHTTPServer((LOOP, 0), H)

    def __enter__(self):
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *a):
        self.srv.shutdown()
        self.srv.server_close()


def _docker(tmp_path, check=None, rc=0):
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    ps = json.dumps({"Service": "context", "State": "running", "Health": "healthy"})
    out = json.dumps(check if check is not None else {"ok": True, "judge": {"on": False}})
    log = tmp_path / "docker.log"
    return fake(
        bindir / "docker",
        "import sys\n"
        f"open({str(log)!r}, 'a').write(' '.join(sys.argv[1:]) + '\\n')\n"
        "if 'exec' in sys.argv:\n"
        f"    sys.stdout.write({out + chr(10)!r})\n"
        f"    sys.exit({rc})\n"
        f"sys.stdout.write({ps + chr(10)!r})\n",
    )


def _health(tmp_path, front, check=None, rc=0, **kw):
    docker = _docker(tmp_path, check, rc)
    host, port = front.srv.server_address[:2]
    v = context_vars(tmp_path, context_bind=host, context_port=port, context_start=True,
                     context_docker_cli=docker, **kw)  # fmt: skip
    env = {"PATH": f"{tmp_path / 'bin'}:{os.environ['PATH']}"}
    return run_role(tmp_path, ROLE, "health", v, env=env)


@needs_ansible
def test_health_asks_ready_and_runs_the_self_check_inside_the_container(tmp_path):
    with _Front() as front:
        r = _health(tmp_path, front)
    assert r.returncode == 0, r.stdout + r.stderr
    assert front.paths == ["GET /health", "GET /ready"]
    calls = (tmp_path / "docker.log").read_text().splitlines()
    exec_call = next(c for c in calls if " exec " in c)
    assert exec_call.endswith("exec -T context python -m homelabnext.context_service check 120")
    assert "is-enabled hnx-context-reindex.timer" in (tmp_path / "calls.log").read_text()


@needs_ansible
@pytest.mark.parametrize(
    "front,check,rc,kw,needle",
    [
        ({"ready": False}, None, 0, {}, "is not ready"),
        ({}, {"ok": False, "judge": {"on": False}, "reason": "x"}, 1, {}, "self-check failed"),
        # the judge is configured on, but the service answers without it
        ({}, None, 0, {"context_gateway_id": "llm-gateway"}, "is not ready"),
    ],
)
def test_health_fails_when_the_index_or_the_self_check_does_not_hold(
    tmp_path, front, check, rc, kw, needle
):
    with _Front(**front) as f:
        r = _health(tmp_path, f, check, rc, **kw)
    assert r.returncode != 0 and needle in r.stdout, r.stdout


# ----------------------------------------------------------------------------- the other hooks


@needs_ansible
def test_backup_names_no_path_and_export_and_restore_have_nothing_to_do(tmp_path):
    v = context_vars(tmp_path)
    assert run_role(tmp_path, ROLE, "backup", v, env=SECRETS).returncode == 0
    manifest = json.loads((tmp_path / "app" / "backup-manifest.json").read_text())
    assert manifest["paths"] == [] and manifest["derived"] == [str(tmp_path / "data")]
    for hook in ("export", "restore"):
        r = run_role(tmp_path, ROLE, hook, v)
        assert r.returncode == 0 and "nothing to" in r.stdout


@needs_ansible
def test_upgrade_refuses_an_unpinned_or_foreign_target(tmp_path):
    v = context_vars(tmp_path)
    results = run_cases(tmp_path, ROLE, "upgrade", v, [
        {"context_target_image": f"{REPO}:latest@{DIGEST}"},
        {"context_target_image": f"{REPO}:0.2.0"},
        {"context_target_image": f"docker.io/x/y:0.2.0@{DIGEST}"},
    ])  # fmt: skip
    assert all(f and "the target must be" in m for f, m in results), results
