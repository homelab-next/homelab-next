# SPDX-License-Identifier: Apache-2.0
"""The web-search module's role (modules/<id>/roles/<id>), run on localhost against fakes (CI is
unprivileged): main renders the container through compose_app and the settings file (0600, the only
file that holds the secret) and a second run is ``changed=0``; the rendered settings are the ported
ones (default engines kept, the JSON format on, the limiter off, the image proxy on, a private
instance); no task that touches the secret logs it; a reference with no value, a secret that is too
short and every malformed input are refused before anything is written; health passes against a
stand-in and fails on a container that is not healthy, a health path that does not answer, a JSON
format that is refused, a body that is not a result list and (unless the site says otherwise) a search
that returns nothing; upgrade refuses an unpinned or foreign target; the stateless hooks write nothing."""

from __future__ import annotations

import grp
import json
import os
import pwd
import socket
from pathlib import Path

import pytest
import yaml
from rolerun import fake, run_role

from tests.modules.web_search_front import Server
from tests.modules.web_search_module import MID, ROLE_DIR, P, defaults, env_for, ref

LOOPBACK = socket.gethostbyname("localhost")  # the stand-in listens here; resolved, never a literal

ROOT = Path(__file__).resolve().parents[2]
ROLE = str(ROLE_DIR)
USER = pwd.getpwuid(os.getuid()).pw_name
DEFAULTS = defaults()
DEFAULT_IMAGE = DEFAULTS[P + "image"]
REPO = DEFAULT_IMAGE.split("@")[0].rsplit(":", 1)[0]
#: the example registry's edge address (a documentation-range address, never connected to)
GUEST = yaml.safe_load((ROOT / "examples" / "services.yml").read_text())["hosts"]["edge-core"][
    "address"
]
#: the secret is built at run time (never a literal that looks like a key to a scanner)
KEY = "k" * 40
KEY_ENV = env_for(ref("secret-key"))
SECRETS = {KEY_ENV: KEY}


def dv(tmp_path: Path, **kw) -> dict:
    """The role's variables for a test: ``kw`` names the role's own variables without their prefix
    (``hnx_`` and ``ansible_`` ones as they are)."""
    v = {
        "logical_id": "search",
        "dir": str(tmp_path / "app"),
        "owner": USER,
        "group": grp.getgrgid(os.getgid()).gr_name,
        "data_root": str(tmp_path / "data"),
        # the unprivileged test's own ids: it can chown to no other
        "uid": os.getuid(),
        "gid": os.getgid(),
        "start": False,
        "validate_with_docker": False,
    }
    v.update(kw)
    out = {"ansible_host": GUEST}
    out.update({k if k.startswith(("hnx_", "ansible_")) else P + k: x for k, x in v.items()})
    return out


def compose(tmp_path: Path) -> dict:
    return yaml.safe_load((tmp_path / "app" / "docker-compose.yml").read_text())


def settings(tmp_path: Path) -> dict:
    return yaml.safe_load((tmp_path / "data" / "config" / "settings.yml").read_text())


# ----------------------------------------------------------------------------- render


def test_main_renders_one_narrow_container_and_the_settings_file(tmp_path):
    v = dv(tmp_path)
    r = run_role(tmp_path, ROLE, "main", v, env=SECRETS)
    assert r.returncode == 0, r.stdout + r.stderr
    doc = compose(tmp_path)
    assert sorted(doc["services"]) == [MID]
    app = doc["services"][MID]
    assert app["image"] == DEFAULT_IMAGE and "@sha256:" in app["image"]
    assert app["cap_drop"] == ["ALL"] and "cap_add" not in app
    assert app["security_opt"] == ["no-new-privileges:true"] and "privileged" not in app
    assert app["ports"] == [GUEST + ":8095:8080"]
    assert app["user"] == f"{os.getuid()}:{os.getgid()}"
    assert app["volumes"] == [f"{tmp_path}/data/config:/etc/searxng"]
    assert "environment" not in app or KEY not in json.dumps(app["environment"])
    cfg = tmp_path / "data" / "config"
    assert oct((cfg / "settings.yml").stat().st_mode & 0o777) == "0o600"
    assert oct(cfg.stat().st_mode & 0o777) == "0o700"
    # the compose project holds no secret: only the settings file does
    for p in (tmp_path / "app").rglob("*"):
        if p.is_file():
            assert KEY not in p.read_text(errors="ignore"), p
    again = run_role(tmp_path, ROLE, "main", v, env=SECRETS)
    assert again.returncode == 0 and "changed=0" in again.stdout, again.stdout


def test_the_settings_are_the_ported_ones(tmp_path):
    assert run_role(tmp_path, ROLE, "main", dv(tmp_path), env=SECRETS).returncode == 0
    s = settings(tmp_path)
    assert s["use_default_settings"] is True  # the default engine set
    assert s["server"]["secret_key"] == KEY
    assert s["server"]["image_proxy"] is True
    assert s["server"]["limiter"] is False  # internal-only, API clients
    assert s["server"]["public_instance"] is False
    assert s["search"]["safe_search"] == 0
    assert s["search"]["formats"] == ["html", "json"]  # json: the consumers' API calls
    assert s["outgoing"]["request_timeout"] == 3.0
    assert s["general"]["instance_name"] == DEFAULTS[P + "instance_name"]
    assert "engines" not in s  # no engine is touched unless the site says so


def test_the_settings_variables_are_data(tmp_path):
    v = dv(
        tmp_path,
        safe_search=2,
        instance_name="Lab search",
        request_timeout=5.5,
        engines_disabled=["bing", "yahoo news"],
    )
    assert run_role(tmp_path, ROLE, "main", v, env=SECRETS).returncode == 0
    s = settings(tmp_path)
    assert s["search"]["safe_search"] == 2 and s["search"]["formats"] == ["html", "json"]
    assert s["general"]["instance_name"] == "Lab search"
    assert s["outgoing"]["request_timeout"] == 5.5
    assert s["use_default_settings"] is True  # merged by name: every other engine keeps its default
    assert s["engines"] == [
        {"name": "bing", "disabled": True},
        {"name": "yahoo news", "disabled": True},
    ]


def test_an_instance_name_that_is_yaml_syntax_stays_a_string(tmp_path):
    v = dv(tmp_path, instance_name="a: b # {c}")
    assert run_role(tmp_path, ROLE, "main", v, env=SECRETS).returncode == 0
    assert settings(tmp_path)["general"]["instance_name"] == "a: b # {c}"


def test_a_changed_setting_restarts_a_running_container_and_an_unchanged_one_does_not(tmp_path):
    env = {**SECRETS, **_docker(tmp_path)}
    log = tmp_path / "docker.log"
    restarts = lambda: [x for x in log.read_text().splitlines() if " restart" in x]  # noqa: E731
    with Server() as front:
        live = {"bind": LOOPBACK, "port": front.addr[1], "start": True}
        assert run_role(tmp_path, ROLE, "main", dv(tmp_path, **live), env=env).returncode == 0
        assert restarts() == []  # a first run creates the container with the file in place
        changed = dv(tmp_path, safe_search=1, **live)
        again = run_role(tmp_path, ROLE, "main", changed, env=env)
        assert again.returncode == 0, again.stdout + again.stderr
        assert len(restarts()) == 1  # a bind-mounted file is read at start: the new one needs it
        same = run_role(tmp_path, ROLE, "main", changed, env=env)
        assert same.returncode == 0 and "changed=0" in same.stdout, same.stdout
        assert len(restarts()) == 1


def test_the_containers_join_the_role_slice_the_module_play_names(tmp_path):
    v = dv(tmp_path, hnx_module_slice=f"hnx-{MID}-server.slice")
    assert run_role(tmp_path, ROLE, "main", v, env=SECRETS).returncode == 0
    assert compose(tmp_path)["services"][MID]["cgroup_parent"] == f"hnx-{MID}-server.slice"


def test_every_task_that_touches_the_secret_hides_it():
    """The key is read by name and rendered into one 0600 file: a task that looks it up or renders
    the settings logs nothing (no_log), so neither the run output nor a callback can carry it."""
    seen = 0
    for path in sorted((ROLE_DIR / "tasks").glob("*.yml")):
        for task in _tasks(yaml.safe_load(path.read_text())):
            text = json.dumps(task)
            if "hnx_secret" in text or "settings.yml" in text and "template" in text:
                seen += 1
                assert task.get("no_log") is True or _probe_only(task), (path.name, task.get("name"))
    assert seen >= 2


def _tasks(doc):
    for t in doc or []:
        if "block" in t:
            yield from _tasks(t["block"])
        else:
            yield t


def _probe_only(task: dict) -> bool:
    """The reference probe keeps only whether a lookup resolved, and says so under no_log too."""
    return task.get("no_log") is True


BAD = [
    ({"logical_id": "Search"}, "registry id"),
    ({"image": REPO + ":2026.11.9"}, "pinned by tag and digest"),
    ({"image": REPO + ":latest@sha256:" + "a" * 64}, "pinned by tag and digest"),
    ({"bind": "0.0.0.0"}, "not all interfaces"),
    ({"bind": "search.example.internal"}, "not all interfaces"),
    ({"port": 0}, "a port"),
    ({"uid": 0}, "never root"),
    ({"data_root": "/srv"}, "canonical directories"),
    ({"data_root": "/var/lib/../etc/x"}, "canonical directories"),
    ({"key_ref": "not-a-ref"}, "secret: reference"),
    ({"safe_search": 3}, "safe_search"),
    ({"safe_search": "off"}, "safe_search"),
    ({"request_timeout": 0}, "request_timeout"),
    ({"request_timeout": 120}, "request_timeout"),
    ({"instance_name": ""}, "instance name"),
    ({"instance_name": "x" * 100}, "instance name"),
    ({"engines_disabled": {"bing": True}}, "engines_disabled"),
    ({"engines_disabled": ["ok", "bad: name"]}, "engine names"),
    ({"engines_disabled": ["bing", "bing"]}, "engine names"),
    ({"health_query": ""}, "health query"),
    ({"health_query": "a&b=c"}, "health query"),
    ({"health_require_results": "yes please"}, "health_require_results"),
    ({"mem_limit": "lots"}, "memory limit"),
]


@pytest.mark.parametrize(("over", "why"), BAD, ids=[str(i) for i in range(len(BAD))])
def test_main_refuses_bad_inputs_and_writes_nothing(tmp_path, over, why):
    r = run_role(tmp_path, ROLE, "main", dv(tmp_path, **over), env=SECRETS)
    assert r.returncode != 0 and why in r.stdout + r.stderr, r.stdout + r.stderr
    assert not (tmp_path / "app").exists() and not (tmp_path / "data").exists()


def test_a_reference_with_no_value_is_named_and_nothing_is_written(tmp_path):
    r = run_role(tmp_path, ROLE, "main", dv(tmp_path), env={})
    out = r.stdout + r.stderr
    assert r.returncode != 0 and ref("secret-key") in out, out
    assert not (tmp_path / "app").exists() and not (tmp_path / "data").exists()


@pytest.mark.parametrize("value", ["short", "k" * 31, "has space " + "k" * 30, "k" * 20 + '"' + "k" * 20])
def test_a_too_short_or_malformed_secret_is_refused_and_never_printed(tmp_path, value):
    r = run_role(tmp_path, ROLE, "main", dv(tmp_path), env={KEY_ENV: value})
    out = r.stdout + r.stderr
    assert r.returncode != 0, out
    assert not (tmp_path / "app").exists() and not (tmp_path / "data").exists()
    assert value not in out


def test_the_secret_is_in_no_output_of_a_run(tmp_path):
    r = run_role(tmp_path, ROLE, "main", dv(tmp_path), env=SECRETS, verbose=True)
    assert r.returncode == 0 and KEY not in r.stdout + r.stderr


def test_readiness_passes_with_the_reference_and_names_a_missing_one(tmp_path):
    ok = run_role(tmp_path, ROLE, "credentials", dv(tmp_path), env=SECRETS)
    assert ok.returncode == 0, ok.stdout + ok.stderr
    bad = run_role(tmp_path, ROLE, "credentials", dv(tmp_path), env={})
    assert bad.returncode != 0 and ref("secret-key") in bad.stdout + bad.stderr


# ----------------------------------------------------------------------------- health


def _docker(tmp_path: Path, health: str = "healthy") -> dict:
    """A fake docker whose ``compose ps`` lists the service in ``health``."""
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    rows = json.dumps({"Service": MID, "State": "running", "Health": health}) + "\n"
    log = str(tmp_path / "docker.log")
    body = (
        f"import sys\nopen({log!r}, 'a').write(' '.join(sys.argv[1:]) + chr(10))\n"
        f"if 'ps' in sys.argv:\n    sys.stdout.write({rows!r})\n"
    )
    fake(bindir / "docker", body)
    return {"PATH": f"{bindir}:{os.environ['PATH']}"}


def _health(tmp_path, front, health="healthy", **kw):
    v = dv(tmp_path, bind=LOOPBACK, port=front.addr[1], **kw)
    env = {**SECRETS, **_docker(tmp_path, health)}
    assert run_role(tmp_path, ROLE, "main", v, env=SECRETS).returncode == 0  # the settings in place
    return run_role(tmp_path, ROLE, "health", v, env=env)


def test_health_passes_with_a_real_json_search_and_only_reads(tmp_path):
    with Server() as front:
        r = _health(tmp_path, front)
        paths = list(front.paths)
    assert r.returncode == 0, r.stdout + r.stderr
    assert paths == ["/healthz", "/search?q=debian&format=json"]


def test_health_asks_the_query_the_site_names(tmp_path):
    with Server() as front:
        r = _health(tmp_path, front, health_query="lab health")
        paths = list(front.paths)
    assert r.returncode == 0, r.stdout + r.stderr
    assert paths[-1] == "/search?q=lab+health&format=json" or paths[-1] == "/search?q=lab%20health&format=json"


def test_health_fails_when_the_search_returns_no_results(tmp_path):
    with Server(results=0) as front:
        r = _health(tmp_path, front)
    assert r.returncode != 0 and "no results" in r.stdout


def test_health_passes_an_empty_search_only_when_the_site_says_it_may_be_empty(tmp_path):
    with Server(results=0) as front:
        r = _health(tmp_path, front, health_require_results=False)
    assert r.returncode == 0, r.stdout + r.stderr


@pytest.mark.parametrize("kw", [{"body": "not json"}, {"body": {"x": 1}}, {"body": {"results": "x"}}])
def test_health_fails_on_a_body_that_is_not_a_result_list_even_when_empty_is_allowed(tmp_path, kw):
    with Server(**kw) as front:
        r = _health(tmp_path, front, health_require_results=False)
    assert r.returncode != 0 and "results" in r.stdout


def test_health_fails_when_the_json_format_is_refused(tmp_path):
    with Server(json_status=403) as front:
        r = _health(tmp_path, front)
    assert r.returncode != 0 and "403" in r.stdout


def test_health_fails_when_the_health_path_does_not_answer(tmp_path):
    with Server(healthz=500) as front:
        r = _health(tmp_path, front)
    assert r.returncode != 0 and "/healthz" in r.stdout


def test_health_fails_when_the_container_is_unhealthy(tmp_path):
    with Server() as front:
        r = _health(tmp_path, front, health="unhealthy")
    assert r.returncode != 0 and "unhealthy" in r.stdout + r.stderr


def test_health_fails_when_the_settings_file_is_not_private(tmp_path):
    with Server() as front:
        v = dv(tmp_path, bind=LOOPBACK, port=front.addr[1])
        assert run_role(tmp_path, ROLE, "main", v, env=SECRETS).returncode == 0
        (tmp_path / "data" / "config" / "settings.yml").chmod(0o644)
        r = run_role(tmp_path, ROLE, "health", v, env={**SECRETS, **_docker(tmp_path)})
    assert r.returncode != 0 and "0600" in r.stdout


# ----------------------------------------------------------------------------- upgrade, stateless hooks


def test_upgrade_records_a_pinned_target_and_refuses_the_rest(tmp_path):
    v = dv(tmp_path)
    assert run_role(tmp_path, ROLE, "main", v, env=SECRETS).returncode == 0
    new = REPO + ":2026.12.1-abcdef123@sha256:" + "b" * 64
    ok = run_role(tmp_path, ROLE, "upgrade", {**v, P + "target_image": new}, env=SECRETS)
    assert ok.returncode == 0, ok.stdout + ok.stderr
    for bad in (
        REPO + ":2026.12.1",  # not pinned
        REPO + ":2026.12.1@sha256:" + "b" * 63,  # a short digest
        "docker.io/other/app:2026.12.1@sha256:" + "b" * 64,  # another repository
    ):
        r = run_role(tmp_path, ROLE, "upgrade", {**v, P + "target_image": bad}, env=SECRETS)
        assert r.returncode != 0, bad


@pytest.mark.parametrize("hook", ["backup", "export", "restore"])
def test_the_stateless_hooks_say_so_and_write_nothing(tmp_path, hook):
    r = run_role(tmp_path, ROLE, hook, dv(tmp_path))
    assert r.returncode == 0, r.stdout + r.stderr
    assert not (tmp_path / "app").exists() and not (tmp_path / "data").exists()
