# SPDX-License-Identifier: Apache-2.0
"""The units of module cti-pipeline, rendered from the role's own templates and variables (no
ansible run: jinja2 with the few filters they use).

* Each job runs in each of its lanes as one instance, ``hnx-<id>@<job>-<lane>.service``.
* The template unit is the orchestration dispatcher's interface (modules/orchestration README,
  "Module job units": the run file loaded as the ``hnx-dispatch`` credential from
  ``<dispatch dir>/<set>/%i.json``, the log appended to ``<log dir>/<set>/%i.log``), hardened, in
  the module's slice, never enabled and writing nothing by itself.
* Each lane's drop-in and spec keep the lanes apart: the shadow lane's user, root and secrets only,
  its forced shadow schema and the stage-only publish mode, nothing of the real lane's; and the
  wrapper's own lane guard accepts what the role renders.
* The data root has one owner (#510): root's, read by the module's group, 0750; each lane's root
  and working directories its own user's, 0700; the export directory root's, 0700.
"""

from __future__ import annotations

import ast
import importlib.util
import json
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

from homelabnext.modules import loader as ld

jinja2 = pytest.importorskip("jinja2")
nativetypes = pytest.importorskip("jinja2.nativetypes")

ROOT = Path(__file__).resolve().parents[2]
ROLE = ROOT / "modules" / "cti-pipeline" / "roles" / "cti_pipeline"


def _env(native: bool):
    cls = nativetypes.NativeEnvironment if native else jinja2.Environment
    env = cls(undefined=jinja2.StrictUndefined, trim_blocks=True, keep_trailing_newline=True)
    env.filters["combine"] = lambda a, *b: {k: v for d in (a, *b) for k, v in d.items()}
    env.filters["to_nice_json"] = lambda v: json.dumps(v, indent=4, sort_keys=True)
    env.filters["int"] = lambda v: int(v)
    return env


LANES_SITE = {
    "cti_pipeline_logical_id": "intel",
    "cti_pipeline_artefact": "/srv/build/intel.tar.gz",
    "cti_pipeline_artefact_sha256": "a" * 64,
    "cti_pipeline_jobs": {
        "fresh": {"steps": [["{python}", "{app}/run.py", "--stage", "ingest"]], "timeout_s": 14400, "max_age_s": 7200},
        "cve": {"steps": [["{python}", "-m", "intel.cve"]], "timeout_s": 10800, "max_age_s": 0, "lanes": ["real"], "refs": ["SOCIAL_HANDLE"]},
    },
    "cti_pipeline_env": {"real": {"APP_MODE": "live"}, "shadow": {"APP_MODE": "trial"}},
    "cti_pipeline_lane_refs": {
        "real": {"FEED_USER": "secret:cti-pipeline/feed-user", "SOCIAL_HANDLE": "secret:cti-pipeline/social-handle"},
        "shadow": {"FEED_USER": "secret:cti-pipeline/feed-shadow-user"},
    },
    "hnx_module_slice": "hnx-cti_pipeline-worker.slice",
}  # fmt: skip


def role_vars(site: dict) -> dict:
    """The role's defaults and vars with the site's values, every expression resolved (nested ones
    too: a mapping's values are expressions of their own)."""
    ctx = {
        **ld.load_yaml(ROLE / "defaults" / "main.yml"),
        **ld.load_yaml(ROLE / "vars" / "main.yml"),
        **site,
    }
    env = _env(native=True)

    def resolve(v):
        if isinstance(v, dict):
            return {k: resolve(x) for k, x in v.items()}
        if isinstance(v, list):
            return [resolve(x) for x in v]
        if not isinstance(v, str) or "{{" not in v:
            return v
        try:
            out = env.from_string(v).render(**ctx)
        except Exception:  # an expression of ansible's own filters, not needed here
            return v
        return ast.literal_eval(out) if isinstance(out, str) and out[:1] in "[{" else out

    for _ in range(8):
        ctx = {k: resolve(v) for k, v in ctx.items()}
    return ctx


def render(name: str, ctx: dict, item=None) -> str:
    text = (ROLE / "templates" / name).read_text()
    return _env(native=False).from_string(text).render(**ctx, item=item)


@pytest.fixture(scope="module")
def site():
    ctx = role_vars(LANES_SITE)
    return ctx, {i["instance"]: i for i in ctx["cti_pipeline_instances"]}


def test_each_job_runs_in_each_of_its_lanes_as_one_instance(site):
    _ctx, inst = site
    assert sorted(inst) == ["cve-real", "fresh-real", "fresh-shadow"]
    assert inst["fresh-shadow"]["unit"].split("@") == ["hnx-intel", "fresh-shadow.service"]
    assert inst["fresh-shadow"]["spec"] == "/etc/hnx/intel/jobs/fresh-shadow.json"


def test_the_template_unit_is_the_dispatchers_interface_and_hardened(site):
    ctx, _ = site
    unit = render("job.service.j2", ctx)
    lines = set(unit.splitlines())
    # modules/orchestration (Module job units): the run file and the log, per set and instance
    assert (
        "LoadCredential=hnx-dispatch:/var/lib/hnx-modules/orchestration/dispatch/intel/%i.json"
        in lines
    )
    assert "StandardOutput=append:/var/log/hnx-jobs/intel/%i.log" in lines
    assert (
        "ExecStart=/opt/hnx/intel/bin/hnx-cti-run --spec /etc/hnx/intel/jobs/%i.json --instance %i"
        in lines
    )
    assert {"Type=oneshot", "User=hnx-intel-shadow", "Slice=hnx-cti_pipeline-worker.slice"} <= lines
    assert {"NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=yes", "CapabilityBoundingSet=",
            "SystemCallFilter=@system-service", "PrivateTmp=yes", "UMask=0077"} <= lines  # fmt: skip
    assert "[Install]" not in unit and not any(x.startswith("ReadWritePaths=") for x in lines)


def test_the_lanes_are_kept_apart_and_the_shadow_lane_never_publishes(site):
    ctx, inst = site
    shadow = render("job-lane.conf.j2", ctx, inst["fresh-shadow"])
    real = render("job-lane.conf.j2", ctx, inst["fresh-real"])
    assert "User=hnx-intel-shadow" in shadow and "User=hnx-intel" in real.splitlines()
    assert "ReadWritePaths=/var/lib/hnx-modules/intel/shadow" in shadow.splitlines()
    assert [x for x in shadow.splitlines() if x.startswith("LoadCredential=")] == [
        "LoadCredential=FEED_USER:/etc/hnx/intel/credentials/shadow/FEED_USER"]  # fmt: skip
    assert "/intel/real" not in shadow and "credentials/real" not in shadow
    sspec = json.loads(render("job-spec.json.j2", ctx, inst["fresh-shadow"]))
    rspec = json.loads(render("job-spec.json.j2", ctx, inst["fresh-real"]))
    assert sspec["forced_env"] == {"CTI_LAKE_SCHEMA": "cti_shadow", "PUBLISH_MODE": "stage"}
    assert rspec["forced_env"] == {"CTI_LAKE_SCHEMA": "cti", "PUBLISH_MODE": "stage"}
    assert sspec["lane_root"] == "/var/lib/hnx-modules/intel/shadow" and sspec["credentials"] == [
        "FEED_USER"
    ]
    assert sspec["env"] == {"APP_MODE": "trial"} and "/intel/real" not in json.dumps(sspec)
    assert rspec["credentials"] == ["FEED_USER", "SOCIAL_HANDLE"]
    cve = json.loads(render("job-spec.json.j2", ctx, inst["cve-real"]))
    assert cve["credentials"] == ["SOCIAL_HANDLE"]  # a job's refs narrow its lane's
    assert "LoadCredential=FEED_USER" not in render("job-lane.conf.j2", ctx, inst["cve-real"])
    # what the role renders, the wrapper accepts: its own lane guard passes both specs
    loader = SourceFileLoader("hnx_cti_run_units", str(ROLE / "files" / "hnx-cti-run"))
    run = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
    loader.exec_module(run)
    run.lane_guard(sspec)
    run.lane_guard(rspec)


def test_the_data_root_has_one_owner_and_each_lane_root_its_own_user(site):
    ctx, _ = site
    tasks = {t["name"]: t for t in ld.load_yaml(ROLE / "tasks" / "dirs.yml")}
    root = tasks[
        "Create the data root (root's, read by the module's group) and the export directory (root's)"
    ]
    env = _env(native=True)
    resolve = lambda v: env.from_string(v).render(**ctx) if isinstance(v, str) else v  # noqa: E731
    items = {resolve(i["path"]): i for i in root["loop"]}
    assert resolve(root["ansible.builtin.file"]["owner"]) == "root"
    data_root = items["/var/lib/hnx-modules/intel"]
    assert (resolve(data_root["group"]), data_root["mode"]) == ("hnx-intel", "0750")
    assert (
        resolve(items["/var/lib/hnx-modules/intel/export"]["group"]),
        items["/var/lib/hnx-modules/intel/export"]["mode"],
    ) == ("root", "0700")
    lanes = tasks["Create each lane's root and its working directories (the lane's user's alone)"][
        "ansible.builtin.file"
    ]
    assert lanes["mode"] == "0700" and "cti_pipeline_lane_user[item.0]" in lanes["owner"]
    assert {"publishable", "dist", "home", "cache", "hnx-runs", "data", "state", "podcast"} <= set(
        ctx["cti_pipeline_lane_dirs"]
    )
    assert ctx["cti_pipeline_lane_user"] == {"real": "hnx-intel", "shadow": "hnx-intel-shadow"}
