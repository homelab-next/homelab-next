# SPDX-License-Identifier: Apache-2.0
"""The units of module cti-pipeline, rendered from the role's own templates and variables (no
ansible run: jinja2 with the few filters they use).

* Each job runs in each of its lanes as one instance, ``hnx-<id>@<job>-<lane>.service``.
* The template unit is the orchestration dispatcher's interface (modules/orchestration README,
  "Module job units", contract v3: no run file loaded by PID 1, the run-file group hnx-<service>_<set> joined, the spec
  naming ``<dispatch dir>/<set>/%i.json`` and its owner for the job to read itself, the log
  appended to ``<log dir>/<set>/%i.log``), hardened, in the module's slice, never enabled and
  writing nothing by itself.
* The real schema as a token: what the role refuses in a shadow job's arguments and env.
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
import re
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
    env.filters["regex_escape"] = re.escape
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
    # modules/orchestration (Module job units, contract v2): the job reads its own run file
    assert not any(x.startswith("LoadCredential=") for x in lines)
    assert "SupplementaryGroups=hnx-orchestrator_intel" in lines
    assert "StandardOutput=append:/var/log/hnx-jobs/intel/%i.log" in lines
    assert (
        "ExecStart=/opt/hnx/intel/bin/hnx-cti-run --spec /etc/hnx/intel/jobs/%i.json --instance %i"
        in lines
    )
    assert {"Type=oneshot", "User=hnx-intel-shadow", "Slice=hnx-cti_pipeline-worker.slice"} <= lines
    assert {"NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=yes", "CapabilityBoundingSet=",
            "SystemCallFilter=@system-service", "PrivateTmp=yes", "UMask=0077"} <= lines  # fmt: skip
    assert "[Install]" not in unit and not any(x.startswith("ReadWritePaths=") for x in lines)


def test_the_job_unit_keeps_the_sandbox_that_refuses_a_setgid_chmod():
    # read as plain text (no jinja needed): the handoff sets no setgid bit because this stays on
    text = (ROLE / "templates" / "job.service.j2").read_text()
    assert "RestrictSUIDSGID=yes" in text.splitlines()


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
    assert sspec["lane_root"] == "/var/lib/hnx-modules/intel/shadow" and "credentials" not in sspec
    assert sspec["env"] == {"APP_MODE": "trial"} and "/intel/real" not in json.dumps(sspec)
    loads = lambda conf: [x for x in conf.splitlines() if x.startswith("LoadCredential=")]  # noqa: E731
    assert [x.split(":")[0] for x in loads(real)] == [
        "LoadCredential=FEED_USER",
        "LoadCredential=SOCIAL_HANDLE",
    ]
    cve = loads(render("job-lane.conf.j2", ctx, inst["cve-real"]))
    assert [x.split(":")[0] for x in cve] == [
        "LoadCredential=SOCIAL_HANDLE"
    ]  # a job's refs narrow its lane's
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


def test_the_spec_names_the_run_file_its_owner_and_the_lanes_consumed_runs(site):
    ctx, inst = site
    spec = json.loads(render("job-spec.json.j2", ctx, inst["fresh-shadow"]))
    assert spec["run_file"] == "/var/lib/hnx-dispatch/orchestrator/intel/fresh-shadow.json"
    assert spec["run_owner"] == "hnx-orchestrator"
    assert spec["consumed_dir"] == "/var/lib/hnx-modules/intel/shadow/hnx-consumed"
    assert spec["release_link"] == "/opt/hnx/intel/current" and spec["real_lake_schema"] == "cti"
    assert "hnx-consumed" in ctx["cti_pipeline_lane_dirs"]


@pytest.mark.parametrize(
    ("text", "hit"),
    [("cti", True), ("--schema=cti", True), ("cti.items", True), ("a cti b", True),
     ("CTI", True), ("--schema=CTI", True), ("Cti.items", True), ("lake.cti.items", True),
     ("`cti`", True), ("(cti)", True), ("[cti]", True), ("cti;", True), ("{cti}", True),
     ("cti_shadow", False), ("cti-rollup", False), ("/var/cti/x", False), ("hnx-cti", False)],
)  # fmt: skip
def test_the_real_schema_token_the_role_refuses_in_a_shadow_job(site, text, hit):
    ctx, _ = site
    assert bool(re.search(ctx["cti_pipeline_real_schema_token"].strip(), text)) is hit


def test_the_run_file_group_fits_its_32_characters_only_with_a_short_enough_id():
    ok = role_vars({**LANES_SITE, "cti_pipeline_logical_id": "a" * 15})
    assert ok["cti_pipeline_dispatch_group"] == "hnx-orchestrator_" + "a" * 15
    assert len(ok["cti_pipeline_dispatch_group"]) == 32
    long = role_vars({**LANES_SITE, "cti_pipeline_logical_id": "a" * 16})
    assert len(long["cti_pipeline_dispatch_group"]) == 33  # validate.yml refuses it (at most 32)
    validate = (ROLE / "tasks" / "validate.yml").read_text()
    assert "cti_pipeline_dispatch_group | length <= 32" in validate


def test_a_converge_lifts_runtime_masks_and_health_refuses_a_masked_unit():
    """An export or restore that died before its always: leaves the lane's units masked; the
    install unmasks every declared instance, and health fails while one is masked."""
    # the install's unmask (busy lanes left alone) is rendered in test_cti_pipeline_render.py
    health = ld.load_yaml(ROLE / "tasks" / "health.yml")[0]["block"]
    names = [t["name"] for t in health]
    show = health[names.index("Read each job unit's load state")]["ansible.builtin.command"]["argv"]
    assert "--property=Id,LoadState" in show
    check = health[
        names.index(
            "No job unit is masked (an export or restore that died before it unmasked them)"
        )
    ]
    assert (
        check["ansible.builtin.assert"]["that"]
        == "'LoadState=masked' not in cti_pipeline_load_states.stdout_lines"
    )


def test_quiesce_also_blocks_a_loaded_instance_the_site_no_longer_declares():
    tasks = ld.load_yaml(ROLE / "tasks" / "quiesce.yml")
    listing = tasks[0]["ansible.builtin.command"]["argv"]
    assert listing[1:5] == ["list-units", "--all", "--plain", "--no-legend"]
    assert (
        listing[5] == "hnx-{{ cti_pipeline_logical_id }}@*-{{ cti_pipeline_quiesce_lane }}.service"
    )
    names = tasks[1]["ansible.builtin.set_fact"]["cti_pipeline_quiesce_units"]
    assert "cti_pipeline_quiesce_loaded.stdout_lines" in names and "unique" in names


def test_synapse_ca_placeholder_is_only_named_when_the_ref_is_set(site):
    ctx, inst = site
    off = json.loads(render("job-spec.json.j2", ctx, inst["fresh-real"]))
    assert "synapse_ca" not in off["placeholders"]
    on_ctx = {**ctx, "cti_pipeline_synapse_ca_ref": "secret:cti-pipeline/synapse-ca"}
    on = json.loads(render("job-spec.json.j2", on_ctx, inst["fresh-real"]))
    assert on["placeholders"]["synapse_ca"] == f"{ctx['cti_pipeline_config_dir']}/synapse-ca.pem"
    assert "lake_ca" not in on["placeholders"]  # independent of the lake CA ref


def test_the_wrapper_accepts_the_synapse_ca_placeholder():
    text = (ROLE / "files" / "hnx-cti-run").read_text()
    assert '"lake_ca", "synapse_ca")' in text
