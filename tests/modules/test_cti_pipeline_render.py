# SPDX-License-Identifier: Apache-2.0
"""Module cti-pipeline's role expressions rendered by ansible's own templar (not a stand-in), so
a filter, a test or an operator's precedence is the one a play applies:

* quiesce.yml's unit list from systemd's real ``list-units --all --plain --no-legend`` lines (job
  names with dashes, the other lane, another set, a capitalised name, an old systemd's leading
  bullet on a failed unit, a declared unit also loaded): every lane unit once, sorted;
* validate.yml's shadow-lane allowlist (what is refused, what passes);
* main.yml's busy and stale quiesce markers (a fresh marker keeps its lane masked, an old one is
  lifted) and the install's unmask, which leaves a lane being quiesced alone.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from homelabnext.modules import loader as ld

pytest.importorskip("ansible.errors")  # the repo's own ansible/ dir also imports as "ansible"
from ansible.parsing.dataloader import DataLoader
from ansible.template import Templar, trust_as_template

ROLE = Path(__file__).resolve().parents[2] / "modules" / "cti-pipeline" / "roles" / "cti_pipeline"
VARS = ld.load_yaml(ROLE / "vars" / "main.yml")


def unit(instance: str, unit_set: str = "cti") -> str:
    """A job unit's name, hnx-<set>@<instance>.service."""
    return "".join(["hnx-", unit_set, "@", instance, ".service"])


def render(expr: str, **variables):
    return Templar(loader=DataLoader(), variables=variables).template(trust_as_template(expr))


def _task(file: str, name: str) -> dict:
    tasks = ld.load_yaml(ROLE / "tasks" / file)
    flat = [t for x in tasks for t in (x.get("block") or [x])]
    return next(t for t in flat if t.get("name") == name)


# systemd 259, list-units --all --plain --no-legend: unit load active sub description
LOADED = [
    unit("daily-feed-real") + " loaded activating start cti-pipeline cti job daily-feed-real",
    unit("old-multi-dash-job-real") + " loaded inactive dead cti-pipeline cti job old",
    "● " + unit("bullet-job-real") + " loaded failed failed cti-pipeline cti job bullet",
    unit("x-shadow") + " loaded active running cti-pipeline cti job x-shadow",
    unit("evil-real", "ctiX") + " loaded inactive dead another set",
    unit("Upper-real") + " loaded inactive dead not a slug",
    "",
]


def test_quiesce_lists_each_unit_of_the_lane_once_from_systemds_real_output():
    expr = _task("quiesce.yml", "Name the lane's units")["ansible.builtin.set_fact"][
        "cti_pipeline_quiesce_units"
    ]
    units = render(
        expr,
        cti_pipeline_logical_id="cti",
        cti_pipeline_quiesce_lane="real",
        cti_pipeline_instances=[
            {"lane": "real", "unit": unit("daily-feed-real")},
            {"lane": "shadow", "unit": unit("daily-feed-shadow")},
        ],
        cti_pipeline_quiesce_loaded={"stdout_lines": LOADED},
    )
    assert units == [
        unit("bullet-job-real"),
        unit("daily-feed-real"),
        unit("old-multi-dash-job-real"),
    ]


@pytest.mark.parametrize(
    ("step", "ok"),
    [
        (["{python}", "-m", "intel.cve", "--all"], True),
        (["{python}", "{app}/run.py", "--stage", "x"], True),
        (["{app}/scripts/episode.sh", "weekly"], True),
        (["/opt/site/tool"], True),  # listed
        (["/opt/other/tool"], False),
        (["{python}", "-Ic", "1"], False),
        (["{python}", "-I", "{app}/run.py"], False),
        (["{python}", "-m", "a;b"], False),
        (["{python}", "{app}/../x.py"], False),
        (["{app}/a/./b"], False),
        (["/bin/sh", "-c", "x"], False),
        (["/usr/bin/timeout", "9", "bash", "-c", "x"], False),
        (["/usr/bin/find", ".", "-exec", "x", ";"], False),
    ],
)
def test_the_roles_shadow_allowlist(step, ok):
    modules = ["intel"]  # the app's package: -m intel.cve passes
    task = _task(
        "validate.yml",
        "Refuse a shadow-lane job that runs a program off the allowlist or names the real lake schema",
    )
    offlist = render(
        task["vars"]["cti_pipeline_shadow_offlist"],
        item={"job": "j", "lane": "shadow"},
        cti_pipeline_jobs={"j": {"steps": [step]}},
        cti_pipeline_shadow_programs=["/opt/site/tool"],
        cti_pipeline_shadow_modules=modules,
        cti_pipeline_module_pattern=VARS["cti_pipeline_module_pattern"],
        cti_pipeline_app_path_pattern=VARS["cti_pipeline_app_path_pattern"],
    )
    assert (offlist == []) is ok, offlist


def test_a_fresh_quiesce_marker_keeps_its_lane_masked_and_an_old_one_is_lifted():
    facts = _task("main.yml", "Name the lanes an export or restore is quiescing right now")[
        "ansible.builtin.set_fact"
    ]
    variables = {
        "cti_pipeline_owner": "root",
        "cti_pipeline_quiesce_marker_max_age_s": 21600,
        "cti_pipeline_markers": {"results": [
            {"item": "real", "stat": {"exists": True, "mtime": 4_000_000_000, "pw_name": "root"}},  # just written
            {"item": "shadow", "stat": {"exists": True, "mtime": 0, "pw_name": "root"}},  # left by a play that died
        ]},
    }  # fmt: skip
    assert render(facts["cti_pipeline_busy_lanes"], **variables) == ["real"]
    assert render(facts["cti_pipeline_stale_markers"], **variables) == ["shadow"]
    variables["cti_pipeline_markers"]["results"] = [{"item": "real", "stat": {"exists": False}}]
    assert render(facts["cti_pipeline_busy_lanes"], **variables) == []
    assert render(facts["cti_pipeline_stale_markers"], **variables) == []


def test_the_install_unmasks_every_instance_but_those_of_a_lane_being_quiesced():
    argv = _task(
        "main.yml", "Lift any runtime mask an aborted export or restore left on the job units"
    )["ansible.builtin.command"]["argv"]
    instances = [
        {"lane": "real", "unit": unit("fresh-real")},
        {"lane": "shadow", "unit": unit("fresh-shadow")},
    ]
    out = render(argv, cti_pipeline_systemctl_cli="systemctl", cti_pipeline_instances=instances,
                 cti_pipeline_busy_lanes=["real"])  # fmt: skip
    assert out == ["systemctl", "unmask", "--runtime", unit("fresh-shadow")]
    out = render(argv, cti_pipeline_systemctl_cli="systemctl", cti_pipeline_instances=instances,
                 cti_pipeline_busy_lanes=[])  # fmt: skip
    assert out[3:] == [unit("fresh-real"), unit("fresh-shadow")]


@pytest.mark.parametrize(
    ("module", "modules", "ok"),
    [("intel.cve", ["intel"], True), ("intel", ["intel"], True), ("timeit", ["intel"], False),
     ("http.server", ["intel"], False), ("cProfile", ["intel"], False), ("intelx.y", ["intel"], False),
     ("timeit", [], True)],  # nothing listed: the wrapper decides from the artefact's packages
)  # fmt: skip
def test_the_roles_shadow_modules(module, modules, ok):
    task = _task(
        "validate.yml",
        "Refuse a shadow-lane job that runs a program off the allowlist or names the real lake schema",
    )
    offlist = render(
        task["vars"]["cti_pipeline_shadow_offlist"],
        item={"job": "j", "lane": "shadow"},
        cti_pipeline_jobs={"j": {"steps": [["{python}", "-m", module]]}},
        cti_pipeline_shadow_programs=[],
        cti_pipeline_shadow_modules=modules,
        cti_pipeline_module_pattern=VARS["cti_pipeline_module_pattern"],
        cti_pipeline_app_path_pattern=VARS["cti_pipeline_app_path_pattern"],
    )
    assert (offlist == []) is ok, offlist


def test_a_quiesce_marker_the_role_did_not_write_is_ignored():
    facts = _task("main.yml", "Name the lanes an export or restore is quiescing right now")[
        "ansible.builtin.set_fact"
    ]
    variables = {
        "cti_pipeline_owner": "root",
        "cti_pipeline_quiesce_marker_max_age_s": 21600,
        "cti_pipeline_markers": {"results": [
            {"item": "real", "stat": {"exists": True, "mtime": 4_000_000_000, "pw_name": "hnx-cti"}},
            {"item": "shadow", "stat": {"exists": True, "mtime": 4_000_000_000, "pw_name": "root"}},
        ]},
    }  # fmt: skip
    assert render(facts["cti_pipeline_foreign_markers"], **variables) == ["real"]
    assert render(facts["cti_pipeline_busy_lanes"], **variables) == ["shadow"]
    assert render(facts["cti_pipeline_stale_markers"], **variables) == []


@pytest.mark.parametrize(
    ("modules", "ok"), [(["intel"], True), (["intel", "timeit"], False), (["pip"], False)]
)
def test_the_role_refuses_an_interpreter_module_as_an_app_package(modules, ok):
    that = _task(
        "validate.yml",
        "Refuse an interpreter module or installer named as one of the app's packages",
    )["ansible.builtin.assert"]["that"][0]
    verdict = render(
        "{{ " + that + " }}",
        cti_pipeline_shadow_modules=modules,
        cti_pipeline_stdlib_names={"stdout": '["os", "sys", "timeit"]'},
        cti_pipeline_not_app_packages=VARS["cti_pipeline_not_app_packages"],
    )
    assert verdict is ok


@pytest.mark.parametrize(
    ("owner", "ok"), [("root", True), ("hnx-cti", False), ("hnx-cti-shadow", False)]
)
def test_the_owner_is_never_a_lane_user(owner, ok):
    that = ld.load_yaml(ROLE / "tasks" / "validate.yml")[0]["ansible.builtin.assert"]["that"]
    expr = next(x for x in that if x.startswith("cti_pipeline_owner not in"))
    verdict = render(
        "{{ " + expr + " }}",
        cti_pipeline_owner=owner,
        cti_pipeline_user="hnx-cti",
        cti_pipeline_shadow_user="hnx-cti-shadow",
    )
    assert verdict is ok
