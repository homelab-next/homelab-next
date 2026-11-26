# SPDX-License-Identifier: Apache-2.0
"""The scheduled copy of the state that is no database server's (ADR-0008 decision 1, ADR-0042 decision 2):
every module that names ``compose_app_export_files`` in its application spec hands them to compose_app in
its main hook (a spec entry the include forgets is a nightly copy that never happens), and what it names is
a kind the dump script knows, under the module's own data root. The status hub schedules its state through
the same timer. The script and the role's own behaviour are in test_compose_app_export_timer.py."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
APPS = sorted(
    p
    for p in [
        *(ROOT / "modules").glob("*/roles/*/tasks/app.yml"),
        *(ROOT / "ansible/roles").glob("*/tasks/app.yml"),
    ]
    if "compose_app_export_files" in p.read_text()
)


def _walk(node):
    if isinstance(node, dict):
        yield node
        for v in node.values():
            yield from _walk(v)
    elif isinstance(node, list):
        for v in node:
            yield from _walk(v)


def _spec_files(app_yml: Path):
    for d in _walk(yaml.safe_load(app_yml.read_text())):
        if "compose_app_export_files" in d:
            return d["compose_app_export_files"]
    raise AssertionError(f"{app_yml}: no compose_app_export_files")


def test_the_stateful_products_without_a_database_server_are_covered():
    assert len(APPS) >= 5


@pytest.mark.parametrize("app", APPS, ids=lambda p: p.parts[-4])
def test_a_module_hands_its_export_files_to_compose_app_and_names_known_kinds(app):
    files = _spec_files(app)
    assert files and len({f["name"] for f in files}) == len(files)
    for f in files:
        assert f["kind"] in ("sqlite", "tree")
        assert f["name"].replace("-", "").isalnum()
        assert f["glob" if f["kind"] == "sqlite" else "path"].startswith("{{ ")
    main = yaml.safe_load((app.parent / "main.yml").read_text())
    passes = [
        d["vars"]
        for d in _walk(main)
        if isinstance(d.get("vars"), dict)
        and "compose_app_export_files" in d["vars"]
        and d.get("ansible.builtin.include_role", {}).get("name") == "compose_app"
    ]
    assert passes, (
        f"{app.parent / 'main.yml'}: compose_app_export_files is not passed to compose_app"
    )
    assert passes[0]["compose_app_export_files"].endswith("compose_app_export_files }}")


@pytest.mark.static
def test_the_status_hub_schedules_its_state_through_the_same_timer_when_the_lab_turns_it_on():
    tasks = yaml.safe_load((ROOT / "ansible/roles/status_hub/tasks/main.yml").read_text())
    task = next(
        t
        for t in tasks
        if t.get("ansible.builtin.include_role", {}).get("tasks_from") == "export_timer"
    )
    assert task["ansible.builtin.include_role"]["name"] == "compose_app"
    assert "compose_app_export_timer" in task["when"]
    kinds = {f["kind"] for f in task["vars"]["compose_app_export_files"]}
    assert kinds == {"sqlite", "tree"}
    assert task["vars"]["compose_app_export_dir"] == "{{ status_hub_export_dir }}"
