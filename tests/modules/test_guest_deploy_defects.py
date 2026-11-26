# SPDX-License-Identifier: Apache-2.0
"""Regression tests for five defects found deploying to a real guest: each assertion fails on the
tree before its fix."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]


def _tasks(rel: str) -> list[dict]:
    return yaml.safe_load((ROOT / rel).read_text())


def _by_module(tasks: list[dict], module: str) -> list[dict]:
    return [t for t in tasks if module in t]


def test_orchestration_creates_the_shared_etc_parent_traversable():
    tasks = _tasks("modules/orchestration/roles/orchestration/tasks/config.yml")
    dirs = _by_module(tasks, "ansible.builtin.file")
    parent = [t for t in dirs if "dirname" in str(t["ansible.builtin.file"]["path"])]
    assert parent, "the parent of the config dir must be created explicitly"
    args = parent[0]["ansible.builtin.file"]
    # root's (the owner variables, root:root by default), never the service group
    assert "orchestration_group" not in str(args["group"])
    assert (args["owner"], args["group"]) == (
        "{{ orchestration_owner }}",
        "{{ orchestration_owner_group }}",
    )
    assert str(args["mode"]) == "0755"
    # and it comes before the restrictive directory task
    assert tasks.index(parent[0]) < tasks.index(
        next(t for t in dirs if str(t["ansible.builtin.file"]["mode"]) == "0750")
    )


def test_the_cti_current_link_does_not_follow_into_the_release():
    tasks = _tasks("modules/cti-pipeline/roles/cti_pipeline/tasks/artefact.yml")
    link = [t for t in tasks if t.get("ansible.builtin.file", {}).get("state") == "link"]
    assert link and link[0]["ansible.builtin.file"].get("follow") is False


def test_the_model_store_cli_install_has_packaging_before_pip():
    tasks = _tasks("ansible/roles/model_store/tasks/install_cli.yml")
    names = [t for t in tasks if "ansible.builtin.package" in t]
    pkgs = [
        p
        for t in names
        for p in t["ansible.builtin.package"]["name"]
        if isinstance(t["ansible.builtin.package"]["name"], list)
    ]
    assert "python3-packaging" in pkgs
    pip_at = next(i for i, t in enumerate(tasks) if "ansible.builtin.pip" in t)
    pkg_at = next(i for i, t in enumerate(tasks) if "python3-packaging" in str(t))
    assert pkg_at < pip_at


@pytest.mark.static
def test_the_automation_front_reaches_its_services_by_absolute_names():
    found = 0
    for path in ROOT.glob("modules/*/roles/*/vars/main.yml"):
        for key, svc in (yaml.safe_load(path.read_text()) or {}).items():
            if key.endswith("_c_services") and {"api", "auth", "stream"} <= set(svc):
                found += 1
                for name in ("api", "auth", "stream"):
                    assert svc[name]["host"].endswith("."), (
                        f"{path}: {name} goes through the search domain first"
                    )
    assert found == 1


@pytest.mark.static
def test_the_tts_build_recipe_tags_the_pinned_repository():
    pinned = "localhost/hnx-tts"
    for rel in ("modules/tts/README.md", "modules/tts/image/Dockerfile"):
        text = (ROOT / rel).read_text()
        for line in text.splitlines():
            if line.startswith(
                ("docker build", "docker save", "docker image inspect", "#   docker build")
            ):
                assert pinned + ":" in line, f"{rel}: {line}"
