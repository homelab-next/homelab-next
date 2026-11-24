# SPDX-License-Identifier: Apache-2.0
"""modules/velociraptor's client role downloads the pinned release on the controller into
``velociraptor_client_controller_cache``: the directory is created first (owner only), under the
same condition as the download, so a fresh controller is not a hand step."""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
TASKS = ROOT / "modules/velociraptor/roles/velociraptor_client/tasks/binary.yml"


def test_the_download_directory_is_created_before_the_fetch_under_the_same_condition():
    tasks = yaml.safe_load(TASKS.read_text())
    mkdir = next(i for i, t in enumerate(tasks) if "ansible.builtin.file" in t)
    fetch = next(i for i, t in enumerate(tasks) if "ansible.builtin.get_url" in t)
    assert mkdir < fetch
    d, f = tasks[mkdir], tasks[fetch]
    assert d["ansible.builtin.file"]["path"] == "{{ velociraptor_client_controller_cache }}"
    assert d["ansible.builtin.file"]["state"] == "directory"
    assert d["ansible.builtin.file"]["mode"] == "0700"
    for key in ("delegate_to", "become", "run_once", "when"):
        assert d[key] == f[key]
