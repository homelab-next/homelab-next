# SPDX-License-Identifier: Apache-2.0
"""Every role task that sends a credential over HTTP (an ``ansible.builtin.uri`` or ``get_url``
task with an ``Authorization``, key or token header, or a URL password) follows no redirect
(``follow_redirects: none``; a 3xx is a failure, as ``status_code`` names the success code only)
and uses no proxy from the environment (``use_proxy: false``).  The module defaults (``safe``
redirects, ``use_proxy: true``) follow a GET's redirect to any origin with the header and hand
the request to ``HTTP(S)_PROXY``.  A static scan of ``ansible/roles/*/tasks/*.yml``."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
MODULES = {"uri", "get_url"}
CREDENTIAL = re.compile(r"authorization|api[-_ ]?key|token|secret|password", re.I)


def _tasks(items):
    for task in items or []:
        if not isinstance(task, dict):
            continue
        yield task
        for nested in ("block", "rescue", "always"):
            yield from _tasks(task.get(nested))


def credential_http_tasks():
    """[(file, task name, module args)] for each uri/get_url task that carries a credential."""
    found = []
    for path in sorted((ROOT / "ansible" / "roles").glob("*/tasks/*.yml")):
        for task in _tasks(yaml.safe_load(path.read_text())):
            for key, args in task.items():
                if key.rsplit(".", 1)[-1] not in MODULES or not isinstance(args, dict):
                    continue
                headers = args.get("headers") or {}
                if CREDENTIAL.search(str(headers)) or args.get("url_password"):
                    found.append((str(path.relative_to(ROOT)), task.get("name", "?"), args))
    return found


def _status_codes(args):
    codes = args.get("status_code", 200)
    return [int(c) for c in (codes if isinstance(codes, list) else str(codes).split(","))]


def test_a_task_sending_a_credential_follows_no_redirect_and_uses_no_proxy():
    found = credential_http_tasks()
    assert found, "the scan found no credential-carrying task (the model server's has one)"
    bad = [
        f"{path}: {name}"
        for path, name, args in found
        if args.get("follow_redirects") != "none"
        or args.get("use_proxy") is not False
        or any(300 <= c < 400 for c in _status_codes(args))
    ]
    assert bad == [], "needs follow_redirects: none, use_proxy: false and no 3xx success code"
