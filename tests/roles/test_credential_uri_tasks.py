# SPDX-License-Identifier: Apache-2.0
"""Every Ansible task that sends a credential over HTTP keeps it on one origin and off any
proxy from the environment.  The module defaults (``safe`` redirects, ``use_proxy: true``) follow
a GET's redirect to any origin with the header and hand the request to ``HTTP(S)_PROXY``.

* ``uri``: ``follow_redirects: none``, ``use_proxy: false``, and no 3xx success code (a 3xx is
  then a failure).
* ``get_url`` (it has no ``follow_redirects``): ``use_proxy: false``, and every credential
  header named in ``unredirected_headers`` (so a redirect does not carry it).

A task carries a credential when it has a header whose name or value looks like one, a
``url_password``/``password``, a ``url_username``/``username`` with ``force_basic_auth``, a
``client_key``/``client_cert``, or userinfo in its ``url``.  A ``headers`` value that is a template
string cannot be inspected, so it is refused unless reviewed in ``HEADERS_REVIEWED`` (and is
then held to the rules with the header names recorded there).  ``module_defaults`` may not set
any of these for ``uri``/``get_url``: a default applies to tasks this scan cannot tie it to.

A static scan of ``ansible/roles/*/{tasks,handlers}`` and ``ansible/playbooks``, with in-test
YAML fixtures for each rule."""

from __future__ import annotations

import re
import shlex
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
ANSIBLE = ROOT / "ansible"
MODULES = {"uri", "get_url"}
PREFIXES = ("", "ansible.builtin.", "ansible.legacy.")
CRED_HEADER = re.compile(r"authorization|api[-_]?key|token|secret|cookie|auth", re.I)
CRED_VALUE = re.compile(r"bearer|basic\s|hnx_secret|password|token", re.I)
USERINFO = re.compile(r"://[^/]*@")
CRED_KEYS = {"headers", "url_password", "password", "url_username", "username",
             "force_basic_auth", "client_key", "client_cert", "url"}  # fmt: skip

# (file path suffix, task name) -> (the credential headers the template builds, why reviewed)
HEADERS_REVIEWED = {
    ("tasks/health.yml", "Ask each instance what it serves"): (
        ("Authorization",),
        "the model server role's health check: only Authorization: Bearer from the hnx_secret"
        " lookup, or no header",
    ),
}


def _reviewed(label, name):
    for (suffix, task), entry in HEADERS_REVIEWED.items():
        if label.endswith("/" + suffix) and name == task:
            return entry
    return None


def _module(name):
    for prefix in PREFIXES:
        if isinstance(name, str) and name.startswith(prefix) and name[len(prefix) :] in MODULES:
            return name[len(prefix) :]
    return None


def _kv(text):
    """``k=v k2=v2`` free-form arguments as a dict (the first bare word is returned apart)."""
    args, bare = {}, []
    for word in shlex.split(text):
        k, eq, v = word.partition("=")
        if eq:
            args[k] = v
        else:
            bare.append(word)
    return bare, args


def _call(task):
    """(module, args) of a task that runs uri or get_url, in any form; None otherwise."""
    for key, value in task.items():
        mod = _module(key)
        if mod:
            args = _kv(value)[1] if isinstance(value, str) else dict(value or {})
            return mod, {**args, **(task.get("args") or {})}
        if key in ("action", "local_action"):
            if isinstance(value, str):
                bare, args = _kv(value)
                mod = _module(bare[0]) if bare else None
            elif isinstance(value, dict):
                args = {k: v for k, v in value.items() if k != "module"}
                mod = _module(value.get("module"))
            else:
                mod = None
            if mod:
                return mod, {**args, **(task.get("args") or {})}
    return None


def _dicts(node):
    if isinstance(node, dict):
        yield node
        for v in node.values():
            yield from _dicts(v)
    elif isinstance(node, list):
        for v in node:
            yield from _dicts(v)


def _status_codes(args):
    codes = args.get("status_code", 200)
    codes = codes if isinstance(codes, list) else str(codes).split(",")
    return [int(c) for c in codes if str(c).strip().isdigit()]


def scan(label, text):
    """(credential tasks found, problems) for one YAML file's text, labelled ``label``."""
    found, problems = [], []
    for doc in yaml.safe_load_all(text):
        for node in _dicts(doc):
            defaults_map = node.get("module_defaults")
            for name, defaults in (defaults_map if isinstance(defaults_map, dict) else {}).items():
                named = _module(name) or str(name).startswith("group/")
                if named and isinstance(defaults, dict) and set(defaults) & CRED_KEYS:
                    problems.append(
                        f"{label}: module_defaults for {name} sets {sorted(set(defaults) & CRED_KEYS)}"
                    )
            call = _call(node)
            if not call:
                continue
            mod, args = call
            where = f"{label}: {node.get('name', '?')}"
            headers, cred_headers, carries = args.get("headers") or {}, [], False
            if isinstance(headers, str):
                reviewed = _reviewed(label, node.get("name"))
                if reviewed is None:
                    problems.append(
                        f"{where}: headers is a template string (review it into HEADERS_REVIEWED)"
                    )
                    continue
                cred_headers, carries = list(reviewed[0]), True
            elif isinstance(headers, dict):
                cred_headers = [
                    k
                    for k, v in headers.items()
                    if CRED_HEADER.search(str(k)) or CRED_VALUE.search(str(v))
                ]
                carries = bool(cred_headers)
            if (
                args.get("url_password") or args.get("password")
                or ((args.get("url_username") or args.get("username")) and args.get("force_basic_auth"))
                or args.get("client_key") or args.get("client_cert")
                or USERINFO.search(str(args.get("url", "")))
            ):  # fmt: skip
                carries = True
            if not carries:
                continue
            found.append(where)
            if args.get("use_proxy") is not False:
                problems.append(f"{where}: needs use_proxy: false")
            if mod == "uri":
                if args.get("follow_redirects") != "none":
                    problems.append(f"{where}: needs follow_redirects: none")
                if any(300 <= c < 400 for c in _status_codes(args)):
                    problems.append(f"{where}: a 3xx success code")
            else:
                kept = {str(h).lower() for h in args.get("unredirected_headers") or []}
                missing = [h for h in cred_headers if h.lower() not in kept]
                if missing:
                    problems.append(f"{where}: unredirected_headers must list {missing}")
    return found, problems


def _files():
    globs = ["roles/*/tasks/**/*.y*ml", "roles/*/handlers/**/*.y*ml", "playbooks/**/*.y*ml"]
    return sorted({p for g in globs for p in ANSIBLE.glob(g)})


def test_a_task_sending_a_credential_follows_no_redirect_and_uses_no_proxy():
    found, problems = [], []
    for path in _files():
        f, p = scan(str(path.relative_to(ROOT)), path.read_text())
        found += f
        problems += p
    assert found, "the scan found no credential-carrying task (the model server's has one)"
    assert problems == []


GOOD_URI = """
- name: t
  ansible.builtin.uri:
    url: https://h/x
    headers: {Authorization: "Bearer {{ k }}"}
    follow_redirects: none
    use_proxy: false
"""

GOOD_GET_URL = """
- name: t
  ansible.builtin.get_url:
    url: https://h/x
    dest: /tmp/x
    headers: {X-Api-Key: "{{ k }}"}
    unredirected_headers: [X-Api-Key]
    use_proxy: false
"""

FIXTURES = {
    # (yaml, expected problem fragment, or None for clean)
    "uri-good": (GOOD_URI, None),
    "get_url-good": (GOOD_GET_URL, None),
    "no-credential": ("- name: t\n  uri: {url: 'https://h/health'}\n", None),
    "uri-follows": (GOOD_URI.replace("follow_redirects: none", "follow_redirects: safe"), "follow_redirects"),
    "uri-proxy": (GOOD_URI.replace("use_proxy: false", "use_proxy: true"), "use_proxy"),
    "uri-3xx-ok": (GOOD_URI + "    status_code: [200, 302]\n", "3xx"),
    "get_url-proxy": (GOOD_GET_URL.replace("    use_proxy: false\n", ""), "use_proxy"),
    "get_url-redirected-header": (GOOD_GET_URL.replace("[X-Api-Key]", "[]"), "unredirected_headers"),
    "header-value": ("- name: t\n  uri: {url: 'https://h', headers: {X-Thing: 'Bearer abc'}}\n", "follow_redirects"),
    "template-headers": ("- name: t\n  uri: {url: 'https://h', headers: '{{ h }}'}\n", "template string"),
    "url_password": ("- name: t\n  uri: {url: 'https://h', url_password: '{{ p }}'}\n", "use_proxy"),
    "password": ("- name: t\n  get_url: {url: 'https://h', dest: /x, password: '{{ p }}'}\n", "use_proxy"),
    "basic-auth": ("- name: t\n  uri: {url: 'https://h', url_username: u, force_basic_auth: true}\n", "use_proxy"),
    "client-key": ("- name: t\n  uri: {url: 'https://h', client_cert: /c, client_key: /k}\n", "use_proxy"),
    "userinfo": ("- name: t\n  uri: {url: 'https://u:p@h/x'}\n", "use_proxy"),
    "action-dict": ("- name: t\n  action: {module: uri, url: 'https://h', url_password: p}\n", "use_proxy"),
    "action-string": ("- name: t\n  local_action: uri url=https://h url_password=p\n", "use_proxy"),
    "free-form": ("- name: t\n  ansible.builtin.uri: url=https://h url_password=p\n", "use_proxy"),
    "in-a-block": ("- block:\n    - name: t\n      uri: {url: 'https://h', url_password: p}\n", "use_proxy"),
    "play-tasks": ("- hosts: all\n  tasks:\n    - name: t\n      uri: {url: 'https://h', url_password: p}\n", "use_proxy"),
    "module-defaults": ("- hosts: all\n  module_defaults:\n    ansible.builtin.uri: {headers: {Authorization: x}}\n  tasks: []\n", "module_defaults"),
    "group-defaults": ("- hosts: all\n  module_defaults:\n    group/ansible.builtin.web: {url_password: x}\n  tasks: []\n", "module_defaults"),
}  # fmt: skip


@pytest.mark.parametrize("case", sorted(FIXTURES))
def test_the_credential_scan_flags_each_unsafe_form(case):
    text, expected = FIXTURES[case]
    _, problems = scan("fixture.yml", text)
    if expected is None:
        assert problems == []
    else:
        assert any(expected in p for p in problems), problems
