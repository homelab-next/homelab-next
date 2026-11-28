# SPDX-License-Identifier: Apache-2.0
"""A set_fact resolves every value before it defines any key, so a value that names another key of the
same task fails at run time ("'x' is undefined"). 2026-11-28 the wazuh_agent drop-in task did exactly
that and the whole baseline failed on every guest; nothing caught it before a deploy."""

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
SET_FACT = ("ansible.builtin.set_fact", "set_fact")


def _tasks(node):
    if isinstance(node, list):
        for item in node:
            yield from _tasks(item)
    elif isinstance(node, dict):
        if any(k in node for k in SET_FACT):
            yield node
        for key in ("block", "rescue", "always"):
            if key in node:
                yield from _tasks(node[key])


def _task_files():
    for base in ("ansible", "modules"):
        for p in (ROOT / base).rglob("*.yml"):
            if "/tasks/" in p.as_posix() or "/handlers/" in p.as_posix():
                yield p


@pytest.mark.static
def test_no_set_fact_value_names_a_key_of_the_same_task():
    bad = []
    for path in _task_files():
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError:
            continue
        for task in _tasks(doc):
            body = next(task[k] for k in SET_FACT if k in task)
            if not isinstance(body, dict):
                continue
            keys = {k for k in body if k != "cacheable"}
            for key, value in body.items():
                text = yaml.safe_dump(value) if not isinstance(value, str) else value
                for other in keys - {key}:
                    if re.search(r"\{\{[^}]*\b" + re.escape(other) + r"\b", text) or re.search(
                        r"\{%[^%]*\b" + re.escape(other) + r"\b", text
                    ):
                        bad.append(
                            f"{path.relative_to(ROOT)}: {task.get('name', '?')}: {key} uses {other}"
                        )
    assert not bad, "set_fact values naming a key of the same task:\n" + "\n".join(bad)
