# SPDX-License-Identifier: Apache-2.0
"""A role that hands its data root to compose_app (``compose_app_data_dir``) and also creates that
directory itself must set it exactly as compose_app's "Create application directories" does: the
project owner (``compose_app_owner``), the project group (``compose_app_group``), 0750.  Anything
else and the two tasks re-own the directory on every run (``changed=2`` on a rerun), ending the
way the later one leaves it: a data root the role meant for the container's user came back
root-owned, the container could not write it and the service never became ready.  What the
container writes belongs in subdirectories of its own user (modules/gateway's dirs.yml).

Static: every role's own defaults resolve the expressions (no ansible run), so this is fast and
covers every role that includes compose_app, present and future."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from jinja2 import ChainableUndefined
from jinja2.nativetypes import NativeEnvironment

ROOT = Path(__file__).resolve().parents[2]
ROLES = sorted(
    p.parents[1]
    for p in [
        *ROOT.glob("modules/*/roles/*/tasks/main.yml"),
        *ROOT.glob("ansible/roles/*/tasks/main.yml"),
    ]
)
ENV = NativeEnvironment(undefined=ChainableUndefined)
ENV.filters["int"] = lambda v, default=0: (
    int(v) if str(v).strip().lstrip("-").isdigit() else default
)
ENV.filters["bool"] = lambda v: str(v).lower() in ("1", "true", "yes", "on")


def _render(expr, ctx):
    """``expr`` rendered until it holds no template (a loop item's value is itself one)."""
    for _ in range(6):
        if not isinstance(expr, str) or "{{" not in expr:
            return expr
        try:
            out = ENV.from_string(expr).render(**ctx)
        except Exception:  # an expression needing ansible's own filters: left as written
            return expr
        if out == expr:
            return expr
        expr = out
    return expr


def _defaults(role: Path) -> dict:
    p = role / "defaults" / "main.yml"
    ctx = dict(yaml.safe_load(p.read_text()) or {}) if p.exists() else {}
    for _ in range(6):  # defaults naming defaults
        ctx = {k: _render(v, ctx) for k, v in ctx.items()}
    return ctx


def _tasks(node):
    """Every task of a task file, through block/rescue/always."""
    for t in node or []:
        if not isinstance(t, dict):
            continue
        yield t
        for key in ("block", "rescue", "always"):
            yield from _tasks(t.get(key))


def _task_files(role: Path):
    for p in sorted((role / "tasks").glob("*.yml")):
        yield p, list(_tasks(yaml.safe_load(p.read_text())))


def _app_spec(role: Path) -> dict | None:
    """The compose_app inputs the role builds (a set_fact holding compose_app_data_dir)."""
    for _, tasks in _task_files(role):
        for t in tasks:
            facts = t.get("ansible.builtin.set_fact") or t.get("set_fact") or {}
            for v in facts.values() if isinstance(facts, dict) else []:
                if isinstance(v, dict) and "compose_app_data_dir" in v:
                    return v
    return None


def _directories(role: Path, ctx: dict):
    """(file, path, owner, group, mode) of every state=directory file task, its loop expanded."""
    for p, tasks in _task_files(role):
        for t in tasks:
            args = t.get("ansible.builtin.file") or t.get("file")
            if not isinstance(args, dict) or args.get("state") != "directory":
                continue
            loop = t.get("loop", t.get("with_items"))
            items = _render(loop, ctx) if loop is not None else [None]
            if not isinstance(items, list):
                continue
            for item in items:
                c = {**ctx, "item": item}
                yield (
                    p.name,
                    *(str(_render(args.get(k), c)) for k in ("path", "owner", "group", "mode")),
                )


CASES = []
for _role in ROLES:
    _spec = _app_spec(_role)
    if _spec is not None:
        CASES.append(pytest.param(_role, _spec, id=str(_role.relative_to(ROOT))))


def test_the_audit_sees_the_compose_app_roles():
    # refuse to pass vacuously: the roles that build compose_app inputs are found and resolved
    assert len(CASES) >= 15, [c.id for c in CASES]
    own = 0
    for case in CASES:
        role, spec = case.values
        ctx = _defaults(role)
        data = str(_render(spec["compose_app_data_dir"], ctx))
        assert data.startswith("/") and "{{" not in data, (case.id, data)
        own += any(d[1] == data for d in _directories(role, ctx))
    assert own >= 10, own  # most create their data root themselves too


@pytest.mark.parametrize("role,spec", CASES)
def test_a_data_root_the_role_creates_is_set_as_compose_app_sets_it(role, spec):
    ctx = _defaults(role)
    data = str(_render(spec["compose_app_data_dir"], ctx))
    want = (
        str(_render(spec.get("compose_app_owner", "root"), ctx)),
        str(_render(spec.get("compose_app_group", "root"), ctx)),
        "0750",
    )
    fights = [
        (f, owner, group, mode)
        for f, path, owner, group, mode in _directories(role, ctx)
        if path == data and (owner, group, mode) != want
    ]
    assert not fights, (
        f"{data} is set to {fights} by the role but to {want} (owner, group, mode) by compose_app: "
        "the two re-own it on every run; give the container's user a subdirectory instead"
    )
