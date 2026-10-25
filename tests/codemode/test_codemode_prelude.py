# SPDX-License-Identifier: Apache-2.0
"""Per-target actions and the runtime prelude (``hnx codemode gen``; docs/codemode.md, CM-3).

A handler document's ``target`` (handler 1.3) gives the method a ``target`` beside its params:
keyword-only in Python, a property of the argument object in TypeScript, ``target`` in the index.
The generated ``prelude.py`` binds each namespace to ``broker.call`` so a program calling a stub
sends exactly the request ``broker.call`` would: the action, the other keywords as params and
``target`` as the request's target.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from homelabnext.codemode import CodemodeError, build_models, render, render_files
from homelabnext.codemode.render import PRELUDE_FILE, render_prelude

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "examples" / "broker"


def _manifest(actions, grants):
    return {
        "manifest_id": "test-broker",
        "default": "deny",
        "mode": "enforce",
        "actions": list(actions),
        "grants": list(grants),
        "lanes": [],
    }


def _exec(action):
    return {
        "action": action,
        "tier": "read",
        "handler": f"h/{action}.sh",
        "requires_approval": False,
    }


def _doc(action, params=None, target=None):
    doc = {
        "action": action,
        "description": "Does one thing for the test.",
        "params_schema": params or {"type": "object", "additionalProperties": False},
    }
    if target:
        doc["target"] = target
    return doc


NAME = {
    "type": "object",
    "properties": {"name": {"type": "string"}},
    "required": ["name"],
    "additionalProperties": False,
}


def _models():
    actions = ["dns.lookup", "dhcp.leases", "host.uptime"]
    manifest = _manifest(
        [_exec(a) for a in actions],
        [{"profile": "profile:reader", "actions": actions, "max_tier": "read"}],
    )
    docs = [
        _doc("dns.lookup", NAME, "required"),
        _doc("dhcp.leases", None, "optional"),
        _doc("host.uptime"),
    ]
    return build_models(manifest, docs)


class _Recorder:
    """A stand-in for the sandbox's ``broker``: records what each call would send."""

    def __init__(self):
        self.sent = []

    def call(self, action, args=None, *, target=None):
        self.sent.append((action, dict(args or {}), target))
        return {"action": action}


def _run_prelude(text, program):
    rec = _Recorder()
    glb = {"__name__": "__program__", "broker": rec}
    exec(compile(text, "<prelude>", "exec"), glb)
    exec(compile(program, "<program>", "exec"), glb)
    return rec, glb


def test_the_target_is_keyword_only_in_python_and_a_property_in_typescript():
    files = render_files(_models())
    index = {a["name"]: a for a in json.loads(files["reader/search.json"])["actions"]}
    assert index["dns.lookup"]["target"] == "required"
    assert index["dhcp.leases"]["target"] == "optional"
    assert index["host.uptime"]["target"] is None
    assert index["dns.lookup"]["signatures"] == {
        "python": "dns.lookup(*, target: str, name: str) -> Any",
        "typescript": "dns.lookup(args: { name: string; target: string }): unknown",
    }
    assert index["dhcp.leases"]["signatures"] == {
        "python": "dhcp.leases(*, target: str | None = None) -> Any",
        "typescript": "dhcp.leases(args?: { target?: string }): unknown",
    }
    assert index["host.uptime"]["signatures"]["python"] == "host.uptime() -> Any"
    assert "params" not in index["dns.lookup"]["params"]["properties"]  # the schema is untouched
    assert "target" not in index["dns.lookup"]["params"]["properties"]
    assert "target: the svc:<name> the call is about" in files["reader/stubs.pyi"]
    assert "@param args.target the svc:<name> the call is about" in files["reader/types.d.ts"]


def test_a_parameter_named_target_on_an_action_about_a_target_is_refused():
    params = {"type": "object", "properties": {"target": {"type": "string"}}}
    manifest = _manifest(
        [_exec("dns.lookup"), _exec("dns.zone")],
        [{"profile": "profile:reader", "actions": ["dns.lookup", "dns.zone"], "max_tier": "read"}],
    )
    with pytest.raises(CodemodeError) as info:
        build_models(manifest, [_doc("dns.lookup", params, "required"), _doc("dns.zone")])
    assert any("'target' clashes" in p for p in info.value.problems), info.value.problems
    # without a target of its own, a parameter called target is only a parameter
    build_models(manifest, [_doc("dns.lookup", params), _doc("dns.zone")])


def test_a_stub_call_is_the_broker_call_it_stands_for():
    text = render_prelude(_models()[0])
    rec, glb = _run_prelude(
        text,
        "a = dns.lookup(target='svc:files', name='files')\n"
        "b = dhcp.leases()\n"
        "c = dhcp.leases(target='svc:dhcp')\n"
        "d = host.uptime()\n"
        "e = broker.call('host.uptime', {})\n",
    )
    assert rec.sent == [
        ("dns.lookup", {"name": "files"}, "svc:files"),
        ("dhcp.leases", {}, None),
        ("dhcp.leases", {}, "svc:dhcp"),
        ("host.uptime", {}, None),
        ("host.uptime", {}, None),
    ]
    assert glb["a"] == {"action": "dns.lookup"}
    # the prelude leaves the namespaces and nothing of its own
    assert {"_bind", "_namespaces"}.isdisjoint(glb)
    with pytest.raises(TypeError):  # the required target is required
        exec("dns.lookup(name='files')", glb)


def test_a_program_that_rebinds_broker_does_not_redirect_the_stubs():
    rec, _glb = _run_prelude(
        render_prelude(_models()[0]),
        "class Other:\n    def call(self, *a, **k):\n        raise AssertionError('redirected')\n"
        "broker = Other()\n"
        "dns.lookup(target='svc:files', name='files')\n",
    )
    assert rec.sent == [("dns.lookup", {"name": "files"}, "svc:files")]


def test_the_committed_preludes_run_and_name_every_namespace_of_their_stubs():
    files = render(EXAMPLE / "manifest.yml")
    for slug in ("reader", "triage"):
        text = files[f"{slug}/{PRELUDE_FILE}"]
        assert text == (ROOT / "examples" / "codemode" / slug / PRELUDE_FILE).read_text()
        index = json.loads(files[f"{slug}/search.json"])
        _, glb = _run_prelude(text, "")
        for entry in index["actions"]:
            ns, method = entry["call"].split(".")
            assert callable(getattr(glb[ns], method)), entry["call"]
        # the prelude and the stubs come from one model (the same digest in their markers)
        assert text.splitlines()[0].rsplit(" ", 1)[1] == index["_generated"].rsplit(" ", 1)[1]


def test_a_profile_with_no_methods_gets_a_prelude_that_binds_nothing():
    model = build_models(
        _manifest(
            [{**_exec("codemode.execute"), "tier": "execute", "requires_approval": True}],
            [{"profile": "profile:reader", "actions": ["codemode.execute"], "max_tier": "read"}],
        ),
        [],
    )[0]
    rec, glb = _run_prelude(render_prelude(model), "")
    assert rec.sent == [] and not any(not k.startswith("__") for k in glb if k != "broker")
