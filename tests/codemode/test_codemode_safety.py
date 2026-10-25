# SPDX-License-Identifier: Apache-2.0
"""``hnx codemode gen`` against hostile or awkward inputs, and against the broker it describes.

Names with a trailing newline, parameters that clash with the stub's own names, bidi and
zero-width characters, astral characters in literals, non-string keys, ``codemode.*`` actions,
namespaces that would shadow an annotation, and an output directory holding symlinks or files
the generator does not own.  The last tests hold the model to the broker itself: the granted set
is ``BrokerService.actions_for``'s, and the documented lane parameters are what the lane accepts.
"""

from __future__ import annotations

import ast
import json
import os
import shutil
from pathlib import Path

import pytest
import yaml

from homelabnext.broker import lanes
from homelabnext.broker.service import BrokerService, load_manifest
from homelabnext.codemode import CodemodeError, build_models, render, render_files
from homelabnext.codemode import cli as codemode_cli
from homelabnext.codemode.cli import main
from homelabnext.codemode.render import GENERATOR, check, write

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "examples" / "broker"
NOW = "2026-01-15T10:00:00Z"
NOTE = {"title": "Raise the drain timeout", "risk": "low", "rollback": "set it back"}


def _manifest(actions, grants, manifest_id="test-broker"):
    return {
        "manifest_id": manifest_id,
        "default": "deny",
        "mode": "enforce",
        "actions": list(actions),
        "grants": list(grants),
    }


def _exec(action, tier="read"):
    return {"action": action, "tier": tier, "handler": "h/x.sh", "requires_approval": False}


def _doc(action, params=None, description="Does one thing for the test."):
    return {
        "action": action,
        "description": description,
        "params_schema": params or {"type": "object", "additionalProperties": False},
    }


def _one(params=None, description="Does one thing for the test.", action="dns.lookup"):
    """The files of profile:p granted the one action ``action``."""
    manifest = _manifest(
        [_exec(action)], [{"profile": "profile:p", "actions": [action], "max_tier": "read"}]
    )
    return render_files(build_models(manifest, [_doc(action, params, description)]))


# ------------------------------------------------------------------- names
@pytest.mark.parametrize(
    ("manifest", "problem"),
    [
        (
            _manifest(
                [_exec("dns.lookup")],
                [{"profile": "profile:p\n", "actions": ["dns.lookup"], "max_tier": "read"}],
            ),
            "is not profile:<slug>",
        ),
        (
            _manifest(
                [_exec("dns.lookup")],
                [{"profile": "profile:p", "actions": ["dns.lookup"], "max_tier": "read"}],
                manifest_id="lab\n",
            ),
            "manifest_id: not a slug",
        ),
        (
            _manifest(
                [_exec("dns.lookup\n")],
                [{"profile": "profile:p", "actions": ["dns.lookup\n"], "max_tier": "read"}],
            ),
            "is not an action name",
        ),
    ],
)
def test_a_name_with_a_trailing_newline_is_refused(manifest, problem):
    docs = [_doc(a["action"]) for a in manifest["actions"]]
    with pytest.raises(CodemodeError, match=problem):
        build_models(manifest, docs)


@pytest.mark.parametrize("name", ["self", "params"])
def test_a_parameter_named_like_the_stubs_own_is_refused(name):
    open_spec = {"type": "object", "properties": {name: {"type": "string"}}}
    with pytest.raises(CodemodeError, match="clashes with the stub's own"):
        _one(open_spec)


def test_params_is_fine_when_no_more_parameters_are_admitted():
    files = _one(
        {
            "type": "object",
            "properties": {"params": {"type": "string"}},
            "additionalProperties": False,
        }
    )
    assert "def lookup(self, *, params: str = ...) -> Any:" in files["p/stubs.pyi"]
    ast.parse(files["p/stubs.pyi"])


def test_codemode_actions_never_appear():
    manifest = _manifest(
        [_exec("codemode.execute", tier="read"), _exec("dns.lookup")],
        [
            {
                "profile": "profile:p",
                "actions": ["codemode.execute", "dns.lookup"],
                "max_tier": "read",
            }
        ],
    )
    files = render_files(build_models(manifest, [_doc("codemode.execute"), _doc("dns.lookup")]))
    text = "".join(files.values())
    assert "codemode.execute" not in text and "execute" not in text
    assert [a["name"] for a in json.loads(files["p/search.json"])["actions"]] == ["dns.lookup"]


def _bound_and_annotation_names(stub: str) -> tuple[set[str], set[str]]:
    """Names a module or class body binds to a value (a method, a namespace binding), and names
    any annotation reads; a class the stub defines is a type, meant to be read."""
    tree = ast.parse(stub)
    bound, read = set(), set()
    for scope in [tree, *(n for n in ast.walk(tree) if isinstance(n, ast.ClassDef))]:
        for node in scope.body:
            if isinstance(node, ast.FunctionDef):
                bound.add(node.name)
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                bound.add(node.target.id)
    annotations = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            annotations += [a.annotation for a in [*node.args.kwonlyargs, *node.args.args]]
            annotations += [node.returns, node.args.kwarg and node.args.kwarg.annotation]
        elif isinstance(node, ast.AnnAssign):
            annotations.append(node.annotation)
    for ann in filter(None, annotations):
        read |= {n.id for n in ast.walk(ann) if isinstance(n, ast.Name)}
    return bound, read


def test_a_namespace_or_method_never_shadows_a_name_the_annotations_read():
    actions = ["list.items", "str.get", "dns.str", "dns.dict", "bool.int"]
    params = {
        "type": "object",
        "properties": {
            "a": {"type": "array", "items": {"type": "string"}},
            "b": {"type": "object", "additionalProperties": {"type": "integer"}},
            "c": {"type": "boolean"},
            "d": {"type": "number"},
        },
        "additionalProperties": False,
    }
    manifest = _manifest(
        [_exec(a) for a in actions],
        [{"profile": "profile:p", "actions": actions, "max_tier": "read"}],
    )
    files = render_files(build_models(manifest, [_doc(a, params) for a in actions]))
    stub = files["p/stubs.pyi"]
    bound, read = _bound_and_annotation_names(stub)
    assert {"list", "str", "dict", "bool", "int", "float"} <= read
    assert not bound & read, bound & read
    assert "list_: _List" in stub and "def str_(" in stub
    calls = {a["call"] for a in json.loads(files["p/search.json"])["actions"]}
    assert calls == {"list_.items", "str_.get", "dns.str_", "dns.dict_", "bool_.int_"}
    # and the example stubs, which a sandbox's Python would load
    for slug in ("reader", "triage"):
        bound, read = _bound_and_annotation_names(
            render(EXAMPLE / "manifest.yml")[f"{slug}/stubs.pyi"]
        )
        assert not bound & read


# -------------------------------------------------------------------- text
@pytest.mark.parametrize(
    "odd",
    ["\u202e", "\u2066", "\u200b", "\ufeff", "\u2028", "\u2029", "\x85", "\x1b"],
)
def test_bidi_zero_width_and_separator_characters_are_refused(odd):
    with pytest.raises(CodemodeError):
        _one(description=f"Looks up{odd} a name.")
    with pytest.raises(CodemodeError):
        _one({"type": "object", "properties": {"q": {"type": "string", "pattern": f"^a{odd}$"}}})


def test_a_backslash_is_fine_and_a_pattern_is_surfaced():
    spec = {
        "type": "object",
        "properties": {
            "name": {"type": "string", "pattern": r"^\d+\.md$", "description": r"a C:\ path"}
        },
        "required": ["name"],
        "additionalProperties": False,
    }
    files = _one(spec, description=r"Looks up \n literally.")
    py, ts = files["p/stubs.pyi"], files["p/types.d.ts"]
    assert r"name: a C:\ path; matching ^\d+\.md$" in py
    assert r"@param args.name a C:\ path; matching ^\d+\.md$" in ts
    method = next(n for n in ast.walk(ast.parse(py)) if isinstance(n, ast.FunctionDef))
    assert ast.get_docstring(method).startswith(r"Looks up \n literally.")  # raw: not a newline
    assert r"matching ^\d+\.md$" in ast.get_docstring(method)
    index = json.loads(files["p/search.json"])["actions"][0]
    assert index["params"]["properties"]["name"]["pattern"] == r"^\d+\.md$"


def test_astral_characters_in_a_literal_are_kept_whole():
    spec = {"type": "object", "properties": {"k": {"enum": ["\U0001f600", 'q"\\', "\u202e"]}}}
    files = _one(spec)
    py = files["p/stubs.pyi"]
    assert "\U0001f600" in py and "\\ud83d" not in py
    assert "\u202e" not in py  # a format character is escaped, never written raw
    ann = next(
        a
        for n in ast.walk(ast.parse(py))
        if isinstance(n, ast.FunctionDef)
        for a in n.args.kwonlyargs
    )
    literal = ann.annotation.slice
    assert [e.value for e in literal.elts] == ["\U0001f600", 'q"\\', "\u202e"]
    assert "\u202e" not in files["p/search.json"] and "\u202e" not in files["p/types.d.ts"]


@pytest.mark.parametrize(
    ("params", "problem"),
    [
        (
            {"type": "object", "properties": {1: {"type": "string"}}},
            "a property key is not a string",
        ),
        ({"type": "object", "properties": {"a": {}}, "required": ["b"]}, "required names 'b'"),
        (
            {
                "type": "object",
                "properties": {"a": {"type": "object", "properties": {}, "required": ["x"]}},
            },
            "params.a: required names 'x'",
        ),
        ({"type": "object", "required": "a"}, "required is not a list"),
        ({"type": "object", "properties": []}, "properties is not an object"),
    ],
)
def test_a_malformed_spec_is_refused_not_a_traceback(params, problem):
    with pytest.raises(CodemodeError, match=problem):
        _one(params)


def test_open_objects_carry_their_value_type():
    spec = {
        "type": "object",
        "properties": {"labels": {"type": "object", "additionalProperties": {"type": "integer"}}},
        "additionalProperties": {"type": "string"},
    }
    files = _one(spec)
    assert "labels?: Record<string, number>; [key: string]: unknown" in files["p/types.d.ts"]
    assert "labels: dict[str, int] = ..., **params: str" in files["p/stubs.pyi"]


# ------------------------------------------------------------- the tree on disk
@pytest.fixture
def lab(tmp_path):
    shutil.copytree(EXAMPLE, tmp_path / "broker")
    out = tmp_path / "codemode"
    args = ["gen", "--manifest", str(tmp_path / "broker" / "manifest.yml"), "--out", str(out)]
    assert main(args) == 0
    return tmp_path, out, args


def _marked_file(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"# {GENERATOR} from somewhere - do not edit\n")


def test_the_stale_sweep_touches_only_slug_and_file_names_it_owns(lab):
    _, out, args = lab
    keep = [
        out / "deep" / "nested" / "stubs.pyi",  # too deep
        out / "triage" / "notes.pyi",  # not one of FILES
        out / "Bad_Slug" / "stubs.pyi",  # not a profile slug
        out / "stubs.pyi",  # not in a profile directory
    ]
    for p in keep:
        _marked_file(p)
    _marked_file(out / "gone" / "types.d.ts")
    assert main([*args, "--check"]) == 1
    assert main(args) == 0
    assert all(p.is_file() for p in keep)
    assert not (out / "gone").exists()


def test_a_symlinked_profile_directory_is_not_swept_or_written(lab, tmp_path):
    _, out, args = lab
    elsewhere = tmp_path / "elsewhere"
    _marked_file(elsewhere / "stubs.pyi")
    (out / "linked").symlink_to(elsewhere, target_is_directory=True)
    assert main(args) == 0
    assert (elsewhere / "stubs.pyi").is_file()  # a symlinked <slug> is never swept
    shutil.rmtree(out / "reader")
    (out / "reader").symlink_to(elsewhere, target_is_directory=True)
    assert main(args) == 2
    assert sorted(p.name for p in elsewhere.iterdir()) == ["stubs.pyi"]  # nothing written there
    assert "symlink: reader/search.json" in "\n".join(
        check(out, render(tmp_path / "broker" / "manifest.yml"))
    )


def test_a_symlinked_destination_file_is_refused(lab, tmp_path, capsys):
    _, out, args = lab
    target = tmp_path / "target.txt"
    target.write_text("someone else's\n")
    (out / "triage" / "stubs.pyi").unlink()
    (out / "triage" / "stubs.pyi").symlink_to(target)
    assert main(args) == 2
    assert "triage/stubs.pyi: is a symlink" in capsys.readouterr().err
    assert target.read_text() == "someone else's\n"
    assert main([*args, "--check"]) == 1


def test_a_write_leaves_no_temporary_file_and_replaces_in_place(lab):
    _, out, args = lab
    stub = out / "triage" / "stubs.pyi"
    stub.write_text("# hand edit\n")
    assert main(args) == 0
    assert sorted(p.name for p in (out / "triage").iterdir()) == [
        "search.json",
        "stubs.pyi",
        "types.d.ts",
    ]
    assert GENERATOR in stub.read_text().splitlines()[0]


def test_write_refuses_before_writing_anything(tmp_path):
    files = render(EXAMPLE / "manifest.yml")
    out = tmp_path / "out"
    out.mkdir()
    (out / "triage").symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(CodemodeError, match="triage: is a symlink"):
        write(out, files)
    assert not (out / "reader").exists()


def test_an_unreadable_output_is_could_not_measure(lab, monkeypatch, capsys):
    _, _, args = lab

    def unreadable(out, files):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(codemode_cli, "check", unreadable)
    assert main([*args, "--check"]) == 100
    assert "cannot read" in capsys.readouterr().err


def test_an_unwritable_output_is_bad_input(lab, capsys):
    root, _, args = lab
    blocker = root / "a-file"
    blocker.write_text("x\n")
    assert main([*args[:3], "--out", str(blocker / "sub")]) == 2
    assert "cannot write" in capsys.readouterr().err


def test_a_non_utf8_golden_is_drift_not_a_crash(lab):
    _, out, args = lab
    (out / "reader" / "stubs.pyi").write_bytes(b"\xff\xfe broken\n")
    assert main([*args, "--check"]) == 1


# ------------------------------------------------------- held to the broker
@pytest.mark.parametrize("profile", ["profile:triage", "profile:reader"])
def test_the_granted_set_is_the_brokers_own(tmp_path, profile):
    svc = BrokerService.from_manifest(EXAMPLE / "manifest.yml", tmp_path / "state")
    broker = {a["action"]: a["needs_approval"] for a in svc.actions_for(profile)}
    manifest, docs = load_manifest(EXAMPLE / "manifest.yml")
    model = next(m for m in build_models(manifest, docs) if m.profile == profile)
    assert {m.action: m.needs_approval for m in model.methods} == broker
    tiers = {a["action"]: a["tier"] for a in svc.actions_for(profile)}
    assert {m.action: m.tier for m in model.methods} == tiers


def _lane_cases():
    manifest, docs = load_manifest(EXAMPLE / "manifest.yml")
    triage = next(m for m in build_models(manifest, docs) if m.profile == "profile:triage")
    lane_of = {a["action"]: a["lane"] for a in manifest["actions"] if "lane" in a}
    by_name = {ld["name"]: lanes.Lane.from_doc(ld) for ld in manifest["lanes"]}
    return [(m, by_name[lane_of[m.action]]) for m in triage.methods if m.kind == "lane"]


VALUES = {
    "name": {"memory": "notes.md", "findings": "2026-01-15-queue.md"},
    "content": "Seen twice.",
    "note": NOTE,
    "body": "Seen twice.",
    "slug": "drain",
}


def _value(lane, name):
    v = VALUES[name]
    return v[lane.name] if isinstance(v, dict) and name == "name" else v


@pytest.mark.parametrize(("method", "lane"), _lane_cases(), ids=lambda x: getattr(x, "action", ""))
def test_the_documented_lane_params_are_what_the_lane_accepts(method, lane):
    props, required = method.params["properties"], method.params["required"]
    check_ = lambda params: lanes.check_params(lane, "profile:triage", params, NOW, key=b"k")  # noqa: E731
    check_({n: _value(lane, n) for n in required})  # the required ones alone
    check_({n: _value(lane, n) for n in props})  # every documented one
    for missing in required:
        with pytest.raises(lanes.LaneError):
            check_({n: _value(lane, n) for n in props if n != missing})
    with pytest.raises(lanes.LaneError):
        check_({**{n: _value(lane, n) for n in props}, "undocumented": "x"})


def test_an_exec_call_result_is_untyped_and_a_lane_result_is_what_a_write_returns(tmp_path):
    files = render(EXAMPLE / "manifest.yml")
    index = {a["name"]: a for a in json.loads(files["triage/search.json"])["actions"]}
    assert index["service.status"]["result"] is None
    svc = BrokerService.from_manifest(
        EXAMPLE / "manifest.yml", tmp_path / "state", data_root=tmp_path / "d"
    )
    written = svc.call("profile:triage", "memory.write", {"name": "notes.md", "content": "x"})
    assert set(written) == set(index["memory.write"]["result"]["schema"]["properties"])


def test_yaml_with_integer_keys_reaches_the_cli_as_exit_2(tmp_path, capsys):
    shutil.copytree(EXAMPLE, tmp_path / "broker")
    path = tmp_path / "broker" / "handlers" / "service-status.handler.json"
    doc = json.loads(path.read_text())
    doc["params_schema"]["properties"] = {"1": {"type": "string"}}
    (tmp_path / "broker" / "handlers" / "service-status.handler.yml").write_text(
        yaml.safe_dump(doc).replace("'1':", "1:")
    )
    man = tmp_path / "broker" / "manifest.yml"
    man.write_text(
        man.read_text().replace("service-status.handler.json", "service-status.handler.yml")
    )
    code = main(["gen", "--manifest", str(man), "--out", str(tmp_path / "out"), "--check"])
    assert code == 2
    assert "Traceback" not in capsys.readouterr().err
    assert not os.path.exists(tmp_path / "out")
