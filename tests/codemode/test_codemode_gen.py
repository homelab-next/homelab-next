# SPDX-License-Identifier: Apache-2.0
"""``hnx codemode gen`` (CM-3, ADR-0031 decisions 3 and 4): per-profile stubs and search index.

A profile's files name only the actions the broker admits for it; parameters are typed from each
action's argument spec; the output is byte-identical across runs and input orderings; ``--check``
fails on a hand edit, a manifest change and a profile no longer rendered, and passes when clean.
"""

from __future__ import annotations

import ast
import json
import shutil
from pathlib import Path

import pytest
import yaml

from homelabnext import cli
from homelabnext.codemode import CodemodeError, build_models, render, render_files
from homelabnext.codemode.cli import main
from homelabnext.codemode.render import GENERATOR, check, py_type, ts_type, write

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "examples" / "broker"


def _manifest(actions, grants, lanes=()):
    return {
        "manifest_id": "test-broker",
        "default": "deny",
        "mode": "enforce",
        "actions": list(actions),
        "grants": list(grants),
        "lanes": list(lanes),
    }


def _exec(action, tier="read", approval=False):
    return {
        "action": action,
        "tier": tier,
        "handler": f"h/{action}.sh",
        "requires_approval": approval,
    }


def _doc(action, params=None, description="Does one thing for the test."):
    return {
        "action": action,
        "description": description,
        "params_schema": params or {"type": "object", "additionalProperties": False},
    }


def _files(manifest, docs):
    return render_files(build_models(manifest, docs))


def _profile_text(files, slug):
    return "".join(text for rel, text in files.items() if rel.startswith(f"{slug}/"))


# ------------------------------------------------------------------ granted only
def test_a_profile_sees_only_what_the_broker_admits_for_it():
    manifest = _manifest(
        [
            _exec("dns.lookup"),
            _exec("vault.unseal", tier="privileged", approval=True),
            _exec("guest.stop", tier="execute", approval=True),
        ],
        [
            {
                "profile": "profile:reader",
                "actions": ["dns.lookup", "guest.stop"],
                "max_tier": "read",
            },
            {"profile": "profile:keeper", "actions": ["vault.unseal"], "max_tier": "privileged"},
        ],
    )
    docs = [_doc(a["action"]) for a in manifest["actions"]]
    files = _files(manifest, docs)
    reader = _profile_text(files, "reader")
    assert "lookup" in reader
    # never granted to the reader, and granted above its max_tier: neither appears anywhere
    for absent in ("vault", "unseal", "guest", "stop"):
        assert absent not in reader, absent
    assert "unseal" in _profile_text(files, "keeper")
    index = json.loads(files["reader/search.json"])
    assert [a["name"] for a in index["actions"]] == ["dns.lookup"]


def test_an_action_without_a_handler_or_in_no_grant_is_not_emitted():
    manifest = _manifest(
        [_exec("dns.lookup"), {**_exec("dns.zone"), "handler": ""}, _exec("dhcp.lease")],
        [{"profile": "profile:reader", "actions": ["dns.lookup", "dns.zone"], "max_tier": "read"}],
    )
    files = _files(manifest, [_doc(a["action"]) for a in manifest["actions"]])
    assert sorted(files) == ["reader/search.json", "reader/stubs.pyi", "reader/types.d.ts"]
    text = _profile_text(files, "reader")
    assert "zone" not in text and "dhcp" not in text and "lease" not in text


def test_the_example_reader_profile_has_no_restart():
    files = render(EXAMPLE / "manifest.yml")
    assert "restart" not in _profile_text(files, "reader")
    assert "restart" in _profile_text(files, "triage")
    assert "memory" not in _profile_text(files, "reader")


# ----------------------------------------------------------------- typed params
SPEC = {
    "type": "object",
    "properties": {
        "name": {"type": "string", "maxLength": 63, "description": "the record name"},
        "count": {"type": "integer", "minimum": 1, "maximum": 50},
        "kind": {"enum": ["A", "AAAA", "PTR"]},
        "verbose": {"type": "boolean"},
        "tags": {"type": "array", "items": {"type": "string"}},
        "ttl": {"type": ["integer", "null"]},
        "mode": {"const": "fast"},
        "weight": {"type": "number"},
    },
    "required": ["name", "kind"],
    "additionalProperties": False,
}


def test_parameters_are_typed_from_the_argument_spec():
    manifest = _manifest(
        [_exec("dns.lookup")],
        [{"profile": "profile:reader", "actions": ["dns.lookup"], "max_tier": "read"}],
    )
    files = _files(manifest, [_doc("dns.lookup", SPEC)])
    ts, py = files["reader/types.d.ts"], files["reader/stubs.pyi"]
    assert (
        'function lookup(args: { count?: number; kind: "A" | "AAAA" | "PTR"; '
        'mode?: "fast"; name: string; tags?: string[]; ttl?: number | null; verbose?: boolean; '
        "weight?: number }): unknown;"
    ) in ts
    # required first, then optional (with a default), all keyword-only
    assert (
        "    def lookup(\n"
        '        self,\n        *,\n        kind: Literal["A", "AAAA", "PTR"],\n        name: str,\n'
        "        count: int = ...,\n"
        '        mode: Literal["fast"] = ...,\n'
        "        tags: list[str] = ...,\n        ttl: int | None = ...,\n"
        "        verbose: bool = ...,\n        weight: float = ...,\n    ) -> Any:"
    ) in py
    assert "count: >= 1, <= 50" in py and "@param args.count >= 1, <= 50" in ts
    assert "name: the record name; length <= 63" in py
    assert "from typing import Any, Literal" in py
    ast.parse(py)  # a stub the sandbox's Python can load


def test_an_open_or_empty_spec():
    manifest = _manifest(
        [_exec("svc.ping"), _exec("svc.any")],
        [{"profile": "profile:reader", "actions": ["svc.ping", "svc.any"], "max_tier": "read"}],
    )
    docs = [_doc("svc.ping"), _doc("svc.any", {"type": "object"})]
    files = _files(manifest, docs)
    ts, py = files["reader/types.d.ts"], files["reader/stubs.pyi"]
    assert "function ping(): unknown;" in ts
    assert "function any(args?: Record<string, unknown>): unknown;" in ts
    assert "def ping(self) -> Any:" in py
    assert "def any(self, **params: Any) -> Any:" in py


@pytest.mark.parametrize(
    ("schema", "ts", "py"),
    [
        ({"type": "string"}, "string", "str"),
        ({"type": "integer"}, "number", "int"),
        ({"enum": [1, 2]}, "1 | 2", "Literal[1, 2]"),
        ({"enum": [0.5, 1.5], "type": "number"}, "0.5 | 1.5", "float"),
        ({"oneOf": [{"type": "string"}, {"type": "integer"}]}, "string | number", "str | int"),
        (
            {"type": "array", "items": {"type": ["string", "null"]}},
            "(string | null)[]",
            "list[str | None]",
        ),
        (
            {"type": "object", "properties": {"a": {"type": "boolean"}}},
            "{ a?: boolean; [key: string]: unknown }",
            "dict[str, Any]",
        ),
        ({"$ref": "https://schemas.example.internal/x"}, "unknown", "Any"),
        ({"anyOf": [{"type": "string"}, {}]}, "unknown", "Any"),
        (True, "unknown", "Any"),
    ],
)
def test_schema_types(schema, ts, py):
    assert ts_type(schema) == ts
    assert py_type(schema, set()) == py


def test_lane_actions_are_typed_from_the_lane():
    files = render(EXAMPLE / "manifest.yml")
    ts, py = files["triage/types.d.ts"], files["triage/stubs.pyi"]
    assert "function write(args: { content: string; name: string }): LaneWrite;" in ts
    assert "interface LaneWrite {" in ts and ts.count("interface LaneWrite") == 1
    assert "def write(self, *, content: str, name: str) -> LaneWrite:" in py
    assert "body?: string; note: Record<string, unknown>; slug?: string" in ts
    assert "class LaneWrite(TypedDict):" in py


# --------------------------------------------------------------- needs approval
def test_actions_needing_approval_are_marked():
    manifest = _manifest(
        [
            _exec("guest.stop", tier="execute", approval=True),
            _exec("dns.set", tier="write", approval=True),
            _exec("dns.lookup"),
        ],
        [
            {
                "profile": "profile:ops",
                "actions": ["guest.stop", "dns.set", "dns.lookup"],
                "max_tier": "execute",
            }
        ],
    )
    files = _files(manifest, [_doc(a["action"]) for a in manifest["actions"]])
    index = {a["name"]: a for a in json.loads(files["ops/search.json"])["actions"]}
    assert {n: a["needs_approval"] for n, a in index.items()} == {
        "dns.lookup": False,
        "dns.set": True,
        "guest.stop": True,
    }
    assert index["guest.stop"]["tier"] == "execute"
    assert index["dns.set"]["call"] == "dns.set"
    assert files["ops/types.d.ts"].count("Needs a person's approval") == 2
    assert files["ops/stubs.pyi"].count("Needs a person's approval") == 2


def test_the_example_restart_needs_approval():
    index = json.loads(render(EXAMPLE / "manifest.yml")["triage/search.json"])
    flags = {a["name"]: a["needs_approval"] for a in index["actions"]}
    assert flags["service.restart"] is True and flags["service.status"] is False


# ---------------------------------------------------------------- determinism
def test_output_is_byte_identical_across_runs_and_orderings():
    actions = [_exec("svc.b"), _exec("dns.lookup"), _exec("svc.a"), _exec("dns.zone")]
    names = [a["action"] for a in actions]
    grants = [{"profile": "profile:p", "actions": names, "max_tier": "read"}]
    docs = [_doc(n, SPEC) for n in names]
    first = _files(_manifest(actions, grants), docs)
    again = _files(_manifest(actions, grants), docs)
    spec_rev = dict(SPEC, properties=dict(reversed(list(SPEC["properties"].items()))))
    flipped = _files(
        _manifest(list(reversed(actions)), [dict(grants[0], actions=list(reversed(names)))]),
        [_doc(n, spec_rev) for n in reversed(names)],
    )
    assert first == again == flipped
    index = json.loads(first["p/search.json"])
    assert [a["name"] for a in index["actions"]] == sorted(names)
    assert list(first) == sorted(first)
    ts = first["p/types.d.ts"]
    assert ts.index("declare namespace dns") < ts.index("declare namespace svc")


def test_every_file_carries_the_marker_and_the_same_digest():
    files = render(EXAMPLE / "manifest.yml")
    for slug in ("reader", "triage"):
        heads = [files[f"{slug}/{f}"].splitlines()[0] for f in ("stubs.pyi", "types.d.ts")]
        heads.append(json.loads(files[f"{slug}/search.json"])["_generated"])
        assert all(GENERATOR in h and "do not edit" in h for h in heads)
        assert len({h.rsplit("sha256:", 1)[1][:64] for h in heads}) == 1


# --------------------------------------------------------------------- --check
@pytest.fixture
def lab(tmp_path):
    """The example broker copied out, with its goldens generated beside it."""
    shutil.copytree(EXAMPLE, tmp_path / "broker")
    out = tmp_path / "codemode"
    args = ["gen", "--manifest", str(tmp_path / "broker" / "manifest.yml"), "--out", str(out)]
    assert main(args) == 0
    return tmp_path, args


def test_check_passes_when_clean(lab, capsys):
    _, args = lab
    assert main([*args, "--check"]) == 0
    assert "6 files" in capsys.readouterr().out


def test_check_fails_on_a_hand_edit(lab, capsys):
    root, args = lab
    stub = root / "codemode" / "reader" / "stubs.pyi"
    stub.write_text(stub.read_text().replace("verbose: bool", "verbose: str"))
    assert main([*args, "--check"]) == 1
    assert "differs: reader/stubs.pyi" in capsys.readouterr().err


def test_check_fails_on_a_manifest_change(lab, capsys):
    root, args = lab
    path = root / "broker" / "manifest.yml"
    doc = yaml.safe_load(path.read_text())
    doc["grants"][1]["actions"] = []  # the reader loses service.status
    path.write_text(yaml.safe_dump(doc))
    assert main([*args, "--check"]) == 1
    err = capsys.readouterr().err
    assert "differs: reader/search.json" in err and "differs: reader/types.d.ts" in err


def test_check_fails_on_a_handler_spec_change(lab, capsys):
    root, args = lab
    path = root / "broker" / "handlers" / "service-status.handler.json"
    doc = json.loads(path.read_text())
    doc["params_schema"]["properties"]["unit"] = {"type": "string"}
    path.write_text(json.dumps(doc))
    assert main([*args, "--check"]) == 1
    assert "differs: triage/stubs.pyi" in capsys.readouterr().err


def test_a_profile_no_longer_granted_is_stale_and_a_write_removes_it(lab, capsys):
    root, args = lab
    path = root / "broker" / "manifest.yml"
    doc = yaml.safe_load(path.read_text())
    doc["grants"] = doc["grants"][:1]
    path.write_text(yaml.safe_dump(doc))
    (root / "codemode" / "notes.md").write_text("authored, not ours\n")
    assert main([*args, "--check"]) == 1
    assert "stale: reader/search.json" in capsys.readouterr().err
    assert main(args) == 0
    assert not (root / "codemode" / "reader").exists()
    assert (root / "codemode" / "notes.md").is_file()  # an unmarked file is never removed
    assert main([*args, "--check"]) == 0


def test_check_reports_a_missing_file(lab, capsys):
    root, args = lab
    (root / "codemode" / "triage" / "types.d.ts").unlink()
    assert main([*args, "--check"]) == 1
    assert "missing: triage/types.d.ts" in capsys.readouterr().err


def test_check_and_write_on_an_empty_directory(tmp_path):
    files = render(EXAMPLE / "manifest.yml")
    assert check(tmp_path / "none", files) == [f"missing: {rel}" for rel in files]
    written, unchanged, removed = write(tmp_path / "out", files)
    assert sorted(written) == sorted(files) and unchanged == [] and removed == []
    assert write(tmp_path / "out", files)[1] == list(files)


def test_the_committed_goldens_are_current():
    args = [
        "gen",
        "--manifest",
        str(EXAMPLE / "manifest.yml"),
        "--out",
        str(ROOT / "examples/codemode"),
    ]
    assert main([*args, "--check"]) == 0


# ---------------------------------------------------------------------- refusals
def test_an_invalid_or_missing_manifest_is_exit_2(tmp_path, capsys):
    assert main(["gen", "--manifest", str(tmp_path / "nosuch.yml"), "--check"]) == 2
    (tmp_path / "bad.yml").write_text('{"a": 1}\n')
    assert main(["gen", "--manifest", str(tmp_path / "bad.yml"), "--check"]) == 2
    assert "Traceback" not in capsys.readouterr().err


def test_a_reserved_word_gets_a_trailing_underscore():
    manifest = _manifest(
        [_exec("import.class"), _exec("svc.delete")],
        [{"profile": "profile:p", "actions": ["import.class", "svc.delete"], "max_tier": "read"}],
    )
    files = _files(manifest, [_doc("import.class"), _doc("svc.delete")])
    assert "declare namespace import_ {" in files["p/types.d.ts"]
    assert "function class_(): unknown;" in files["p/types.d.ts"]
    assert "function delete_(): unknown;" in files["p/types.d.ts"]
    assert "import_: _Import" in files["p/stubs.pyi"]
    assert json.loads(files["p/search.json"])["actions"][0]["call"] == "import_.class_"
    ast.parse(files["p/stubs.pyi"])


@pytest.mark.parametrize(
    ("actions", "doc", "problem"),
    [
        (["dns.zone-get", "dns.zone.get"], {}, "are both dns.zone_get"),
        (
            ["dns.lookup"],
            {"params": {"type": "object", "properties": {"rr-type": {}}}},
            "not an identifier",
        ),
        (["dns.lookup"], {"description": "Looks up */ a name."}, "would end a stub comment"),
        (["dns.lookup"], {"description": "Looks up\na name."}, "control character"),
        (
            ["dns.lookup"],
            {"params": {"properties": {"q": {"description": 'a """ quote'}}}},
            "would end a stub comment",
        ),
    ],
)
def test_what_cannot_be_rendered_is_refused(actions, doc, problem):
    manifest = _manifest(
        [_exec(a) for a in actions],
        [{"profile": "profile:p", "actions": actions, "max_tier": "read"}],
    )
    with pytest.raises(CodemodeError, match=problem):
        _files(manifest, [_doc(a, **doc) for a in actions])


def test_an_exec_action_without_a_handler_document_is_refused():
    manifest = _manifest(
        [_exec("dns.lookup")],
        [{"profile": "profile:p", "actions": ["dns.lookup"], "max_tier": "read"}],
    )
    with pytest.raises(CodemodeError, match="no handler document"):
        _files(manifest, [])


def test_hnx_codemode_is_registered():
    assert "codemode" in cli.COMMANDS
    assert cli.main(["codemode", "gen", "--help"]) == 0


# ------------------------------------------------------- describe, synchronous
def test_the_index_carries_what_codemode_describe_needs():
    files = render(EXAMPLE / "manifest.yml")
    index = {a["name"]: a for a in json.loads(files["triage/search.json"])["actions"]}
    handler = json.loads((EXAMPLE / "handlers" / "service-restart.handler.json").read_text())
    restart = index["service.restart"]
    assert restart["kind"] == "exec" and restart["params"] == handler["params_schema"]
    assert restart["result"]["schema"] == handler["result_schema"]
    assert restart["signatures"] == {
        "python": "service.restart(*, grace_s: int) -> ServiceRestartResult",
        "typescript": "service.restart(args: { grace_s: number }): ServiceRestartResult",
    }
    memory = index["memory.write"]
    assert memory["kind"] == "lane" and memory["result"]["type"] == "LaneWrite"
    assert memory["params"]["properties"]["name"]["pattern"] == r"^[a-z0-9][a-z0-9-]{0,62}\.md$"
    assert memory["signatures"]["typescript"] == (
        "memory.write(args: { content: string; name: string }): LaneWrite"
    )
    assert files["triage/search.json"].isascii()


def test_calls_are_synchronous_in_both_languages():
    files = render(EXAMPLE / "manifest.yml")
    for slug in ("reader", "triage"):
        assert "Promise" not in files[f"{slug}/types.d.ts"]
        tree = ast.parse(files[f"{slug}/stubs.pyi"])
        assert not any(isinstance(n, ast.AsyncFunctionDef) for n in ast.walk(tree))
        assert any(isinstance(n, ast.FunctionDef) for n in ast.walk(tree))
    assert (
        "function restart(args: { grace_s: number }): ServiceRestartResult;"
        in files["triage/types.d.ts"]
    )
    assert "the run pauses until it is decided" in files["triage/types.d.ts"]
