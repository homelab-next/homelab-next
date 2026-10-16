# SPDX-License-Identifier: Apache-2.0
"""Scaffold generators and the checkers that gate their output.

``hnx new role|schema|capability|detection <name> [--dest DIR]`` writes a
minimal artefact that already passes ``verify``; a scaffold whose output fails
its own checker is a bug in the scaffold.

Wiring ``hnx new`` into the top-level CLI is a one-liner: call ``main(argv)``
from this module.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from collections.abc import Callable
from pathlib import Path

import yaml

SPDX = "SPDX-License-Identifier: Apache-2.0"
ROLE_NAME = re.compile(r"^[a-z][a-z0-9_]*$")
SLUG_NAME = re.compile(r"^[a-z][a-z0-9-]*$")
HOOKS = ("health", "readiness", "backup", "restore", "upgrade", "export")


class ScaffoldError(ValueError):
    pass


def _role_lint():
    path = Path(__file__).resolve().parents[2] / "tools" / "role_lint.py"
    if not path.is_file():
        raise ScaffoldError("scaffold checks need a source checkout (tools/role_lint.py)")
    spec = importlib.util.spec_from_file_location("hnx_role_lint", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["hnx_role_lint"] = mod
    spec.loader.exec_module(mod)
    return mod


def _write(root: Path, rel: str, text: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def _fresh(path: Path) -> None:
    if path.exists():
        raise ScaffoldError(f"{path} already exists; refusing to overwrite")


# ---------------------------------------------------------------- role
def new_role(name: str, dest: Path) -> Path:
    if not ROLE_NAME.match(name):
        raise ScaffoldError("role name must match ^[a-z][a-z0-9_]*$")
    root = Path(dest) / "roles" / name
    _fresh(root)
    h = f"# {SPDX}\n"
    opt = lambda t, d, **k: {"type": t, "description": d, **k}  # noqa: E731
    main_opts = {
        f"{name}_logical_id": opt("str", "Logical service id in the registry.", required=True),
        f"{name}_version": opt("str", "Pinned version.", default="0.1.0"),
        f"{name}_data_dir": opt(
            "path", "Data directory.", default=f"/var/lib/{name.replace('_', '-')}"
        ),
        f"{name}_export_dir": opt(
            "path",
            "Open-format export directory.",
            default=f"/var/backups/{name.replace('_', '-')}/export",
        ),
    }
    specs: dict = {"main": {"short_description": f"Deploy {name}.", "options": main_opts}}
    hook_opts = {
        "health": [f"{name}_logical_id"],
        "readiness": [f"{name}_logical_id"],
        "backup": [f"{name}_logical_id", f"{name}_data_dir"],
        "restore": [f"{name}_logical_id", f"{name}_data_dir"],
        "upgrade": [f"{name}_logical_id", f"{name}_version"],
        "export": [f"{name}_logical_id", f"{name}_data_dir", f"{name}_export_dir"],
    }
    for hook, keys in hook_opts.items():
        specs[hook] = {
            "short_description": f"{hook} hook.",
            "options": {k: dict(main_opts[k]) for k in keys},
        }
    _write(
        root,
        "meta/argument_specs.yml",
        h + yaml.safe_dump({"argument_specs": specs}, sort_keys=False, width=100),
    )
    _write(
        root,
        "meta/main.yml",
        h
        + 'galaxy_info:\n  author: HomelabNext contributors\n  license: Apache-2.0\n  min_ansible_version: "2.15"\ndependencies: []\n',
    )
    _write(
        root,
        "defaults/main.yml",
        h
        + "".join(
            f"{k}: {json.dumps(v['default'])}\n" for k, v in main_opts.items() if "default" in v
        ),
    )
    _write(
        root,
        "tasks/main.yml",
        h
        + f"""- name: Create data directory
  ansible.builtin.file:
    path: "{{{{ {name}_data_dir }}}}"
    state: directory
    mode: "0750"
""",
    )
    bodies = {
        "health": "- name: TODO replace with a real probe (uri, command, or wait_for)\n  ansible.builtin.debug:\n    msg: health not implemented for {n}\n  tags: [health]\n",
        "readiness": "- name: TODO check dependencies via lookup('hnx_registry', ...)\n  ansible.builtin.debug:\n    msg: readiness not implemented for {n}\n  tags: [readiness]\n",
        "backup": '- name: Declare backup paths\n  ansible.builtin.debug:\n    msg: "back up {{{{ {n}_data_dir }}}}"\n  tags: [backup]\n',
        "restore": "- name: TODO restore from backup\n  ansible.builtin.debug:\n    msg: restore not implemented for {n}\n  tags: [restore]\n",
        "upgrade": '- name: TODO pinned version bump path\n  ansible.builtin.debug:\n    msg: "upgrade from {{{{ {n}_version }}}}"\n  tags: [upgrade]\n',
        "export": '- name: TODO open-format export to the export dir\n  ansible.builtin.debug:\n    msg: "export to {{{{ {n}_export_dir }}}}"\n  tags: [export]\n',
    }
    for hook, body in bodies.items():
        _write(root, f"tasks/{hook}.yml", h + body.format(n=name))
    return root


def verify_role(path: Path) -> list[str]:
    return [str(f) for f in _role_lint().lint_role(Path(path))]


# ---------------------------------------------------------------- schema
def new_schema(name: str, dest: Path) -> Path:
    if not SLUG_NAME.match(name):
        raise ScaffoldError("schema name must match ^[a-z][a-z0-9-]*$")
    root = Path(dest) / "schemas" / name
    _fresh(root)
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"https://schemas.example.internal/{name}/1.0.0.json",
        "title": name,
        "type": "object",
        "required": ["id", "schema_version"],
        "additionalProperties": False,
        "properties": {
            "id": {"type": "string", "pattern": "^[a-z][a-z0-9-]*$"},
            "schema_version": {"const": "1.0.0"},
            "note": {"type": "string"},
        },
    }
    _write(root, f"{name}.schema.json", json.dumps(schema, indent=2) + "\n")
    _write(
        root,
        "examples/valid.json",
        json.dumps({"id": "example-one", "schema_version": "1.0.0"}, indent=2) + "\n",
    )
    _write(
        root, "negatives/missing-id.json", json.dumps({"schema_version": "1.0.0"}, indent=2) + "\n"
    )
    _write(
        root,
        "negatives/unknown-field.json",
        json.dumps({"id": "x", "schema_version": "1.0.0", "extra": 1}, indent=2) + "\n",
    )
    return root


def verify_schema(path: Path) -> list[str]:
    import jsonschema

    path = Path(path)
    errs: list[str] = []
    schemas = sorted(path.glob("*.schema.json"))
    if len(schemas) != 1:
        return [f"{path}: expected exactly one *.schema.json"]
    schema = json.loads(schemas[0].read_text())
    try:
        jsonschema.Draft202012Validator.check_schema(schema)
    except jsonschema.SchemaError as exc:
        return [f"{schemas[0]}: invalid schema: {exc.message}"]
    v = jsonschema.Draft202012Validator(schema)
    ex = sorted((path / "examples").glob("*.json"))
    neg = sorted((path / "negatives").glob("*.json"))
    if not ex:
        errs.append(f"{path}: needs at least one example")
    if not neg:
        errs.append(f"{path}: needs at least one negative")
    for f in ex:
        for e in v.iter_errors(json.loads(f.read_text())):
            errs.append(f"{f}: example rejected: {e.message}")
    for f in neg:
        if not list(v.iter_errors(json.loads(f.read_text()))):
            errs.append(f"{f}: negative was accepted")
    return errs


# ---------------------------------------------------------------- capability
def new_capability(name: str, dest: Path) -> Path:
    if not SLUG_NAME.match(name):
        raise ScaffoldError("capability name must match ^[a-z][a-z0-9-]*$")
    root = Path(dest) / "conformance" / name
    _fresh(root)
    ident = name.replace("-", "_")
    _write(
        root,
        "CONTRACT.md",
        f"""<!-- {SPDX} -->
# Capability contract: {name}

Operations (each is a conformance check id `{name}-NN`):

1. `{name}-01` `put(key, value)` then `get(key)` returns `value`.
2. `{name}-02` `get(missing)` raises `KeyError`.

A swap is safe only if the replacement passes every check in `test_conformance.py`.
""",
    )
    _write(
        root,
        "fake.py",
        f'''# {SPDX}
"""In-memory fake of the {name} capability; the reference implementation of the contract."""


class Fake{ident.title().replace("_", "")}:
    def __init__(self):
        self._data = {{}}

    def put(self, key, value):
        self._data[key] = value

    def get(self, key):
        return self._data[key]
''',
    )
    _write(
        root,
        "test_conformance.py",
        f'''# {SPDX}
"""Conformance checks for {name}. Point ``IMPLEMENTATION`` at any implementation to test it."""
import importlib.util
from pathlib import Path

import pytest

_spec = importlib.util.spec_from_file_location("fake_{ident}", Path(__file__).with_name("fake.py"))
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
IMPLEMENTATION = _mod.Fake{ident.title().replace("_", "")}


@pytest.fixture
def impl():
    return IMPLEMENTATION()


def test_{ident}_01_put_get(impl):
    impl.put("k", "v")
    assert impl.get("k") == "v"


def test_{ident}_02_missing_raises(impl):
    with pytest.raises(KeyError):
        impl.get("absent")
''',
    )
    return root


def verify_capability(path: Path) -> list[str]:
    path = Path(path)
    errs = []
    for f in ("CONTRACT.md", "fake.py", "test_conformance.py"):
        if not (path / f).is_file():
            errs.append(f"{path}: missing {f}")
    for f in path.glob("*.py"):
        if SPDX not in f.read_text():
            errs.append(f"{f}: missing SPDX header")
    if (path / "test_conformance.py").is_file():
        n = len(re.findall(r"^def test_", (path / "test_conformance.py").read_text(), re.M))
        if n < 1:
            errs.append(f"{path}: conformance test file has no tests")
    return errs


# ---------------------------------------------------------------- detection
def new_detection(name: str, dest: Path) -> Path:
    if not SLUG_NAME.match(name):
        raise ScaffoldError("detection name must match ^[a-z][a-z0-9-]*$")
    root = Path(dest) / "detections" / name
    _fresh(root)
    rule = {
        "title": f"Example detection {name}",
        "status": "experimental",
        "description": "Fires when a process runs with an encoded command line (synthetic example).",
        "logsource": {"category": "process_creation", "product": "linux"},
        "detection": {
            "selection": {"CommandLine|contains": "base64 -d"},
            "condition": "selection",
        },
        "level": "medium",
        "tags": ["attack.execution"],
    }
    _write(root, "rule.yml", f"# {SPDX}\n" + yaml.safe_dump(rule, sort_keys=False))
    _write(
        root,
        "fixtures/must_fire.json",
        json.dumps([{"CommandLine": "echo aGk= | base64 -d | sh"}], indent=2) + "\n",
    )
    _write(
        root,
        "fixtures/must_not_fire.json",
        json.dumps([{"CommandLine": "ls -la /tmp"}], indent=2) + "\n",
    )
    return root


def verify_detection(path: Path) -> list[str]:
    path = Path(path)
    errs = []
    rf = path / "rule.yml"
    if not rf.is_file():
        return [f"{path}: missing rule.yml"]
    rule = yaml.safe_load(rf.read_text()) or {}
    for k in ("title", "logsource", "detection", "level"):
        if k not in rule:
            errs.append(f"{rf}: missing '{k}'")
    det = rule.get("detection") or {}
    if "condition" not in det:
        errs.append(f"{rf}: detection has no condition")
    for fx in ("must_fire", "must_not_fire"):
        f = path / "fixtures" / f"{fx}.json"
        if not f.is_file():
            errs.append(f"{path}: missing fixtures/{fx}.json")
        elif not json.loads(f.read_text()):
            errs.append(f"{f}: fixture set is empty")
    if re.search(r"\b(?:rule|sid)[ _-]?(?:id)?\s*[:=]?\s*\d{5,}\b", rf.read_text(), re.I):
        errs.append(f"{rf}: contains a numeric product rule id; keep rules product-neutral")
    return errs


KINDS: dict[str, tuple[Callable[[str, Path], Path], Callable[[Path], list[str]]]] = {
    "role": (new_role, verify_role),
    "schema": (new_schema, verify_schema),
    "capability": (new_capability, verify_capability),
    "detection": (new_detection, verify_detection),
}


def new(kind: str, name: str, dest: Path) -> Path:
    if kind not in KINDS:
        raise ScaffoldError(f"unknown kind '{kind}', expected one of {sorted(KINDS)}")
    return KINDS[kind][0](name, Path(dest))


def verify(kind: str, path: Path) -> list[str]:
    return KINDS[kind][1](Path(path))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="hnx", description="HomelabNext scaffolds")
    sub = ap.add_subparsers(dest="cmd", required=True)
    n = sub.add_parser("new", help="create a scaffold and verify it")
    n.add_argument("kind", choices=sorted(KINDS))
    n.add_argument("name")
    n.add_argument("--dest", default=".")
    args = ap.parse_args(argv)
    try:
        out = new(args.kind, args.name, Path(args.dest))
    except ScaffoldError as exc:
        print(f"hnx new: {exc}", file=sys.stderr)
        return 1
    problems = verify(args.kind, out)
    if problems:
        print("\n".join(problems), file=sys.stderr)
        return 3
    print(f"created {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
