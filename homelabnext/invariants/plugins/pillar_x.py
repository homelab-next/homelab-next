# SPDX-License-Identifier: Apache-2.0
"""Pillar X - modularity. Eight criteria; five are checkable on a laptop, three need a server.

    X-01  no raw endpoints outside the registry          (runs tools/no_raw_endpoints.py)
    X-02  registry completeness vs live listeners        SERVER (needs the live platform)
    X-03  schemas version-pinned, examples valid, negatives rejected
    X-04  every capability has a conformance test
    X-05  role linter clean                              (runs tools/role_lint.py)
    X-06  detection ids are logical (``det:`` ids), no raw rule numbers in specs
    X-07  every stateful product's export hook exercised SERVER (needs a restore drill)
    X-08  cutover-commit audit                           SERVER (needs a real cutover)

Every check takes ``ctx.root`` as the repository root, never reads outside it, and returns
``skip`` (with a reason) when the thing it audits does not exist yet.

Layout conventions (kept in one place so adopters can see what to match):
    schemas/**/NAME.schema.json         schema; carries $schema, $id, and a version
                                        (``x-version: "1.2"`` or a ``/v1`` segment in ``$id``)
    schemas/**/examples/NAME.*.json     must validate;  schemas/**/negatives/NAME.*.json must not
    capabilities.yml                    ``capabilities: [name, ...]``
    conformance/<capability>/test_*.py  the capability's conformance test
    det_map.yml                         ``detections: {logical.id: rule_number}``
"""

from __future__ import annotations

import json
import pathlib
import re
import sys

import yaml

from ..api import ERROR, FAIL, PASS, SKIP, Check, CheckResult, Context, Registry

__all__ = ["SERVER_ONLY", "register", "x01", "x03", "x04", "x05", "x06"]

SERVER_ONLY = {
    "X-02": "registry rows vs live listeners needs the running platform",
    "X-07": "export hooks exercised in a restore drill needs the running platform",
    "X-08": "cutover-commit audit needs a real cutover",
}


def _tool_check(ctx: Context, tool: str, args: list[str], ok_msg: str) -> CheckResult:
    path = ctx.root / tool
    if not path.exists():
        return CheckResult(SKIP, f"{tool} not present in this tree")
    rc, out = ctx.run([sys.executable, str(path), *args], 300)
    if rc == 0:
        return CheckResult(PASS, ok_msg)
    return CheckResult(FAIL if rc < 100 else ERROR, f"[exit {rc}] {out}"[-600:])


def x01(ctx: Context) -> CheckResult:
    return _tool_check(ctx, "tools/no_raw_endpoints.py", [], "no raw endpoints")


def x05(ctx: Context) -> CheckResult:
    if not (ctx.root / "ansible" / "roles").is_dir():
        return CheckResult(SKIP, "no ansible/roles directory")
    return _tool_check(ctx, "tools/role_lint.py", ["ansible/roles"], "role linter clean")


# ---- X-03 -----------------------------------------------------------------------------------

_VERSION_ID = re.compile(r"(/v\d+(?:\.\d+)*(?:/|$|\.)|@\d+(?:\.\d+)*$)")
_VERSION_FIELD = re.compile(r"^\d+\.\d+(\.\d+)?$")


def _load(path: pathlib.Path):
    text = path.read_text()
    return yaml.safe_load(text) if path.suffix in (".yml", ".yaml") else json.loads(text)


def x03(ctx: Context) -> CheckResult:
    sdir = ctx.root / "schemas"
    schemas = sorted(sdir.rglob("*.schema.json")) if sdir.is_dir() else []
    if not schemas:
        return CheckResult(SKIP, "no schemas/ tree")
    try:
        import jsonschema
    except ImportError:
        return CheckResult(ERROR, "jsonschema is not installed")
    problems = []
    for sp in schemas:
        rel = sp.relative_to(ctx.root).as_posix()
        name = sp.name[: -len(".schema.json")]
        try:
            schema = json.loads(sp.read_text())
            jsonschema.Draft202012Validator.check_schema(schema)
        except Exception as ex:
            problems.append(f"{rel}: not a valid schema ({type(ex).__name__})")
            continue
        if "$schema" not in schema or "$id" not in schema:
            problems.append(f"{rel}: needs $schema and $id")
        ver = schema.get("x-version")
        if not (isinstance(ver, str) and _VERSION_FIELD.match(ver)) and not _VERSION_ID.search(
            str(schema.get("$id", ""))
        ):
            problems.append(f"{rel}: not version-pinned (x-version or /vN in $id)")
        validator = jsonschema.Draft202012Validator(schema)
        good = sorted((sp.parent / "examples").glob(f"{name}.*.json")) + sorted(
            (sp.parent / "examples").glob(f"{name}.*.y*ml")
        )
        bad = sorted((sp.parent / "negatives").glob(f"{name}.*.json")) + sorted(
            (sp.parent / "negatives").glob(f"{name}.*.y*ml")
        )
        if not good:
            problems.append(f"{rel}: no example in examples/{name}.*")
        if not bad:
            problems.append(f"{rel}: no negative in negatives/{name}.*")
        for g in good:
            errs = list(validator.iter_errors(_load(g)))
            if errs:
                problems.append(
                    f"{g.relative_to(ctx.root).as_posix()}: example invalid ({errs[0].message[:80]})"
                )
        for b in bad:
            if validator.is_valid(_load(b)):
                problems.append(f"{b.relative_to(ctx.root).as_posix()}: negative was ACCEPTED")
    if problems:
        return CheckResult(FAIL, "; ".join(problems))
    return CheckResult(PASS, f"{len(schemas)} schemas pinned, examples valid, negatives rejected")


# ---- X-04 -----------------------------------------------------------------------------------


def _capabilities(root: pathlib.Path) -> list[str] | None:
    for cand in ("capabilities.yml", "registry/capabilities.yml"):
        p = root / cand
        if p.exists():
            data = yaml.safe_load(p.read_text()) or {}
            return [str(c) for c in data.get("capabilities", [])]
    conf = root / "conformance"
    if conf.is_dir():
        return sorted(
            d.name for d in conf.iterdir() if d.is_dir() and not d.name.startswith(("_", "."))
        )
    return None


def x04(ctx: Context) -> CheckResult:
    caps = _capabilities(ctx.root)
    if caps is None:
        return CheckResult(SKIP, "no capabilities.yml or conformance/ tree")
    missing = [c for c in caps if not list((ctx.root / "conformance" / c).glob("test_*.py"))]
    if missing:
        return CheckResult(FAIL, f"capabilities without a conformance test: {', '.join(missing)}")
    return CheckResult(PASS, f"{len(caps)} capabilities, each with a conformance test")


# ---- X-06 -----------------------------------------------------------------------------------

SPEC_DIRS = ("charters", "profiles", "decisions", "schedules")
SPEC_SUFFIXES = {".md", ".yml", ".yaml", ".json", ".txt", ".toml"}
RAW_RULE = re.compile(r"(?i)\brule[\s_-]*(?:id|no\.?|number|#)?\s*[:=#]?\s*[\"']?(\d{4,8})\b")
DET_REF = re.compile(r"\bdet:([a-z0-9_.\-]+[a-z0-9])")


def x06(ctx: Context) -> CheckResult:
    files = [
        f
        for d in SPEC_DIRS
        if (ctx.root / d).is_dir()
        for f in sorted((ctx.root / d).rglob("*"))
        if f.is_file() and f.suffix in SPEC_SUFFIXES
    ]
    if not files:
        return CheckResult(SKIP, "no charters/profiles/decisions/schedules to lint")
    known = None
    mp = ctx.root / "det_map.yml"
    if mp.exists():
        known = set((yaml.safe_load(mp.read_text()) or {}).get("detections", {}))
    problems = []
    for f in files:
        rel = f.relative_to(ctx.root).as_posix()
        text = f.read_text(errors="replace")
        for m in RAW_RULE.finditer(text):
            problems.append(f"{rel}: raw rule number {m.group(1)}; use a det: logical id")
        if known is not None:
            for m in DET_REF.finditer(text):
                if m.group(1) not in known:
                    problems.append(f"{rel}: det:{m.group(1)} is not in det_map.yml")
    if problems:
        return CheckResult(FAIL, "; ".join(problems[:20]))
    return CheckResult(PASS, f"{len(files)} spec files use logical detection ids only")


def _server(id_):
    def fn(ctx: Context) -> CheckResult:
        return CheckResult(SKIP, f"SERVER: {SERVER_ONLY[id_]}")

    return fn


def register(reg: Registry) -> None:
    reg.register(Check("X-01", "no raw endpoint literals outside the registry", x01))
    reg.register(Check("X-03", "schemas version-pinned; examples valid; negatives rejected", x03))
    reg.register(Check("X-04", "every capability has a conformance test", x04))
    reg.register(Check("X-05", "role linter reports clean", x05))
    reg.register(Check("X-06", "detection ids in specs are logical, never raw rule numbers", x06))
    for id_ in SERVER_ONLY:
        reg.register(Check(id_, SERVER_ONLY[id_], _server(id_)))
