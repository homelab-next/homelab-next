# SPDX-License-Identifier: Apache-2.0
"""What actually runs each script, compared with what the headers claim (checklist M-02, M-04).

Callers are discovered, never declared.  Each becomes a trigger string in the header's grammar:

==================  ====================================================================
``make:T``          a recipe line of target ``T`` in the root ``Makefile`` names the script
                    (simple ``VAR := value`` assignments are expanded first)
``ci:W/J``          a ``run:`` step of job ``J`` in ``.github/workflows/W.yml`` names it; a
                    workflow with an ``on: schedule`` trigger is a **timer**
``pre-commit:H``    the ``entry`` of hook ``H`` in ``.pre-commit-config.yaml`` names it
``compose:S/V``     service ``V`` of the compose stack in directory ``S`` runs it (its
                    ``command``/``entrypoint``, mapped back through the Dockerfile's ``COPY``)
``script:I``        catalogued script ``I`` runs it (a non-comment line names it)
``code:P``          package module ``P`` loads it with ``paths.checkout_tool("NAME")``
``fleet-unit:N``    entry ``N`` of a fleet_units spec (``fleet_unit_specs`` globs) execs it:
                    a **timer**
``timer:R/U``       role ``R`` ships ``U.timer`` and ``U.service`` whose ``ExecStart`` (or
                    ``ExecStartPre``/``ExecStopPost``, the last-run writer) runs it: a **timer**
``role:R``          a task file of role ``R`` names a script shipped in that role
``profile:P``       a file of profile ``P`` names a script shipped in that profile
==================  ====================================================================

Invariant criteria are discovered too: a criterion runs a script when its ``observable`` names the
script's path, or, for ``evidence: plugin``, when a string constant in the registered check
function's body does.  They are compared with the header's ``invariant:`` list.

An ``ExecStart``/``exec`` resolves to a script by its ``installs_to`` path, by ending in the
script's repository path, or not at all; ``hnx`` itself is the platform's entry point (package
code, not a script).  An unresolved exec is a scheduled job nobody catalogued, unless the
allowlist names it with a reason.

Settings and the reviewed allowlist live in ``tools/scripts.allow.yml``; every allowlist entry
needs a reason, and one that no longer matches anything is itself a finding.
"""

from __future__ import annotations

import ast
import fnmatch
import inspect
import pathlib
import re
import shlex
import textwrap
from collections import defaultdict
from dataclasses import dataclass, field

from .catalog import Catalog

__all__ = [
    "ALLOW_FILE",
    "Allow",
    "AllowError",
    "Reality",
    "discover",
    "load_allow",
    "reality_problems",
    "runner_problems",
]

ALLOW_FILE = "tools/scripts.allow.yml"
DEFAULT_REGISTERS = ("examples/registers/invariants.yml",)
DEFAULT_FLEET_SPECS = ("**/fleet_units.yml", "**/fleet_units/*.yml")
TIMER_KINDS = ("fleet-unit", "timer")  # plus ci jobs of a scheduled workflow
_INTERPRETERS = {"env", "python", "python3", "bash", "sh", "exec"}
_PATHLIKE = r"(?:\./)?[A-Za-z0-9_][A-Za-z0-9_./-]*\.(?:py|sh|bash)"
# a path anywhere in a command line (for callers of known scripts)
_MENTION = re.compile(r"(?:^|(?<=[\s;&|(=\"'/]))(?P<p>" + _PATHLIKE + r")(?![\w.-])", re.M)
# a path in command position: run directly or through an interpreter (for unknown files)
_COMMAND = re.compile(
    r"(?:^|[;&|(]|&&|\|\||\brun:)\s*(?:(?:/usr/bin/env\s+)?(?:python3?|bash|sh|\.)\s+(?:-\S+\s+)*)?"
    r"(?P<p>" + _PATHLIKE + r")(?![\w.-])",
    re.M,
)
_CHECKOUT_TOOL = re.compile(r"checkout_tool\(\s*[\"']([A-Za-z0-9_.-]+)[\"']")


class AllowError(ValueError):
    """The allowlist file is malformed."""


@dataclass
class Allow:
    registers: list[str] = field(default_factory=lambda: list(DEFAULT_REGISTERS))
    fleet_unit_specs: list[str] = field(default_factory=lambda: list(DEFAULT_FLEET_SPECS))
    #: globs under fleet_unit_specs that are not this tree's scheduled jobs (the fictional module
    #: examples, whose code is named but not shipped); their own tests validate them instead
    fleet_unit_specs_exclude: list[str] = field(default_factory=list)
    uncalled: dict[str, str] = field(default_factory=dict)
    not_in_runner: dict[str, str] = field(default_factory=dict)
    external_exec: dict[str, str] = field(default_factory=dict)


def load_allow(root: pathlib.Path, path: str | None = None) -> Allow:
    import yaml

    p = pathlib.Path(root) / (path or ALLOW_FILE)
    if not p.is_file():
        if path:
            raise AllowError(f"{path}: not found")
        return Allow()
    try:
        doc = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise AllowError(f"{p.name}: not YAML ({exc.__class__.__name__})") from exc
    if not isinstance(doc, dict):
        raise AllowError(f"{p.name}: must be a mapping")
    unknown = set(doc) - set(Allow.__dataclass_fields__)
    if unknown:
        raise AllowError(f"{p.name}: unknown key(s) {sorted(unknown)}")
    allow = Allow()
    for key in ("registers", "fleet_unit_specs", "fleet_unit_specs_exclude"):
        if key in doc:
            v = doc[key]
            if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
                raise AllowError(f"{p.name}: {key} must be a list of paths or globs")
            setattr(allow, key, v)
    for key in ("uncalled", "not_in_runner", "external_exec"):
        v = doc.get(key) or {}
        if not isinstance(v, dict):
            raise AllowError(f"{p.name}: {key} must map a name to its reason")
        for name, why in v.items():
            if not isinstance(why, str) or len(why.strip()) < 10:
                raise AllowError(f"{p.name}: {key}.{name} needs a reason (a sentence, not a word)")
        setattr(allow, key, {str(k): v for k, v in v.items()})
    return allow


@dataclass
class Reality:
    """Discovered callers per script path, and what could not be matched to a script."""

    callers: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    invariants: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    timers: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    uncatalogued: list[str] = field(default_factory=list)  # "<caller>: runs <file> (no header)"
    unresolved_exec: list[tuple[str, str]] = field(default_factory=list)  # (caller, exec)
    criterion_ids: set[str] = field(default_factory=set)
    problems: list[str] = field(default_factory=list)  # sources that could not be read
    #: fleet_unit_specs_exclude globs that skipped at least one spec (the rest are stale)
    excludes_used: set[str] = field(default_factory=set)


# ---- helpers ---------------------------------------------------------------------------------


def _yaml(path: pathlib.Path):
    import yaml

    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _norm(p: str) -> str:
    return p[2:] if p.startswith("./") else p


class _Index:
    def __init__(self, root: pathlib.Path, cat: Catalog, files: list[str]):
        self.root = root
        self.cat = cat
        self.files = set(files)
        self.paths = cat.by_path()
        self.installs = {e["installs_to"]: e["path"] for e in cat.entries if e.get("installs_to")}

    def mentions(self, text: str) -> set[str]:
        """Catalogued script paths a command text names anywhere."""
        return {p for m in _MENTION.finditer(text) if (p := _norm(m["p"])) in self.paths}

    def commands(self, text: str) -> set[str]:
        """Tracked files a command text runs, catalogued or not."""
        return {p for m in _COMMAND.finditer(text) if (p := _norm(m["p"])) in self.files}

    def resolve_exec(self, cmdline: str) -> tuple[str, str]:
        """('hnx'|'script'|'unknown', detail) for an ExecStart/exec line."""
        try:
            argv = shlex.split(cmdline.lstrip("-@+!:"))
        except ValueError:
            argv = cmdline.split()
        i = 0
        while i < len(argv) and (
            pathlib.PurePosixPath(argv[i]).name in _INTERPRETERS
            or (i > 0 and argv[i].startswith("-"))
        ):
            i += 1
        if i >= len(argv):
            return "unknown", cmdline
        tok = argv[i]
        if pathlib.PurePosixPath(tok).name == "hnx":
            return "hnx", " ".join(argv[i:])
        if tok in self.installs:
            return "script", self.installs[tok]
        for rel in self.paths:
            if tok == rel or tok.endswith("/" + rel):
                return "script", rel
        return "unknown", tok


def _strip_comments(text: str) -> str:
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def _record(real: Reality, idx: _Index, caller: str, text: str, timer: bool = False) -> None:
    for p in idx.mentions(text):
        real.callers[p].add(caller)
        if timer:
            real.timers[p].add(caller)
    for p in idx.commands(text):
        if p not in idx.paths:
            real.uncatalogued.append(f"{caller}: runs {p}, which has no script header")


# ---- sources ---------------------------------------------------------------------------------

_ASSIGN = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*(?::=|\?=|=)\s*(.*)$")
_TARGET = re.compile(r"^([A-Za-z0-9_.%/-]+(?:\s+[A-Za-z0-9_.%/-]+)*)\s*:(?!=)")
_VAR = re.compile(r"\$\(([A-Za-z_][A-Za-z0-9_]*)\)")


def _makefile(real: Reality, idx: _Index) -> None:
    mk = idx.root / "Makefile"
    if not mk.is_file():
        return
    variables: dict[str, str] = {}
    recipes: dict[str, list[str]] = defaultdict(list)
    current: list[str] = []
    for line in mk.read_text(encoding="utf-8").splitlines():
        if line.startswith("\t"):
            for t in current:
                recipes[t].append(line[1:])
            continue
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if m := _ASSIGN.match(line):
            variables[m[1]] = m[2]
            current = []
        elif m := _TARGET.match(line):
            current = [t for t in m[1].split() if not t.startswith(".")]
        else:
            current = []

    def expand(s: str, depth: int = 0) -> str:
        if depth > 8:
            return s
        out = _VAR.sub(lambda m: variables.get(m[1], m[0]), s)
        return out if out == s else expand(out, depth + 1)

    for target, lines in recipes.items():
        _record(real, idx, f"make:{target}", expand("\n".join(lines)))


def _workflows(real: Reality, idx: _Index) -> None:
    wdir = idx.root / ".github" / "workflows"
    if not wdir.is_dir():
        return
    for wf in sorted([*wdir.glob("*.yml"), *wdir.glob("*.yaml")]):
        try:
            doc = _yaml(wf) or {}
        except Exception as exc:  # report, never guess
            real.problems.append(
                f"{wf.relative_to(idx.root).as_posix()}: unreadable ({exc.__class__.__name__})"
            )
            continue
        on = doc.get("on", doc.get(True, {}))  # YAML 1.1 reads a bare `on:` key as True
        scheduled = isinstance(on, dict) and "schedule" in on
        for job_id, job in (doc.get("jobs") or {}).items():
            runs = [s.get("run", "") for s in (job or {}).get("steps", []) if isinstance(s, dict)]
            _record(real, idx, f"ci:{wf.stem}/{job_id}", "\n".join(r for r in runs if r), scheduled)


def _precommit(real: Reality, idx: _Index) -> None:
    pc = idx.root / ".pre-commit-config.yaml"
    if not pc.is_file():
        return
    try:
        doc = _yaml(pc) or {}
    except Exception as exc:  # report, never guess
        real.problems.append(f".pre-commit-config.yaml: unreadable ({exc.__class__.__name__})")
        return
    for repo in doc.get("repos", []):
        for hook in repo.get("hooks", []):
            if hook.get("entry"):
                _record(real, idx, f"pre-commit:{hook['id']}", hook["entry"])


def _copies(dockerfile: pathlib.Path) -> dict[str, str]:
    """Container path -> build-context path, from the Dockerfile's COPY/ADD lines."""
    out = {}
    if not dockerfile.is_file():
        return out
    for line in dockerfile.read_text(encoding="utf-8").splitlines():
        parts = line.split()
        if (
            len(parts) >= 3
            and parts[0].upper() in ("COPY", "ADD")
            and not parts[1].startswith("--")
        ):
            src, dest = parts[1], parts[-1]
            if dest.endswith("/"):
                dest += pathlib.PurePosixPath(src).name
            out[dest] = src
    return out


def _compose(real: Reality, idx: _Index) -> None:
    for rel in sorted(idx.files):
        name = rel.rsplit("/", 1)[-1]
        if not (rel.startswith("compose/") and fnmatch.fnmatch(name, "*compose*.y*ml")):
            continue
        cfile = idx.root / rel
        stack = cfile.parent.name
        try:
            doc = _yaml(cfile) or {}
        except Exception as exc:
            real.problems.append(f"{rel}: unreadable ({exc.__class__.__name__})")
            continue
        for svc, spec in (doc.get("services") or {}).items():
            spec = spec or {}
            build = spec.get("build")
            copies: dict[str, str] = {}
            ctx = cfile.parent
            if isinstance(build, dict):
                ctx = (cfile.parent / build.get("context", ".")).resolve()
                copies = _copies(ctx / build.get("dockerfile", "Dockerfile"))
            elif isinstance(build, str):
                ctx = (cfile.parent / build).resolve()
                copies = _copies(ctx / "Dockerfile")
            argv: list[str] = []
            for key in ("entrypoint", "command"):
                v = spec.get(key)
                argv += v if isinstance(v, list) else shlex.split(v) if isinstance(v, str) else []
            for tok in argv:
                src = copies.get(str(tok))
                if src is None:
                    continue
                try:
                    repo_rel = (ctx / src).resolve().relative_to(idx.root.resolve()).as_posix()
                except ValueError:
                    continue
                caller = f"compose:{stack}/{svc}"
                if repo_rel in idx.paths:
                    real.callers[repo_rel].add(caller)
                elif repo_rel in idx.files:
                    real.uncatalogued.append(
                        f"{caller}: runs {repo_rel}, which has no script header"
                    )


def _script_calls(real: Reality, idx: _Index) -> None:
    for e in idx.cat.entries:
        text = _strip_comments((idx.root / e["path"]).read_text(encoding="utf-8", errors="replace"))
        here = e["path"].rsplit("/", 1)[0] if "/" in e["path"] else ""
        for other in idx.cat.entries:
            if other is e:
                continue
            name = other["path"].rsplit("/", 1)[-1]
            same_dir = (other["path"].rsplit("/", 1)[0] if "/" in other["path"] else "") == here
            pat = (
                re.escape(other["path"])
                if not same_dir
                else r"(?:" + re.escape(other["path"]) + "|" + re.escape(name) + ")"
            )
            if re.search(r"(?:^|(?<=[\s\"'/=(]))" + pat + r"(?![\w.-])", text, re.M):
                real.callers[other["path"]].add(f"script:{e['id']}")


def _package_code(real: Reality, idx: _Index) -> None:
    for rel in sorted(idx.files):
        if not (rel.startswith("homelabnext/") and rel.endswith(".py")):
            continue
        text = (idx.root / rel).read_text(encoding="utf-8", errors="replace")
        for name in _CHECKOUT_TOOL.findall(text):
            target = f"tools/{name}"
            if target in idx.paths:
                real.callers[target].add(f"code:{rel}")
            elif target in idx.files:
                real.uncatalogued.append(f"code:{rel}: runs {target}, which has no script header")


def _fleet_units(real: Reality, idx: _Index, allow: Allow) -> None:
    for rel in sorted(idx.files):
        if rel.startswith(("tests/", "tools/tests/")):
            continue
        if not any(_glob(rel, g) for g in allow.fleet_unit_specs):
            continue
        hit = [g for g in allow.fleet_unit_specs_exclude if _glob(rel, g)]
        if hit:
            real.excludes_used.update(hit)
            continue
        try:
            entries = _yaml(idx.root / rel) or []
        except Exception as exc:
            real.problems.append(f"{rel}: unreadable ({exc.__class__.__name__})")
            continue
        for e in entries if isinstance(entries, list) else []:
            if not isinstance(e, dict) or not e.get("exec") or e.get("replaced_by"):
                continue
            _exec(real, idx, f"fleet-unit:{e.get('name')}", str(e["exec"]))


def _glob(rel: str, pattern: str) -> bool:
    """fnmatch, where a leading ``**/`` also matches at the root."""
    return fnmatch.fnmatch(rel, pattern) or (
        pattern.startswith("**/") and fnmatch.fnmatch(rel, pattern[3:])
    )


def _exec(real: Reality, idx: _Index, caller: str, cmd: str) -> None:
    kind, detail = idx.resolve_exec(cmd)
    if kind == "script":
        real.callers[detail].add(caller)
        real.timers[detail].add(caller)
    elif kind == "unknown":
        real.unresolved_exec.append((caller, detail))


_EXECSTART = re.compile(r"^Exec(?:Start|StartPre|StopPost)=(.+)$", re.M)


def _roles_and_profiles(real: Reality, idx: _Index) -> None:
    groups: dict[tuple[str, str], list[str]] = defaultdict(list)
    for rel in idx.files:
        parts = rel.split("/")
        if rel.startswith("ansible/roles/") and len(parts) > 3:
            groups[("role", parts[2])].append(rel)
        elif rel.startswith("profiles/") and len(parts) > 2:
            groups[("profile", parts[1])].append(rel)
    for (kind, name), rels in sorted(groups.items()):
        units = {}
        for rel in rels:
            base = rel.rsplit("/", 1)[-1].removesuffix(".j2")
            if base.endswith((".timer", ".service")):
                units[base] = rel
        for base in units:
            if not base.endswith(".timer"):
                continue
            svc = units.get(base[: -len(".timer")] + ".service")
            if svc is None:
                continue
            for cmd in _EXECSTART.findall((idx.root / svc).read_text(encoding="utf-8")):
                _exec(real, idx, f"timer:{name}/{base[: -len('.timer')]}", cmd.strip())
        shipped = [p for p in rels if p in idx.paths]
        if not shipped:
            continue
        readers = [
            p
            for p in rels
            if p.endswith((".yml", ".yaml"))
            and (kind == "profile" or "/tasks/" in p or "/handlers/" in p)
        ]
        for p in shipped:
            fname = p.rsplit("/", 1)[-1]
            for r in readers:
                if re.search(
                    r"(?<![\w.-])" + re.escape(fname) + r"(?![\w.-])",
                    (idx.root / r).read_text(encoding="utf-8"),
                ):
                    real.callers[p].add(f"{kind}:{name}")


def _function_strings(fn) -> set[str]:
    """String constants in a check function's body (its docstring and comments excluded)."""
    try:
        src = textwrap.dedent(inspect.getsource(fn))
        tree = ast.parse(src)
    except (OSError, TypeError, SyntaxError):
        return set()
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            body = node.body if isinstance(node.body, list) else []
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                docstrings.add(id(body[0].value))
    return {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and id(node) not in docstrings
    }


def load_criteria(root: pathlib.Path, allow: Allow) -> tuple[list[dict], list[str]]:
    crit, problems = [], []
    for rel in allow.registers:
        p = root / rel
        if not p.is_file():
            problems.append(f"{rel}: invariants register not found ({ALLOW_FILE} registers)")
            continue
        try:
            doc = _yaml(p) or {}
        except Exception as exc:
            problems.append(f"{rel}: unreadable ({exc.__class__.__name__})")
            continue
        crit += [c for c in doc.get("criteria", []) if isinstance(c, dict) and "id" in c]
    return crit, problems


def _invariants(real: Reality, idx: _Index, allow: Allow, plugin_registry=None) -> None:
    criteria, problems = load_criteria(idx.root, allow)
    real.problems += problems
    if plugin_registry is None and any(c.get("evidence") == "plugin" for c in criteria):
        from homelabnext.invariants import default_registry, load_entry_points

        plugin_registry = default_registry()
        load_entry_points(plugin_registry)
    for c in criteria:
        if c.get("evidence") == "auto":
            texts = {c.get("observable", "")}
        elif c.get("evidence") == "plugin":
            chk = plugin_registry.get(c.get("plugin", ""))
            texts = _function_strings(chk.fn) if chk else set()
        else:
            continue
        for t in texts:
            for p in idx.mentions(str(t)):
                real.invariants[p].add(c["id"])
    real.criterion_ids = {c["id"] for c in criteria}


def discover(
    root: pathlib.Path, cat: Catalog, files: list[str], allow: Allow, plugin_registry=None
) -> Reality:
    root = pathlib.Path(root)
    idx = _Index(root, cat, files)
    real = Reality()
    _makefile(real, idx)
    _workflows(real, idx)
    _precommit(real, idx)
    _compose(real, idx)
    _script_calls(real, idx)
    _package_code(real, idx)
    _fleet_units(real, idx, allow)
    _roles_and_profiles(real, idx)
    _invariants(real, idx, allow, plugin_registry)
    return real


# ---- the two verdicts ------------------------------------------------------------------------


def reality_problems(cat: Catalog, real: Reality, allow: Allow) -> list[str]:
    """M-02: 0 scheduled-but-uncatalogued scripts, 0 uncalled active scripts, 0 duplicate ids."""
    out = list(real.problems)
    out += sorted(set(real.uncatalogued))
    used_exec = set()
    for caller, ex in sorted(set(real.unresolved_exec)):
        if ex in allow.external_exec:
            used_exec.add(ex)
        else:
            out.append(
                f"{caller}: execs {ex}, which is neither a catalogued script (path or installs_to) "
                f"nor `hnx`; catalogue it or allowlist it under external_exec with a reason"
            )
    out += [
        f"{ALLOW_FILE}: external_exec {ex} matches no scheduled exec (stale entry)"
        for ex in sorted(set(allow.external_exec) - used_exec)
    ]
    out += [
        f"{ALLOW_FILE}: fleet_unit_specs_exclude {g} skips no fleet_units spec (stale entry)"
        for g in allow.fleet_unit_specs_exclude
        if g not in real.excludes_used
    ]
    out += [p for p in cat.problems if "duplicate script id" in p]
    known = cat.by_id()
    for e in cat.entries:
        found = real.callers.get(e["path"], set())
        declared = {t for t in e["trigger"] if t != "manual"}
        for t in sorted(found - declared):
            out.append(f"{e['path']}: called by {t}, which its header's trigger list does not name")
        for t in sorted(declared - found):
            out.append(f"{e['path']}: header names trigger {t}, but nothing there runs it")
        called = bool(found or real.invariants.get(e["path"]))
        active = e.get("status", "active") == "active"
        if e["id"] in allow.uncalled:
            if called:
                out.append(f"{ALLOW_FILE}: uncalled {e['id']} has a caller now (stale entry)")
            elif not active:
                out.append(f"{ALLOW_FILE}: uncalled {e['id']} is deprecated and needs no entry")
        elif active and not called:
            out.append(
                f"{e['path']}: active script with no caller; add one, mark it deprecated, "
                f"or allowlist it under uncalled with a reason"
            )
    out += [
        f"{ALLOW_FILE}: uncalled {i} names no catalogued script (stale entry)"
        for i in sorted(set(allow.uncalled) - set(known))
    ]
    return out


def runner_problems(cat: Catalog, real: Reality, allow: Allow) -> list[str]:
    """M-04: every check runs through the invariants runner; no standalone check timers."""
    out = list(real.problems)
    criterion_ids = real.criterion_ids
    known = cat.by_id()
    for e in cat.entries:
        refs = real.invariants.get(e["path"], set())
        declared = set(e.get("invariant", []))
        if e["kind"] != "check":
            if refs:
                out.append(
                    f"{e['path']}: criteria {', '.join(sorted(refs))} run it as a check, but its "
                    f"header says kind: {e['kind']}"
                )
            continue
        for t in sorted(real.timers.get(e["path"], set())):
            out.append(
                f"{e['path']}: check scheduled directly by {t}; schedule `hnx invariants run` and "
                f"let the criterion run it"
            )
        for i in sorted(declared - criterion_ids):
            out.append(f"{e['path']}: header names invariant {i}, which no register defines")
        for i in sorted(declared & criterion_ids - refs):
            out.append(
                f"{e['path']}: header names invariant {i}, but that criterion does not run it"
            )
        for i in sorted(refs - declared):
            out.append(
                f"{e['path']}: criterion {i} runs it, but its header's invariant list omits it"
            )
        if not refs:
            if e["id"] not in allow.not_in_runner:
                out.append(
                    f"{e['path']}: check that no invariants criterion runs; add a criterion whose "
                    f"observable runs it, or allowlist it under not_in_runner with a reason"
                )
        elif e["id"] in allow.not_in_runner:
            out.append(
                f"{ALLOW_FILE}: not_in_runner {e['id']} runs in the runner now (stale entry)"
            )
    for i in sorted(set(allow.not_in_runner)):
        if i not in known:
            out.append(f"{ALLOW_FILE}: not_in_runner {i} names no catalogued script (stale entry)")
        elif known[i]["kind"] != "check":
            out.append(f"{ALLOW_FILE}: not_in_runner {i} is not a check (stale entry)")
    return out
