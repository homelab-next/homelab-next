#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: role-lint
#   kind: check
#   purpose: Fail when a role or playbook breaks the role interface (docs/role-interface.md).
#   owner: maintainers
#   trigger: [ci:ci/schemas, code:homelabnext/scaffold/core.py, make:gates]
#   invariant: [X-05]
#   inputs: role directories, or --playbook files with --inventory
#   outputs: one line per finding with its rule id
#   exit:
#     "0": clean
#     "1": findings
#     "2": could not run
"""Role linter for the HomelabNext role interface (docs/role-interface.md).

Usage:
    python tools/role_lint.py ansible/roles/*            # lint roles
    python tools/role_lint.py --playbook ansible/playbooks/x.yml --inventory ansible/inventory/example/hosts.yml

Exit codes: 0 clean, 1 findings, 2 could not run (bad arguments / unreadable input).
Every finding has a stable rule id (RLnnn for roles, PBnnn for playbooks).
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

HOOKS = ("health", "readiness", "backup", "restore", "upgrade", "export")
ENTRY_POINTS = ("main", *HOOKS)

RULES = {
    "RL000": "a role file is not valid YAML",
    "RL001": "meta/argument_specs.yml is missing",
    "RL002": "argument_specs lacks an entry point, a required input, or a typed+described option",
    "RL003": "a standard hook task file is missing or empty",
    "RL004": "an IP literal appears in defaults/vars/tasks/templates (use a registry lookup)",
    "RL005": "a hostname literal appears in defaults/vars/tasks (use a registry lookup)",
    "RL006": "a defaults/vars variable is not prefixed with the role name",
    "RL007": "defaults and argument_specs disagree (undocumented default or documented-but-missing default)",
    "RL008": "a hook task is not tagged with its hook name",
    "RL009": "a container image is not pinned by tag and sha256 digest in defaults/vars/templates",
    "RL010": "a secret-looking variable carries a literal default",
    "RL011": "a task references a secret-looking variable without no_log: true",
    "RL012": "a task uses the shell/raw module, or gives command a templated free-form string",
    "RL013": "a task or variable turns TLS certificate validation off (validate_certs: false)",
    "RL014": "a privileged container or a docker.sock mount appears in defaults/vars/templates",
    "PB001": "a playbook targets a hostname instead of a capability group",
    "PB002": "a playbook has no hosts: pattern",
}

SECRET_WORDS = re.compile(r"(password|passwd|secret|token|api_?key|private_?key|credential)", re.I)
IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
IPV6 = re.compile(r"(?<![\w:])(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}(?![\w:])")
HOSTNAME = re.compile(
    r"(?<![\w./@-])(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+"
    r"(?:internal|lan|local|home|lab|example|com|net|org|io|dev|corp)(?![\w-])",
    re.I,
)
IMAGE_KEY = re.compile(r"(_image|_images|_repository|_repo)$")
# Variables whose value is an image reference are checked by RL009, not RL005.


@dataclass(frozen=True)
class Finding:
    rule: str
    path: str
    message: str

    def __str__(self) -> str:
        return f"{self.path}: {self.rule} {self.message}"


def _load(path: Path, findings: list[Finding]) -> Any:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        findings.append(Finding("RL000", str(path), f"invalid YAML: {str(exc).splitlines()[0]}"))
        return None


def _strip_comments(text: str) -> Iterable[tuple[int, str]]:
    for n, line in enumerate(text.splitlines(), 1):
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        yield n, line


def _bad_ip(token: str) -> bool:
    try:
        ip = ipaddress.ip_address(token)
    except ValueError:
        return False
    return not (ip.is_loopback or ip.is_unspecified)


def _walk_scalars(node: Any, key: str = "") -> Iterable[tuple[str, str]]:
    """Yield (nearest-dict-key, string value) for every string scalar."""
    if isinstance(node, dict):
        for k, v in node.items():
            yield from _walk_scalars(v, str(k))
    elif isinstance(node, list):
        for v in node:
            yield from _walk_scalars(v, key)
    elif isinstance(node, str):
        yield key, node


def _check_literals(role: Path, findings: list[Finding]) -> None:
    for sub, scan_hosts in (
        ("defaults", True),
        ("vars", True),
        ("tasks", True),
        ("templates", False),
    ):
        base = role / sub
        if not base.is_dir():
            continue
        for f in sorted(p for p in base.rglob("*") if p.is_file()):
            text = f.read_text(encoding="utf-8", errors="replace")
            rel = str(f)
            for n, line in _strip_comments(text):
                for m in IPV4.finditer(line):
                    if _bad_ip(m.group(0)):
                        findings.append(Finding("RL004", f"{rel}:{n}", f"IP literal {m.group(0)}"))
                for m in IPV6.finditer(line):
                    if _bad_ip(m.group(0)):
                        findings.append(
                            Finding("RL004", f"{rel}:{n}", f"IPv6 literal {m.group(0)}")
                        )
            if not scan_hosts:
                continue
            if f.suffix in (".yml", ".yaml"):
                try:
                    doc = yaml.safe_load(text)
                except yaml.YAMLError:
                    continue  # reported elsewhere
                for key, val in _walk_scalars(doc):
                    if IMAGE_KEY.search(key) or ("{{" in val and "lookup(" in val):
                        continue
                    for m in HOSTNAME.finditer(val):
                        findings.append(
                            Finding("RL005", rel, f"hostname literal {m.group(0)} in '{key}'")
                        )
            else:
                for n, line in _strip_comments(text):
                    for m in HOSTNAME.finditer(line):
                        findings.append(
                            Finding("RL005", f"{rel}:{n}", f"hostname literal {m.group(0)}")
                        )


def _defaults_vars(role: Path, findings: list[Finding]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for sub in ("defaults", "vars"):
        for f in sorted((role / sub).glob("*.y*ml")) if (role / sub).is_dir() else []:
            doc = _load(f, findings)
            if isinstance(doc, dict):
                for k, v in doc.items():
                    out[k] = (sub, v)
    return out


def _check_specs(role: Path, findings: list[Finding], defaults: dict[str, Any]) -> None:
    spec_path = role / "meta" / "argument_specs.yml"
    if not spec_path.is_file():
        findings.append(Finding("RL001", str(role / "meta"), "meta/argument_specs.yml missing"))
        return
    doc = _load(spec_path, findings)
    specs = (doc or {}).get("argument_specs") if isinstance(doc, dict) else None
    if not isinstance(specs, dict):
        findings.append(Finding("RL002", str(spec_path), "no argument_specs mapping"))
        return
    documented: set[str] = set()
    for ep in ENTRY_POINTS:
        entry = specs.get(ep)
        if not isinstance(entry, dict):
            findings.append(Finding("RL002", str(spec_path), f"entry point '{ep}' not declared"))
            continue
        opts = entry.get("options") or {}
        if ep == "main":
            if not any(isinstance(o, dict) and o.get("required") for o in opts.values()):
                findings.append(Finding("RL002", str(spec_path), "main declares no required input"))
            documented.update(opts)
        for name, o in opts.items():
            if not isinstance(o, dict) or "type" not in o or not o.get("description"):
                findings.append(
                    Finding(
                        "RL002",
                        str(spec_path),
                        f"option '{name}' in '{ep}' needs type and description",
                    )
                )
    main_opts = (specs.get("main") or {}).get("options") or {}
    for name, (where, _value) in defaults.items():
        if where != "defaults":
            continue
        if name not in main_opts:
            findings.append(
                Finding(
                    "RL007",
                    str(role / "defaults"),
                    f"default '{name}' is not documented in argument_specs",
                )
            )
    for name, o in main_opts.items():
        if (
            isinstance(o, dict)
            and not o.get("required")
            and "default" not in o
            and name not in defaults
        ):
            findings.append(
                Finding(
                    "RL007",
                    str(spec_path),
                    f"optional option '{name}' has no default in defaults/ or spec",
                )
            )


def _task_tags(task: Any) -> set[str]:
    tags: set[str] = set()
    if isinstance(task, dict):
        t = task.get("tags")
        if isinstance(t, str):
            tags.add(t)
        elif isinstance(t, list):
            tags.update(str(x) for x in t)
    return tags


def _untagged(tasks: list[Any], hook: str, inherited: bool = False) -> int:
    bad = 0
    for t in tasks:
        if not isinstance(t, dict):
            continue
        has = inherited or hook in _task_tags(t)
        if "block" in t:
            bad += _untagged(t["block"] or [], hook, has)
            continue
        if not has:
            bad += 1
    return bad


def _check_hooks(role: Path, findings: list[Finding]) -> None:
    for hook in HOOKS:
        f = role / "tasks" / f"{hook}.yml"
        if not f.is_file():
            findings.append(Finding("RL003", str(f), f"hook '{hook}' missing"))
            continue
        doc = _load(f, findings)
        if not doc:
            if doc is not None:
                findings.append(Finding("RL003", str(f), f"hook '{hook}' is empty"))
            continue
        if not isinstance(doc, list):
            findings.append(Finding("RL003", str(f), "hook must be a task list"))
            continue
        n = _untagged(doc, hook)
        if n:
            findings.append(Finding("RL008", str(f), f"{n} task(s) not tagged '{hook}'"))


def _check_prefix_and_secrets(
    role: Path, defaults: dict[str, Any], findings: list[Finding]
) -> None:
    prefix = role.name + "_"
    for name, (where, value) in defaults.items():
        if not name.startswith(prefix):
            findings.append(
                Finding("RL006", str(role / where), f"variable '{name}' must start with '{prefix}'")
            )
        if SECRET_WORDS.search(name) and isinstance(value, str) and value and "{{" not in value:
            findings.append(
                Finding(
                    "RL010",
                    str(role / where),
                    f"secret-looking variable '{name}' has a literal value",
                )
            )


DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
IMAGE_REF = re.compile(
    r"^(?:image:\s*)?['\"]?(?P<ref>[\w.\-/{}$ ]+(?::[\w.\-{}$ ]+)?)(?:@sha256:\S+)?['\"]?$"
)


def _check_images(role: Path, findings: list[Finding]) -> None:
    for sub in ("defaults", "vars", "templates"):
        base = role / sub
        if not base.is_dir():
            continue
        for f in sorted(p for p in base.rglob("*") if p.is_file()):
            for n, line in _strip_comments(f.read_text(encoding="utf-8", errors="replace")):
                m = re.search(r"\bimage:\s*['\"]?([^\s'\"#]+)", line) or re.search(
                    r"_image\w*:\s*['\"]?([^\s'\"#]+)", line
                )
                if not m:
                    continue
                ref = m.group(1)
                if "{{" in ref:
                    continue  # rendered from a validated spec (compose_app checks tag and digest)
                name, _, digest = ref.partition("@")
                last = name.rsplit("/", 1)[-1]
                if ":" not in last or last.endswith(":latest"):
                    findings.append(Finding("RL009", f"{f}:{n}", f"unpinned image '{ref}'"))
                elif not DIGEST.fullmatch(digest):
                    findings.append(
                        Finding("RL009", f"{f}:{n}", f"image '{ref}' has no sha256 digest")
                    )


# Task keywords: whatever key of a task is not one of these is its module.
TASK_KEYWORDS = {
    "name", "tags", "when", "loop", "loop_control", "register", "changed_when", "failed_when",
    "no_log", "diff", "become", "become_user", "become_method", "vars", "notify", "listen",
    "delegate_to", "delegate_facts", "run_once", "ignore_errors", "ignore_unreachable",
    "environment", "args", "block", "rescue", "always", "until", "retries", "delay",
    "check_mode", "any_errors_fatal", "throttle", "timeout", "module_defaults", "collections",
    "connection", "async", "poll", "local_action", "action",
}  # fmt: skip
SHELL_MODULES = {"shell", "raw"}  # both hand a string to a shell
COMMAND_MODULES = {"command"}
# keys whose templated value is evaluated but never echoed into task output
NOT_LOGGED = {"name", "when", "changed_when", "failed_when", "until", "tags", "no_log"}
JINJA = re.compile(r"{{(.*?)}}|{%(.*?)%}", re.S)
QUOTED = re.compile(r"'[^']*'|\"[^\"]*\"")
IDENT = re.compile(r"[A-Za-z_]\w*")
FALSY = {"false", "no", "off", "0", "n"}


def _falsy(value: Any) -> bool:
    if isinstance(value, bool | int):
        return not value
    return isinstance(value, str) and value.strip().lower() in FALSY


def _short(module: str) -> str:
    return module.rsplit(".", 1)[-1]


def _module(task: dict[str, Any]) -> str | None:
    for k in task:
        if k not in TASK_KEYWORDS and not str(k).startswith("with_"):
            return str(k)
    return None


def _secret_refs(node: Any) -> set[str]:
    """Secret-looking variable names used inside Jinja expressions anywhere in ``node``."""
    out: set[str] = set()
    for _key, val in _walk_scalars(node):
        for m in JINJA.finditer(val):
            expr = QUOTED.sub("", m.group(1) or m.group(2) or "")
            out.update(i for i in IDENT.findall(expr) if SECRET_WORDS.search(i))
    return out


def _iter_tasks(tasks: Any, no_log: bool = False) -> Iterable[tuple[dict[str, Any], bool]]:
    """Yield (task, effective no_log) for every task, descending into blocks."""
    if not isinstance(tasks, list):
        return
    for t in tasks:
        if not isinstance(t, dict):
            continue
        quiet = no_log or ("no_log" in t and not _falsy(t["no_log"]))
        if any(k in t for k in ("block", "rescue", "always")):
            for k in ("block", "rescue", "always"):
                yield from _iter_tasks(t.get(k), quiet)
            continue
        yield t, quiet


def _certs_off(node: Any) -> bool:
    if isinstance(node, dict):
        return any(
            (str(k) == "validate_certs" and _falsy(v)) or _certs_off(v) for k, v in node.items()
        )
    if isinstance(node, list):
        return any(_certs_off(v) for v in node)
    return False


def _check_tasks(role: Path, findings: list[Finding]) -> None:
    base = role / "tasks"
    if not base.is_dir():
        return
    for f in sorted(base.rglob("*.y*ml")):
        try:
            doc = yaml.safe_load(f.read_text(encoding="utf-8"))
        except yaml.YAMLError:
            continue  # reported elsewhere
        for task, quiet in _iter_tasks(doc):
            label = f"{f}: task '{task.get('name', '?')}'"
            module = _module(task)
            short = _short(module) if module else ""
            logged = {k: v for k, v in task.items() if k not in NOT_LOGGED}
            refs = _secret_refs(logged)
            if refs and not quiet:
                findings.append(
                    Finding("RL011", label, f"uses {', '.join(sorted(refs))} without no_log: true")
                )
            if short in SHELL_MODULES:
                findings.append(Finding("RL012", label, f"uses the {short} module; use argv"))
            elif short in COMMAND_MODULES:
                arg = task.get(module)
                free = arg if isinstance(arg, str) else None
                if isinstance(arg, dict) and isinstance(arg.get("cmd"), str):
                    free = arg["cmd"]
                if isinstance(task.get("args"), dict) and isinstance(task["args"].get("cmd"), str):
                    free = task["args"]["cmd"]
                if free is not None and ("{{" in free or "{%" in free):
                    findings.append(
                        Finding(
                            "RL012", label, "command with a templated free-form string; use argv"
                        )
                    )
            if _certs_off(task):
                findings.append(Finding("RL013", label, "validate_certs is false"))


PRIVILEGED = re.compile(
    r"(?:(?<![A-Za-z])privileged['\"]?\s*[:=]\s*['\"]?(?:true|yes|on|1)\b|--privileged\b|docker\.sock)",
    re.I,
)


def _check_container_escape(role: Path, defaults: dict[str, Any], findings: list[Finding]) -> None:
    for name, (where, value) in defaults.items():
        if name.endswith("validate_certs") and _falsy(value):
            findings.append(
                Finding("RL013", str(role / where), f"variable '{name}' turns validation off")
            )
    for sub in ("defaults", "vars", "templates"):
        base = role / sub
        if not base.is_dir():
            continue
        for f in sorted(p for p in base.rglob("*") if p.is_file()):
            for n, line in _strip_comments(f.read_text(encoding="utf-8", errors="replace")):
                m = PRIVILEGED.search(line)
                if m:
                    findings.append(
                        Finding("RL014", f"{f}:{n}", f"container escape hatch '{m.group(0)}'")
                    )


def lint_role(role: Path) -> list[Finding]:
    findings: list[Finding] = []
    role = Path(role)
    defaults = _defaults_vars(role, findings)
    _check_specs(role, findings, defaults)
    _check_hooks(role, findings)
    _check_literals(role, findings)
    _check_prefix_and_secrets(role, defaults, findings)
    _check_images(role, findings)
    _check_tasks(role, findings)
    _check_container_escape(role, defaults, findings)
    return findings


def _inventory_hosts(inv: Path) -> tuple[set[str], set[str]]:
    """Return (host names, group names) from a YAML inventory."""
    doc = yaml.safe_load(inv.read_text(encoding="utf-8")) or {}
    hosts: set[str] = set()
    groups: set[str] = set()

    def walk(name: str, node: Any) -> None:
        groups.add(name)
        if not isinstance(node, dict):
            return
        hosts.update((node.get("hosts") or {}).keys())
        for child, sub in (node.get("children") or {}).items():
            walk(child, sub)

    for top, node in doc.items():
        walk(top, node)
    return hosts, groups


def lint_playbook(playbook: Path, inventory: Path | None = None) -> list[Finding]:
    findings: list[Finding] = []
    hosts, groups = _inventory_hosts(inventory) if inventory else (set(), set())
    doc = _load(Path(playbook), findings)
    if not isinstance(doc, list):
        return findings
    for play in doc:
        if not isinstance(play, dict) or "import_playbook" in play:
            continue
        pattern = play.get("hosts")
        if not pattern:
            findings.append(Finding("PB002", str(playbook), "play without hosts:"))
            continue
        for tok in re.split(r"[:,]", str(pattern)):
            tok = tok.strip().lstrip("!&")
            if not tok or tok in ("all", "localhost") or "{{" in tok:
                continue
            if tok in hosts and tok not in groups:
                findings.append(
                    Finding("PB001", str(playbook), f"targets host '{tok}', use a capability group")
                )
            elif tok not in groups and (HOSTNAME.search(tok) or _bad_ip(tok)):
                findings.append(
                    Finding(
                        "PB001", str(playbook), f"targets literal '{tok}', use a capability group"
                    )
                )
    return findings


def expand_roles(path: Path) -> list[Path]:
    """A role directory is itself; a directory of roles (``ansible/roles``) is its sub-roles.

    Without this, ``role_lint.py ansible/roles`` read the roles directory as one role and reported
    its ``meta`` and ``tasks`` children as findings.
    """
    if (path / "tasks").is_dir() or (path / "meta").is_dir() or (path / "defaults").is_dir():
        return [path]
    children = sorted(p for p in path.iterdir() if p.is_dir() and not p.name.startswith("."))
    return children or [path]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("roles", nargs="*", help="role directories")
    ap.add_argument(
        "--playbook", action="append", default=[], help="playbook to check (repeatable)"
    )
    ap.add_argument("--inventory", help="YAML inventory used for the playbook host check")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--list-rules", action="store_true")
    args = ap.parse_args(argv)
    if args.list_rules:
        for k, v in RULES.items():
            print(f"{k}  {v}")
        return 0
    if not args.roles and not args.playbook:
        ap.print_usage(sys.stderr)
        return 2
    findings: list[Finding] = []
    try:
        for r in args.roles:
            if not Path(r).is_dir():
                print(f"not a directory: {r}", file=sys.stderr)
                return 2
            findings += [f for role in expand_roles(Path(r)) for f in lint_role(role)]
        for p in args.playbook:
            findings += lint_playbook(Path(p), Path(args.inventory) if args.inventory else None)
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps([f.__dict__ for f in findings], indent=2))
    else:
        for f in findings:
            print(f)
        print(f"{len(findings)} finding(s)")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
