# SPDX-License-Identifier: Apache-2.0
"""CLI: ``python -m homelabnext.detections <cmd>``, also mounted as ``hnx detections``."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

from . import attack, coverage, detmap, lint
from .adapters import Target, UnsupportedConstruct, get_backend
from .runner import compiled_backends, run_all, run_compiled
from .sigma import load_mapping, load_rules


def _resolve_known_ids(root: Path, backend_name: str, snapshot_arg: str | None):
    """Snapshot explicitly named (``--snapshot``) wins; otherwise ask the backend, through its
    ``known_technique_ids()`` method or, when it has none, its ``known_ids_snapshot`` path
    (relative to the detections root, or absolute); return ``None`` when neither path produces
    a known set. A named or advertised snapshot that cannot be read raises.
    """
    if snapshot_arg:
        return attack.load_snapshot(snapshot_arg)
    try:
        be = get_backend(backend_name)
    except KeyError:
        return None
    fn = getattr(be, "known_technique_ids", None)
    if fn is None:
        snap = getattr(be, "known_ids_snapshot", None)
        if snap is None:
            return None
        path = Path(snap)
        return attack.load_snapshot(path if path.is_absolute() else root / path)
    try:
        ids = fn(root)
    except TypeError:
        ids = fn()
    return ids or None


def mapping_for(root: Path, backend: str) -> Path | None:
    """``mappings/<backend>.yml`` when the backend has its own field map, else
    ``mappings/generic.yml`` (with a warning for a non-generic backend), else ``None``."""
    own = root / "mappings" / f"{backend}.yml"
    if own.exists():
        return own
    generic = root / "mappings" / "generic.yml"
    if backend != "generic":
        print(
            f"warning: no mappings/{backend}.yml; compiling {backend} with the generic field map",
            file=sys.stderr,
        )
    return generic if generic.exists() else None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="hnx detections")
    ap.add_argument("--root", default="detections", type=Path)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("lint")
    sub.add_parser("run")
    mp = sub.add_parser("map")
    mp.add_argument("--check", action="store_true")
    cv = sub.add_parser("coverage", help="ATT&CK coverage from rules whose fixtures pass (D-04)")
    cv.add_argument("--out", type=Path, help="write the report here (default: stdout)")
    cv.add_argument("--check", type=Path, help="fail unless this golden report is current")
    ln = sub.add_parser("lint-ids")
    ln.add_argument("paths", nargs="*", type=Path)
    cp = sub.add_parser("compile")
    cp.add_argument("backend")
    vt = sub.add_parser(
        "validate-techniques",
        help="check each rule's ATT&CK ids against an engine's known-id snapshot",
    )
    vt.add_argument("--backend", default="wazuh")
    vt.add_argument(
        "--snapshot",
        help="snapshot file (overrides the backend's default); .yml/.yaml/.json/.txt",
    )
    vt.add_argument(
        "--suggest-parent",
        action="store_true",
        help="for an unknown sub-technique whose parent IS known, suggest tagging the parent",
    )
    a = ap.parse_args(argv)
    root: Path = a.root
    mapfile = root / "det_map.yml"

    if a.cmd == "lint":
        probs = lint.lint_rules(root)
        print("\n".join(probs) or "lint ok")
        return 1 if probs else 0
    if a.cmd == "run":
        rep = run_all(root)
        print(rep.render())
        # the same fixtures through every backend that can evaluate what it compiled
        compiled = [run_compiled(root, name, rep) for name in compiled_backends()]
        for b in compiled:
            print(b.render())
        return 0 if rep.ok and all(b.ok for b in compiled) else 1
    if a.cmd == "map":
        rules = load_rules(root)
        existing = detmap.load(mapfile) if mapfile.exists() else None
        if a.check:
            probs = detmap.check_current(rules, existing or {"entries": {}})
            print("\n".join(probs) or "det map current")
            return 1 if probs else 0
        mapfile.write_text(detmap.dump(detmap.generate(rules, existing)), encoding="utf-8")
        print(f"wrote {mapfile}")
        return 0
    if a.cmd == "coverage":
        rep = coverage.report_for(root)
        if a.check:
            golden = a.check.read_text(encoding="utf-8") if a.check.exists() else "{}"
            probs = coverage.check_golden(rep, golden)
            print("\n".join(probs) or f"ATT&CK coverage report current ({a.check})")
            return 1 if probs else 0
        text = coverage.dumps(rep)
        if a.out:
            a.out.write_text(text, encoding="utf-8")
            print(f"wrote {a.out}")
        else:
            sys.stdout.write(text)
        return 0
    if a.cmd == "lint-ids":
        m = detmap.load(mapfile) if mapfile.exists() else None
        files = a.paths or lint.find_agent_files(Path("."))
        probs = lint.lint_agent_ids(files, m, str(mapfile))
        print("\n".join(probs) or "no engine rule numbers in agent-facing files")
        return 1 if probs else 0
    if a.cmd == "compile":
        m = detmap.load(mapfile) if mapfile.exists() else {"entries": {}}
        fm = mapping_for(root, a.backend)
        tgt = Target(a.backend, load_mapping(fm), m["entries"])
        be = get_backend(a.backend)
        # an unsupported (inert) or deprecated rule is tested but never shipped to an engine;
        # a rule this engine cannot express is reported and left out, never aborting the bundle
        arts, skipped = [], []
        for r in load_rules(root):
            if not r.deployable:
                continue
            try:
                arts.append(be.compile(r, tgt))
            except UnsupportedConstruct as exc:
                skipped.append(f"{r.det_id}: not expressible in {a.backend} ({exc})")
        sys.stdout.write(
            be.bundle(arts) if hasattr(be, "bundle") else "\n".join(x.content for x in arts)
        )
        for line in skipped:
            print(f"left out of the bundle: {line}", file=sys.stderr)
        return 1 if skipped else 0
    if a.cmd == "validate-techniques":
        rules = load_rules(root)
        try:
            known = _resolve_known_ids(root, a.backend, a.snapshot)
        except (OSError, ValueError, yaml.YAMLError) as exc:
            print(f"could not load the ATT&CK known-id snapshot: {exc}", file=sys.stderr)
            return 100  # could not measure (invariants-runner convention)
        if known is None:
            print(
                f"no ATT&CK known-id snapshot for backend {a.backend!r}; set its "
                f"'known_ids_snapshot' or pass --snapshot",
                file=sys.stderr,
            )
            return 100  # could not measure (invariants-runner convention)
        probs = attack.validate_rules(rules, known, suggest_parent=a.suggest_parent)
        print("\n".join(probs) or "ATT&CK ids all known to the engine")
        return 1 if probs else 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
