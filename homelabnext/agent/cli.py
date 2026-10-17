# SPDX-License-Identifier: Apache-2.0
"""``hnx agent compile|pack``.

``compile SPEC --library LIB``  compile a profile spec against a parts library file.
``pack MANIFEST --inputs FILE`` assemble a context pack and print its hash.

Library file (YAML or JSON): ``{parts: {<logical id>: <path relative to the file>}}``.
Exit codes: 0 ok, 1 refused (missing part, ceiling or budget violation, bad input),
3 (``pack`` only) the pack was assembled but is ``deferred``.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from homelabnext.ids import MappingResolver

from .compiler import PartsLibrary, compile_profile
from .errors import AgentError
from .pack import assemble_pack
from .schemas import schema_errors


def _load(path: str) -> Any:
    text = Path(path).read_text(encoding="utf-8")
    if path.endswith(".json"):
        return json.loads(text)
    import yaml

    return yaml.safe_load(text)


def _library(path: str) -> PartsLibrary:
    base = Path(path).resolve().parent
    doc = _load(path)
    mapping = (doc or {}).get("parts")
    if not isinstance(mapping, dict) or not mapping:
        raise AgentError(f"{path}: expected a non-empty 'parts' mapping of logical id -> path")

    def read(locator: str) -> str:
        target = (base / locator).resolve()
        if base not in target.parents:
            raise AgentError(f"part path {locator!r} escapes the library directory")
        return target.read_text(encoding="utf-8")

    return PartsLibrary(MappingResolver("parts", mapping), read)


def _emit(doc: dict, out: str | None) -> None:
    text = json.dumps(doc, indent=2, sort_keys=True) + "\n"
    if out:
        Path(out).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="hnx agent", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("compile", help="compile a profile spec")
    c.add_argument("spec")
    c.add_argument("--library", required=True)
    c.add_argument("--out")
    p = sub.add_parser("pack", help="assemble a context pack")
    p.add_argument("manifest")
    p.add_argument("--inputs", required=True)
    p.add_argument("--out", help="write the pack JSON here (default: stdout)")
    args = ap.parse_args(argv)
    try:
        if args.cmd == "compile":
            profile = compile_profile(_load(args.spec), _library(args.library))
            _emit(profile, args.out)
            print(f"compiled {profile['id']} {profile['digest']}", file=sys.stderr)
            return 0
        manifest = _load(args.manifest)
        errs = schema_errors("agent", "context_manifest", manifest)
        if errs:
            print("hnx agent pack: manifest invalid:\n  " + "\n  ".join(errs), file=sys.stderr)
            return 1
        pack, digest = assemble_pack(manifest, _load(args.inputs) or {})
        _emit({"hash": digest, "pack": pack}, args.out)
        print(f"pack {digest} status={pack['status']}", file=sys.stderr)
        for r in pack["deferred_reasons"]:
            print(f"deferred: {r}", file=sys.stderr)
        return 0 if pack["status"] == "ready" else 3
    except (AgentError, OSError, ValueError) as exc:
        print(f"hnx agent {args.cmd}: {exc}", file=sys.stderr)
        return 1
