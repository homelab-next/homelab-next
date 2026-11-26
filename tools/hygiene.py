#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: hygiene
#   kind: check
#   purpose: Fail when a tracked file is a symlink, larger than 512 KB, holds a merge-conflict marker or a private key block, or is YAML or JSON that does not parse.
#   owner: maintainers
#   trigger: [make:hygiene]
#   inputs: the tracked tree (git ls-files), from the repository root or ROOT
#   outputs: "one line per problem, or hygiene: clean"
#   exit:
#     "0": every tracked file is clean
#     "1": some file is not
"""The pre-commit hooks that need no environment of their own, over every tracked file.

Run on the whole tree (``make hygiene``, part of ``make precheck``), not only on the staged files
as the hooks are, so a file committed without the hooks is still caught: a symbolic link (the
packaging refuses them), a file over 512 KB, a merge-conflict marker, a private key block, and YAML
or JSON that does not parse.  YAML tags (Ansible's ``!vault``, CloudFormation's ``!Ref``) are data
here: only the syntax is checked.  The fixtures malformed on purpose are listed in
:data:`INVALID_ON_PURPOSE`.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import yaml

#: fixtures that are malformed on purpose (a role-lint parse-error case)
INVALID_ON_PURPOSE = ("tests/roles/fixtures/RL000/",)
LIMIT = 512 * 1024
MARKER = re.compile(rb"^(?:<{7}|>{7})(?: |$)|^={7}$", re.M)
KEY = re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY")


class _Loader(yaml.SafeLoader):
    pass


# Ansible and CloudFormation tags are data here; only the syntax is checked
_Loader.add_multi_constructor("!", lambda loader, suffix, node: None)


def problems(root: Path) -> list[str]:
    files = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"], capture_output=True, check=True
    )
    out = []
    for name in files.stdout.decode().split("\0"):
        if not name:
            continue
        path = root / name
        if os.path.islink(path):
            out.append(f"{name}: symbolic link (packaging refuses them)")
            continue
        if not path.is_file():
            continue  # deleted in the working tree, not yet staged
        data = path.read_bytes()
        if len(data) > LIMIT:
            hint = " (CONTRIBUTING.md, 'Changelog rotation')" if name == "CHANGELOG.md" else ""
            out.append(f"{name}: larger than 512 KB{hint}")
        if MARKER.search(data):
            out.append(f"{name}: merge-conflict marker")
        if KEY.search(data):
            out.append(f"{name}: private key block")
        try:
            if name.startswith(INVALID_ON_PURPOSE):
                pass
            elif name.endswith((".yml", ".yaml")):
                list(yaml.load_all(data, Loader=_Loader))
            elif name.endswith(".json"):
                json.loads(data)
        except Exception as exc:
            out.append(f"{name}: does not parse ({exc.__class__.__name__})")
    return out


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    root = Path(args[0]) if args else Path(__file__).resolve().parent.parent
    found = problems(root)
    print("\n".join(found) or "hygiene: clean")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
