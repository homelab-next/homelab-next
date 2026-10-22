# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: model-store-promote
#   kind: tool
#   purpose: Verify a staged model-store download by size and sha256, then rename each file into the live store.
#   owner: platform
#   trigger: [role:model_store]
#   inputs: one JSON argument (the entry's format, staging and live directories, and its files)
#   outputs: the files renamed into place; one JSON line naming them
#   exit:
#     "0": every staged file verified and promoted
#     "1": a staged file is missing, out of place, or not the manifest's; nothing was moved
"""Promote one fetched model-store entry from its staging directory into the live store.

Run by the model_store role (``ansible.builtin.script``) on the store host, after ``hf download``
wrote the missing files of an entry into ``<root>/.staging/<entry id>/``.  One JSON argument:
``{"format": "hf"|"gguf", "staged": <the entry's staged dir>, "stage_top": <the staging dir>,
"live": <the entry's live dir>, "blobs": <the live repository's blobs/, hf only>, "files":
[{"path", "sha256", "size"}, ...]}``.

Every staged file is checked first (inside the staging tree, its size, its sha256); one bad file
and nothing is moved.  Then each file is renamed into place: an ``hf`` blob into the repository's
``blobs/`` and its snapshot link replaced by a rename, a ``gguf`` file over its live path.  Every
step is a rename on the store's filesystem, so the live store never holds a partial or unverified
file.  Prints ``{"promoted": [...]}``; exits 1 (with the problems on stderr) on a bad file.
Standard library only.
"""

import hashlib
import json
import os
import sys
from pathlib import Path


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            block = fh.read(8 << 20)
            if not block:
                return digest.hexdigest()
            digest.update(block)


def _inside(path: Path, top: Path) -> bool:
    return path == top or top in path.parents


def main(spec: dict) -> int:
    staged, live = Path(spec["staged"]), Path(spec["live"])
    stage_top = Path(spec.get("stage_top") or staged).resolve()
    problems, ready = [], []
    for f in spec["files"]:
        src = staged / f["path"]
        if not src.is_file():
            problems.append(f"{f['path']}: not downloaded")
            continue
        real = src.resolve()
        if not _inside(real, stage_top):
            problems.append(f"{f['path']}: resolves out of the staging directory ({real})")
        elif real.stat().st_size != f["size"]:
            problems.append(f"{f['path']}: size {real.stat().st_size}, manifest {f['size']}")
        elif _sha256(real) != f["sha256"]:
            problems.append(f"{f['path']}: sha256 differs from the manifest")
        else:
            ready.append((f, real, src.is_symlink()))
    if problems:
        print("\n".join(problems), file=sys.stderr)
        return 1
    for f, real, linked in ready:
        dest = live / f["path"]
        dest.parent.mkdir(parents=True, exist_ok=True)
        if spec["format"] == "hf":
            blobs = Path(spec["blobs"])
            blobs.mkdir(parents=True, exist_ok=True)
            blob = blobs / (real.name if linked else f["sha256"])
            if real.exists():  # two files with one body share one blob, moved once
                os.replace(real, blob)
            tmp = dest.with_name(f".{dest.name}.hnx-promote")
            if tmp.is_symlink() or tmp.exists():
                tmp.unlink()
            tmp.symlink_to(os.path.relpath(blob, dest.parent))
            os.replace(tmp, dest)
        else:
            os.replace(real, dest)
    print(json.dumps({"promoted": [f["path"] for f, _, _ in ready]}))
    return 0


if __name__ == "__main__":
    sys.exit(main(json.loads(sys.argv[1])))
