# SPDX-License-Identifier: Apache-2.0
"""The pinned embedding model for the semantic ``context`` adapter, and how it is fetched.

One small CPU sentence-embedding model, named by repository, 40-hex revision and the sha256 and
size of every file, in the same shape as the model store (``homelabnext.models.store``): a
branch name is never a revision and a file is used only when its hash matches.  :func:`fetch`
is the only code that touches the network and runs when an operator provisions the model,
never at query time; :func:`check_dir` is what the adapter calls before it loads anything, and
it refuses a missing, extra-less or tampered directory.  Standard library only.
"""

from __future__ import annotations

import hashlib
import os
import urllib.request
from pathlib import Path, PurePosixPath

__all__ = ["FILES", "REPO", "REVISION", "ModelError", "check_dir", "fetch"]

REPO = "sentence-transformers/all-MiniLM-L6-v2"  # Apache-2.0, 384 dimensions, mean pooling
REVISION = "1110a243fdf4706b3f48f1d95db1a4f5529b4d41"

#: path -> (sha256, size in bytes)
FILES: dict[str, tuple[str, int]] = {
    "1_Pooling/config.json": (
        "4be450dde3b0273bb9787637cfbd28fe04a7ba6ab9d36ac48e92b11e350ffc23",
        190,
    ),
    "config.json": (
        "953f9c0d463486b10a6871cc2fd59f223b2c70184f49815e7efbcab5d8908b41",
        612,
    ),
    "model.safetensors": (
        "53aa51172d142c89d9012cce15ae4d6cc0ca6895895114379cacb4fab128d9db",
        90868376,
    ),
    "modules.json": (
        "84e40c8e006c9b1d6c122e02cba9b02458120b5fb0c87b746c41e0207cf642cf",
        349,
    ),
    "sentence_bert_config.json": (
        "fc1993fde0a95c24ec6c022539d41cf6e2f7c9721e5415d6fb6897472a9cd4b7",
        53,
    ),
    "special_tokens_map.json": (
        "303df45a03609e4ead04bc3dc1536d0ab19b5358db685b6f3da123d05ec200e3",
        112,
    ),
    "tokenizer.json": (
        "be50c3628f2bf5bb5e3a7f17b1f74611b2561a3a27eeab05e5aa30f411572037",
        466247,
    ),
    "tokenizer_config.json": (
        "acb92769e8195aabd29b7b2137a9e6d6e25c476a4f15aa4355c233426c61576b",
        350,
    ),
    "vocab.txt": (
        "07eced375cec144d27c900241f3e339478dec958f92fddbc551f295c992038a3",
        231508,
    ),
}


class ModelError(Exception):
    """The model directory is missing a file, has one of the wrong size or hash, or a download
    failed.  The message names the file, never its content."""


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def check_dir(root: str | os.PathLike[str]) -> Path:
    """The model directory ``root``, verified file by file (size, then sha256), or ``ModelError``."""
    base = Path(root)
    if not base.is_dir():
        raise ModelError("model directory does not exist (provision it with fetch)")
    problems = []
    for rel, (want, size) in sorted(FILES.items()):
        p = base / rel
        if p.is_symlink() or not p.is_file():
            problems.append(f"{rel}: missing")
        elif p.stat().st_size != size:
            problems.append(f"{rel}: wrong size")
        elif _sha256(p) != want:
            problems.append(f"{rel}: sha256 mismatch")
    if problems:
        raise ModelError("; ".join(problems))
    return base


def fetch(dest: str | os.PathLike[str]) -> Path:
    """Download the pinned files into ``dest`` (created, never a shallow path) and verify them.

    Each file is written to a temporary sibling, hashed, and renamed only when it matches; a
    mismatch deletes that temporary file alone and raises.  Run by an operator, not at query time.
    """
    base = Path(dest).resolve()
    if len(base.parts) < 3 or base == Path(base.anchor):
        raise ModelError("refusing a shallow destination")
    for rel, (want, size) in sorted(FILES.items()):
        rp = PurePosixPath(rel)
        if rp.is_absolute() or ".." in rp.parts:
            raise ModelError("manifest path escapes the destination")
        out = base / rel
        if out.is_file() and out.stat().st_size == size and _sha256(out) == want:
            continue
        out.parent.mkdir(parents=True, exist_ok=True)
        tmp = out.with_name(out.name + ".part")
        url = f"https://huggingface.co/{REPO}/resolve/{REVISION}/{rel}"
        try:
            with urllib.request.urlopen(url, timeout=120) as r, tmp.open("wb") as f:
                while chunk := r.read(1 << 20):
                    f.write(chunk)
            if tmp.stat().st_size != size or _sha256(tmp) != want:
                raise ModelError(f"{rel}: downloaded file does not match the pinned hash")
            tmp.replace(out)
        except OSError as exc:
            raise ModelError(f"{rel}: download failed ({type(exc).__name__})") from exc
        finally:
            tmp.unlink(missing_ok=True)
    return check_dir(base)


if __name__ == "__main__":  # python -m homelabnext.context.semantic_model DEST
    import sys

    if len(sys.argv) != 2:
        raise SystemExit("usage: python -m homelabnext.context.semantic_model DEST")
    print(fetch(sys.argv[1]))
