# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: cti-pipeline-artefact
#   kind: tool
#   purpose: Install the pipeline's pinned app artefact as a release (sha256 first, a safe extract, an offline venv, then a rename), and prune old releases.
#   owner: platform
#   trigger: [role:cti_pipeline]
#   inputs: "install ARCHIVE SHA256 RELEASES_DIR PYTHON | prune RELEASES_DIR CURRENT KEEP"
#   outputs: one JSON line on stdout (changed, release); install writes RELEASES_DIR/<sha16>/, prune removes old release directories
#   exit:
#     "0": installed (or already installed), or pruned
#     "1": refused (a wrong sha256, an unsafe or malformed archive, a failed venv; the reason on stderr); nothing replaced
#     "2": usage error
"""The cti-pipeline role's artefact installer (modules/cti-pipeline/README.md, "The artefact").

    python3 -I cti_artefact.py install ARCHIVE SHA256 RELEASES_DIR PYTHON
    python3 -I cti_artefact.py prune RELEASES_DIR CURRENT KEEP

``install`` hashes ARCHIVE (opened without following a link) and refuses it unless it is the pin,
before anything is written.  The archive is a tar (optionally gzip) holding::

    hnx-artefact.json   {"name": ..., "version": ..., "packages": [<top-level package>, ...]}
                        (packages optional: the modules a shadow-lane ``-m`` may run)
    app/                the application tree (the job's working code; never written at run time)
    requirements.txt    optional: every wheel the app needs, pinned with --hash
    wheels/             optional: those wheels

Only regular files and directories are accepted: a link, a device, a path that is absolute,
climbs (``..``), holds a backslash or a control character, or repeats an entry is refused, as is
an archive over 20 000 entries or 2 GiB.  It is extracted into ``RELEASES_DIR/.<sha16>.incoming``,
a virtual environment is built there offline (``pip --no-index --require-hashes --only-binary``
from ``wheels/``; with no requirement, a venv without pip), the pin is recorded in
``.hnx-installed`` and only then is the directory renamed (owner-only: the role then gives the
module's group read access, never anyone else) to ``RELEASES_DIR/<sha16>``: a refused or
failed install never touches a release in use.  The venv is always run as ``venv/bin/python``
(never a generated script), so the rename does not break it.

``prune`` removes release directories (named as one, never a link) past the KEEP newest, never
CURRENT.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import unicodedata

NF = os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
SHA_RE = re.compile(r"^[0-9a-f]{64}\Z")
PACKAGE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\Z")
NOT_APP_PACKAGES = set(sys.stdlib_module_names) | {"pip", "setuptools", "ensurepip", "wheel"}
RELEASE_RE = re.compile(r"^[0-9a-f]{16}\Z")
MAX_ENTRIES = 20_000
MAX_BYTES = 2 << 30
MARKER = ".hnx-installed"
META = "hnx-artefact.json"
PIP_TIMEOUT = 1800


class Refused(Exception):
    """The archive or the target is refused: exit 1, nothing replaced."""


def open_archive(path: str):
    """The archive as a binary file object, opened without following a link; a regular file."""
    try:
        fd = os.open(path, os.O_RDONLY | NF)
    except OSError as e:
        raise Refused(f"{path} cannot be opened ({e.strerror}, or a link)") from e
    f = os.fdopen(fd, "rb")
    if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
        f.close()
        raise Refused(f"{path} is not a regular file")
    return f


def sha256_of(f) -> str:
    """The sha256 of the open archive ``f``, read from its start."""
    f.seek(0)
    h = hashlib.sha256()
    for chunk in iter(lambda: f.read(1 << 20), b""):
        h.update(chunk)
    return h.hexdigest()


def safe_name(name: str) -> str:
    """The member's path, normalised, or Refused."""
    if not name or "\\" in name or any(ord(c) < 32 or ord(c) == 127 for c in name):
        raise Refused(f"archive entry {name!r}: an empty name, a backslash or a control character")
    if unicodedata.normalize("NFC", name) != name:
        raise Refused(f"archive entry {name!r} is not NFC")
    if name.startswith("/"):
        raise Refused(f"archive entry {name!r} is absolute")
    parts = [p for p in name.split("/") if p not in ("", ".")]
    if not parts or ".." in parts:
        raise Refused(f"archive entry {name!r} climbs out of the release")
    return "/".join(parts)


def real_dir(path: str, what: str) -> str:
    """``path`` resolved, which must be a directory that is not a link, three components deep."""
    if os.path.islink(path) or not os.path.isdir(path):
        raise Refused(f"{what} {path} is not a directory (or is a link)")
    resolved = os.path.realpath(path)
    if resolved != os.path.abspath(path) or len([p for p in resolved.split("/") if p]) < 3:
        raise Refused(f"{what} {path} resolves elsewhere or is too shallow")
    return resolved


def remove_inside(path: str, parent: str) -> None:
    """Remove ``path``, a directory directly inside ``parent`` (resolved), never anything else."""
    if os.path.islink(path) or not os.path.isdir(path):
        raise Refused(f"{path} is not a directory (or is a link): not removed")
    if os.path.dirname(os.path.realpath(path)) != parent:
        raise Refused(f"{path} is not directly inside {parent}: not removed")
    shutil.rmtree(path)


def extract(f, dest: str, label: str) -> None:
    """Every member of the archive open as ``f`` (read from its start) into ``dest`` (a new, empty
    directory), or Refused."""
    f.seek(0)
    try:
        with tarfile.open(fileobj=f, mode="r:*") as tf:
            _extract_members(tf, dest)
    except (tarfile.TarError, EOFError) as e:
        raise Refused(f"{label} is not a readable tar archive: {e}") from e
    for root, dirs, _files in os.walk(dest):
        for d in dirs:
            os.chmod(os.path.join(root, d), 0o700)


def _extract_members(tf: tarfile.TarFile, dest: str) -> None:
    try:
        _extract_each(tf, dest)
    except OSError as e:  # a file where a directory is (or the reverse), or a write that failed
        raise Refused(f"the archive does not unpack cleanly: {e.strerror} ({e.filename})") from e


def _extract_each(tf: tarfile.TarFile, dest: str) -> None:
    seen: set[str] = set()
    total = 0
    for count, m in enumerate(tf, start=1):
        if count > MAX_ENTRIES:
            raise Refused(f"the archive holds more than {MAX_ENTRIES} entries")
        name = safe_name(m.name)
        key = name.casefold()
        if key in seen:
            raise Refused(f"archive entry {name!r} repeats (or differs only by case)")
        seen.add(key)
        target = os.path.join(dest, name)
        if m.isdir():
            os.makedirs(target, mode=0o700, exist_ok=True)
            continue
        if not m.isreg():
            raise Refused(f"archive entry {name!r} is not a regular file or a directory")
        total += m.size
        if total > MAX_BYTES:
            raise Refused("the archive unpacks to more than 2 GiB")
        os.makedirs(os.path.dirname(target), mode=0o700, exist_ok=True)
        src = tf.extractfile(m)
        if src is None:
            raise Refused(f"archive entry {name!r} cannot be read")
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | NF, 0o600)
        with os.fdopen(fd, "wb") as out, src:
            shutil.copyfileobj(src, out, 1 << 20)
        os.chmod(target, 0o700 if m.mode & 0o111 else 0o600)


def check_layout(stage: str) -> dict:
    meta_path = os.path.join(stage, META)
    if not os.path.isfile(meta_path) or not os.path.isdir(os.path.join(stage, "app")):
        raise Refused(f'the archive has no {META} or no app/ directory (README, "The artefact")')
    try:
        with open(meta_path, encoding="utf-8") as f:
            meta = json.load(f)
    except ValueError as e:
        raise Refused(f"{META} is not JSON: {e}") from e
    if not isinstance(meta, dict) or not all(
        isinstance(meta.get(k), str) and meta[k] for k in ("name", "version")
    ):
        raise Refused(f"{META} must name the app and its version")
    pkgs = meta.get("packages", [])
    if not isinstance(pkgs, list) or not all(
        isinstance(p, str) and PACKAGE_RE.match(p) and p not in NOT_APP_PACKAGES for p in pkgs
    ):
        raise Refused(
            f"{META} packages must be a list of the app's own top-level package names "
            "(never the interpreter's modules or its installers)"
        )
    if os.path.lexists(os.path.join(stage, "venv")):
        raise Refused("the archive carries a venv/: it is built on the host, never shipped")
    return meta


def requirement_lines(stage: str) -> list[str]:
    path = os.path.join(stage, "requirements.txt")
    if not os.path.isfile(path):
        return []
    with open(path, encoding="utf-8") as f:
        return [x for x in f.read().splitlines() if x.strip() and not x.lstrip().startswith("#")]


def build_venv(stage: str, python: str) -> None:
    venv = os.path.join(stage, "venv")
    reqs = requirement_lines(stage)
    args = [python, "-m", "venv"] + ([] if reqs else ["--without-pip"]) + [venv]
    r = subprocess.run(args, capture_output=True, text=True, check=False)
    if r.returncode != 0:
        raise Refused(f"the venv could not be created: {r.stderr[-800:]}")
    if not reqs:
        return
    if not os.path.isdir(os.path.join(stage, "wheels")):
        raise Refused("requirements.txt names wheels, but the archive has no wheels/")
    r = subprocess.run(
        [os.path.join(venv, "bin", "python"), "-m", "pip", "install", "--no-index", "--no-deps",
         "--require-hashes", "--only-binary=:all:", "--no-cache-dir", "--disable-pip-version-check",
         "--find-links", os.path.join(stage, "wheels"), "-r", os.path.join(stage, "requirements.txt")],
        capture_output=True, text=True, check=False, timeout=PIP_TIMEOUT,
    )  # fmt: skip
    if r.returncode != 0:
        raise Refused(f"the wheels did not install (offline, hashed): {r.stderr[-1200:]}")


def install(archive: str, pin: str, releases: str, python: str) -> dict:
    if not SHA_RE.match(pin):
        raise Refused("the pin is not 64 lowercase hex")
    releases = real_dir(releases, "the releases directory")
    with open_archive(archive) as f:  # one descriptor: what is hashed is what is unpacked
        return _install(f, os.path.basename(archive), pin, releases, python)


def _install(f, label: str, pin: str, releases: str, python: str) -> dict:
    got = sha256_of(f)
    if got != pin:
        raise Refused(f"{label} hashes to {got}, the pin is {pin}; nothing was installed")
    name = pin[:16]
    final = os.path.join(releases, name)
    if os.path.lexists(final):
        marker = os.path.join(final, MARKER)
        if os.path.islink(final) or not os.path.isfile(marker):
            raise Refused(
                f"{final} exists but is not an installed release (no {MARKER}): move it aside"
            )
        with open(marker, encoding="utf-8") as m:
            if m.read().strip() != pin:
                raise Refused(f"{final} records another pin: move it aside")
        return {"changed": False, "release": final}
    stage = os.path.join(releases, f".{name}.incoming")
    if os.path.lexists(stage):
        remove_inside(stage, releases)
    os.mkdir(stage, 0o700)
    try:
        extract(f, stage, label)
        meta = check_layout(stage)
        build_venv(stage, python)
        with open(os.path.join(stage, MARKER), "w", encoding="utf-8") as m:
            m.write(pin + "\n")
        os.rename(stage, final)
    except BaseException:
        if os.path.isdir(stage) and not os.path.islink(stage):
            remove_inside(stage, releases)
        raise
    return {"changed": True, "release": final, "app": meta["name"], "version": meta["version"]}


def prune(releases: str, current: str, keep: int) -> dict:
    """Release directories past the ``keep`` newest (the current one counted, never removed), each
    removed only under an exclusive, non-blocking lock on its marker: a job holds a shared one for
    its whole run (the job wrapper), so a release in use is skipped and kept for a later prune."""
    releases = real_dir(releases, "the releases directory")
    found = []
    for entry in os.scandir(releases):
        if (
            RELEASE_RE.match(entry.name)
            and entry.is_dir(follow_symlinks=False)
            and entry.name != current
        ):
            found.append((entry.stat(follow_symlinks=False).st_mtime, entry.name))
    found.sort(reverse=True)
    removed, in_use = [], []
    for _mtime, name in found[max(keep - 1, 0) :]:
        path = os.path.join(releases, name)
        try:
            fd = os.open(os.path.join(path, MARKER), os.O_RDONLY | NF)
        except FileNotFoundError:
            fd = None  # never finished installing: nothing can be running it
        try:
            if fd is not None:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    in_use.append(name)
                    continue
            gone = os.path.join(releases, f".{name}.removing")
            if os.path.lexists(gone):
                remove_inside(gone, releases)
            os.rename(path, gone)  # under the lock: a job starting now finds no marker and retries
            remove_inside(gone, releases)
            removed.append(name)
        finally:
            if fd is not None:
                os.close(fd)
    return {"changed": bool(removed), "removed": removed, "in_use": in_use}


def main(argv: list[str]) -> int:
    try:
        if len(argv) == 5 and argv[0] == "install":
            out = install(argv[1], argv[2], argv[3], argv[4])
        elif len(argv) == 4 and argv[0] == "prune" and argv[3].isdigit():
            out = prune(argv[1], argv[2], int(argv[3]))
        else:
            print(__doc__.split("\n\n")[1], file=sys.stderr)
            return 2
    except Refused as e:
        print(f"cti-pipeline artefact: refused: {e}", file=sys.stderr)
        return 1
    print(json.dumps(out, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
