# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: wazuh-rules-sync
#   kind: tool
#   purpose: Load the site's native rule and decoder files into the SIEM manager, test them with the manager's own configuration test before it restarts, and put the previous set back when the test or the restart fails.
#   owner: platform
#   trigger: [role:wazuh]
#   inputs: "sync --stage DIR --etc DIR --compose FILE --prev DIR [--force-restart]; digest --etc DIR | --stage DIR"
#   outputs: one JSON line on stdout, {changed, digest, files}; the reason on stderr when refused
#   exit:
#     "0": the set is in place and tested (changed or not)
#     "1": the new set was refused by the configuration test or the restart and the previous set is back
#     "2": usage error or an unsafe path
"""The wazuh role's rules sync (modules/wazuh/README.md, "Native rules").

    python3 -I hnx_wazuh_rules.py sync --stage S --etc E --compose F --prev P [--force-restart]

``S`` holds ``rules/*.xml`` and ``decoders/*.xml`` (copied from the site's native-rules directory by
the role).  Each lands in the manager's ``etc/rules`` or ``etc/decoders`` as ``hnx-<name>.xml``;
only files with that prefix are ever written or removed here, the manager's own ``local_rules.xml``
and any other file are never touched.  When the set differs from what is installed, the previous
``hnx-*`` files are kept in ``P``, the new set is written (a temporary file then a rename), the
manager's configuration test (``wazuh-analysisd -t``) runs in the container, and only a passing set
is followed by a restart of the manager's daemons and a check that they are alive.  A failing test
or a daemon that did not come back restores the previous set (and restarts it) and exits 1.
``--force-restart`` restarts even when the set is unchanged (the role changed the integration or the
internal options).  ``digest`` prints the installed set's digest, what the manager reports as
deployed (``wazuh/rule-drift`` compares it with the site's).
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path

PREFIX = "hnx-"
KINDS = ("rules", "decoders")
GROUP_ID = (
    999  # the product's service group inside the container (its etc/rules is root:this, 0770)
)
DAEMONS = (
    "wazuh-analysisd",
    "wazuh-remoted",
    "wazuh-authd",
    "wazuh-db",
    "wazuh-modulesd",
    "wazuh-monitord",
)
ALIVE_WAIT = 90


class Refused(Exception):
    """An unsafe path or a refused input (exit 2)."""


def _safe_dir(p: str, what: str) -> Path:
    path = Path(p)
    if not path.is_absolute() or ".." in path.parts or len(path.parts) < 3 or path.is_symlink():
        raise Refused(
            f"{what} must be an absolute, canonical, non-symlink path of at least 3 parts: {p}"
        )
    return path


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def desired(stage: Path) -> dict[str, Path]:
    """The files to install, keyed ``rules/hnx-<name>.xml`` (relative to etc/)."""
    out: dict[str, Path] = {}
    for kind in KINDS:
        d = stage / kind
        if not d.is_dir():
            continue
        for f in sorted(d.iterdir()):
            if f.is_symlink() or not f.is_file() or not f.name.endswith(".xml"):
                raise Refused(f"{f} is not a regular .xml file")
            out[f"{kind}/{PREFIX}{f.name}"] = f
    return out


def installed(etc: Path) -> dict[str, Path]:
    out: dict[str, Path] = {}
    for kind in KINDS:
        d = etc / kind
        if d.is_dir():
            for f in sorted(d.glob(f"{PREFIX}*.xml")):
                out[f"{kind}/{f.name}"] = f
    return out


def digest_of(files: dict[str, Path]) -> str:
    h = hashlib.sha256()
    for rel in sorted(files):
        h.update(f"{rel}\0{_sha(files[rel])}\n".encode())
    return h.hexdigest()


def _exec(compose: str, *argv: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "compose", "-f", compose, "exec", "-T", "manager", *argv],
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )


def _alive(compose: str) -> bool:
    return all(_exec(compose, "pgrep", "-x", d).returncode == 0 for d in DAEMONS)


def _wait_alive(compose: str, wait: int) -> bool:
    end = time.monotonic() + wait
    while True:
        if _alive(compose):
            return True
        if time.monotonic() >= end:
            return False
        time.sleep(3)


def _write(dest: Path, src: Path) -> None:
    tmp = dest.with_name(dest.name + ".tmp")
    # born at its final mode, never widened after: the product's own directory sets the policy
    # (its etc/rules is root:group, 0770), so a file is the directory's mode with the group's write
    # and everything for others taken away (0640: the manager reads, nobody else does).  The umask
    # is pinned for the create so that mode is exactly what the file gets.
    mode = stat.S_IMODE(dest.parent.stat().st_mode) & 0o640
    old = os.umask(0o027)
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
    finally:
        os.umask(old)
    with os.fdopen(fd, "wb") as out, open(src, "rb") as inp:
        shutil.copyfileobj(inp, out)
    with contextlib.suppress(
        PermissionError
    ):  # not root (a test run): the mode is what matters there
        os.chown(tmp, 0, GROUP_ID)
    os.replace(tmp, dest)


def _restore(etc: Path, prev: Path) -> None:
    for f in installed(etc).values():
        f.unlink()
    for kind in KINDS:
        for f in sorted((prev / kind).glob(f"{PREFIX}*.xml")) if (prev / kind).is_dir() else []:
            _write(etc / kind / f.name, f)


def sync(
    stage: Path, etc: Path, compose: str, prev: Path, force: bool, wait: int = ALIVE_WAIT
) -> tuple[int, dict]:
    want = desired(stage)
    have = installed(etc)
    same = set(want) == set(have) and all(_sha(want[k]) == _sha(have[k]) for k in want)
    if same and not force:
        return 0, {"changed": False, "digest": digest_of(have), "files": sorted(have)}
    if not same:
        prev.mkdir(parents=True, exist_ok=True)
        for kind in KINDS:
            (prev / kind).mkdir(exist_ok=True)
            for old in (prev / kind).glob(f"{PREFIX}*.xml"):
                old.unlink()
            for rel, f in have.items():
                if rel.startswith(kind + "/"):
                    shutil.copyfile(f, prev / kind / f.name)
        for rel in set(have) - set(want):
            have[rel].unlink()
        for rel, src in want.items():
            dest = etc / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            _write(dest, src)
    test = _exec(compose, "/var/ossec/bin/wazuh-analysisd", "-t")
    if test.returncode != 0:
        if not same:
            _restore(etc, prev)
        print(
            "the manager's configuration test refused the set: "
            + (test.stderr or test.stdout)[-800:],
            file=sys.stderr,
        )
        return 1, {
            "changed": False,
            "digest": digest_of(installed(etc)),
            "files": sorted(installed(etc)),
        }
    restart = _exec(compose, "/var/ossec/bin/wazuh-control", "restart")
    if restart.returncode != 0 or not _wait_alive(compose, wait):
        if not same:
            _restore(etc, prev)
        _exec(compose, "/var/ossec/bin/wazuh-control", "restart")
        _wait_alive(compose, wait)
        print(
            "the manager's daemons did not come back with the new set; the previous set is restored",
            file=sys.stderr,
        )
        return 1, {
            "changed": False,
            "digest": digest_of(installed(etc)),
            "files": sorted(installed(etc)),
        }
    now = installed(etc)
    return 0, {"changed": True, "digest": digest_of(now), "files": sorted(now)}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="hnx_wazuh_rules")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sync")
    for a in ("--stage", "--etc", "--compose", "--prev"):
        s.add_argument(a, required=True)
    s.add_argument("--force-restart", action="store_true")
    s.add_argument("--wait", type=int, default=ALIVE_WAIT)
    d = sub.add_parser("digest")
    d.add_argument("--etc")
    d.add_argument("--stage")
    args = ap.parse_args(argv)
    try:
        if args.cmd == "digest":
            if bool(args.etc) == bool(args.stage):
                raise Refused(
                    "digest takes --etc (what is installed) or --stage (what the site wants), not both"
                )
            if args.etc:
                files = installed(_safe_dir(args.etc, "--etc"))
            else:
                files = desired(_safe_dir(args.stage, "--stage"))
            print(json.dumps({"digest": digest_of(files)}))
            return 0
        stage = _safe_dir(args.stage, "--stage")
        etc = _safe_dir(args.etc, "--etc")
        prev = _safe_dir(args.prev, "--prev")
        compose = str(_safe_dir(args.compose, "--compose"))
        if prev == etc or (etc in prev.parents and prev.name in KINDS):
            raise Refused("--prev must not be the manager's rule directories")
        code, report = sync(stage, etc, compose, prev, args.force_restart, args.wait)
    except Refused as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
