# SPDX-License-Identifier: Apache-2.0
"""The static-site adapter: ``wrangler pages deploy`` from an installed, pinned wrangler.

The old pipeline ran ``npx --yes wrangler@latest`` every hour: an unpinned supply-chain pull on
each run.  Here the version is an exact ``X.Y.Z`` the site pins, installed once by the role from a
lockfile (``npm ci``, hashes checked, scripts off), and this adapter refuses to deploy unless

* the pin is an exact version (never ``latest``, a range or a tag),
* the lockfile is the one whose sha256 the site pinned and names that version for ``wrangler``,
* the installed package is that version, and
* ``wrangler --version`` prints that version,

and it never runs ``npx``.  The deploy always names ``--branch`` (the production branch: a deploy
to any other branch is a preview at another URL, not the site).
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

SEMVER = re.compile(r"^\d+\.\d+\.\d+\Z")
_HEX64 = re.compile(r"^[0-9a-f]{64}\Z")
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,57}\Z")


class PagesError(RuntimeError):
    pass


@dataclass(frozen=True)
class PagesConfig:
    project: str
    branch: str
    wrangler_version: str
    #: the sha256 of package-lock.json: it pins every package and its integrity hash
    lock_sha256: str
    install_dir: Path  # holds package-lock.json and node_modules/
    timeout_s: int = 180

    def __post_init__(self) -> None:
        if not SEMVER.match(self.wrangler_version):
            raise PagesError(
                f"wrangler version {self.wrangler_version!r} is not an exact X.Y.Z pin"
            )
        if not _HEX64.match(self.lock_sha256):
            raise PagesError(
                "the lockfile pin is not 64 lowercase hex (sha256 of package-lock.json)"
            )
        if not _NAME.match(self.project):
            raise PagesError("the Pages project name is not a lowercase slug")
        if not self.branch or not re.match(r"^[A-Za-z0-9._/-]{1,60}\Z", self.branch):
            raise PagesError("the Pages branch is not set (the production branch is required)")

    @property
    def bin(self) -> Path:
        return self.install_dir / "node_modules" / ".bin" / "wrangler"


def verify_pin(cfg: PagesConfig) -> None:
    """Refuse unless the lockfile and the installed package both say the pinned version."""
    try:
        raw = (cfg.install_dir / "package-lock.json").read_bytes()
        lock = json.loads(raw)
        entry = lock["packages"]["node_modules/wrangler"]
    except (OSError, ValueError, KeyError) as exc:
        raise PagesError(f"no usable lockfile entry for wrangler ({type(exc).__name__})") from exc
    if hashlib.sha256(raw).hexdigest() != cfg.lock_sha256:
        raise PagesError(
            "the lockfile is not the pinned one (sha256 differs): its packages are not the reviewed set"
        )
    if entry.get("version") != cfg.wrangler_version:
        raise PagesError(
            f"the lockfile pins wrangler {entry.get('version')!r}, not {cfg.wrangler_version}"
        )
    if not str(entry.get("integrity", "")).startswith("sha512-"):
        raise PagesError("the lockfile's wrangler entry has no sha512 integrity")
    try:
        installed = json.loads(
            (cfg.install_dir / "node_modules" / "wrangler" / "package.json").read_text(
                encoding="utf-8"
            )
        )["version"]
    except (OSError, ValueError, KeyError) as exc:
        raise PagesError(
            f"wrangler is not installed under {cfg.install_dir} ({type(exc).__name__})"
        ) from exc
    if installed != cfg.wrangler_version:
        raise PagesError(f"wrangler {installed} is installed, the pin is {cfg.wrangler_version}")


Runner = Callable[[list[str], dict[str, str], int], tuple[int, str]]


def subprocess_runner(argv: list[str], env: dict[str, str], timeout: int) -> tuple[int, str]:
    try:
        p = subprocess.run(
            argv, env=env, capture_output=True, text=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PagesError(f"{argv[0]}: {type(exc).__name__}") from exc
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def deploy_argv(cfg: PagesConfig, dist_dir: Path) -> list[str]:
    argv = [
        str(cfg.bin),
        "pages",
        "deploy",
        str(dist_dir),
        f"--project-name={cfg.project}",
        f"--branch={cfg.branch}",
        "--commit-dirty=true",
    ]
    if any(
        "@latest" in a or a in ("npx", "npm") for a in argv
    ):  # unreachable by construction; a guard
        raise PagesError("an unpinned or npx-based invocation was built")
    return argv


def _env(cfg: PagesConfig, token: str, account_id: str, home: Path) -> dict[str, str]:
    env = {
        "PATH": f"{cfg.install_dir / 'node_modules' / '.bin'}:/usr/local/bin:/usr/bin:/bin",
        "HOME": str(home),
        "CI": "true",
        "WRANGLER_SEND_METRICS": "false",
        "CLOUDFLARE_API_TOKEN": token,
    }
    if account_id:
        env["CLOUDFLARE_ACCOUNT_ID"] = account_id
    return env


def deploy(
    cfg: PagesConfig,
    dist_dir: Path,
    *,
    token: str,
    account_id: str,
    home: Path,
    runner: Runner = subprocess_runner,
) -> str:
    """Verify the pin, check the running version, deploy.  Returns wrangler's output (token-free)."""
    verify_pin(cfg)
    env = _env(cfg, token, account_id, home)
    code, out = runner([str(cfg.bin), "--version"], env, 60)
    shown = set(re.findall(r"\b\d+\.\d+\.\d+\b", _ANSI.sub("", out)))
    if code != 0 or shown != {cfg.wrangler_version}:
        raise PagesError(
            f"wrangler --version printed {sorted(shown)}, the pin is {cfg.wrangler_version}"
        )
    code, out = runner(deploy_argv(cfg, dist_dir), env, cfg.timeout_s)
    out = out.replace(token, "[redacted]") if token else out
    if code != 0:
        raise PagesError(f"wrangler pages deploy failed (exit {code}): {out[-600:]}")
    return out
