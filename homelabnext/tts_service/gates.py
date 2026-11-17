# SPDX-License-Identifier: Apache-2.0
"""What must hold before the engine loads: the card's power cap and the weights' bytes.

Both run at **every** load (the engine is loaded per job on a GPU backend and unloaded when idle),
inside the service, so there is one implementation of each rule: a refusal is a :class:`Refusal`
that the HTTP layer answers with 503 and the readiness endpoint reports.

* Power: on ``cuda`` the card's ``power.limit`` (``nvidia-smi``) must be a number above 0 and at
  most the limit (the operator's rule, 200 W; a setting can only tighten it).  Unreadable,
  unparseable, 0 ("no limit set") or above refuses: a cap that cannot be read is not a cap that
  holds.  The ``cpu`` backend has no card and passes.
* Bytes: the model store's listing (``<sha256>  <path>`` per file) must hash to the pinned entry
  digest, every file in it must hash to its listed sha256, and every file the engine loads must be
  in the listing.  A file already hashed is not read again while its size and mtime are unchanged.
"""

from __future__ import annotations

import hashlib
import math
import re
import subprocess
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

#: the operator's rule: no setting raises the cap limit above this many watts
POWER_CAP_CEILING_WATTS = 200
#: every file the engine reads from the model directory
REQUIRED_MODEL_FILES = (
    "config.json",
    "dvae.pth",
    "mel_stats.pth",
    "model.pth",
    "speakers_xtts.pth",
    "vocab.json",
)
BACKENDS = ("cpu", "cuda")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}\Z")
_LINE_RE = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9_][A-Za-z0-9._/-]*)\Z")
_CHUNK = 8 * 1024 * 1024


class Refusal(Exception):
    """A gate that does not hold; the message says which and why."""


def power_cap_watts(
    gpu_index: int, run: Callable[..., Any] = subprocess.run, smi: str = "nvidia-smi"
) -> float:
    """The card's power limit in watts, or a :class:`Refusal` when it cannot be read."""
    try:
        done = run(
            [smi, "-i", str(gpu_index), "--query-gpu=power.limit", "--format=csv,noheader,nounits"],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise Refusal(f"cannot run {smi} to read GPU {gpu_index}'s power limit: {exc}") from exc
    out = (done.stdout or "").strip()
    if done.returncode != 0:
        raise Refusal(f"{smi} cannot read GPU {gpu_index}'s power limit (exit {done.returncode})")
    try:
        watts = float(out)
    except ValueError:
        raise Refusal(
            f"{smi} reports GPU {gpu_index}'s power limit as {out[:40]!r}, not a number"
        ) from None
    return watts


def check_power_cap(
    backend: str,
    max_watts: int,
    gpu_index: int = 0,
    run: Callable[..., Any] = subprocess.run,
    smi: str = "nvidia-smi",
) -> dict[str, Any]:
    """Pass (a dict) or raise :class:`Refusal`; the cpu backend has no card."""
    if backend == "cpu":
        return {"backend": "cpu", "limit_watts": None, "watts": None}
    if backend != "cuda":
        raise Refusal(f"unknown backend {backend!r}")
    if not 1 <= max_watts <= POWER_CAP_CEILING_WATTS:
        raise Refusal(
            f"the power cap limit {max_watts} W is outside 1..{POWER_CAP_CEILING_WATTS} W"
        )
    watts = power_cap_watts(gpu_index, run, smi)
    # NaN and the infinities parse as floats and compare false against everything: only a finite
    # number inside (0, limit] is a cap that holds
    if not (math.isfinite(watts) and 0 < watts <= max_watts):
        if math.isfinite(watts) and watts > max_watts:
            raise Refusal(
                f"GPU {gpu_index}'s power limit is {watts:g} W, above the {max_watts} W limit"
            )
        raise Refusal(
            f"GPU {gpu_index}'s power limit is {watts:g}: not a finite cap above 0, "
            f"so not within {max_watts} W"
        )
    return {"backend": "cuda", "limit_watts": max_watts, "watts": watts}


def parse_listing(text: str) -> dict[str, str]:
    """``<sha256>  <path>`` lines to {path: sha256}; anything else (or none) is a refusal."""
    files: dict[str, str] = {}
    for n, line in enumerate(text.splitlines(), 1):
        m = _LINE_RE.match(line)
        if not m or ".." in m.group(2).split("/"):
            raise Refusal(f"listing line {n} is not '<sha256>  <relative path>'")
        files[m.group(2)] = m.group(1)
    if not files:
        raise Refusal("the listing names no file")
    return files


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(_CHUNK):
            h.update(chunk)
    return h.hexdigest()


@dataclass
class WeightsGate:
    """The weights check, with a memory of what it already hashed."""

    model_dir: Path
    listing: Path
    digest: str
    required: tuple[str, ...] = REQUIRED_MODEL_FILES
    _seen: dict[str, tuple[int, int, str]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not _DIGEST_RE.match(self.digest):
            raise Refusal("the pinned model digest is not sha256:<64 hex>")

    def check_listing(self) -> dict[str, str]:
        """Cheap: the listing is the pinned one and names every file the engine loads."""
        try:
            raw = self.listing.read_bytes()
        except OSError as exc:
            raise Refusal(
                f"the model listing {self.listing} cannot be read: {exc.strerror}"
            ) from exc
        have = "sha256:" + hashlib.sha256(raw).hexdigest()
        if have != self.digest:
            raise Refusal(f"the model listing is {have}, the pin is {self.digest}")
        files = parse_listing(raw.decode("utf-8", "replace"))
        missing = [n for n in self.required if n not in files]
        if missing:
            raise Refusal(
                f"the listing does not name {', '.join(missing)}: it is not the voice model"
            )
        return files

    def verify(self) -> None:
        """Every listed file is there and is its listed bytes (the slow pass, cached per file)."""
        files = self.check_listing()
        for name, want in sorted(files.items()):
            path = self.model_dir / name
            try:
                st = path.stat()
            except OSError:
                raise Refusal(f"{name} is not in the model directory (run model_store)") from None
            if not path.is_file():
                raise Refusal(f"{name} is not a regular file")
            sig = (st.st_size, st.st_mtime_ns)
            seen = self._seen.get(name)
            if seen and seen[:2] == sig and seen[2] == want:
                continue
            got = sha256_file(path)
            if got != want:
                self._seen.pop(name, None)
                raise Refusal(f"{name} is sha256:{got[:12]}..., the listing says {want[:12]}...")
            self._seen[name] = (*sig, want)


def readiness(
    gate: WeightsGate | None,
    refs: Mapping[str, Path],
    backend: str,
    max_watts: int,
    gpu_index: int,
    run: Callable[..., Any] = subprocess.run,
) -> dict[str, Any]:
    """Every gate, none of them loading anything: {ready, checks: {name: {ok, detail}}}."""
    checks: dict[str, dict[str, Any]] = {}

    def record(name: str, fn: Callable[[], Any]) -> None:
        try:
            info = fn()
            checks[name] = {"ok": True, "detail": info if isinstance(info, dict) else {}}
        except Refusal as exc:
            checks[name] = {"ok": False, "detail": str(exc)}

    missing = sorted(n for n, p in refs.items() if not p.is_file())

    def refs_present() -> dict[str, Any]:
        if missing:
            raise Refusal(f"voice reference file(s) missing: {', '.join(missing)}")
        return {"files": sorted(refs)}

    record("voice_refs", refs_present)
    record("weights_listing", (lambda: {"files": len(gate.check_listing())}) if gate else _no_gate)
    record("power_cap", lambda: check_power_cap(backend, max_watts, gpu_index, run))
    return {"ready": all(c["ok"] for c in checks.values()), "checks": checks}


def _no_gate() -> dict[str, Any]:
    raise Refusal("no model directory is configured")
