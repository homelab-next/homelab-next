# SPDX-License-Identifier: Apache-2.0
"""A probe for the provisional ``tts`` slot (the shared adapter of modules/tts).

The slot has no contract or conformance suite yet, so this is not one: it asks the service the
things the role's health hook asks, from the endpoint the registry resolver gives
(``HNX_ENDPOINT_TTS``; no default, no credential): ``/health`` in the old shape, ``/ready`` (every
gate holds), and, only when asked, one real synthesis, checked as a 24 kHz mono 16-bit WAV.
"""

from __future__ import annotations

import io
import json
import urllib.error
import urllib.request
import wave
from typing import Any

from homelabnext.conform.adapters._env import resolve

__all__ = ["TtsProbe", "make"]


class TtsProbe:
    def __init__(self, base_url: str, timeout: float = 10.0, synth_timeout: float = 900.0) -> None:
        self._base = base_url.rstrip("/")
        self._timeout = timeout
        self._synth_timeout = synth_timeout

    def _get(self, path: str) -> tuple[int, dict[str, Any]]:
        req = urllib.request.Request(self._base + path, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as r:
                return r.status, json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def health(self) -> dict[str, Any]:
        status, doc = self._get("/health")
        if status != 200:
            raise RuntimeError(f"/health answered {status}")
        return doc

    def ready(self) -> bool:
        return self._get("/ready")[0] == 200

    def synthesize(self, text: str) -> dict[str, Any]:
        """One real render; {sample_rate, channels, sample_width, seconds}."""
        req = urllib.request.Request(
            self._base + "/synthesize",
            data=json.dumps({"text": text}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self._synth_timeout) as r:
            data = r.read()
        with wave.open(io.BytesIO(data)) as w:
            return {
                "sample_rate": w.getframerate(),
                "channels": w.getnchannels(),
                "sample_width": w.getsampwidth(),
                "seconds": w.getnframes() / w.getframerate(),
            }

    def close(self) -> None:  # the harness's teardown; nothing is held
        return None


def make(
    config: dict[str, Any] | None = None, *, resolver: Any = None, domain: str | None = None
) -> TtsProbe:
    cfg = config or {}
    ep = resolve(
        "tts",
        resolver=resolver,
        domain=domain,
        env_only=resolver is None and domain is None,
        schemes=("http", "https"),
    )
    return TtsProbe(ep.url, float(cfg.get("timeout", 10.0)), float(cfg.get("synth_timeout", 900.0)))
