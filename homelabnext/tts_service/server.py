# SPDX-License-Identifier: Apache-2.0
"""The HTTP service (``python -m tts_service serve``) and its self-check (``... check``).

Standard library HTTP: one job at a time (the engine is one model on one device; a second request
waits for the first, as the old service's callers already allow with their 30 minute timeout).
"""

from __future__ import annotations

import io
import json
import os
import sys
import urllib.error
import urllib.request
import wave
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from . import gates
from .contract import (
    MAX_BODY_BYTES,
    SAMPLE_RATE,
    ApiError,
    detail,
    normalize_for_speech,
    parse_synthesize,
)
from .engine import EngineHost, Unavailable

#: the fixed sentence of the health check: short, plain, no number or abbreviation to be spoken
CHECK_TEXT = "This is a short test of the narration voice."
DEFAULT_REFS = ("ref1.wav", "ref2.wav", "ref3.wav", "ref4.wav")


@dataclass(frozen=True)
class Config:
    backend: str
    port: int
    model_dir: Path
    listing: Path
    model_digest: str
    refs_dir: Path
    ref_files: tuple[str, ...]
    cache_dir: Path
    idle_unload_s: float
    power_cap_max_watts: int
    gpu_index: int

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> Config:
        def need(name: str) -> str:
            if not env.get(name):
                raise ValueError(f"{name} is not set")
            return env[name]

        backend = env.get("TTS_BACKEND", "cpu")
        if backend not in gates.BACKENDS:
            raise ValueError(f"TTS_BACKEND must be one of {gates.BACKENDS}")
        cap = int(env.get("TTS_POWER_CAP_MAX_WATTS", str(gates.POWER_CAP_CEILING_WATTS)))
        if not 1 <= cap <= gates.POWER_CAP_CEILING_WATTS:
            raise ValueError(f"TTS_POWER_CAP_MAX_WATTS must be 1..{gates.POWER_CAP_CEILING_WATTS}")
        idle = float(env.get("TTS_IDLE_UNLOAD_S", "0"))
        if idle < 0:
            raise ValueError("TTS_IDLE_UNLOAD_S must be 0 (never) or more")
        refs = tuple(x for x in env.get("TTS_REF_FILES", ",".join(DEFAULT_REFS)).split(",") if x)
        if not refs or any("/" in r or r.startswith(".") for r in refs):
            raise ValueError("TTS_REF_FILES must be file names")
        return cls(
            backend=backend,
            port=int(env.get("TTS_PORT", "8091")),
            model_dir=Path(need("TTS_MODEL_DIR")),
            listing=Path(need("TTS_MODEL_LISTING")),
            model_digest=need("TTS_MODEL_DIGEST"),
            refs_dir=Path(need("TTS_REFS_DIR")),
            ref_files=refs,
            cache_dir=Path(need("TTS_CACHE_DIR")),
            idle_unload_s=idle,
            power_cap_max_watts=cap,
            gpu_index=int(env.get("TTS_GPU_INDEX", "0")),
        )

    @property
    def refs(self) -> dict[str, Path]:
        return {n: self.refs_dir / n for n in self.ref_files}


def wav_bytes(samples: Sequence[float], rate: int = SAMPLE_RATE) -> bytes:
    """16-bit PCM mono WAV of float samples in [-1, 1] (what soundfile wrote for the old service)."""
    import array

    pcm = array.array("h", (max(-32768, min(32767, round(s * 32767.0))) for s in samples))
    if sys.byteorder == "big":
        pcm.byteswap()
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(pcm.tobytes())
    return buf.getvalue()


class Service:
    """The routes, independent of the socket (the tests call these)."""

    def __init__(
        self,
        config: Config,
        host: EngineHost,
        gate: gates.WeightsGate | None = None,
        run: Any = None,
    ) -> None:
        self.config = config
        self.host = host
        self.gate = gate
        self._run = run

    def health(self) -> dict[str, Any]:
        return {
            "status": "ok",
            "model_loaded": self.host.loaded,
            "refs": [str(p) for p in self.config.refs.values()],
        }

    def ready(self) -> tuple[int, dict[str, Any]]:
        kw: dict[str, Any] = {"run": self._run} if self._run else {}
        report = gates.readiness(
            self.gate,
            self.config.refs,
            self.config.backend,
            self.config.power_cap_max_watts,
            self.config.gpu_index,
            **kw,
        )
        report["model_loaded"] = self.host.loaded
        report["backend"] = self.config.backend
        return (200 if report["ready"] else 503), report

    def synthesize(self, body: bytes) -> bytes:
        req = parse_synthesize(body)
        try:
            with self.host.lease() as engine:
                samples = engine.synthesize(
                    normalize_for_speech(req.text), req.temperature, req.top_p
                )
        except Unavailable as exc:
            raise detail(503, str(exc)) from exc
        return wav_bytes(samples)


def make_handler(service: Service) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "tts"

        def log_message(self, fmt: str, *args: Any) -> None:
            sys.stderr.write(f"{self.address_string()} - {fmt % args}\n")

        def _send(self, status: int, body: bytes, ctype: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status: int, doc: Any) -> None:
            self._send(status, json.dumps(doc).encode(), "application/json")

        def _path(self) -> str:
            return self.path.split("?", 1)[0]

        def do_GET(self) -> None:
            path = self._path()
            if path == "/health":
                self._json(200, service.health())
            elif path == "/ready":
                status, doc = service.ready()
                self._json(status, doc)
            elif path == "/synthesize":
                self._json(405, {"detail": "Method Not Allowed"})
            else:
                self._json(404, {"detail": "Not Found"})

        def do_POST(self) -> None:
            if self._path() in ("/health", "/ready"):
                self._json(405, {"detail": "Method Not Allowed"})
                return
            if self._path() != "/synthesize":
                self._json(404, {"detail": "Not Found"})
                return
            try:
                length = int(self.headers.get("Content-Length", "-1"))
            except ValueError:
                length = -1
            if length < 0:
                self._json(411, {"detail": "Content-Length is required"})
                self.close_connection = True
                return
            if length > MAX_BODY_BYTES:
                self._json(413, {"detail": "request body too large"})
                self.close_connection = True
                return
            body = self.rfile.read(length)
            try:
                self._send(200, service.synthesize(body), "audio/wav")
            except ApiError as exc:
                self._json(exc.status, exc.body)

    return Handler


def build(config: Config, run: Any = None) -> Service:
    """The service for a configuration: the real engine, loaded on demand behind the gates."""
    gate = gates.WeightsGate(config.model_dir, config.listing, config.model_digest)
    refs = [config.refs_dir / n for n in config.ref_files]

    def before_load() -> None:
        if not all(p.is_file() for p in refs):
            raise gates.Refusal("voice reference file(s) missing under " + str(config.refs_dir))
        gates.check_power_cap(
            config.backend,
            config.power_cap_max_watts,
            config.gpu_index,
            **({"run": run} if run else {}),
        )
        gate.verify()

    def load() -> Any:
        from .engine import XttsEngine

        device = f"cuda:{config.gpu_index}" if config.backend == "cuda" else "cpu"
        listing = gate.check_listing()
        return XttsEngine(
            config.model_dir, refs, device, config.cache_dir, listing.get("model.pth", "")
        )

    host = EngineHost(load, before_load, config.idle_unload_s)
    return Service(config, host, gate, run)


def serve(env: Mapping[str, str]) -> None:
    config = Config.from_env(env)
    service = build(config)
    service.host.start_reaper()
    httpd = ThreadingHTTPServer(("0.0.0.0", config.port), make_handler(service))
    httpd.daemon_threads = True
    sys.stderr.write(f"tts: serving on :{config.port} ({config.backend})\n")
    httpd.serve_forever()


def check(env: Mapping[str, str], argv: Sequence[str]) -> int:
    """The health probe: one real synthesis of the fixed sentence; sample rate and duration checked.

    Prints one JSON object; exit 0 when the answer is a 24000 Hz mono WAV whose duration is within
    the bounds, 1 otherwise.
    """
    import argparse

    p = argparse.ArgumentParser(prog="tts_service check")
    p.add_argument("--min-seconds", type=float, default=0.8)
    p.add_argument("--max-seconds", type=float, default=15.0)
    p.add_argument("--timeout", type=float, default=900.0)
    a = p.parse_args(list(argv))
    port = int(env.get("TTS_PORT", "8091"))
    url = env.get("TTS_CHECK_URL", f"http://localhost:{port}")
    body = json.dumps({"text": CHECK_TEXT}).encode()
    req = urllib.request.Request(
        url.rstrip("/") + "/synthesize", data=body, headers={"Content-Type": "application/json"}
    )
    out: dict[str, Any] = {"ok": False}
    try:
        with urllib.request.urlopen(req, timeout=a.timeout) as r:
            data = r.read()
            ctype = r.headers.get("Content-Type", "")
        with wave.open(io.BytesIO(data)) as w:
            rate, chans, width, frames = (
                w.getframerate(), w.getnchannels(), w.getsampwidth(), w.getnframes(),
            )  # fmt: skip
        seconds = frames / rate if rate else 0.0
        out.update(
            content_type=ctype, sample_rate=rate, channels=chans, sample_width=width,
            seconds=round(seconds, 2), bytes=len(data),
        )  # fmt: skip
        out["ok"] = (
            ctype == "audio/wav"
            and rate == SAMPLE_RATE
            and chans == 1
            and width == 2
            and a.min_seconds <= seconds <= a.max_seconds
        )
    except (urllib.error.URLError, OSError, wave.Error, EOFError) as exc:
        out["error"] = str(exc)[:200]
    print(json.dumps(out))
    return 0 if out["ok"] else 1


def main(argv: Sequence[str] | None = None, env: Mapping[str, str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    env = os.environ if env is None else env
    if args[:1] == ["serve"]:
        serve(env)
        return 0
    if args[:1] == ["check"]:
        return check(env, args[1:])
    sys.stderr.write(
        "usage: python -m tts_service serve | check [--min-seconds N --max-seconds N]\n"
    )
    return 2
