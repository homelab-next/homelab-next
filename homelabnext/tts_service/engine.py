# SPDX-License-Identifier: Apache-2.0
"""The speech engine and the policy that loads it only while it is needed.

:class:`EngineHost` is the policy and imports nothing heavy: a job takes a *lease* (one job at a
time), the engine is loaded on the first lease after being absent (after the load gates pass) and
unloaded by :meth:`EngineHost.reap` once it has sat idle for ``idle_unload_s`` seconds (0: never,
the CPU default).  On a GPU backend that is what returns the card's memory between jobs.

:class:`XttsEngine` is the real engine (the voice model, torch imported inside it).  It does
what the old service did, call for call - ``TTS(model_path, config_path).tts(text, speaker_wav=refs,
language="en", temperature, top_p, split_sentences=True)`` - and adds one thing that cannot change
the sound: the conditioning latents of the reference recordings are computed once per
(recordings, model) and kept (in memory and in the cache directory) instead of once per sentence.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import sys
import threading
import time
import traceback
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path
from typing import Any, Protocol

from .contract import LANGUAGE, SAMPLE_RATE


class Unavailable(Exception):
    """The engine cannot take the job now (a refused or failed load); the message is the 503."""


class Engine(Protocol):
    def synthesize(self, text: str, temperature: float, top_p: float) -> Sequence[float]: ...

    def unload(self) -> None: ...


class EngineHost:
    """Loads on demand, serialises jobs, unloads when idle."""

    def __init__(
        self,
        load: Callable[[], Engine],
        before_load: Callable[[], Any] | None = None,
        idle_unload_s: float = 0.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._load = load
        self._before_load = before_load
        self._idle = float(idle_unload_s)
        self._clock = clock
        self._job = threading.Lock()  # held for a whole job, and by the reaper while it unloads
        self._engine: Engine | None = None
        self._last_used = clock()
        self.loads = 0
        self.unloads = 0

    @property
    def loaded(self) -> bool:
        return self._engine is not None

    @contextlib.contextmanager
    def lease(self) -> Iterator[Engine]:
        with self._job:
            if self._engine is None:
                try:
                    if self._before_load:
                        self._before_load()
                    self._engine = self._load()
                except Unavailable:
                    raise
                except Exception as exc:  # a refusal or a failed load: one answer, 503
                    traceback.print_exc(
                        file=sys.stderr
                    )  # the 503 carries the message, the log the cause
                    raise Unavailable(str(exc) or type(exc).__name__) from exc
                self.loads += 1
            try:
                yield self._engine
            finally:
                self._last_used = self._clock()

    def reap(self) -> bool:
        """Unload the engine if it is idle past the timeout and no job is running; True if it did."""
        if self._idle <= 0 or self._engine is None:
            return False
        if not self._job.acquire(blocking=False):
            return False  # a job is running
        try:
            if self._engine is None or self._clock() - self._last_used < self._idle:
                return False
            engine, self._engine = self._engine, None
            self.unloads += 1
            engine.unload()
            return True
        finally:
            self._job.release()

    def start_reaper(self, every_s: float = 5.0) -> threading.Event:
        """A daemon thread that calls :meth:`reap`; set the returned event to stop it."""
        stop = threading.Event()

        def run() -> None:
            while not stop.wait(every_s):
                with contextlib.suppress(Exception):
                    self.reap()

        threading.Thread(target=run, name="tts-reaper", daemon=True).start()
        return stop


# ----------------------------------------------------------------------------- the real engine


def _latent_key(refs: Sequence[Path], model_sha256: str, params: dict[str, Any]) -> str:
    h = hashlib.sha256()
    h.update(model_sha256.encode())
    for ref in refs:
        h.update(hashlib.sha256(ref.read_bytes()).digest())
    h.update(json.dumps(params, sort_keys=True, default=str).encode())
    return h.hexdigest()


class XttsEngine:
    """XTTS-v2 with the operator's reference recordings; the model files are already verified."""

    def __init__(
        self,
        model_dir: Path,
        refs: Sequence[Path],
        device: str,
        cache_dir: Path,
        model_sha256: str = "",
    ) -> None:
        import torch  # imported here: nothing else in the package needs it

        self._torch = torch
        self._device = device
        self._refs = [str(r) for r in refs]
        self._ref_paths = list(refs)
        self._cache_dir = cache_dir
        self._model_sha256 = model_sha256
        self._tts: Any = None
        with _trusted_checkpoint_loading(torch):
            from TTS.api import TTS

            self._tts = TTS(
                model_path=str(model_dir),
                config_path=str(model_dir / "config.json"),
                progress_bar=False,
            ).to(device)
        self._cache_latents()

    def _cache_latents(self) -> None:
        model = self._tts.synthesizer.tts_model
        original = model.get_conditioning_latents
        memo: dict[str, Any] = {}
        torch = self._torch

        def cached(audio_path: Any, *args: Any, **kwargs: Any) -> Any:
            paths = [audio_path] if isinstance(audio_path, (str, Path)) else list(audio_path)
            if [str(p) for p in paths] != self._refs or args:
                return original(audio_path, *args, **kwargs)  # not the voice: never cached
            key = _latent_key(self._ref_paths, self._model_sha256, kwargs)
            if key in memo:
                return memo[key]
            file = self._cache_dir / f"latents-{key[:32]}.pt"
            if file.is_file():
                try:
                    got = torch.load(file, map_location=self._device, weights_only=True)
                    memo[key] = (got["gpt_cond_latent"], got["speaker_embedding"])
                    return memo[key]
                except Exception:  # a damaged cache file is a miss, never a failure
                    file.unlink(missing_ok=True)
            result = original(audio_path, *args, **kwargs)
            memo[key] = result
            try:
                self._cache_dir.mkdir(parents=True, exist_ok=True)
                tmp = file.with_suffix(".tmp")
                torch.save(
                    {"gpt_cond_latent": result[0].cpu(), "speaker_embedding": result[1].cpu()}, tmp
                )
                tmp.replace(file)
            except OSError:
                pass  # a cache that cannot be written only costs time
            return result

        model.get_conditioning_latents = cached

    def synthesize(self, text: str, temperature: float, top_p: float) -> Sequence[float]:
        return self._tts.tts(
            text=text,
            speaker_wav=self._refs,
            language=LANGUAGE,
            temperature=temperature,
            top_p=top_p,
            split_sentences=True,
        )

    @property
    def sample_rate(self) -> int:
        return SAMPLE_RATE

    def unload(self) -> None:
        import gc

        self._tts = None
        gc.collect()
        if self._device.startswith("cuda") and self._torch.cuda.is_available():
            self._torch.cuda.empty_cache()


@contextlib.contextmanager
def _trusted_checkpoint_loading(torch: Any) -> Iterator[None]:
    """The voice checkpoint is a pickle (``.pth``); torch >= 2.6 refuses it by default.  It is the
    pinned, sha256-verified file of the model store, so loading it is allowed - for the load
    only, and torch.load is put back afterwards.  The audio decoder torchaudio dropped is
    redirected to soundfile the same way (the old service did both).  torch.save is switched off
    for the load: the library converts an original-format checkpoint in memory and then rewrites
    the file, which here would change pinned bytes (and fails on the read-only mount)."""
    import soundfile
    import torchaudio

    original_load = torch.load

    def load(*a: Any, **k: Any) -> Any:
        k.setdefault("weights_only", False)
        return original_load(*a, **k)

    def read(path: Any, *a: Any, **k: Any) -> Any:
        data, rate = soundfile.read(str(path), dtype="float32", always_2d=True)
        return torch.from_numpy(data.T.copy()), rate

    def no_save(*_a: Any, **_k: Any) -> None:
        # the library rewrites an original-format checkpoint in place after converting it in
        # memory; the weights are the model store's, read-only and pinned by sha256: never written
        return None

    original_save = torch.save
    torch.load, torchaudio.load, torch.save = load, read, no_save
    try:
        yield
    finally:
        torch.load, torch.save = original_load, original_save
        # torchaudio.load stays the soundfile reader: the references are read at every job
        torchaudio.load = read
