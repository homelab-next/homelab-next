# SPDX-License-Identifier: Apache-2.0
"""The ``/synthesize`` contract, as the old service answered it (the point of this module is that
the publishing pipeline switches over without an edit).

Derived from the archived service (``voice-tts/service/app.py`` of the old lab) and pinned by
``tests/tts_service/test_tts_contract.py``:

* ``POST /synthesize`` takes JSON ``{"text": str, "temperature": float|null, "top_p": float|null}``.
  ``text`` is required; ``temperature`` is in (0, 1.5] and ``top_p`` in (0, 1] when given; a
  field left out or null takes the settled default (0.6 and 0.85).  There is no ``speaker``
  field: the voice is always the operator's own recordings.  Unknown fields are ignored.
* 200: the body is a WAV file (RIFF, 24000 Hz, mono, 16-bit PCM), ``Content-Type: audio/wav``.
* 400 ``{"detail": "text must not be empty"}`` for a text that is empty or only white space
  (checked before anything about the engine).
* 413 ``{"detail": "text is longer than N characters"}`` for a text over ``TTS_MAX_TEXT_CHARS`` (default
  200000; new: the old service had no bound) and for a body over 4 MiB.
* 422 ``{"detail": [{"type", "loc", "msg", "input"}, ...]}`` for a body that is not a JSON object
  of that shape (the shape FastAPI answered with).
* 504 ``{"detail": "synthesis exceeded N seconds"}`` when one job runs past ``TTS_JOB_TIMEOUT_S`` (default
  7200; 0 = no limit; new): the job is abandoned and the next one gets a freshly loaded engine.
* 503 ``{"detail": ...}`` when the engine cannot take the job (before: "model not loaded yet";
  now also a refused load: the power cap, the weights, the voice files).
* ``GET /health`` is 200 ``{"status": "ok", "model_loaded": bool, "refs": [path, ...]}``.

The one text rule the service owns: the literal upper-case token ``US`` is spoken as ``U.S.``
(the engine reads it as the pronoun otherwise).
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from typing import Any

SAMPLE_RATE = 24000
LANGUAGE = "en"
DEFAULT_TEMPERATURE = 0.6
DEFAULT_TOP_P = 0.85
MAX_TEMPERATURE = 1.5
MAX_TOP_P = 1.0
#: a whole episode's script is tens of KiB; nothing legitimate is near this
MAX_BODY_BYTES = 4 * 1024 * 1024
#: the longest text one request may carry, in characters (a whole episode script is tens of thousands)
DEFAULT_MAX_TEXT_CHARS = 200_000

# Raw "US" (the country) is a homograph of the pronoun "us"; matched on the literal upper-case
# token only (word boundary), so the pronoun is never touched.
_US_ABBREV_RE = re.compile(r"\bUS\b")


def normalize_for_speech(text: str) -> str:
    """Text fixes for known mispronunciations; additive only (changes how a token is spoken)."""
    return _US_ABBREV_RE.sub("U.S.", text)


class ApiError(Exception):
    """An answer other than 200: the status and the JSON body."""

    def __init__(self, status: int, body: dict[str, Any]) -> None:
        super().__init__(f"{status} {body}")
        self.status = status
        self.body = body


def detail(status: int, message: str) -> ApiError:
    return ApiError(status, {"detail": message})


@dataclass(frozen=True)
class SynthesizeRequest:
    text: str
    temperature: float
    top_p: float


def _problem(loc: str, kind: str, msg: str, value: Any) -> dict[str, Any]:
    return {"type": kind, "loc": ["body", loc] if loc else ["body"], "msg": msg, "input": value}


def _number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def parse_synthesize(
    body: bytes, max_text_chars: int = DEFAULT_MAX_TEXT_CHARS
) -> SynthesizeRequest:
    """Validate a request body; raises :class:`ApiError` (422, or 400 for an empty text)."""
    try:
        doc = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise ApiError(
            422, {"detail": [_problem("", "json_invalid", "JSON decode error", None)]}
        ) from None
    if not isinstance(doc, dict):
        raise ApiError(
            422,
            {
                "detail": [
                    _problem("", "model_attributes_type", "Input should be a JSON object", doc)
                ]
            },
        )
    problems: list[dict[str, Any]] = []
    text = doc.get("text")
    if "text" not in doc:
        problems.append(_problem("text", "missing", "Field required", None))
    elif not isinstance(text, str):
        problems.append(_problem("text", "string_type", "Input should be a valid string", text))
    values: dict[str, float] = {}
    for field, default, upper in (
        ("temperature", DEFAULT_TEMPERATURE, MAX_TEMPERATURE),
        ("top_p", DEFAULT_TOP_P, MAX_TOP_P),
    ):
        raw = doc.get(field)
        if raw is None:
            values[field] = default
        elif not _number(raw):
            problems.append(_problem(field, "float_type", "Input should be a valid number", raw))
        elif raw <= 0.0:
            problems.append(_problem(field, "greater_than", "Input should be greater than 0", raw))
        elif raw > upper:
            problems.append(
                _problem(
                    field, "less_than_equal", f"Input should be less than or equal to {upper}", raw
                )
            )
        else:
            values[field] = float(raw)
    if problems:
        raise ApiError(422, {"detail": problems})
    assert isinstance(text, str)
    if not text.strip():
        raise detail(400, "text must not be empty")
    if len(text) > max_text_chars:
        raise detail(413, f"text is longer than {max_text_chars} characters")
    return SynthesizeRequest(text, values["temperature"], values["top_p"])
