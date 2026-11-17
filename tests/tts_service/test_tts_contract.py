# SPDX-License-Identifier: Apache-2.0
"""The ``/synthesize`` contract of the old cloned-voice service, pinned (homelabnext/tts_service).

Each case is a fact read from the archived service: the old module's own tests (the text
normalisation) ported verbatim, and its request model, defaults and answers as the cases below.
"""

from __future__ import annotations

import json

import pytest

from homelabnext.tts_service import contract as c


def body(**doc) -> bytes:
    return json.dumps(doc).encode()


# --- the text rule the old service's own tests pinned ------------------------------------------


def test_us_abbreviation_is_spoken_dotted():
    assert c.normalize_for_speech("The US government warned about this.") == (
        "The U.S. government warned about this."
    )


def test_the_pronoun_us_is_left_alone():
    assert c.normalize_for_speech("Trust us to get this right.") == "Trust us to get this right."


def test_a_word_that_contains_us_is_left_alone():
    assert c.normalize_for_speech("USB drives were found on site.") == (
        "USB drives were found on site."
    )


def test_an_already_dotted_form_is_unchanged():
    assert c.normalize_for_speech("The U.S. government responded.") == (
        "The U.S. government responded."
    )


def test_several_occurrences_and_both_ends_of_the_string():
    assert c.normalize_for_speech("US officials briefed US allies.") == (
        "U.S. officials briefed U.S. allies."
    )
    assert c.normalize_for_speech("US") == "U.S."
    assert c.normalize_for_speech("Reported by the US") == "Reported by the U.S."


# --- the request ---------------------------------------------------------------------------------


def test_defaults_are_the_settled_sampling_values():
    r = c.parse_synthesize(body(text="Hello there."))
    assert (r.text, r.temperature, r.top_p) == ("Hello there.", 0.6, 0.85)
    assert (c.DEFAULT_TEMPERATURE, c.DEFAULT_TOP_P, c.SAMPLE_RATE, c.LANGUAGE) == (
        0.6,
        0.85,
        24000,
        "en",
    )


def test_null_sampling_values_take_the_defaults():
    r = c.parse_synthesize(body(text="x", temperature=None, top_p=None))
    assert (r.temperature, r.top_p) == (0.6, 0.85)


def test_the_callers_sampling_values_are_used_as_sent():
    """What cti-agent sends with every call (TTS_SAMPLING)."""
    r = c.parse_synthesize(body(text="x", temperature=0.6, top_p=0.85))
    assert (r.temperature, r.top_p) == (0.6, 0.85)
    r = c.parse_synthesize(body(text="x", temperature=1, top_p=1))
    assert (r.temperature, r.top_p) == (1.0, 1.0)


def test_the_text_is_not_trimmed_or_rewritten_by_parsing():
    assert c.parse_synthesize(body(text="  US  ")).text == "  US  "


@pytest.mark.parametrize("text", ["", " ", "\n\t  \n"])
def test_an_empty_text_is_a_400_with_the_old_detail(text):
    with pytest.raises(c.ApiError) as e:
        c.parse_synthesize(body(text=text))
    assert e.value.status == 400 and e.value.body == {"detail": "text must not be empty"}


def test_there_is_no_speaker_field_and_unknown_fields_are_ignored():
    r = c.parse_synthesize(body(text="x", speaker="Craig Gutsy", speaker_wav="/etc/passwd", x=1))
    assert r.text == "x" and not hasattr(r, "speaker") and not hasattr(r, "speaker_wav")


@pytest.mark.parametrize(
    ("doc", "loc"),
    [
        ({}, "text"),
        ({"text": 7}, "text"),
        ({"text": None}, "text"),
        ({"text": "x", "temperature": 0}, "temperature"),
        ({"text": "x", "temperature": -0.1}, "temperature"),
        ({"text": "x", "temperature": 1.5001}, "temperature"),
        ({"text": "x", "temperature": "0.5"}, "temperature"),
        ({"text": "x", "temperature": True}, "temperature"),
        ({"text": "x", "top_p": 0}, "top_p"),
        ({"text": "x", "top_p": 1.01}, "top_p"),
    ],
)
def test_an_invalid_field_is_a_422_naming_it(doc, loc):
    with pytest.raises(c.ApiError) as e:
        c.parse_synthesize(body(**doc))
    assert e.value.status == 422
    problems = e.value.body["detail"]
    assert isinstance(problems, list) and problems[0]["loc"] == ["body", loc]
    assert {"type", "loc", "msg", "input"} <= set(problems[0])


def test_the_upper_bounds_are_inclusive():
    r = c.parse_synthesize(body(text="x", temperature=1.5, top_p=1.0))
    assert (r.temperature, r.top_p) == (1.5, 1.0)


@pytest.mark.parametrize(
    "raw", [b"", b"not json", b"\xff\xfe", b"[1, 2]", b'"text"', b"null", b"7"]
)
def test_a_body_that_is_not_a_json_object_is_a_422(raw):
    with pytest.raises(c.ApiError) as e:
        c.parse_synthesize(raw)
    assert e.value.status == 422 and isinstance(e.value.body["detail"], list)


def test_every_problem_is_reported_not_only_the_first():
    with pytest.raises(c.ApiError) as e:
        c.parse_synthesize(body(temperature=0, top_p=2))
    assert [p["loc"][1] for p in e.value.body["detail"]] == ["text", "temperature", "top_p"]


def test_a_text_over_the_limit_is_a_413_and_one_at_the_limit_passes():
    assert c.parse_synthesize(body(text="x" * 50), 50).text == "x" * 50
    with pytest.raises(c.ApiError) as e:
        c.parse_synthesize(body(text="x" * 51), 50)
    assert e.value.status == 413 and e.value.body == {"detail": "text is longer than 50 characters"}


def test_the_default_limit_is_two_hundred_thousand_characters():
    assert c.DEFAULT_MAX_TEXT_CHARS == 200_000
    assert c.parse_synthesize(body(text="a" * 200_000)).text
    with pytest.raises(c.ApiError) as e:
        c.parse_synthesize(body(text="a" * 200_001))
    assert e.value.status == 413


def test_the_length_is_checked_after_the_shape_and_emptiness():
    with pytest.raises(c.ApiError) as e:
        c.parse_synthesize(body(text="  "), 1)
    assert e.value.status == 400
