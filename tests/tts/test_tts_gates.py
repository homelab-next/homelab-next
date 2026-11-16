# SPDX-License-Identifier: Apache-2.0
"""The two gates every load passes: the card's power cap and the weights' bytes."""

from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from homelabnext.tts_service import gates as g


def smi(stdout: str = "200.00\n", rc: int = 0, raises: Exception | None = None):
    calls: list[list[str]] = []

    def run(cmd, **kw):
        calls.append(cmd)
        if raises:
            raise raises
        return SimpleNamespace(returncode=rc, stdout=stdout, stderr="")

    run.calls = calls  # type: ignore[attr-defined]
    return run


# --- power -----------------------------------------------------------------------------------


def test_the_cpu_backend_has_no_card_and_passes_without_asking():
    run = smi()
    assert g.check_power_cap("cpu", 200, 0, run)["backend"] == "cpu"
    assert run.calls == []


@pytest.mark.parametrize("reported", ["150.00", "200", "200.00", " 199.5 \n"])
def test_a_cap_at_or_under_the_limit_passes(reported):
    out = g.check_power_cap("cuda", 200, 1, smi(reported))
    assert out["watts"] <= 200 and out["limit_watts"] == 200


def test_the_card_asked_about_is_the_one_configured():
    run = smi("150")
    g.check_power_cap("cuda", 200, 3, run)
    assert run.calls == [
        ["nvidia-smi", "-i", "3", "--query-gpu=power.limit", "--format=csv,noheader,nounits"]
    ]


@pytest.mark.parametrize("reported", ["200.01", "250.00", "300"])
def test_a_cap_above_the_limit_refuses(reported):
    with pytest.raises(g.Refusal, match="above the 200 W limit"):
        g.check_power_cap("cuda", 200, 0, smi(reported))


def test_a_lower_configured_limit_is_enforced():
    with pytest.raises(g.Refusal, match="above the 180 W limit"):
        g.check_power_cap("cuda", 180, 0, smi("200"))


@pytest.mark.parametrize("reported", ["0", "0.00", "-5", "[N/A]", "", "Not Supported"])
def test_no_cap_set_or_unreadable_refuses(reported):
    with pytest.raises(g.Refusal):
        g.check_power_cap("cuda", 200, 0, smi(reported))


def test_a_failing_or_missing_tool_refuses():
    with pytest.raises(g.Refusal, match="cannot read"):
        g.check_power_cap("cuda", 200, 0, smi("", rc=9))
    with pytest.raises(g.Refusal, match="cannot run"):
        g.check_power_cap("cuda", 200, 0, smi(raises=FileNotFoundError("nvidia-smi")))


@pytest.mark.parametrize("limit", [0, -1, 201, 1000])
def test_the_limit_itself_can_only_tighten_the_rule(limit):
    with pytest.raises(g.Refusal, match=r"outside 1\.\.200"):
        g.check_power_cap("cuda", limit, 0, smi("100"))


def test_an_unknown_backend_refuses():
    with pytest.raises(g.Refusal, match="unknown backend"):
        g.check_power_cap("vulkan", 200, 0, smi())


# --- weights ---------------------------------------------------------------------------------


def make_store(tmp: Path, files: dict[str, bytes] | None = None):
    files = files or {n: f"bytes of {n}".encode() for n in g.REQUIRED_MODEL_FILES}
    model = tmp / "model"
    model.mkdir()
    lines = []
    for name, data in sorted(files.items()):
        (model / name).write_bytes(data)
        lines.append(f"{hashlib.sha256(data).hexdigest()}  {name}\n")
    listing = tmp / "listing.sha256"
    listing.write_text("".join(lines))
    digest = "sha256:" + hashlib.sha256(listing.read_bytes()).hexdigest()
    return model, listing, digest


def test_pinned_listing_and_matching_bytes_pass(tmp_path):
    model, listing, digest = make_store(tmp_path)
    g.WeightsGate(model, listing, digest).verify()


def test_a_listing_that_is_not_the_pinned_one_refuses(tmp_path):
    model, listing, _ = make_store(tmp_path)
    with pytest.raises(g.Refusal, match="the pin is"):
        g.WeightsGate(model, listing, "sha256:" + "0" * 64).verify()


def test_one_changed_byte_in_a_weights_file_refuses(tmp_path):
    model, listing, digest = make_store(tmp_path)
    (model / "model.pth").write_bytes(b"bytes of model.pth!")
    with pytest.raises(g.Refusal, match=r"model\.pth is sha256:"):
        g.WeightsGate(model, listing, digest).verify()


def test_a_missing_file_refuses(tmp_path):
    model, listing, digest = make_store(tmp_path)
    (model / "dvae.pth").unlink()
    with pytest.raises(g.Refusal, match=r"dvae\.pth is not in the model directory"):
        g.WeightsGate(model, listing, digest).verify()


def test_a_listing_that_lacks_a_file_the_engine_loads_refuses(tmp_path):
    files = {n: b"x" for n in g.REQUIRED_MODEL_FILES if n != "vocab.json"}
    model, listing, digest = make_store(tmp_path, files)
    with pytest.raises(g.Refusal, match=r"does not name vocab\.json"):
        g.WeightsGate(model, listing, digest).verify()


@pytest.mark.parametrize(
    "line", ["nonsense", "abc  model.pth", f"{'a' * 64}  ../escape", f"{'a' * 64} model.pth"]
)
def test_a_malformed_listing_refuses(tmp_path, line):
    model, listing, _ = make_store(tmp_path)
    listing.write_text(line + "\n")
    digest = "sha256:" + hashlib.sha256(listing.read_bytes()).hexdigest()
    with pytest.raises(g.Refusal, match="listing line 1"):
        g.WeightsGate(model, listing, digest).check_listing()


def test_an_empty_listing_refuses(tmp_path):
    model, listing, _ = make_store(tmp_path)
    listing.write_text("")
    digest = "sha256:" + hashlib.sha256(b"").hexdigest()
    with pytest.raises(g.Refusal, match="names no file"):
        g.WeightsGate(model, listing, digest).check_listing()


def test_an_unreadable_listing_refuses(tmp_path):
    model, _, digest = make_store(tmp_path)
    with pytest.raises(g.Refusal, match="cannot be read"):
        g.WeightsGate(model, tmp_path / "nope", digest).check_listing()


def test_a_bad_pinned_digest_is_refused_at_construction(tmp_path):
    model, listing, _ = make_store(tmp_path)
    with pytest.raises(g.Refusal, match="not sha256"):
        g.WeightsGate(model, listing, "sha256:short")


def test_a_hashed_file_is_not_read_again_until_it_changes(tmp_path, monkeypatch):
    model, listing, digest = make_store(tmp_path)
    gate = g.WeightsGate(model, listing, digest)
    reads: list[str] = []
    real = g.sha256_file
    monkeypatch.setattr(g, "sha256_file", lambda p: (reads.append(p.name), real(p))[1])
    gate.verify()
    first = len(reads)
    assert first == len(g.REQUIRED_MODEL_FILES)
    gate.verify()
    assert len(reads) == first  # unchanged size and mtime: not hashed again
    # a changed file (same size, new mtime) is hashed again and refused
    p = model / "config.json"
    p.write_bytes(b"x" * p.stat().st_size)
    import os

    os.utime(p, ns=(p.stat().st_mtime_ns + 10**9,) * 2)
    with pytest.raises(g.Refusal, match=r"config\.json is sha256:"):
        gate.verify()
    assert reads[-1:] == ["config.json"]


# --- readiness ----------------------------------------------------------------------------------


def test_readiness_reports_every_gate_without_loading_anything(tmp_path):
    model, listing, digest = make_store(tmp_path)
    refs = {n: tmp_path / n for n in ("ref1.wav", "ref2.wav")}
    for p in refs.values():
        p.write_bytes(b"RIFF")
    out = g.readiness(g.WeightsGate(model, listing, digest), refs, "cpu", 200, 0)
    assert out["ready"] is True and set(out["checks"]) == {
        "voice_refs",
        "weights_listing",
        "power_cap",
    }


def test_readiness_names_a_missing_voice_file_and_a_hot_card(tmp_path):
    model, listing, digest = make_store(tmp_path)
    refs = {"ref1.wav": tmp_path / "ref1.wav"}
    out = g.readiness(g.WeightsGate(model, listing, digest), refs, "cuda", 200, 0, smi("300"))
    assert out["ready"] is False
    assert "ref1.wav" in out["checks"]["voice_refs"]["detail"]
    assert "above the 200 W limit" in out["checks"]["power_cap"]["detail"]
    assert out["checks"]["weights_listing"]["ok"] is True
