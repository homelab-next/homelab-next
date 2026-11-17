# SPDX-License-Identifier: Apache-2.0
"""The trusted-checkpoint load window of the real engine, against stand-in torch modules (the real
ones are 2 GB; the container run in modules/tts/README.md covers them): while the model loads the
library may read the original-format checkpoint but must never write it (the weights are the model
store's, read-only, pinned by sha256), and everything is put back afterwards."""

from __future__ import annotations

import sys
import types

from homelabnext.tts_service import engine


def fake_modules(monkeypatch):
    torch = types.ModuleType("torch")
    saved: list = []
    torch.load = lambda *a, **k: ("loaded", k)
    torch.save = lambda *a, **k: saved.append(a)
    torch.from_numpy = lambda x: x
    audio = types.ModuleType("torchaudio")
    audio.load = lambda *a, **k: "decoder dropped by the library"
    sound = types.ModuleType("soundfile")
    for name, mod in (("torch", torch), ("torchaudio", audio), ("soundfile", sound)):
        monkeypatch.setitem(sys.modules, name, mod)
    return torch, audio, saved


def test_the_library_may_read_the_checkpoint_but_never_write_it(monkeypatch):
    torch, _audio, saved = fake_modules(monkeypatch)
    original_load, original_save = torch.load, torch.save
    with engine._trusted_checkpoint_loading(torch):
        assert torch.load("model.pth")[1]["weights_only"] is False  # the pickle may be read
        assert torch.load("model.pth", weights_only=True)[1]["weights_only"] is True  # as asked
        torch.save({"config": {}}, "model.pth")  # the library's in-place conversion
    assert saved == []  # nothing was written
    assert torch.load is original_load and torch.save is original_save  # put back
    torch.save("later", "latents.pt")
    assert saved == [("later", "latents.pt")]  # the embeddings cache can write afterwards


def test_the_load_window_is_closed_even_when_the_load_fails(monkeypatch):
    torch, _audio, _ = fake_modules(monkeypatch)
    original_load, original_save = torch.load, torch.save
    try:
        with engine._trusted_checkpoint_loading(torch):
            raise RuntimeError("out of memory")
    except RuntimeError:
        pass
    assert torch.load is original_load and torch.save is original_save
