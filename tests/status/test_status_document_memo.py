# SPDX-License-Identifier: Apache-2.0
"""The served document is built once per change of its inputs, not once per request: a burst of
cheap requests must not each load every activity event (the hub is the one network-facing
server), and a write, a retention purge or the clock leaving its window must rebuild it."""

from __future__ import annotations

import os

import pytest

from homelabnext.status.serve import DOCUMENT_BUCKET_S, DocumentMemo


class Clock:
    def __init__(self) -> None:
        self.t = 1_700_000_000.0

    def __call__(self) -> float:
        return self.t


def _memo(tmp_path, clock):
    state = tmp_path / "state.json"
    state.write_text("{}")
    builds: list[int] = []

    def build():
        builds.append(1)
        return {"n": len(builds), "items": [{"id": "a"}]}

    return DocumentMemo(build, lambda: [state, tmp_path / "store.db-wal"], clock), state, builds


def test_unchanged_inputs_reuse_one_build(tmp_path):
    clock = Clock()
    memo, _, builds = _memo(tmp_path, clock)
    docs = [memo() for _ in range(20)]
    assert len(builds) == 1 and memo.builds == 1
    assert all(d == docs[0] for d in docs)


def test_a_changed_input_file_rebuilds(tmp_path):
    clock = Clock()
    memo, state, builds = _memo(tmp_path, clock)
    memo()
    state.write_text('{"changed": true}')
    assert memo()["n"] == 2
    (tmp_path / "store.db-wal").write_bytes(b"x")  # a write (or a purge) appears
    assert memo()["n"] == 3
    os.unlink(tmp_path / "store.db-wal")  # a checkpoint removed it
    assert memo()["n"] == 4 and len(builds) == 4


def test_the_clock_leaving_its_window_rebuilds(tmp_path):
    clock = Clock()
    clock.t = (clock.t // DOCUMENT_BUCKET_S) * DOCUMENT_BUCKET_S  # the start of a window
    memo, _, builds = _memo(tmp_path, clock)
    memo()
    clock.t += DOCUMENT_BUCKET_S - 1
    memo()
    assert len(builds) == 1
    clock.t += 1
    memo()
    assert len(builds) == 2


def test_each_caller_gets_its_own_copy(tmp_path):
    memo, _, _ = _memo(tmp_path, Clock())
    first = memo()
    first["items"].append({"id": "injected"})
    assert memo()["items"] == [{"id": "a"}]


def test_a_bucket_must_be_positive(tmp_path):
    with pytest.raises(ValueError):
        DocumentMemo(dict, list, Clock(), bucket_s=0)


def test_serve_builds_its_document_through_the_memo(tmp_path, monkeypatch):
    from pathlib import Path

    from homelabnext.status import cli, serve

    root = Path(__file__).resolve().parents[2]
    seen = {}

    def capture(document, **kw):
        seen["document"] = document
        raise ValueError("captured")  # stop before binding: main() answers 2

    monkeypatch.setattr(serve, "make_server", capture)
    rc = cli.main(
        [
            "serve",
            "--registry",
            str(root / "examples" / "services.yml"),
            "--views",
            str(root / "examples" / "status" / "views.yml"),
            "--state",
            str(tmp_path / "state.json"),
        ]
    )
    assert rc == 2 and isinstance(seen["document"], DocumentMemo)
    first = seen["document"]()
    assert seen["document"]() == first and seen["document"].builds == 1
