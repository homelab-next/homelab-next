# SPDX-License-Identifier: Apache-2.0
"""The manifest schema describes refusal_limit for the peers the socket server applies it to."""

import json

from homelabnext import paths
from homelabnext.broker import server

SCHEMA = json.loads(paths.schema_file("broker", "manifest.schema.json").read_text("utf-8"))
WORDS = {10: "ten"}


def _texts() -> list[str]:
    top = SCHEMA["description"]
    return [
        top[top.index("1.4 adds") : top.index("1.5 adds")],
        SCHEMA["properties"]["refusal_limit"]["description"],
    ]


def test_both_descriptions_name_the_peers_the_limit_applies_to_and_exempts():
    factor = WORDS.get(server.UNKNOWN_TOKEN_FACTOR, str(server.UNKNOWN_TOKEN_FACTOR))
    for text in _texts():
        for peer in ("a caller", "an operator", "an unknown peer"):
            assert peer in text or peer.split()[-1] + "s" in text, (peer, text)
        assert "approval relays and the Code Mode runner are exempt" in text, text
        assert "per presented token" in text, text
        assert f"{factor} times" in text, text
