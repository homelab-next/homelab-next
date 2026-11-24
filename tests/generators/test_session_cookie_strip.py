"""The edge's session-cookie deletion must leave a Cookie header a strict parser accepts."""

import re

import pytest

from homelabnext.generators.builtin import SESSION_COOKIE_FIND, SESSION_COOKIE_LEAD


def _strip(header: str) -> str:
    """Apply the two generated ``request_header Cookie`` directives in order (Caddy runs them so)."""
    header = re.sub(SESSION_COOKIE_FIND, "", header)
    return re.sub(SESSION_COOKIE_LEAD, "", header)


@pytest.mark.parametrize(
    ("sent", "kept"),
    [
        ("sec=A; __Host-hnx_auth=X", "sec=A"),
        ("__Host-hnx_auth=X; sec=A", "sec=A"),
        ("a=1; __Host-hnx_auth_0=X; sec=A; __Host-hnx_auth_1=Y", "a=1; sec=A"),
        ("__Host-hnx_auth_0=X; __Host-hnx_auth_1=Y; b=2", "b=2"),
        ("__Host-HNX_AUTH=X; b=2", "b=2"),
        ("__Host-hnx_auth=X", ""),
        ("a=1", "a=1"),
    ],
)
def test_strip_leaves_a_well_formed_header(sent, kept):
    out = _strip(sent)
    assert out == kept
    assert not out.startswith(";") and ";;" not in out.replace(" ", "")
