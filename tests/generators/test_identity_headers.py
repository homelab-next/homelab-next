# SPDX-License-Identifier: Apache-2.0
"""homelabnext.edge_identity: the one identity-header declaration (ADR-0034)."""

import pytest

from homelabnext.edge_identity import IDENTITY_HEADERS, IdentityHeaders, fold


def test_the_platform_set_is_the_auth_proxys():
    assert IDENTITY_HEADERS.headers == (
        "X-Auth-Request-User", "X-Auth-Request-Groups", "X-Auth-Request-Email",
        "X-Auth-Request-Preferred-Username",
    )  # fmt: skip
    # the person's name is the IdP's preferred_username, as the reference proxy copies it
    assert IDENTITY_HEADERS.username == "X-Auth-Request-Preferred-Username"
    assert IDENTITY_HEADERS.groups_separator == ","
    assert IDENTITY_HEADERS.strip_patterns() == ("*auth-request*", "*auth_request*")


@pytest.mark.parametrize(
    "name",
    ["X-Auth-Request-User", "x_auth_request_groups", "X-AUTH_REQUEST-Preferred-Username",
     "HTTP_X_AUTH_REQUEST_EMAIL"],
)  # fmt: skip
def test_the_mark_is_read_in_every_case_and_spelling(name):
    assert IDENTITY_HEADERS.carries_mark(name)


@pytest.mark.parametrize("name", ["X-Request-Id", "Authorization", "X-Auth-Token", "X-Authrequest"])
def test_a_name_without_the_mark_is_not_an_identity_header(name):
    assert not IDENTITY_HEADERS.carries_mark(name)


def test_every_spelling_of_a_three_word_mark():
    s = IdentityHeaders(
        "X-A-B-C-User", "X-A-B-C-Groups", "X-A-B-C-Email", "X-A-B-C-Name", mark="a-b-c"
    )
    assert set(s.mark_spellings()) == {"a-b-c", "a-b_c", "a_b-c", "a_b_c"}
    assert s.strip_lines("\t") == "".join(f"\trequest_header -*{p}*\n" for p in s.mark_spellings())


@pytest.mark.parametrize(
    "kwargs, match",
    [
        ({"user": "X-Remote-User"}, "does not carry the mark"),
        ({"mark": "Auth_Request"}, "lower-case words"),
        ({"email": "X-Auth-Request-User"}, "distinct"),
        ({"groups": "X-Auth-Request-Groups\n"}, "letters and digits"),
        ({"groups_separator": "a"}, "punctuation"),
    ],
)
def test_a_bad_declaration_is_refused(kwargs, match):
    base = {"user": "X-Auth-Request-User", "groups": "X-Auth-Request-Groups",
            "email": "X-Auth-Request-Email",
            "username": "X-Auth-Request-Preferred-Username", "mark": "auth-request"}  # fmt: skip
    with pytest.raises(ValueError, match=match):
        IdentityHeaders(**{**base, **kwargs})


def test_fold():
    assert fold("X_Auth-Request_User") == "x-auth-request-user"
