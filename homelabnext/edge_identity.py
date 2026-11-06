# SPDX-License-Identifier: Apache-2.0
"""The identity headers the edge's forward auth hands a service: the one declaration (ADR-0034).

Single sign-on for an app with no login of its own goes through the **auth proxy** (a registry
service with capability :data:`AUTH_PROXY_CAPABILITY`, the default an oauth2-proxy-style proxy
in front of the OIDC IdP): the edge asks it about every request (``forward_auth``), and on a yes
copies the identity it answers with onto the request.  The service trusts those headers, so
every consumer has to agree on exactly which names they are:

* the Caddy generator (:mod:`homelabnext.generators.builtin`) copies them and strips every
  client-sent copy first;
* ``tools/caddy_lint.py`` (F-23) refuses any config that lets a client set one;
* the status hub (:mod:`homelabnext.status.agents.auth`) reads the username and the groups.

They read :data:`IDENTITY_HEADERS` and nothing else.  The defaults are the names the reference
auth proxy (oauth2-proxy) sets with ``--set-xauthrequest``: ``X-Auth-Request-User``, ``-Groups``,
``-Email`` and ``-Preferred-Username``, all four copied (it also sends ``-Access-Token`` with
``--pass-access-token``, which is never copied but carries the mark, so it is stripped too).  It
sends one value per group, and Caddy joins a copied header's values with ``,``:
:attr:`IdentityHeaders.groups_separator`.

**A person's one name: the IdP's** :data:`USERNAME_CLAIM` **claim** (``preferred_username``).
The reference proxy fills ``X-Auth-Request-User`` with its *user-id* claim (``email`` by default,
or ``sub``: an address with ``@`` or an opaque id), so that header names nobody the platform's
allowlists list.  The person is :attr:`IdentityHeaders.username` (``-Preferred-Username``, the
proxy's copy of ``preferred_username``, sent only when the token holds the claim): the status
hub's private tier and its approver subject read it, and the SSH CA
(:mod:`homelabnext.sshca`) signs a principal from the same claim, so one person is one name on
the approver allowlist and on their SSH certificate.  The IdP must not let a user change it
(the generated realm sets ``editUsernameAllowed: false``).

**The mark.**  Every identity header carries :attr:`IdentityHeaders.mark` (``auth-request``).
The strip deletes, case-insensitively, every client-sent header whose name contains the mark in
any spelling, with ``-`` or ``_`` at each separator inside it: a CGI-style upstream (PHP-FPM,
WSGI ``environ``, Django ``META``) folds ``-`` and ``_`` alike, so ``X-Auth-Request-User``,
``X_Auth_Request_User`` and the mixed ``X-Auth_Request-User`` all become
``HTTP_X_AUTH_REQUEST_USER``.  Caddy's ``request_header -*x*`` deletes every header containing
``x`` in any case, so one delete per spelling of the mark (:meth:`IdentityHeaders.strip_patterns`:
``*auth-request*`` and ``*auth_request*``) covers every spelling of every identity header, the
ones never copied included.

A lab with another auth proxy changes this one declaration (and so every consumer at once); a
set is validated when it is built, so a header that does not carry its mark cannot be declared.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

#: the registry capability of the forward-auth proxy the edge asks about every request
AUTH_PROXY_CAPABILITY = "auth-proxy"
#: the auth proxy's endpoints: the check ``forward_auth`` asks (2xx: signed in, 401: not), the
#: sign-in page a 401 is sent to, and the path prefix the edge proxies to it on every site
AUTH_PROXY_CHECK = "/oauth2/auth"
AUTH_PROXY_SIGN_IN = "/oauth2/sign_in"
AUTH_PROXY_PREFIX = "/oauth2/*"
#: the IdP claim that names a person to the platform: the status hub's identity and approver
#: subject (through :attr:`IdentityHeaders.username`) and the SSH CA's principal
USERNAME_CLAIM = "preferred_username"
#: where the IdP sends a signed-in user back to the auth proxy (each guarded site's own host)
AUTH_PROXY_CALLBACK = "/oauth2/callback"

_HEADER = re.compile(r"^[A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)*$")
_MARK = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


def fold(name: str) -> str:
    """A header name as a CGI-style upstream compares it: lower case, ``_`` read as ``-``."""
    return name.lower().replace("_", "-")


@dataclass(frozen=True)
class IdentityHeaders:
    """One declared identity-header set (see the module docstring): ``user`` is the auth proxy's
    user-id claim, ``username`` its copy of :data:`USERNAME_CLAIM` (the name the platform knows a
    person by)."""

    user: str
    groups: str
    email: str
    username: str
    mark: str
    groups_separator: str = ","

    def __post_init__(self) -> None:
        if not _MARK.fullmatch(self.mark):
            raise ValueError(f"identity mark {self.mark!r}: lower-case words joined by '-'")
        for h in self.headers:
            if not _HEADER.fullmatch(h):
                raise ValueError(f"identity header {h!r}: letters and digits joined by '-'")
            if not self.carries_mark(h):
                raise ValueError(f"identity header {h} does not carry the mark {self.mark!r}")
        if len({fold(h) for h in self.headers}) != len(self.headers):
            raise ValueError("identity headers must be distinct")
        if len(self.groups_separator) != 1 or self.groups_separator.isalnum():
            raise ValueError("the groups separator is one punctuation character")

    @property
    def headers(self) -> tuple[str, str, str, str]:
        """The headers ``forward_auth`` copies from the auth proxy's answer, in order."""
        return (self.user, self.groups, self.email, self.username)

    def carries_mark(self, name: str) -> bool:
        """Whether a header (or ``HTTP_<header>`` variable) name carries the mark, in any case
        and with ``-`` or ``_`` at any separator."""
        return fold(self.mark) in fold(name)

    def mark_spellings(self) -> tuple[str, ...]:
        """Every spelling of the mark with ``-`` or ``_`` at each separator, lower case."""
        parts = self.mark.split("-")
        out = [parts[0]]
        for part in parts[1:]:
            out = [f"{o}{sep}{part}" for o in out for sep in "-_"]
        return tuple(out)

    def strip_patterns(self) -> tuple[str, ...]:
        """The ``request_header -<pattern>`` deletes that remove every client-sent identity
        header in every spelling: one contains-wildcard per spelling of the mark."""
        return tuple(f"*{s}*" for s in self.mark_spellings())

    def strip_lines(self, indent: str = "") -> str:
        """The strip as Caddyfile lines, each ending in a newline."""
        return "".join(f"{indent}request_header -{p}\n" for p in self.strip_patterns())


#: the platform's identity-header set: every consumer reads this one
IDENTITY_HEADERS = IdentityHeaders(
    user="X-Auth-Request-User",
    groups="X-Auth-Request-Groups",
    email="X-Auth-Request-Email",
    username="X-Auth-Request-Preferred-Username",
    mark="auth-request",
)
