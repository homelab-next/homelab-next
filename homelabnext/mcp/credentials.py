# SPDX-License-Identifier: Apache-2.0
"""What counts as a literal credential in a stdio server's arguments and settings (ADR-0024).

One module for both directions, so they cannot drift apart: ``hnx mcp catalog check`` refuses a
record whose arguments or settings carry what :func:`scan_args` and :func:`setting_problem`
find, and ``hnx mcp catalog import`` replaces exactly those (and, failing closed, more) by
``secret:`` references.  ``tests/mcp/test_mcp_credentials.py`` holds both lists: shapes that must
be found (by check and stripped by import) and shapes that must be accepted (by check and kept by
import).

* a **credential name** (a flag or a key) has a credential word (``token``, ``key``,
  ``password``, ``secret``, ``auth``, ``cookie`` ...) in any spelling (``--github-token``,
  ``--githubToken``, ``GITHUB_TOKEN``), unless it is a switch (``--no-auth``) or its last word
  says the value is about the credential, not the credential (``--token-file``,
  ``--secret-name``, ``--session-timeout``, ``KEY_PATH``);
* a **value** follows a flag unless it is another flag or a path (``--key /etc/ssl/k.pem``), and
  ``--auth`` takes a method name (``--auth oauth``) without it being a credential; the short
  ``-p`` (a password unless it is a port), ``-u`` (``user:password``) and ``-k`` are read too;
* a value **looks like a token** when it has a token prefix (``ghp_``, ``glpat-``, ``xoxb-``,
  ``sk-``, ``AKIA`` ...), carries a URL password, or is long, mixes letters and digits and has
  high entropy; ``/`` separated base64 (an AWS-style secret key) counts, a path does not; an
  identifier made of plain words and numbers (``claude-3-5-sonnet-20241022``,
  ``gpt-4o-mini-2024-07-18``), a ULID or UUID, a package spec and an image digest do not;
* a **URL** carries one in its userinfo, a credential-named query parameter, or a path segment or
  query value that looks like a token (a webhook);
* an **argument** also carries one in a JSON object with a credential-named key, in a container
  runner's ``-e KEY=VALUE`` whose setting would be refused, and in a shell line (``sh -c``) whose
  own words would be found.
"""

from __future__ import annotations

import json
import math
import re
import shlex
from collections.abc import Iterable
from dataclasses import dataclass
from urllib.parse import parse_qsl, unquote, urlsplit

from . import launch

#: a key or flag that names a credential (substring: ``GITHUBTOKEN``, ``DB_PASSWORD``)
SECRET_KEY = re.compile(r"TOKEN|SECRET|PASSW|API_?KEY|PRIVATE|CREDENTIAL|COOKIE|SESSION", re.I)
#: credential words, one word of a flag or key
CREDENTIAL_WORDS = frozenset(
    (
        "token", "tokens", "key", "keys", "apikey", "password", "passwd", "pass", "pwd", "passphrase",
        "secret", "secrets", "auth", "bearer", "credential", "credentials", "pat", "cookie",
        "cookies", "session",
    )
)  # fmt: skip
#: a last word that makes the name about a credential, not one (its value is a path, a name ...)
ABOUT_WORDS = frozenset(
    (
        "file", "files", "path", "dir", "directory", "env", "var", "name", "timeout", "ttl", "url",
        "uri", "endpoint", "host", "port", "type", "mode", "method", "scheme", "provider", "header",
        "prefix", "length", "size", "format", "id", "count", "limit", "expiry", "lifetime", "store",
        "source", "version", "algorithm",
    )
)  # fmt: skip
PATH_WORDS = frozenset(("file", "files", "path", "dir", "directory"))
#: method names ``--auth`` (and ``--auth-type`` ...) take; never a credential
AUTH_METHODS = frozenset(
    (
        "none", "no", "off", "oauth", "oauth2", "oidc", "basic", "bearer", "token", "apikey",
        "api-key", "digest", "ntlm", "kerberos", "mtls", "jwt", "header", "env", "keychain",
        "anonymous", "iam", "sigv4",
    )
)  # fmt: skip
#: a flag whose next argument is an HTTP header (``Name: value``)
HEADER_FLAGS = ("--header", "-H")
#: a container runner's flags whose value is ``KEY=VALUE`` (or ``KEY``)
RUNNER_ENV_FLAGS = ("-e", "--env")
#: shells whose ``-c`` argument is a command line
SHELLS = ("sh", "bash", "zsh", "dash", "ksh", "fish", "busybox")
#: a package spec as a launcher takes it (``name==1.2.0``, ``@scope/name@1.2.0``): never a secret
PACKAGE_SPEC = re.compile(
    r"^(@[a-z0-9][a-z0-9._-]*/)?[A-Za-z0-9][A-Za-z0-9._-]*(==|@)v?[0-9][A-Za-z0-9._+-]*$"
)
SECRET_REF = re.compile(r"secret:[a-z][a-z0-9_-]*(?:/[a-z][a-z0-9_-]*)*")
#: ``Header-Name: [Scheme ]secret:<name>``, the argument after ``--header`` (mcp-remote and kin)
_HEADER_ARG = re.compile(r"^[A-Za-z][A-Za-z0-9-]*:\s*(?:[A-Za-z]+ )?(secret:\S+)$")
_TOKEN_PREFIX = re.compile(
    r"^(?:gh[pousr]_|github_pat_|glpat-|xox[abposr]-|sk-|sk_live_|rk_live_|AKIA|ASIA|AIza|ya29\."
    r"|npm_|pypi-|hf_|dop_v1_)[A-Za-z0-9_\-.]{12,}$"
)
_ULID = re.compile(r"^[0-9A-HJKMNP-TV-Z]{26}$")
_UUID = re.compile(r"^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
_DIGEST_REF = re.compile(r"^(?:[a-z0-9][a-z0-9._/:-]*@)?sha256:[0-9a-f]{64}$")
_URL_PASSWORD = re.compile(r"://[^/@\s:]+:[^/@\s]+@")
_B64_PATHLIKE = re.compile(r"^[A-Za-z0-9+/=]{30,}$")
#: ``$VAR``, ``${VAR}``, ``${VAR:-default}``, ``${VAR-default}`` as a whole value
VAR = re.compile(
    r"^\$(?:\{(?P<b>[A-Za-z_][A-Za-z0-9_]*)(?::?[-=?+][^}]*)?\}|(?P<n>[A-Za-z_][A-Za-z0-9_]*))$"
)


def words(name: str) -> list[str]:
    """The words of a flag or key: ``--githubToken`` and ``GITHUB_TOKEN`` are github, token."""
    n = name.lstrip("-")
    n = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", n)
    n = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", n)
    return [w for w in re.split(r"[-_.\s]+", n.lower()) if w]


def credential_name(name: str) -> bool:
    """A flag or key whose value is a credential (see the module docstring)."""
    ws = words(name)
    if not ws or ws[0] == "no" or ws[-1] in ABOUT_WORDS:
        return False
    return any(w in CREDENTIAL_WORDS for w in ws) or bool(SECRET_KEY.search(ws[-1]))


def about_a_credential_path(name: str) -> bool:
    """A key that names where a credential is (``TOKEN_FILE``, ``KEY_PATH``): its value must be a
    path, or it is the credential itself."""
    ws = words(name)
    return bool(ws) and ws[-1] in PATH_WORDS and any(w in CREDENTIAL_WORDS for w in ws[:-1])


def is_path(value: str) -> bool:
    return value.startswith(("/", "~/", "./", "../"))


def is_ref(value: str) -> bool:
    return bool(SECRET_REF.fullmatch(value))


def arg_secret(arg: str) -> str | None:
    """The secret ref an argument carries (``secret:x``, ``--flag=secret:x`` or
    ``Header: [Scheme ]secret:x``), else None."""
    m = _HEADER_ARG.match(arg)
    value = m.group(1) if m else arg.split("=", 1)[1] if arg.startswith("-") and "=" in arg else arg
    return value if SECRET_REF.fullmatch(value) else None


def _plain_words(value: str) -> bool:
    """An identifier of plain words and numbers (a model id, a dated name), not a token."""
    parts = [p for p in re.split(r"[-._:]+", value) if p]
    return len(parts) > 1 and all(p.isalpha() or p.isdigit() or len(p) < 8 for p in parts)


def _entropy(v: str) -> float:
    counts = {c: v.count(c) for c in set(v)}
    return -sum(n / len(v) * math.log2(n / len(v)) for n in counts.values())


def looks_secret(value: str) -> bool:
    """A value that is probably a credential (see the module docstring)."""
    if _URL_PASSWORD.search(value):
        return True
    v = value.strip()
    if _TOKEN_PREFIX.match(v):
        return True
    if len(v) < 20 or " " in v or v.startswith("$") or PACKAGE_SPEC.match(v):
        return False
    if _ULID.match(v) or _UUID.match(v) or _DIGEST_REF.match(v) or "://" in v:
        return False
    if not (re.search(r"[0-9]", v) and re.search(r"[A-Za-z]", v)):
        return False
    if "/" in v:  # a path is not a token; base64 with a / (an AWS-style secret key) is
        return (
            not is_path(v)
            and bool(_B64_PATHLIKE.match(v))
            and bool(re.search(r"[a-z]", v) and re.search(r"[A-Z]", v))
            and _entropy(v) >= 4.0
        )
    if _plain_words(v):
        return False
    return _entropy(v) >= 3.5


def url_carries(value: str) -> bool:
    """A URL with a credential in it: userinfo (a password, or a user that is not a plain account
    name), a credential-named query parameter, or a path segment or query value that looks like a
    token."""
    if "://" not in value:
        return False
    try:
        parts = urlsplit(value)
        user, password = parts.username, parts.password
    except ValueError:
        return True  # an unparseable URL: fail closed
    if password or (user and not re.fullmatch(r"[a-z][a-z._-]{0,31}", user)):
        return True
    for k, v in parse_qsl(parts.query, keep_blank_values=True) + parse_qsl(parts.fragment):
        if credential_name(k) or k.lower() in ("sig", "signature", "code") or looks_secret(v):
            return True
    segments = (re.sub(r"@[0-9a-f]{40}$", "", unquote(seg)) for seg in parts.path.split("/"))
    return any(looks_secret(seg) for seg in segments)  # (a git commit is not a token)


def json_carries(value: str) -> bool:
    """A JSON object (or list) with a credential-named key holding a literal."""
    if not value.lstrip().startswith(("{", "[")):
        return False
    try:
        doc = json.loads(value)
    except ValueError:
        return False

    def walk(x) -> bool:
        if isinstance(x, dict):
            return any(
                (credential_name(str(k)) and isinstance(v, str) and v and not is_ref(v)) or walk(v)
                for k, v in x.items()
            )
        return isinstance(x, list) and any(walk(i) for i in x)

    return walk(doc)


def carries(value: str) -> bool:
    """A value that is, or carries, a literal credential."""
    return looks_secret(value) or url_carries(value) or json_carries(value)


def setting_problem(key: str, value: str) -> str | None:
    """Why ``KEY=VALUE`` (a setting, a container's ``-e``) may not be a literal, or None."""
    if "$" in value or "secret:" in value:
        return "holds $ or secret:"
    if credential_name(key) and not is_path(value):
        return "names a credential"
    if about_a_credential_path(key) and not is_path(value):
        return "names a credential and its value is not a path"
    if carries(value):
        return "looks like a literal credential"
    return None


def flag_value_credential(flag: str, value: str) -> bool:
    """``flag`` (a credential name) given ``value``: a credential unless ``--auth`` names a method."""
    ws = words(flag)
    return not (ws and ws[-1] == "auth" and value.lower() in AUTH_METHODS)


def is_value(arg: str) -> bool:
    """An argument that can be the previous flag's value (not a flag, not a path)."""
    return bool(arg) and not arg.startswith("-") and not is_path(arg)


def _short_value_credential(flag: str, value: str) -> bool:
    if flag == "-p":  # a password, unless it is a port or host:port
        return not re.fullmatch(r"(?:[A-Za-z0-9.-]+:)?[0-9]{1,5}(?::[0-9]{1,5})?", value)
    if flag == "-u":  # user:password
        return ":" in value
    if flag == "-k":  # a key, unless a path or a URL (curl's -k is a switch)
        return "://" not in value
    return False


def _after_credential_flag(prev: str, value: str) -> bool:
    """``value`` is the credential ``prev`` takes (``--token X``, ``-p X``, ``-u user:pw``)."""
    if prev in ("-p", "-u", "-k"):
        return _short_value_credential(prev, value)
    return (
        len(prev) > 2
        and prev.startswith("-")
        and "=" not in prev
        and credential_name(prev)
        and flag_value_credential(prev, value)
    )


@dataclass(frozen=True)
class Finding:
    """One argument that carries a literal credential (or something a client would expand)."""

    index: int
    #: ``dollar`` (a ``$`` a client would expand), ``inline`` (``secret:`` inside a value),
    #: ``flag-value`` (``--token=X``), ``after-flag`` (``--token X``: the value), ``header``
    #: (``--header 'Authorization: ...'``), ``env`` (a runner's ``-e KEY=VALUE``), ``shell``
    #: (a ``-c`` line), ``value`` (a token, a URL or JSON carrying one)
    kind: str
    #: the flag concerned (``--token``, ``-e``), or ""
    flag: str = ""


def _shell_carries(line: str) -> bool:
    try:
        toks = shlex.split(line)
    except ValueError:
        return True  # an unparseable line: fail closed
    while toks and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", toks[0]):
        k, _, v = toks.pop(0).partition("=")
        if setting_problem(k, v):
            return True
    return bool(toks) and bool(scan_args(toks[0], toks[1:]))


def scan_args(command: str, args: Iterable[str]) -> list[Finding]:
    """Every argument of ``command args`` that carries a literal credential or a ``$``.  The
    launcher's own flags (:mod:`.launch`) are read as the launcher reads them (a runner's ``-e``,
    ``-p`` publish, ``-u`` user); the server's own arguments as above."""
    args = [str(a) for a in args]
    got = launch.parse(command, args)
    start = got.server_args if got.ecosystem in ("npm", "pypi", "image") else 0
    base = got.launcher
    out: list[Finding] = []
    for i, a in enumerate(args):
        if "$" in a:
            out.append(Finding(i, "dollar"))
            continue
        ref = arg_secret(a)
        if "secret:" in a and not ref:
            out.append(Finding(i, "inline"))
            continue
        if ref:
            continue
        if i < start:  # the launcher's own flags and the launched spec
            if got.ecosystem == "image" and got.flag_names.get(i) in RUNNER_ENV_FLAGS:
                k, eq, v = got.flag_values[i].partition("=")
                if eq and setting_problem(k, v):
                    out.append(Finding(i, "env", got.flag_names[i]))
                continue
            if i == got.spec_index:
                if "://" in a and url_carries(a.removeprefix("git+")):
                    out.append(Finding(i, "value"))
            elif carries(got.flag_values.get(i, a)):
                out.append(Finding(i, "value"))
            continue
        prev = args[i - 1] if i > start else ""
        flag, eq, val = a.partition("=")
        if a.startswith("-") and eq:
            if credential_name(flag) and flag_value_credential(flag, val) and not is_path(val):
                out.append(Finding(i, "flag-value", flag))
            elif carries(val):
                out.append(Finding(i, "value", flag))
            continue
        if a.startswith("-"):
            continue  # a flag's own name
        if prev in HEADER_FLAGS:
            out.append(Finding(i, "header", prev))
        elif base in SHELLS and prev == "-c":
            if _shell_carries(a):
                out.append(Finding(i, "shell", prev))
        elif is_value(a) and _after_credential_flag(prev, a):
            out.append(Finding(i, "after-flag", prev))
        elif carries(a) or re.search(r"(?i)authorization:", a):
            out.append(Finding(i, "value"))
    return out
