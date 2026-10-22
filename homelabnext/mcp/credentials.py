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
* an **argument** also carries one in a JSON object with a credential-named key, and in a
  ``KEY=VALUE`` whose setting would be refused.

The arguments scanned are a server's own: a record never writes a launcher, a shell line or a
container runner's flags (:func:`homelabnext.mcp.servers.launch` generates the launch), and the
importer does not map a command line it cannot read.  This is defense in depth: ``leak_scan`` and
gitleaks guard the repository, and a credential belongs in ``env`` as a ``secret:`` reference.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Iterable
from dataclasses import dataclass
from urllib.parse import parse_qsl, unquote, urlsplit

#: a key or flag that names a credential (substring: ``GITHUBTOKEN``, ``DB_PASSWORD``)
SECRET_KEY = re.compile(r"TOKEN|SECRET|PASSW|API_?KEY|PRIVATE|CREDENTIAL|COOKIE|SESSION", re.I)
#: credential words: the last word of a flag or key that names a credential
CREDENTIAL_WORDS = frozenset(
    (
        "token", "apikey", "password", "passwd", "pass", "pwd", "pw", "passphrase", "secret",
        "bearer", "credential", "pat", "cookie", "cookies", "authorization", "jwt",
    )
)  # fmt: skip
#: words that name a credential only when the value is not a plain name: ``--key id``,
#: ``--sort-key created_at``, ``--session default``, ``--auth github`` and
#: ``GOOGLE_APPLICATION_CREDENTIALS=/etc/x.json`` are not credentials; ``--key fake-k3y0``,
#: ``--auth user:pw`` are
WEAK_WORDS = frozenset(("key", "keys", "auth", "session", "credentials", "secrets"))
#: a word before ``key`` that makes it a credential whatever its value (``--api-key``)
KEY_QUALIFIERS = frozenset(
    ("api", "access", "secret", "private", "signing", "encryption", "master", "client", "auth")
)
#: a last word that says the value *is* the credential named before it (``--token-value``,
#: ``AUTH_HEADER``, ``--token-header``)
VALUE_WORDS = frozenset(("value", "string", "literal", "data", "header"))
#: a glued last word ending in a credential word (``GITHUBTOKEN``, ``PGPASSWORD``, ``DBPASS``)
_GLUED = re.compile(
    r".+(?:token|secret|password|passwd|passphrase|apikey|accesskey|secretkey|privatekey|pass|pwd"
    r"|credential|cookie|bearer)"
)
#: a last word that makes the name about a credential, not one (its value is a path, a name ...)
ABOUT_WORDS = frozenset(
    (
        "file", "files", "path", "dir", "directory", "env", "var", "name", "timeout", "ttl", "url",
        "uri", "endpoint", "host", "port", "type", "mode", "method", "scheme", "provider",
        "prefix", "length", "size", "format", "id", "count", "limit", "expiry", "lifetime", "store",
        "source", "version", "algorithm", "enabled", "disabled", "backend", "budget", "max", "min",
        "through", "jar", "browser", "keychain", "chain",
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
#: a git commit or a sha256 digest in hex: an identifier, not a token
_HEX_DIGEST = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
_MODULE = re.compile(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+(?::[A-Za-z_]\w*)?")
#: ``user:password@host`` without a scheme
_BARE_USERINFO = re.compile(r"[^\s:/@]+:[^\s/@]+@[A-Za-z0-9.-]+")
#: ``key=value`` pairs (a libpq DSN, an ADO connection string, a query) with a credential key
_KV_PAIR = re.compile(r"(?:^|[\s;&,?])([A-Za-z_][A-Za-z0-9_ -]*?)\s*=\s*([^\s;&,]+)")
#: ``$VAR``, ``${VAR}``, ``${VAR:-default}``, ``${VAR-default}`` as a whole value
VAR = re.compile(
    r"^\$(?:\{(?P<b>[A-Za-z_][A-Za-z0-9_]*)(?::?[-=?+][^}]*)?\}|(?P<n>[A-Za-z_][A-Za-z0-9_]*))$"
)


_DASHES = "-\u2010\u2011\u2012\u2013\u2014\u2015\u2212"


def words(name: str) -> list[str]:
    """The words of a flag or key: ``--githubToken`` and ``GITHUB_TOKEN`` are github, token."""
    n = name.lstrip(_DASHES)
    n = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", n)
    n = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", n)
    return [w for w in re.split(r"[-_.\s]+", n.lower()) if w]


def strength(name: str) -> str | None:
    """``strong`` (the value is a credential), ``weak`` (it is unless it is a plain name or a
    path, :data:`WEAK_WORDS`) or None (not a credential name).  Only the last word counts:
    ``--max-tokens``, ``TOKENIZER``, ``AUTH_ENABLED``, ``SESSION_BACKEND`` and ``--pass-through``
    name no credential."""
    ws = words(name)
    if not ws or ws[0] == "no" or ws[-1] in ABOUT_WORDS:
        return None
    if ws[-1] in VALUE_WORDS and len(ws) > 1:
        core = ws[-2]
        return "strong" if core in CREDENTIAL_WORDS | WEAK_WORDS or _GLUED.fullmatch(core) else None
    last = ws[-1]
    if last in CREDENTIAL_WORDS or _GLUED.fullmatch(last):
        return "strong"
    if last in ("key", "keys") and len(ws) > 1 and ws[-2] in KEY_QUALIFIERS:
        return "strong"
    return "weak" if last in WEAK_WORDS else None


def credential_name(name: str) -> bool:
    """A flag or key whose value is (or may be) a credential (:func:`strength`)."""
    return strength(name) is not None


def about_a_credential_path(name: str) -> bool:
    """A key that names where a credential is (``TOKEN_FILE``, ``KEY_PATH``): its value must be a
    path, or it is the credential itself."""
    ws = words(name)
    return (
        bool(ws)
        and ws[-1] in PATH_WORDS
        and any(w in CREDENTIAL_WORDS | WEAK_WORDS for w in ws[:-1])
    )


_PATH = re.compile(r"(?:~?/|\.{1,2}/)[^\s;|&<>'\"`$]*|[A-Za-z]:\\[^\s;|&<>'\"`$]*")


def is_path(value: str) -> bool:
    """A plain path (POSIX or Windows): nothing after it (``/run/x; pw`` is not one)."""
    return bool(_PATH.fullmatch(value))


#: a value a weak credential name may take: plain lowercase words (``id``, ``created_at``,
#: ``name,email``, ``azure-cli``), no digits, at most one separator per item
_PLAIN_NAME = re.compile(r"[a-z][a-z_]*(?:[-.][a-z_]+)?(?:,[a-z][a-z_]*(?:[-.][a-z_]+)?)*")


def name_value_credential(name: str, value: str) -> bool:
    """``name`` (a flag or key) given ``value``: is the value a credential?  A strong name: always
    (a path only after a ``*_FILE``/``*_PATH`` name, which is not a credential name); a weak one:
    unless the value is a plain name, a path or (``auth``) a method."""
    kind = strength(name)
    if kind is None or is_ref(value):
        return False
    if kind == "weak":
        return not (_PLAIN_NAME.fullmatch(value) or is_path(value) or value.lower() in AUTH_METHODS)
    return not (words(name)[-1] == "auth" and value.lower() in AUTH_METHODS)


#: ``$NAME``, ``${...}`` and ``$(...)``: what a client or shell would expand (a regex's
#: trailing ``$`` is not)
_EXPANSION = re.compile(r"\$(?:[A-Za-z_{(])")


def expands(value: str) -> bool:
    return bool(_EXPANSION.search(value))


def is_ref(value: str) -> bool:
    return bool(SECRET_REF.fullmatch(value))


def arg_secret(arg: str) -> str | None:
    """The secret ref an argument carries (``secret:x``, ``--flag=secret:x``,
    ``Header: [Scheme ]secret:x`` or ``--header=Header: [Scheme ]secret:x``), else None."""
    value = arg.split("=", 1)[1] if arg.startswith("-") and "=" in arg else arg
    m = _HEADER_ARG.match(value)
    value = m.group(1) if m else value
    return value if SECRET_REF.fullmatch(value) else None


def _random_part(p: str) -> bool:
    """A part that alternates letters and digits like a random token (``a8f3k2``), not a word
    with a number (``qwen2``, ``32b``, ``4o``)."""
    return len(p) >= 5 and len(re.findall(r"[a-zA-Z](?=[0-9])|[0-9](?=[a-zA-Z])", p)) >= 3


def _plain_words(value: str) -> bool:
    """An identifier of plain words and numbers (a model id, a dated name), not a token."""
    parts = [p for p in re.split(r"[-._:]+", value) if p]
    return (
        len(parts) > 1
        and all(p.isalpha() or p.isdigit() or len(p) < 8 for p in parts)
        and not any(_random_part(p) for p in parts)
    )


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
    if _HEX_DIGEST.fullmatch(v) or _EMAIL.fullmatch(v) or _MODULE.fullmatch(v) or is_path(v):
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
    if password or (
        user and (not re.fullmatch(r"[A-Za-z][A-Za-z0-9._-]{0,63}", user) or looks_secret(user))
    ):
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

    def literal(k: str, v) -> bool:
        if isinstance(v, bool) or v is None or v == "":
            return False
        if isinstance(v, int | float):  # {"password": 12345}
            return strength(k) == "strong"
        return isinstance(v, str) and name_value_credential(k, v)

    def walk(x) -> bool:
        if isinstance(x, dict):
            return any(literal(str(k), v) or walk(v) for k, v in x.items())
        return isinstance(x, list) and any(walk(i) for i in x)

    return walk(doc)


def kv_carries(value: str) -> bool:
    """``key=value`` pairs (``host=db password=x``, ``Server=db;Password=x;``) with a credential
    key, or ``user:password@host`` without a scheme."""
    if _BARE_USERINFO.fullmatch(value.strip()):
        return True
    return any(name_value_credential(k.strip(), v) for k, v in _KV_PAIR.findall(value))


def carries(value: str) -> bool:
    """A value that is, or carries, a literal credential (an inline PEM key included)."""
    return (
        "-----BEGIN" in value
        or looks_secret(value)
        or url_carries(value)
        or json_carries(value)
        or kv_carries(value)
    )


def setting_problem(key: str, value: str) -> str | None:
    """Why ``KEY=VALUE`` (a setting, a container's ``-e``) may not be a literal, or None."""
    if expands(value) or "secret:" in value:
        return "holds $ or secret:"
    if name_value_credential(key, value):
        return "names a credential"
    if about_a_credential_path(key) and not is_path(value):
        return "names a credential and its value is not a path"
    if carries(value):
        return "looks like a literal credential"
    return None


def flag_value_credential(flag: str, value: str) -> bool:
    """``flag`` given ``value``: a credential (:func:`name_value_credential`)."""
    return name_value_credential(flag, value)


def is_flag(arg: str) -> bool:
    """A flag (``--x``, ``-x``, a Unicode dash too), not a value that starts with a dash: a
    single-dash argument is a flag only when it is one letter or a short cluster."""
    if not arg or arg[0] not in _DASHES or arg.startswith("-----BEGIN"):
        return False
    return (
        arg.startswith("--") or arg[0] != "-" or bool(re.fullmatch(r"-[A-Za-z][A-Za-z]{0,7}", arg))
    )


def is_value(arg: str) -> bool:
    """An argument that can be the previous flag's value (not a flag)."""
    return bool(arg) and not is_flag(arg)


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
        return not is_path(value) and _short_value_credential(prev, value)
    return (
        len(prev) > 2
        and prev[0] in _DASHES
        and "=" not in prev
        and name_value_credential(prev, value)
    )


#: single-dash long flags that start with p (Go style ``-port 8080``), not ``-p<password>``
_P_WORDS = frozenset(
    ("port", "path", "prefix", "profile", "project", "provider", "proxy", "pretty", "print",
     "parallel", "pid", "prompt", "protocol", "public", "publish", "pull", "push", "plugin",
     "pool", "page", "pattern", "policy", "preview", "private", "process", "progress")
)  # fmt: skip


def _attached_password(arg: str) -> bool:
    """``-pPASSWORD`` (mysql and kin): a password attached to ``-p``, unless a port or a flag."""
    if not re.fullmatch(r"-p[^-=\s].*", arg):
        return False
    rest = arg[2:]
    return not (
        re.fullmatch(r"[0-9]{1,5}(?::[0-9]{1,5})?", rest)
        or arg[1:].lower() in _P_WORDS
        or arg[1:].lower().split("-", 1)[0] in _P_WORDS
    )


@dataclass(frozen=True)
class Finding:
    """One argument that carries a literal credential (or something a client would expand)."""

    index: int
    #: ``dollar`` (a ``$`` a client would expand), ``inline`` (``secret:`` inside a value),
    #: ``flag-value`` (``--token=X``), ``after-flag`` (``--token X``: the value), ``header``
    #: (``--header 'Authorization: ...'``), ``env`` (``KEY=VALUE`` naming a credential),
    #: ``value`` (a token, a URL or JSON carrying one)
    kind: str
    #: the flag concerned (``--token``, ``-e``), or ""
    flag: str = ""


_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")


def scan_args(args: Iterable[str]) -> list[Finding]:
    """Every argument of a server (a record's ``args``, the server's own: a record never writes
    a launcher) that carries a literal credential or something a client would expand."""
    args = [str(a) for a in args]
    out: list[Finding] = []
    for i, a in enumerate(args):
        if expands(a):
            out.append(Finding(i, "dollar"))
            continue
        ref = arg_secret(a)
        if "secret:" in a and not ref:
            out.append(Finding(i, "inline"))
            continue
        if ref:
            continue
        if "-----BEGIN" in a:  # an inline PEM key, after a flag or not
            out.append(Finding(i, "value"))
            continue
        prev = args[i - 1] if i > 0 else ""
        flag, eq, val = a.partition("=")
        if is_flag(a) and eq:
            if flag in HEADER_FLAGS:
                out.append(Finding(i, "header", flag))
            elif name_value_credential(flag, val):
                out.append(Finding(i, "flag-value", flag))
            elif carries(val):
                out.append(Finding(i, "value", flag))
            continue
        if _attached_password(a):
            out.append(Finding(i, "flag-value", "-p"))
            continue
        if is_flag(a):
            continue  # a flag's own name
        if prev in HEADER_FLAGS:
            out.append(Finding(i, "header", prev))
        elif is_flag(prev) and _after_credential_flag(prev, a):
            out.append(Finding(i, "after-flag", prev))
        elif _ASSIGNMENT.match(a) and setting_problem(*a.split("=", 1)):
            out.append(Finding(i, "env", a.split("=", 1)[0]))
        elif carries(a) or re.search(r"(?i)authorization:", a):
            out.append(Finding(i, "value"))
    return out


# ------------------------------------------------------------------------- safe messages
# A problem, note or exception message of the MCP catalog never carries a value taken from a
# record, a render spec, a profile or a parameter: those values reach stdout, stderr and CI logs,
# and a value can be a credential pasted by mistake (which check exists to catch).  A message
# names the field and the rule it broke; a name or id validated against its own pattern may
# appear; a URL appears only as its scheme and host, its userinfo as ``***``.

#: a key named in a schema message (an unexpected property): a plain identifier, else not named
_KEY_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_-]{0,63}")


def redact_url(url: str) -> str:
    """A URL as a message may show it: its scheme and host (and port), userinfo as ``***``, no
    path, query or fragment."""
    text = str(url)
    try:
        parts = urlsplit(text.removeprefix("git+"))
        host, port = parts.hostname, parts.port
    except ValueError:
        return "a URL that does not parse"
    if not parts.scheme or not host:
        return "a value that is not a URL"
    user = "***@" if parts.username is not None or parts.password is not None else ""
    return f"{parts.scheme}://{user}{host}{f':{port}' if port else ''}"


def reason(exc: BaseException) -> str:
    """Why a file could not be read, without its content: a YAML or JSON error's problem and
    position (never the line it quotes), an OS error's description, else the error's type."""
    mark = getattr(exc, "problem_mark", None)
    if mark is not None:  # yaml.MarkedYAMLError: its str() quotes the offending line
        return f"{getattr(exc, 'problem', None) or 'not YAML'} (line {mark.line + 1}, column {mark.column + 1})"
    if isinstance(exc, json.JSONDecodeError):
        return f"{exc.msg} (line {exc.lineno}, column {exc.colno})"
    if isinstance(exc, OSError):
        return exc.strerror or type(exc).__name__
    return type(exc).__name__


def schema_message(e: object) -> str:
    """A jsonschema error's message without the value it is about (jsonschema's own messages
    quote the instance: ``'https://user:pw@...' does not match ...``)."""
    validator = getattr(e, "validator", None)
    expected = getattr(e, "validator_value", None)
    instance = getattr(e, "instance", None)
    if validator == "pattern":
        return f"does not match {expected!r}"
    if validator == "enum":
        return f"is not one of {expected!r}"
    if validator == "const":
        return f"is not {expected!r}"
    if validator == "type":
        return f"is not of type {expected!r}"
    if validator == "required":
        return str(getattr(e, "message", "a required property is missing"))  # a schema name
    if validator == "additionalProperties" and isinstance(instance, dict):
        known = set((getattr(e, "schema", None) or {}).get("properties") or {})
        extra = sorted(str(k) for k in instance if k not in known)
        if extra and all(_KEY_NAME.fullmatch(k) for k in extra):
            return f"Additional properties are not allowed ({', '.join(map(repr, extra))} was unexpected)"
        return "Additional properties are not allowed (an unexpected key)"
    if validator in ("oneOf", "anyOf"):
        return "is not valid under any of the given schemas"
    if validator == "not":
        return "is not allowed here"
    if validator in ("maxLength", "minLength", "maxItems", "minItems", "maximum", "minimum",
                     "uniqueItems", "maxProperties", "minProperties"):  # fmt: skip
        return f"fails {validator} {expected!r}"
    return f"fails {validator}"


def safe_schema_errors(directory: str, name: str, doc: object) -> list[str]:
    """``schemas/<directory>/<name>.schema.json`` errors as :func:`schema_message` words them
    (``homelabnext.agent.schemas.schema_errors`` quotes the values)."""
    from jsonschema import Draft202012Validator

    from homelabnext import paths
    from homelabnext.agent.schemas import _registry

    schema = json.loads(paths.schema_file(directory, f"{name}.schema.json").read_text("utf-8"))
    v = Draft202012Validator(schema, registry=_registry())
    return [
        f"{'/'.join(map(str, e.absolute_path)) or '$'}: {schema_message(e)}"
        for e in sorted(v.iter_errors(doc), key=lambda e: list(map(str, e.absolute_path)))
    ]


#: a name a message may quote (a server, parameter, lane or kind name as a spec writes it)
_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@-]{0,63}")


def name(value: object) -> str:
    """``value`` quoted when it is a plain name, else a placeholder (it is not one, and it may be
    anything, a credential included)."""
    text = str(value)
    return repr(text) if _SAFE_NAME.fullmatch(text) and not looks_secret(text) else "(not a name)"
