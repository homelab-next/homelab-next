# SPDX-License-Identifier: Apache-2.0
"""The hub's TLS listener with client-certificate authentication (Stage 5, H1; docs/status.md
"The edge-to-hub hop").

``hnx status serve --tls-cert FILE --tls-key FILE --client-ca FILE`` serves over TLS and
**requires** a client certificate signed by the CA bundle in ``--client-ca``: a peer with no
certificate, or one from another CA, is refused in the handshake, before any HTTP is read.
``--client-name NAME`` (repeatable) also pins the certificate's subject: a peer whose certificate
names none of them (its DNS subjectAltNames or, only when it has none, its common name; exact,
case-insensitive, never a wildcard) is closed right after the handshake, before any HTTP is read.

The handshake runs on the connection's own thread with a deadline (:data:`HANDSHAKE_TIMEOUT_S`;
the whole connection has :data:`CONNECTION_DEADLINE_S`),
never on the accepting thread, so a peer that connects and stalls holds one bounded slot and
cannot stop the server from accepting others (``serve.BoundedHTTPServer``).

"Came from the edge" is then a cryptographic fact: the private tier and the Approvals page trust a
request's identity headers only when it arrives **from a trusted proxy address over a verified
certificate** (``serve``'s handler passes no client address to the front door otherwise, and drops
every identity header first).  Plain HTTP stays possible on loopback, and off loopback only with
the explicit ``--plain-http`` opt-in (tests, lab-in-a-box), where trust is the source address
alone, as before Stage 5.
"""

from __future__ import annotations

import json
import re
import ssl
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

#: how long a peer has to finish the TLS handshake (s)
HANDSHAKE_TIMEOUT_S = 5.0
#: how long one TLS connection may last in all (s): a peer that handshakes and then trickles
CONNECTION_DEADLINE_S = 60.0
#: the most of an answer the hooks' probe reads (the status document)
MAX_PROBE_BYTES = 16 << 20
#: a pinned client name: a DNS name or a bare host name, never a wildcard or an address range
_NAME_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$"
)


class TLSConfigError(ValueError):
    """The TLS settings are incomplete or unusable (message names the setting, never key bytes)."""


def client_name_ok(name: str) -> bool:
    """Whether ``name`` may be pinned: lower-case DNS labels, no ``*``, at most 253 characters."""
    return len(name) <= 253 and bool(_NAME_RE.match(name))


def peer_names(cert: Mapping[str, Any] | None) -> frozenset[str]:
    """The names a verified peer certificate (``SSLSocket.getpeercert()``) is for: its DNS
    subjectAltNames; its subject's common names only when it has no subjectAltName extension at
    all (a certificate with only IP or other SANs names no DNS name, and its CN is not read);
    lower-cased, a trailing dot dropped.  Empty for no certificate."""
    if not cert:
        return frozenset()
    if "subjectAltName" in cert:
        names = {v for k, v in cert["subjectAltName"] if k == "DNS"}
    else:
        names = {v for rdn in cert.get("subject", ()) for k, v in rdn if k == "commonName"}
    return frozenset(n.strip().lower().rstrip(".") for n in names if n.strip())


@dataclass(frozen=True)
class TLSSettings:
    """The listener's certificate and key, the CA bundle client certificates must chain to, and
    the client names pinned (empty: any certificate that CA signed)."""

    cert_file: Path
    key_file: Path
    client_ca_file: Path
    client_names: frozenset[str] = field(default_factory=frozenset)

    @classmethod
    def from_args(
        cls,
        cert: str | None,
        key: str | None,
        client_ca: str | None,
        client_names: Iterable[str] = (),
    ) -> TLSSettings | None:
        """The settings from the command line, or None when no TLS option is given.  All three
        files are required together; a client name needs them and must pass
        :func:`client_name_ok`."""
        names = [n.strip().lower().rstrip(".") for n in client_names if n.strip()]
        given = [x for x in (cert, key, client_ca) if x]
        if not given:
            if names:
                raise TLSConfigError("--client-name needs --tls-cert, --tls-key and --client-ca")
            return None
        if len(given) != 3:
            raise TLSConfigError("--tls-cert, --tls-key and --client-ca go together")
        bad = [n for n in names if not client_name_ok(n)]
        if bad:
            raise TLSConfigError(
                f"--client-name {bad[0]!r}: a DNS name, no wildcard (it pins the edge's certificate)"
            )
        return cls(Path(cert), Path(key), Path(client_ca), frozenset(names))  # type: ignore[arg-type]

    def context(self) -> ssl.SSLContext:
        """A server context: TLS 1.2 or later, this certificate, and a client certificate
        required and verified against the CA bundle (OpenSSL's ``ssl_client`` purpose: a
        certificate whose extended key usage excludes client authentication is refused)."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.options |= ssl.OP_NO_RENEGOTIATION | ssl.OP_NO_COMPRESSION
        try:
            ctx.load_cert_chain(self.cert_file, self.key_file)
        except (OSError, ssl.SSLError) as exc:
            raise TLSConfigError(
                f"cannot load the server certificate {self.cert_file} with its key "
                f"{self.key_file}: {type(exc).__name__}"
            ) from None
        try:
            ctx.load_verify_locations(cafile=self.client_ca_file)
        except (OSError, ssl.SSLError) as exc:
            raise TLSConfigError(
                f"cannot load the client CA bundle {self.client_ca_file}: {type(exc).__name__}"
            ) from None
        if not ctx.get_ca_certs():
            raise TLSConfigError(f"the client CA bundle {self.client_ca_file} holds no CA")
        ctx.verify_mode = ssl.CERT_REQUIRED
        return ctx

    def name_allowed(self, cert: Mapping[str, Any] | None) -> bool:
        """Whether a verified peer certificate passes the pin (no pin: any certificate)."""
        if not cert:
            return False
        return not self.client_names or bool(peer_names(cert) & self.client_names)


# ---------------------------------------------------------------- the hooks' probe
@dataclass(frozen=True)
class ProbeResult:
    ok: bool
    outcome: str  # refused | answered | closed | not-tls | server-cert | unreachable
    detail: str


def _alerted(exc: BaseException) -> bool:
    """A TLS alert from the server (certificate required, bad or unknown certificate, handshake
    failure): the hub's refusal.  A reset or a bare close is not one (a crashing hub does that
    too), so it never passes as a refusal."""
    return isinstance(exc, ssl.SSLError) and "ALERT" in (exc.reason or "").upper()


def _leaf_sha256(path: str) -> str | None:
    """The SHA-256 of the first certificate in a PEM file (the hub's leaf), or None."""
    import hashlib

    text = Path(path).read_text(encoding="ascii", errors="replace")
    end = "-----END CERTIFICATE-----"
    if end not in text:
        return None
    first = text[: text.index(end) + len(end)] + "\n"
    try:
        return hashlib.sha256(
            ssl.PEM_cert_to_DER_cert(first[first.index("-----BEGIN") :])
        ).hexdigest()
    except ValueError:
        return None


def probe(
    address: str,
    port: int,
    *,
    host_header: str,
    server_cert: str,
    server_name: str,
    client_cert: str | None = None,
    client_key: str | None = None,
    timeout_s: float = 10.0,
) -> ProbeResult:
    """What the role's health and readiness hooks check on the hub's TLS listener.

    The probe verifies the server it reaches: ``server_cert`` (the hub's own installed
    certificate) is its one trust anchor and ``server_name`` must be a name in it, so the probe
    talks to that certificate's holder and nothing else, and a hub serving a certificate without
    the name the edge uses fails here.  Without a client certificate the hub must then **refuse**
    (a TLS alert, or the connection cut before any HTTP): ``ok`` only then; an HTTP answer, a peer
    that does not speak TLS, another server certificate or no listener is not ok.  With
    ``client_cert``/``client_key`` (the hooks' own certificate, signed by the hub's client CA)
    ``GET /status.json`` must answer ``200`` with the status document (a mapping with
    ``schema_version`` or ``generated_at``)."""
    import socket

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # verify_mode CERT_REQUIRED, check_hostname on
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    # the leaf itself is the trust anchor (no CA needed to pin exactly the hub's certificate)
    ctx.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    ctx.load_verify_locations(cafile=server_cert)
    leaf = _leaf_sha256(server_cert)
    if leaf is None:
        return ProbeResult(False, "server-cert", f"{server_cert} holds no certificate")
    with_cert = bool(client_cert)
    if with_cert:
        ctx.load_cert_chain(client_cert, client_key)  # type: ignore[arg-type]
    try:
        raw = socket.create_connection((address, port), timeout=timeout_s)
    except OSError as exc:
        return ProbeResult(False, "unreachable", f"no listener: {type(exc).__name__}")
    request = (
        f"GET /status.json HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\n\r\n"
    ).encode("ascii")
    try:
        try:
            tls = ctx.wrap_socket(raw, server_hostname=server_name)
        except (ssl.SSLError, OSError) as exc:
            if isinstance(exc, ssl.SSLCertVerificationError):
                return ProbeResult(
                    False,
                    "server-cert",
                    f"not the hub's certificate for {server_name}: {_why(exc)}",
                )
            if _alerted(exc):
                return _refused(with_cert, exc)
            return ProbeResult(False, "not-tls", f"no TLS handshake: {_why(exc)}")
        with tls:
            import hashlib

            # the leaf itself, not only a chain to anything server_cert holds (an intermediate
            # appended to it is a trust anchor too under the partial-chain flag)
            peer = tls.getpeercert(binary_form=True) or b""
            if hashlib.sha256(peer).hexdigest() != leaf:
                return ProbeResult(
                    False, "server-cert", f"not the hub's own certificate ({server_cert})"
                )
            try:
                tls.sendall(request)
                data = b""
                while len(data) < MAX_PROBE_BYTES:
                    chunk = tls.recv(65536)
                    if not chunk:
                        break
                    data += chunk
            except (ssl.SSLError, OSError) as exc:
                if _alerted(exc) and not data:
                    return _refused(with_cert, exc)
                return ProbeResult(False, "closed", f"closed without an alert: {_why(exc)}")
    finally:
        raw.close()
    if not data:
        return ProbeResult(False, "closed", "closed before any HTTP, without a TLS alert")
    status = data.split(b"\r\n", 1)[0].decode("latin-1")
    if not with_cert:
        return ProbeResult(False, "answered", f"answered without a client certificate: {status}")
    if status.split(" ")[1:2] != ["200"]:
        return ProbeResult(False, "answered", f"not 200 with the client certificate: {status}")
    try:
        doc = json.loads(data.split(b"\r\n\r\n", 1)[1])
    except (IndexError, ValueError):
        doc = None
    if not isinstance(doc, dict) or not ({"schema_version", "generated_at"} & doc.keys()):
        return ProbeResult(False, "answered", "200, but not the hub's status document")
    return ProbeResult(True, "answered", status)


def _why(exc: BaseException) -> str:
    return getattr(exc, "reason", None) or type(exc).__name__


def _refused(with_cert: bool, exc: BaseException) -> ProbeResult:
    why = _why(exc)
    if with_cert:
        return ProbeResult(False, "refused", f"refused the hooks' client certificate: {why}")
    return ProbeResult(True, "refused", f"refused without a client certificate: {why}")
