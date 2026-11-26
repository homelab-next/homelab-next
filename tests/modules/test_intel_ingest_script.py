# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the intel-ingest script (modules/intel-ingest/roles/intel_ingest/files).

Ported from the old lab's job's own tests (the walk's state machine is unchanged), plus the module's
TLS rules: a pin per host or a CA file, never unverified.

The tests inject a fake MISP (FakeMisp) and a fake Cortex (FakeCortex) via the
`fetch_page_fn` / `cortex_ingest_fn` / `save_state_fn` seams on walk_type, so
there is no network, no filesystem, and the real STATE_FILE path is never
touched. The point of these tests is the state machine: watermark advancement,
in_progress checkpointing, resume-from-saved-page, and that Cortex sees the
right (type, value) pairs.
"""

from __future__ import annotations

import importlib.util
import pathlib
import socket
import ssl
import subprocess
import sys
import threading

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures" / "intel_ingest"
SCRIPT = (
    ROOT / "modules" / "intel-ingest" / "roles" / "intel_ingest" / "files" / "hnx_intel_ingest.py"
)
SPEC = importlib.util.spec_from_file_location("hnx_intel_ingest", SCRIPT)
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)  # type: ignore[union-attr]


# ---------------------------------------------------------------------------
# Fakes.
# ---------------------------------------------------------------------------
class FakeMisp:
    """A tiny MISP that returns a canned set of (id, value) attributes per type,
    paginated id-desc exactly the way the live restSearch does."""

    def __init__(self, per_type: dict[str, list[tuple[int, str]]], *, page_size: int = 1000):
        self.per_type = per_type
        self.page_size = page_size
        self.calls: list[tuple[str, int]] = []
        self.fail_on: tuple[str, int] | None = None  # (type, page) to simulate a transient failure

    def fetch_page(self, misp_url: str, authkey: str, misp_type: str, page: int) -> list:
        self.calls.append((misp_type, page))
        if self.fail_on == (misp_type, page):
            raise RuntimeError("simulated MISP outage")
        all_attrs = sorted(self.per_type.get(misp_type, []), key=lambda t: t[0], reverse=True)
        start = (page - 1) * self.page_size
        end = start + self.page_size
        slice_ = all_attrs[start:end]
        return [{"id": str(i), "value": v} for i, v in slice_]


class FakeCortex:
    """Records every Storm query that would have been sent; no SSL, no handshake."""

    def __init__(self):
        self.queries: list[str] = []
        self.fail_next = 0

    def ingest(self, cortex_url, user, password, query: str):
        if self.fail_next > 0:
            self.fail_next -= 1
            raise RuntimeError("simulated Cortex transient")
        self.queries.append(query)

    def all_values(self) -> list[str]:
        """Return every `[inet:... = "value" +#rep.misp]` value seen, in call order."""
        out = []
        for q in self.queries:
            for line in q.split("\n"):
                # [inet:fqdn="example.com" +#rep.misp]
                if '="' in line:
                    val = line.split('="', 1)[1].rsplit('"', 1)[0]
                    out.append(val)
        return out


def _in_memory_saver(dest: dict) -> callable:
    def _save(state: dict) -> None:
        dest.clear()
        dest.update({k: dict(v) if isinstance(v, dict) else v for k, v in state.items()})

    return _save


# ---------------------------------------------------------------------------
# Tests.
# ---------------------------------------------------------------------------
def test_cold_walk_ingests_all_and_advances_watermark(monkeypatch):
    monkeypatch.setattr(mod, "PAGE_SIZE", 5)
    monkeypatch.setattr(mod, "BATCH_SIZE", 3)
    misp = FakeMisp(
        {"domain": [(i, f"d{i}.example.com") for i in range(1, 13)]},  # 12 rows, pages of 5
        page_size=5,
    )
    cortex = FakeCortex()
    state = {}
    saved: dict = {}
    n, complete = mod.walk_type(
        "https://misp",
        "k",
        "domain",
        "https://cortex",
        "u",
        "p",
        state,
        fetch_page_fn=misp.fetch_page,
        cortex_ingest_fn=cortex.ingest,
        save_state_fn=_in_memory_saver(saved),
    )
    assert complete is True
    assert n == 12
    assert state["domain"]["watermark_id"] == 12
    assert state["domain"]["in_progress"] is None
    # Every (type, value) pair was sent to Cortex. We don't care about order here, just completeness.
    assert sorted(cortex.all_values()) == sorted(f"d{i}.example.com" for i in range(1, 13))


def test_warm_walk_fetches_only_one_page(monkeypatch):
    monkeypatch.setattr(mod, "PAGE_SIZE", 5)
    monkeypatch.setattr(mod, "BATCH_SIZE", 3)
    misp = FakeMisp(
        {"domain": [(i, f"d{i}.example.com") for i in range(1, 13)]},
        page_size=5,
    )
    cortex = FakeCortex()
    state = {"domain": {"watermark_id": 12, "in_progress": None}}
    saved: dict = {}
    n, complete = mod.walk_type(
        "https://misp",
        "k",
        "domain",
        "https://cortex",
        "u",
        "p",
        state,
        fetch_page_fn=misp.fetch_page,
        cortex_ingest_fn=cortex.ingest,
        save_state_fn=_in_memory_saver(saved),
    )
    assert complete is True
    assert n == 0
    assert cortex.queries == []
    # One page fetched, immediately hit_known_territory on id=12.
    assert misp.calls == [("domain", 1)]
    assert state["domain"]["watermark_id"] == 12


def test_resume_from_saved_page(monkeypatch):
    monkeypatch.setattr(mod, "PAGE_SIZE", 5)
    monkeypatch.setattr(mod, "BATCH_SIZE", 3)
    misp = FakeMisp(
        {"domain": [(i, f"d{i}.example.com") for i in range(1, 13)]},
        page_size=5,
    )
    cortex = FakeCortex()
    # Pretend pages 1 (ids 12..8) and 2 (ids 7..3) were already done last run.
    state = {"domain": {"watermark_id": 0, "in_progress": {"page": 3, "newest_id": 12}}}
    saved: dict = {}
    n, complete = mod.walk_type(
        "https://misp",
        "k",
        "domain",
        "https://cortex",
        "u",
        "p",
        state,
        fetch_page_fn=misp.fetch_page,
        cortex_ingest_fn=cortex.ingest,
        save_state_fn=_in_memory_saver(saved),
    )
    assert complete is True
    # Resumed at page 3, which has ids 2..1 (the last two). So n == 2, not 12.
    assert n == 2
    assert misp.calls == [("domain", 3)]
    assert state["domain"]["watermark_id"] == 12
    assert state["domain"]["in_progress"] is None


def test_deadline_pauses_walk_and_saves_state(monkeypatch):
    """A deadline that fires mid-walk pauses cleanly and saves in_progress."""
    monkeypatch.setattr(mod, "PAGE_SIZE", 5)
    monkeypatch.setattr(mod, "BATCH_SIZE", 3)
    misp = FakeMisp(
        {"domain": [(i, f"d{i}.example.com") for i in range(1, 13)]},
        page_size=5,
    )
    cortex = FakeCortex()
    state = {}
    saved: dict = {}

    # Fire the "shutdown requested" flag after one page's ingest completes.
    original_ingest = cortex.ingest
    call_count = {"n": 0}

    def ingest_then_signal(*a, **k):
        original_ingest(*a, **k)
        call_count["n"] += 1
        if call_count["n"] >= 2:  # after 2 batches (page 1 ingested)
            mod._exit_requested = True

    try:
        mod._exit_requested = False
        n, complete = mod.walk_type(
            "https://misp",
            "k",
            "domain",
            "https://cortex",
            "u",
            "p",
            state,
            fetch_page_fn=misp.fetch_page,
            cortex_ingest_fn=ingest_then_signal,
            save_state_fn=_in_memory_saver(saved),
        )
    finally:
        mod._exit_requested = False

    assert complete is False
    # Page 1 was ingested (5 pairs), then paused BEFORE page 2's fetch.
    assert n == 5
    # State recorded in_progress so next run resumes at page 2.
    assert state["domain"]["watermark_id"] == 0
    assert state["domain"]["in_progress"] is not None
    assert state["domain"]["in_progress"]["page"] == 2


def test_normalise_state_migrates_legacy_flat_schema():
    legacy = {"ip-src": 6051196, "domain": 999, "url": {"watermark_id": 42, "in_progress": None}}
    out = mod._normalise_state(legacy)
    assert out["ip-src"] == {"watermark_id": 6051196, "in_progress": None}
    assert out["domain"] == {"watermark_id": 999, "in_progress": None}
    assert out["url"] == {"watermark_id": 42, "in_progress": None}


def test_normalise_state_preserves_in_progress():
    nested = {"domain": {"watermark_id": 5, "in_progress": {"page": 7, "newest_id": 99}}}
    out = mod._normalise_state(nested)
    assert out["domain"]["in_progress"] == {"page": 7, "newest_id": 99}


def test_lean_params_present_in_fetch_page_body(monkeypatch):
    """Guard against a future refactor dropping the lean MISP params -- without them
    the DB-side cost of each page regresses. We verify by inspecting the body http_json
    would be given."""
    captured_body = {}

    def _fake_http_json(url, headers, body):
        captured_body.update(body)
        return {"response": {"Attribute": []}}

    monkeypatch.setattr(mod, "http_json", _fake_http_json)
    mod.fetch_page("https://misp", "k", "domain", 1)
    for key in mod.MISP_LEAN_PARAMS:
        assert key in captured_body, f"lean param {key!r} missing from restSearch body"
        assert captured_body[key] == 0, (
            f"lean param {key!r} should be 0, got {captured_body[key]!r}"
        )


def test_storm_quote_escapes_double_quotes_and_backslashes():
    assert mod.storm_quote(r'a\b"c') == r'"a\\b\"c"'


@pytest.mark.static
def test_attribute_to_storm_line_v4_vs_v6_vs_cidr():
    """ip-src and ip-dst values from the platform's feeds are a mixed bag: bare v4, bare v6 and CIDR
    ranges all show up. The v4 form rejects anything non-dotted-quad, and a reject inside a chained
    batch poisons the whole batch (LL-504), so attribute_to_storm_line routes each shape to its form."""
    cases = yaml.safe_load((FIXTURES / "ip_forms.yml").read_text())["cases"]
    for c in cases:
        assert mod.attribute_to_storm_line(c["type"], c["value"]).startswith(f"[{c['form']}="), c
    # Non-ip types untouched -- domain stays inet:fqdn even with weird input, hash stays hash:md5
    assert mod.attribute_to_storm_line("domain", "example.com").startswith("[inet:fqdn=")
    assert mod.attribute_to_storm_line("md5", "d41d8cd98f00b204e9800998ecf8427e").startswith(
        "[hash:md5="
    )


def test_storm_quote_escapes_newlines_too():
    """A raw \\n in a value would split a chained [stmt1][stmt2] batch across lines
    and corrupt it; collapse CR/LF to a space so the batch stays one Storm pipeline."""
    assert "\n" not in mod.storm_quote("a\nb")
    assert "\r" not in mod.storm_quote("a\rb")


def test_full_resync_flag_deletes_state_before_run(tmp_path, monkeypatch):
    monkeypatch.setattr(mod, "STATE_FILE", tmp_path / "state.json")
    mod.STATE_FILE.write_text('{"domain": 999}')
    assert mod.STATE_FILE.exists()
    # Bypass env-var and the actual MISP/Cortex calls: patch main to short-circuit
    # once state is cleared.
    monkeypatch.setenv("INGEST_SOURCE_URL", "https://misp")
    monkeypatch.setenv("INGEST_SOURCE_KEY", "k")
    monkeypatch.setenv("INGEST_GRAPH_URL", "https://cortex")
    monkeypatch.setenv("INGEST_GRAPH_USER", "u")
    monkeypatch.setenv("INGEST_GRAPH_PASSWORD", "p")
    monkeypatch.setattr(mod, "TYPE_MAP", {})  # no types -> main exits cleanly
    rc = mod.main(["--full-resync"])
    assert rc == 0
    assert not mod.STATE_FILE.exists()


# ---------------------------------------------------------------------------
# TLS: ordinary verification against a CA file, hostname checking on, never unverified.
# ---------------------------------------------------------------------------
sys.path.insert(0, str(ROOT / "tests" / "roles"))
from forge_front import LOOPBACK, make_pki


def _selfsigned(directory, name):
    """A self-signed certificate (no CA flag) for ``name`` and its key: what a service that makes its own has."""
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", f"/CN={name}",
         "-addext", f"subjectAltName=DNS:{name}", "-keyout", "ss.key", "-out", "ss.pem"],
        check=True, capture_output=True, cwd=directory,
    )  # fmt: skip
    return (directory / "ss.pem").read_text(), (directory / "ss.key").read_text()


def _serve(tmp_path, chain, key):
    (tmp_path / "chain.pem").write_text(chain)
    (tmp_path / "key.pem").write_text(key)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(tmp_path / "chain.pem"), str(tmp_path / "key.pem"))
    srv = socket.socket()
    srv.bind((LOOPBACK, 0))
    srv.listen(5)
    stop = threading.Event()

    def serve():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except OSError:
                continue
            try:
                with ctx.wrap_socket(conn, server_side=True):
                    pass
            except (ssl.SSLError, OSError):
                pass

    threading.Thread(target=serve, daemon=True).start()
    return srv, stop


def _handshake(ctx, port, name):
    with (
        socket.create_connection((LOOPBACK, port), timeout=5) as sock,
        ctx.wrap_socket(sock, server_hostname=name),
    ):
        return True


@pytest.fixture(autouse=True)
def _fresh_tls_cache(monkeypatch):
    monkeypatch.setattr(mod, "_PINNED_CTX_CACHE", {})
    monkeypatch.delenv("INGEST_CA_FILE", raising=False)


def test_a_host_with_no_ca_file_is_refused():
    with pytest.raises(RuntimeError, match="without verifying"):
        mod._pinned_ctx_for("https://graph.example.internal")


def test_the_context_verifies_the_certificate_and_the_host_name(monkeypatch, tmp_path):
    chain, key, ca = make_pki(tmp_path, "svc.example.internal")
    (tmp_path / "ca.pem").write_text(ca)
    monkeypatch.setenv("INGEST_CA_FILE", str(tmp_path / "ca.pem"))
    ctx = mod._pinned_ctx_for("https://svc.example.internal")
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname is True
    srv, stop = _serve(tmp_path, chain, key)
    try:
        port = srv.getsockname()[1]
        assert _handshake(ctx, port, "svc.example.internal")
        with pytest.raises(ssl.SSLCertVerificationError):  # right certificate, wrong name
            _handshake(ctx, port, "other.example.internal")
    finally:
        stop.set()
        srv.close()


def test_a_certificate_from_another_ca_is_rejected(monkeypatch, tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    chain, key, _ca = make_pki(tmp_path / "a", "svc.example.internal")
    _c, _k, other_ca = make_pki(tmp_path / "b", "svc.example.internal")
    (tmp_path / "other-ca.pem").write_text(other_ca)
    monkeypatch.setenv("INGEST_CA_FILE", str(tmp_path / "other-ca.pem"))
    ctx = mod._pinned_ctx_for("https://svc.example.internal")
    srv, stop = _serve(tmp_path, chain, key)
    try:
        with pytest.raises(ssl.SSLCertVerificationError):
            _handshake(ctx, srv.getsockname()[1], "svc.example.internal")
    finally:
        stop.set()
        srv.close()


def test_a_self_signed_certificate_is_trusted_only_as_that_exact_certificate(monkeypatch, tmp_path):
    (tmp_path / "x").mkdir()
    (tmp_path / "y").mkdir()
    cert, key = _selfsigned(tmp_path / "x", "graph")
    other_cert, _ = _selfsigned(tmp_path / "y", "graph")  # same name, a different certificate
    (tmp_path / "trust.pem").write_text(cert)
    monkeypatch.setenv("INGEST_CA_FILE", str(tmp_path / "trust.pem"))
    ctx = mod._pinned_ctx_for("https://graph")
    srv, stop = _serve(tmp_path, cert, key)
    try:
        assert _handshake(ctx, srv.getsockname()[1], "graph")
    finally:
        stop.set()
        srv.close()
    # the service now presents another certificate with the same name: rejected
    other_key = (tmp_path / "y" / "ss.key").read_text()
    srv, stop = _serve(tmp_path, other_cert, other_key)
    try:
        with pytest.raises(ssl.SSLCertVerificationError):
            _handshake(ctx, srv.getsockname()[1], "graph")
    finally:
        stop.set()
        srv.close()
