# SPDX-License-Identifier: Apache-2.0
"""The ACME renewal scripts install their certificate under the unit's capability set.

``hnx-caddy-acme.service`` and ``hnx-openbao-acme.service`` run as root with
``CapabilityBoundingSet=CAP_CHOWN``: root can give the key to its reader but, without
CAP_DAC_OVERRIDE or CAP_DAC_READ_SEARCH, cannot open a file that reader owns (mode 0600/0640).
The first real deploy found the install's own pair check failing on exactly that ("the new pair
did not check out ... nothing is installed", reproduced with ``systemd-run -p
CapabilityBoundingSet=CAP_CHOWN``, rc 1; plain root rc 0).

CI is unprivileged and cannot chown to another account, so the simulation is the same denial
reached the other way round: ``os.fchown`` is replaced by a ``fchmod(fd, 0)``, so the staged key
becomes a file its own process cannot open by path (EACCES, for the script and for the ``openssl``
it spawns), while a descriptor opened before that keeps working, exactly as under the unit. A
check that opens the installed key by path fails here as it fails there."""

from __future__ import annotations

import grp
import json
import os
import pwd
import subprocess
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
from pathlib import Path

import pytest

jinja2 = pytest.importorskip("jinja2")  # present wherever ansible is

pytestmark = [
    pytest.mark.requires_tool("ansible-playbook"),  # the job that has ansible has jinja2
    pytest.mark.requires_tool("openssl"),
]

ROOT = Path(__file__).resolve().parents[2]
NAME = "hub.example.internal"
CADDY = ROOT / "modules/caddy/roles/caddy/templates/caddy-acme-renew.py.j2"
OPENBAO = ROOT / "ansible/roles/openbao/templates/openbao-acme-renew.py.j2"
SERVICES = {
    "caddy": ROOT / "modules/caddy/roles/caddy/templates/acme-renew.service.j2",
    "openbao": ROOT / "ansible/roles/openbao/templates/acme-renew.service.j2",
}


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    """A throwaway CA, and two certificates it issued for NAME (so a key can be the wrong one)."""
    d = tmp_path_factory.mktemp("pki")
    ec = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "2"]
    run = lambda *a: subprocess.run(a, check=True, capture_output=True)  # noqa: E731
    run("openssl", "req", "-x509", *ec, "-subj", "/CN=test ca", "-keyout", d / "ca-key.pem",
        "-out", d / "ca.pem", "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign")  # fmt: skip
    for n in ("one", "two"):
        run("openssl", "req", "-x509", *ec, "-subj", f"/CN={NAME}", "-CA", d / "ca.pem",
            "-CAkey", d / "ca-key.pem", "-addext", f"subjectAltName=DNS:{NAME}",
            "-addext", "basicConstraints=critical,CA:FALSE", "-addext", "extendedKeyUsage=serverAuth",
            "-keyout", d / f"{n}.key", "-out", d / f"{n}.leaf")  # fmt: skip
        (d / f"{n}.crt").write_bytes((d / f"{n}.leaf").read_bytes() + (d / "ca.pem").read_bytes())
    return d


def render(template: Path, tmp_path: Path, pki: Path, **v) -> object:
    """The renewal script rendered with its variables, loaded as a module; it installs into
    ``tmp_path/tls`` from the stored pair in ``tmp_path/acme/certificates``."""
    env = jinja2.Environment(undefined=jinja2.StrictUndefined)
    env.filters["to_json"] = json.dumps
    common = {
        "acme_dir": str(tmp_path / "acme"), "server": "https://acme.example.internal/directory",
        "email": "", "dns_provider": "cloudflare", "token_env": {"cloudflare": "CF_DNS_API_TOKEN"},
        "env_file": str(tmp_path / "dns.env"), "wait": "30s", "renew_days": 30, "key_type": "ec256",
        "domains": [NAME], "bundle": str(pki / "ca.pem"),
    }  # fmt: skip
    tls = tmp_path / "tls"
    tls.mkdir(exist_ok=True)
    if template == CADDY:
        names = {
            "caddy_install_dir": "/opt/c", "caddy_lego_version": "5.6.0", "caddy_acme_dir": common["acme_dir"],
            "caddy_acme_server": common["server"], "caddy_acme_email": "", "caddy_acme_dns_provider": "cloudflare",
            "caddy_acme_token_env": common["token_env"], "caddy_acme_env_file": common["env_file"],
            "caddy_acme_propagation_wait": "30s", "caddy_acme_renew_days": 30, "caddy_acme_key_type": "ec256",
            "caddy_acme_domains": [NAME], "caddy_acme_trust_bundle": common["bundle"],
            "caddy_cert_file": str(tls / "edge.pem"), "caddy_key_file": str(tls / "edge-key.pem"),
            "caddy_uid": 61010, "caddy_gid": 61010, "caddy_dir": str(tmp_path / "app"),
            "caddy_container_config_dir": "/etc/caddy", "caddy_acme_cert_name": "edge",
        }  # fmt: skip
        stored = "edge"
    else:
        names = {
            "openbao_install_dir": "/opt/o", "openbao_lego_version": "5.6.0", "openbao_acme_dir": common["acme_dir"],
            "openbao_acme_server": common["server"], "openbao_acme_email": "", "openbao_acme_dns_provider": "cloudflare",
            "openbao_acme_token_env": common["token_env"], "openbao_acme_env_file": common["env_file"],
            "openbao_acme_propagation_wait": "30s", "openbao_acme_renew_days": 30, "openbao_acme_key_type": "ec256",
            "openbao_acme_domains": [NAME], "openbao_acme_trust_bundle": common["bundle"],
            "openbao_tls_cert_file": str(tls / "server.pem"), "openbao_tls_key_file": str(tls / "server-key.pem"),
            "openbao_owner": pwd.getpwuid(os.getuid()).pw_name, "openbao_group": grp.getgrgid(os.getgid()).gr_name, "openbao_systemctl_cli": "/bin/true",
            "openbao_service": "openbao",
        }  # fmt: skip
        stored = "openbao"
    names.update(v)
    script = tmp_path / "renew.py"
    script.write_text(env.from_string(template.read_text()).render(**names))
    loader = SourceFileLoader(f"acme_{template.name}_{id(tmp_path)}", str(script))
    mod = module_from_spec(spec_from_loader(loader.name, loader))
    loader.exec_module(mod)
    mod.stored = stored
    return mod


def store(mod, tmp_path, pki, which="one"):
    d = tmp_path / "acme" / "certificates"
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{mod.stored}.crt").write_bytes((pki / f"{which}.crt").read_bytes())
    (d / f"{mod.stored}.key").write_bytes((pki / f"{which}.key").read_bytes())
    return d


def readers_key_is_unreadable(monkeypatch):
    """The unit's denial: giving the key to its reader (fchown) leaves this process unable to open it."""

    # root opens any file, so the denial cannot be shown to it: fail loudly rather than skip
    assert os.geteuid() != 0, "run this test unprivileged (CI does)"

    def fchown(fd, uid, gid):
        if not os.fstat(fd).st_mode & 0o004:  # the key (the certificate is world-readable)
            os.fchmod(fd, 0)

    monkeypatch.setattr(os, "fchown", fchown)


def can_open(path) -> bool:
    try:
        open(path, "rb").close()
    except PermissionError:
        return False
    return True


@pytest.mark.parametrize("template", [CADDY, OPENBAO], ids=["caddy", "openbao"])
def test_a_key_the_unit_cannot_open_is_still_checked_and_installed(
    tmp_path, pki, monkeypatch, template
):
    """The blocker: the pair check after the rename read the installed key by path. Now it reads
    the key through the descriptor staging kept open, so the install goes through under the unit's
    capability set, and the key it checks is the one in place."""
    mod = render(template, tmp_path, pki)
    store(mod, tmp_path, pki)
    readers_key_is_unreadable(monkeypatch)
    assert mod.install_pair() == (None, True)
    assert not can_open(mod.CONF["key"])  # the denial really held: by path, the key is closed to us
    assert os.stat(mod.CONF["key"]).st_size > 0
    assert Path(mod.CONF["cert"]).read_bytes() == (pki / "one.crt").read_bytes()
    assert sorted(p.name for p in Path(mod.CONF["key"]).parent.glob(".acme-*")) == []
    os.chmod(mod.CONF["key"], 0o600)  # the test, not the unit, looks at what was installed
    assert Path(mod.CONF["key"]).read_bytes() == (pki / "one.key").read_bytes()


@pytest.mark.parametrize("template", [CADDY, OPENBAO], ids=["caddy", "openbao"])
def test_the_check_through_the_held_key_still_refuses_a_key_that_does_not_pair(
    tmp_path, pki, monkeypatch, template
):
    """Reading through the descriptor must not make the check weaker: a stored key that is not the
    certificate's is refused (and, on a first install, nothing is left installed)."""
    mod = render(template, tmp_path, pki)
    d = store(mod, tmp_path, pki)
    (d / f"{mod.stored}.key").write_bytes((pki / "two.key").read_bytes())
    readers_key_is_unreadable(monkeypatch)
    why, intact = mod.install_pair()
    assert "is not the key of" in why and why.endswith("nothing is installed"), why
    assert intact
    assert sorted(p.name for p in Path(mod.CONF["key"]).parent.iterdir()) == []


@pytest.mark.parametrize("template", [CADDY, OPENBAO], ids=["caddy", "openbao"])
def test_a_later_run_does_not_reinstall_a_current_pair_it_cannot_open(
    tmp_path, pki, monkeypatch, template
):
    """The installed key is closed to the unit, so byte-comparing it failed and every daily run
    re-installed (and reloaded for) a certificate that had not changed. A current certificate
    means a current key (the key is renamed first); a different certificate does not."""
    mod = render(template, tmp_path, pki)
    d = store(mod, tmp_path, pki)
    readers_key_is_unreadable(monkeypatch)
    assert mod.install_pair() == (None, True)
    assert mod.same(mod.STORED_CERT, mod.CONF["cert"]) and mod.key_current()
    (d / f"{mod.stored}.crt").write_bytes((pki / "two.crt").read_bytes())
    (d / f"{mod.stored}.key").write_bytes((pki / "two.key").read_bytes())
    assert not mod.same(mod.STORED_CERT, mod.CONF["cert"])
    os.chmod(mod.CONF["key"], 0o600)  # a key that can be read is compared byte for byte
    assert not mod.key_current()


@pytest.mark.parametrize("template", [CADDY, OPENBAO], ids=["caddy", "openbao"])
def test_a_refused_pair_over_an_unreadable_key_is_rolled_back_and_not_called_current(
    tmp_path, pki, monkeypatch, template
):
    """The earlier key cannot be read here to be written back, so it is set aside by rename and the
    same file put back: after a failed check the OLD pair is in place (the old key's inode, the old
    certificate), nothing is left over, and the next run does not treat the refused pair as
    current (the stored certificate still differs from the installed one)."""
    mod = render(template, tmp_path, pki)
    store(mod, tmp_path, pki)
    readers_key_is_unreadable(monkeypatch)
    assert mod.install_pair() == (None, True)
    key = Path(mod.CONF["key"])
    inode = key.stat().st_ino
    d = store(mod, tmp_path, pki, "two")
    real = mod.problem
    mod.problem = lambda c, *a: "it did not verify" if c == mod.CONF["cert"] else real(c, *a)
    why, intact = mod.install_pair()
    assert why.endswith("it did not verify; the old pair is back") and intact, why
    assert key.stat().st_ino == inode
    assert Path(mod.CONF["cert"]).read_bytes() == (pki / "one.crt").read_bytes()
    assert sorted(p.name for p in key.parent.glob(".acme-*")) == []
    assert not mod.same(mod.STORED_CERT, mod.CONF["cert"])  # the next run installs the stored pair
    assert (d / f"{mod.stored}.crt").exists()


@pytest.mark.parametrize("name", sorted(SERVICES))
def test_the_unit_keeps_only_the_capability_to_chown(name):
    """The fix adds no capability: this is the set the simulation above stands for."""
    text = SERVICES[name].read_text()
    assert "CapabilityBoundingSet=CAP_CHOWN\n" in text
    assert "CAP_DAC" not in text
