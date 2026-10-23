# SPDX-License-Identifier: Apache-2.0
"""A third party's hosted MCP server: ``transport.type: remote`` (round 4, F5).

A lab server is reached by registry name (``endpoint: svc:<name>``); a vendor's hosted server
(a tracker, a notes service, a code host's hosted MCP) has no registry entry, so its record names
an explicit https URL: no userinfo, no query, a public DNS host, internet egress, credentials only
as headers' ``secret:`` names.  Every value is fictional."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
import yaml

from homelabnext.mcp import clients, servers
from homelabnext.registry.model import load

ROOT = Path(__file__).resolve().parents[2]
REMOTE = yaml.safe_load((ROOT / "schemas/platform/examples/mcp_server.remote.yml").read_text())
REGISTRY = load(ROOT / "examples" / "services.yml")


def _problems(rec: dict, registry=None) -> list[str]:
    return servers._schema_problems(rec, "x") or (
        servers.remote_problems(rec, "x", registry)
        + servers._egress_problems(rec, "x")
        + servers._literal_problems(rec, "x")
    )


def _edit(**changes) -> dict:
    rec = copy.deepcopy(REMOTE)
    for path, value in changes.items():
        *head, last = path.split("__")
        d = rec
        for k in head:
            d = d[k]
        if value is None:
            d.pop(last, None)
        else:
            d[last] = value
    return rec


def test_a_hosted_server_with_an_https_url_is_a_valid_record():
    assert _problems(REMOTE, REGISTRY) == []


@pytest.mark.parametrize(
    ("changes", "phrase"),
    [
        ({"transport__url": "http://mcp.tracker.example.com/mcp"}, "does not match"),
        ({"transport__url": "https://fakeuser:fakepw@mcp.tracker.example.com/mcp"}, "does not match"),
        ({"transport__url": "https://mcp.tracker.example.com/mcp?api_key=fake1"}, "does not match"),
        ({"transport__url": "https://mcp.tracker.example.com/mcp#x"}, "does not match"),
        ({"transport__url": "https://192.0.2.10/mcp"}, "names a public host"),  # no-raw-endpoint: allow the IP literal check refuses
        ({"transport__url": "https://localhost/mcp"}, "does not match"),
        # private suffixes, assembled so the repository holds no private host name
        ({"transport__url": "https://mcp.tracker." + "internal/mcp"}, "names a public host"),
        ({"transport__url": "https://tracker." + "home.arpa/mcp"}, "names a public host"),
        ({"transport__url": "https://mcp.example/mcp"}, "names a public host"),
        ({"egress": "none"}, "egress names internet"),
        ({"egress": ["svc:notify"]}, "egress names internet"),
        ({"data_tier": "local-only"}, "data_tier is cloud-allowed"),
        ({"runtime": "agent-local"}, "runtime hosted goes with a remote transport"),
        ({"origin": {"kind": "image", "image": "registry.example/x", "digest": None}},
         "a hosted origin goes with a remote transport"),
        ({"headers__Authorization": "Bearer fakeTok3nAbC9xYz12345"}, "does not match"),
        ({"env": {"TOKEN": "secret:mcp/x"}}, "env is for a stdio server"),
    ],
    ids=lambda v: str(v)[:60],
)  # fmt: skip
def test_a_hosted_server_is_https_public_internet_and_secret_headers_only(changes, phrase):
    problems = _problems(_edit(**changes), REGISTRY)
    assert any(phrase in p for p in problems), problems


#: key-shaped path segments, assembled so the repository holds no token-shaped literal
_PATH_KEYS = ["sk-" + "ak-" + "9f8e7d6c5b4a3928" + "1706f5e4d3c2b1a0", "gh" + "p_" + "fake0123456789" +
              "abcdefghijklmnopqrstuv", "Fake" + "Key" + "9x8y7z"]  # fmt: skip


@pytest.mark.parametrize(
    "path", [f"/mcp/{_PATH_KEYS[0]}/sse", f"/{_PATH_KEYS[1]}/mcp", f"/v1/{_PATH_KEYS[2]}"]
)
def test_a_credential_in_a_hosted_urls_path_is_refused_and_never_rendered(path):
    """Hosted endpoints often carry the key in the path; a record cannot hold a secret: name
    there, so check refuses any path but an MCP path or plain words, and render refuses too."""
    rec = _edit(transport__url="https://mcp.tracker.example.com" + path)
    assert any("URL path may carry a credential" in p for p in _problems(rec, REGISTRY))
    with pytest.raises(clients.RenderError, match="URL path may carry a credential"):
        clients.definition(_inst({**rec, "status": "active"}), "claude-code")


#: key-shaped host labels, assembled so the repository holds no token-shaped literal
_HOST_KEYS = ["9f8e7d6c5b4a3928" + "1706f5e4d3c2b1a0", _PATH_KEYS[0]]


@pytest.mark.parametrize(
    "host",
    [
        f"{_HOST_KEYS[0]}.mcp.tracker.example.com",
        f"{_HOST_KEYS[1]}.tracker.example.com",
        f"{_HOST_KEYS[1]}.com",  # the second-level label itself
        f"mcp.{_HOST_KEYS[1]}",  # the top-level position
    ],
)
def test_a_credential_in_a_hosted_urls_host_is_refused_and_never_rendered(host):
    rec = _edit(transport__url=f"https://{host}/mcp")
    assert any("URL host may carry a credential" in p for p in _problems(rec, REGISTRY))
    with pytest.raises(clients.RenderError, match="URL host may carry a credential"):
        clients.definition(_inst({**rec, "status": "active"}), "claude-code")


@pytest.mark.parametrize(
    "host",
    [
        "mcp.tracker.example.com",
        "eu-west-3.mcp.tracker.example.com",
        "api2.example.com",
        # long IDN labels read as random letters and digits encoded; they are judged decoded
        "mcp.xn--80aealotwbjpid2k.example.com",
        "mcp.xn--3e0bx5e6xzftae3gxzpskhile.example.com",
        "xn--ok-gzel-trke-alan-ad-20bl98bfa15k.example.com",
    ],
)
def test_a_plain_hosted_url_host_is_accepted(host):
    assert _problems(_edit(transport__url=f"https://{host}/mcp"), REGISTRY) == []


@pytest.mark.parametrize("path", ["", "/", "/mcp", "/sse", "/v1/mcp", "/servers/tracker/mcp"])
def test_a_plain_hosted_url_path_is_accepted(path):
    assert _problems(_edit(transport__url="https://mcp.tracker.example.com" + path), REGISTRY) == []


#: ordinary hosted paths: lower-case words, hyphenated words and versions, in any order
_ORDINARY_PATHS = [
    "/v1/mcp", "/v2/mcp/", "/api/v2/sse", "/api/v1/mcp/stream", "/mcp/stream", "/mcp/v2",
    "/tenant-name/mcp", "/tenant-name/v3/sse", "/servers/issue-tracker/mcp",
]  # fmt: skip


@pytest.mark.parametrize("path", _ORDINARY_PATHS)
def test_an_ordinary_hosted_url_path_is_checked_and_rendered(path):
    """The path-segment rule refuses a key-shaped segment, not an ordinary one: words, hyphenated
    words and versions pass check and render as written."""
    from homelabnext.mcp.credentials import plain_url_path

    url = "https://mcp.tracker.example.com" + path
    rec = _edit(transport__url=url)
    assert plain_url_path(path)
    assert _problems(rec, REGISTRY) == []
    assert url in json.dumps(clients.definition(_inst({**rec, "status": "active"}), "claude-code"))


@pytest.mark.parametrize(
    "path",
    [
        f"/tenant-name/{_PATH_KEYS[0]}/mcp",
        f"/api/v2/{_PATH_KEYS[2]}/sse",
        f"/mcp/stream/{_PATH_KEYS[1]}",
    ],
)
def test_a_key_shaped_segment_among_ordinary_ones_is_still_refused(path):
    rec = _edit(transport__url="https://mcp.tracker.example.com" + path)
    assert any("URL path may carry a credential" in p for p in _problems(rec, REGISTRY))


#: credential shapes the path-segment rule cannot detect, accepted by design: it judges shape, and
#: these are shaped like words (``plain_url_path``'s docstring names the limit)
_UNDETECTABLE_PATHS = [
    "/mcp/correct-horse-battery-staple/sse",  # a capability slug made of words
    "/tenant-name/brave-purple-otter/mcp",  # an adjective-noun capability slug
    "/tenant-name/zmnvflrwyvxlcovq/mcp",  # a random letters-only run, 16 characters
    "/tenant-name/zmnvflrwyvxlcovqdyfqmlpxapbjwtss/mcp",  # the same, 32 characters
    "/mcp/beacadddfdbadaddeafdcfbeacaaafea/sse",  # 32 hex digits that use only a-f
]


@pytest.mark.parametrize("path", _UNDETECTABLE_PATHS)
def test_a_word_shaped_credential_in_the_path_is_not_detected_by_design(path):
    """The rule's stated limit, pinned so it stays visible: a letters-only segment is accepted
    whatever it carries. Deciding whether a word-shaped segment is a secret is the reviewer's
    call; if the rule is tightened, move the newly refused shapes out of this list."""
    from homelabnext.mcp.credentials import plain_url_path, url_carries

    assert plain_url_path(path)
    assert not url_carries("https://mcp.tracker.example.com" + path)
    assert _problems(_edit(transport__url="https://mcp.tracker.example.com" + path), REGISTRY) == []


def test_a_lab_servers_transport_path_carries_no_credential_either():
    rec = yaml.safe_load((ROOT / "schemas/platform/examples/mcp_server.http.yml").read_text())
    assert _problems(rec, REGISTRY) == []
    rec["transport"]["path"] = f"/mcp/{_PATH_KEYS[0]}"
    assert any("transport.path may carry a credential" in p for p in _problems(rec, REGISTRY))


@pytest.mark.parametrize(
    "host",
    [
        "0x7f.0x1",  # the loopback address to a WHATWG URL parser and to getaddrinfo
        "198.51.100.0x1",  # no-raw-endpoint: allow a hex last label the IPv4 check refuses
        "192.0.2.0xa",  # no-raw-endpoint: allow a hex last label the IPv4 check refuses
        "0177.0.0.1",  # no-raw-endpoint: allow an octal address the IPv4 check refuses
        "2130706433",  # one decimal number
        "a1.0x0",  # a name that ends in a number is an address
        "0x7f.0x0.0x0.0x1",
    ],
)
def test_a_remote_url_never_names_an_ipv4_address_in_any_notation(host):
    problems = _problems(_edit(transport__url=f"https://{host}/mcp"), REGISTRY)
    assert any("names a public host" in p or "does not match" in p for p in problems), problems
    assert servers.numeric_host(host)


@pytest.mark.parametrize("host", ["mcp.tracker.example.com", "x0a.example.com", "0x7f.example.com"])
def test_a_name_with_a_number_like_label_is_still_a_name(host):
    assert not servers.numeric_host(host)


def test_a_lab_host_is_reached_by_registry_name_not_a_remote_url():
    host = sorted(REGISTRY.hosts)[0]
    rec = _edit(transport__url=f"https://{host}.tools.example.com/mcp")
    assert any("names a lab host" in p for p in _problems(rec, REGISTRY))
    rec = _edit(transport__url=f"https://mcp.{REGISTRY.domain}/mcp")
    assert any("names a lab host" in p or "public host" in p for p in _problems(rec, REGISTRY))


def test_a_hosted_origin_is_not_a_stdio_server():
    rec = _edit(transport={"type": "stdio"}, headers=None, runtime="hosted")
    assert any("a hosted origin goes with a remote transport" in p for p in _problems(rec))


def _inst(rec: dict) -> clients.Instance:
    return clients.Instance(name=rec["id"], server=rec["id"], profile="p", lane="real",
                            record=rec, params={})  # fmt: skip


def test_a_hosted_server_renders_for_the_clients_that_speak_http():
    inst = _inst({**REMOTE, "status": "active"})
    assert clients.definition(inst, "claude-code") == {
        "type": "http",
        "url": "https://mcp.tracker.example.com/mcp",
        "headers": {"Authorization": "Bearer ${HNX_SECRET_MCP_TRACKER_TOKEN}"},
    }
    assert clients.definition(inst, "generic")["transport"] == "streamable-http"
    assert clients.definition(inst, "hermes")["url"] == "https://mcp.tracker.example.com/mcp"
    assert clients.definition(inst, "claude-desktop") is None  # stdio only: reported, left out
    sse = _inst(_edit(transport__protocol="sse"))
    assert clients.definition(sse, "claude-code")["type"] == "sse"
    with pytest.raises(clients.RenderError, match="legacy sse"):
        clients.definition(sse, "hermes")
    plain = _inst(_edit(transport__url="http://mcp.tracker.example.com/mcp"))
    with pytest.raises(clients.RenderError, match="never plaintext"):
        clients.definition(plain, "claude-code")
    entry, why = clients.orch_kind("tracker", REMOTE)
    assert entry is None and "remote is skipped" in why[0]
    json.dumps(clients.definition(inst, "claude-code"))  # a plain JSON value


def _hosted_classes(tmp_path: Path):
    from homelabnext.agent.readers import ToolClasses

    d = tmp_path / "mcp"
    d.mkdir()
    (d / "tracker.yml").write_text(yaml.safe_dump(REMOTE))
    (d / "notes.yml").write_text((ROOT / "examples/mcp/notes.yml").read_text())
    return ToolClasses.from_catalog(servers.load(d))


def test_a_local_only_profile_gets_a_hosted_server_only_by_a_named_exception(tmp_path):
    """Round 5: a cloud-allowed hosted server granted to a local-only profile (one that also
    holds local-only servers) would carry the local-only context to the vendor."""
    from homelabnext.agent.compiler import CeilingPolicy

    classes = _hosted_classes(tmp_path)
    grant = ["notes", "tracker"]
    entry = {"mcp": grant, "capabilities": [], "tier": "read", "data_tier": "local-only"}

    def problems(e: dict, tier: str = "local-only") -> list[str]:
        pol = CeilingPolicy.from_mapping({"ceilings": {"profile:x": e}})
        return pol.attestation_problems("profile:x", tier, None, grant, classes)

    refused = problems(entry)
    assert any("reach the internet" in p and "'tracker'" in p for p in refused), refused
    assert not any("'notes'" in p for p in refused)  # notes stays in the lab
    assert problems({**entry, "internet_mcp": ["tracker"]}) == []
    # a profile that declares itself local-only (the policy attests no tier) is held to it too
    declared = problems({k: v for k, v in entry.items() if k != "data_tier"})
    assert any("reach the internet" in p for p in declared), declared
    # a cloud-allowed profile may use it (and is refused the local-only server instead)
    cloud = problems({**entry, "data_tier": "cloud-allowed"}, "cloud-allowed")
    assert not any("reach the internet" in p for p in cloud), cloud


@pytest.mark.parametrize("bad", ["tracker", [1], ["Not A Slug"]])
def test_the_internet_exception_is_a_list_of_server_ids(bad):
    from homelabnext.agent.compiler import CeilingPolicy
    from homelabnext.agent.errors import SpecError

    entry = {"mcp": [], "capabilities": [], "tier": "read", "internet_mcp": bad}
    with pytest.raises(SpecError, match="internet_mcp is a list of MCP server ids"):
        CeilingPolicy.from_mapping({"ceilings": {"profile:x": entry}})


@pytest.mark.parametrize(
    ("host", "labels"),
    [
        (_HOST_KEYS[1], [0]),  # a single-label host
        (_HOST_KEYS[1] + ".", [0]),
        (f"mcp.{_HOST_KEYS[1]}", [1]),  # the top-level position
        ("localhost", []),
        ("mcp", []),
        ("xn--80aealotwbjpid2k.example", []),
        # does not decode: judged as written (no digits here, so not a credential)
        ("xn--zzzz-abcdefghij.example", []),
        # does not decode, and reads as a key as written
        ("xn--zzzz-a1b2c3d4e5f6g7h8i9j0.example", [0]),
    ],
)
def test_every_host_label_is_checked_and_idn_labels_are_judged_decoded(host, labels):
    from homelabnext.mcp import credentials

    assert credentials.secret_host_labels(host) == labels


#: a label Python 3.13's punycode decoder answers with OverflowError, not UnicodeError
_OVERFLOW_LABEL = "xn--792ad84db474521944884823204797e8aeb26"


def test_an_idn_label_the_decoder_crashes_on_is_judged_not_raised():
    from homelabnext.mcp import credentials, importer

    host = f"{_OVERFLOW_LABEL}.tracker.example.com"
    assert credentials.secret_host_labels(host) == [0]  # read as written: key-shaped
    rec = _edit(transport__url=f"https://{host}/mcp")
    assert any("URL host may carry a credential" in p for p in _problems(rec, REGISTRY))
    assert importer._plain_host(host) == "unknown.tracker.example.com"
