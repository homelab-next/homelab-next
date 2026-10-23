# SPDX-License-Identifier: Apache-2.0
"""tools/caddy_lint.py: forward_auth strips client identity headers first; Caddy >= 2.11.2."""

import io
import json
import sys
import textwrap
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import caddy_lint as lint

REPO = Path(__file__).resolve().parents[2]

GOOD = """\
(hnx_forward_auth) {
	route {
		# client-sent identity headers never reach the service
		request_header -*authentik*
		forward_auth idp:9443 {
			uri /outpost.goauthentik.io/auth/caddy
			copy_headers X-Authentik-Username X-Authentik-Groups
		}
	}
}

app.lab.example {
	import hnx_forward_auth
	reverse_proxy app:8080
}
"""


def _strip(text: str) -> list[str]:
    return [f.detail for f in lint.lint_caddy(textwrap.dedent(text))]


def _missed(header: str, *spellings: str) -> str:
    return (
        f"client-sent {header} is not deleted before forward_auth in the same route in every "
        f"spelling (missed: {', '.join(spellings)})"
    )


ALL_USER = ("X-Authentik-Username", "X-Authentik_Username", "X_Authentik-Username",
            "X_Authentik_Username")  # fmt: skip


def test_the_generators_shape_passes():
    assert _strip(GOOD) == []


def test_forward_auth_outside_a_route_fails():
    # outside a route, Caddy runs forward_auth before request_header: the strip is too late
    text = GOOD.replace("\troute {\n", "\thandle {\n")
    assert _strip(text) == ["forward_auth is not directly inside a route block"]


def test_a_bare_forward_auth_in_a_site_fails():
    text = "app.lab.example {\n\tforward_auth idp:9443 {\n\t\tcopy_headers X-Authentik-Username\n\t}\n}\n"
    assert _strip(text) == ["forward_auth is not directly inside a route block"]


def test_a_strip_after_forward_auth_does_not_count():
    text = """\
    route {
        forward_auth idp:9443 {
            copy_headers X-Authentik-Username
        }
        request_header -*authentik*
    }
    """
    assert _strip(text) == [_missed("X-Authentik-Username", *ALL_USER)]


def test_the_underscore_spelling_is_required():
    text = GOOD.replace("-*authentik*", "-X-Authentik-*")
    assert _strip(text) == [
        _missed("X-Authentik-Username", *ALL_USER[1:]),
        _missed("X-Authentik-Groups", "X-Authentik_Groups", "X_Authentik-Groups",
                "X_Authentik_Groups"),
    ]  # fmt: skip


def test_the_mixed_spellings_are_required():
    """The snippet main generated: a dash and an underscore prefix wildcard.  A CGI-style
    upstream folds X-Authentik_Groups into HTTP_X_AUTHENTIK_GROUPS too, and Caddy 2.11.1 passes
    it through both wildcards (observed live)."""
    text = GOOD.replace("-*authentik*", "-X-Authentik-*\n\t\trequest_header -X_Authentik_*")
    assert _strip(text) == [
        _missed("X-Authentik-Username", "X-Authentik_Username", "X_Authentik-Username"),
        _missed("X-Authentik-Groups", "X-Authentik_Groups", "X_Authentik-Groups"),
    ]


@pytest.mark.parametrize("pattern", ["*authentik*", "*AUTHENTIK*", "*Authentik-*", "*thent*"])
def test_a_contains_wildcard_covers_every_spelling_in_any_case(pattern):
    text = GOOD.replace("*authentik*", pattern)
    if pattern == "*Authentik-*":  # a contains with a separator in it covers only that one
        assert len(_strip(text)) == 2
    else:
        assert _strip(text) == []


def test_header_names_match_case_insensitively():
    text = GOOD.replace("-*authentik*", "-x-authentik-*\n\t\trequest_header -x_authentik_*")
    text = text.replace("X-Authentik-Username X-Authentik-Groups", "X-AUTHENTIK-USER")
    assert _strip(text) == [_missed("X-AUTHENTIK-USER", "X-AUTHENTIK_USER", "X_AUTHENTIK-USER")]


def test_spellings():
    assert lint.spellings("A-b_C") == ["A-b-C", "A-b_C", "A_b-C", "A_b_C"]
    assert lint.spellings("Remote") == ["Remote"]


def test_exact_names_cover_only_themselves():
    text = """\
    route {
        request_header -X-Authentik-Username
        request_header -X_Authentik_Username
        request_header -X-Authentik_Username
        request_header -X_Authentik-Username
        forward_auth idp:9443 {
            copy_headers X-Authentik-Username X-Authentik-Email
        }
    }
    """
    assert _strip(text) == [
        _missed("X-Authentik-Email", "X-Authentik-Email", "X-Authentik_Email",
                "X_Authentik-Email", "X_Authentik_Email")
    ]  # fmt: skip


def test_a_strip_in_another_route_does_not_count():
    text = """\
    route {
        request_header -*authentik*
    }
    route {
        forward_auth idp:9443 {
            copy_headers X-Authentik-Groups
        }
    }
    """
    assert len(_strip(text)) == 1


def test_a_renamed_header_and_the_block_form_are_both_read():
    text = """\
    route {
        request_header -X-Remote-*
        request_header -X_Remote-*
        request_header -*_User
        forward_auth idp:9443 {
            copy_headers {
                X-Authentik-Username>X-Remote-User
            }
        }
    }
    """
    assert _strip(text) == []
    assert _strip(text.replace("-*_User", "-*_Groups")) == [
        _missed("X-Remote-User", "X-Remote_User", "X_Remote_User")
    ]


def test_a_templated_copy_headers_fails_closed():
    text = """\
    route {
        request_header -*authentik*
        forward_auth idp:9443 {
            copy_headers {{ authentik_copy_headers }}
        }
    }
    """
    assert _strip(text) == [
        "copy_headers is templated, so its strip cannot be checked: list the headers"
    ]


def test_an_inline_allow_waives_a_forward_auth():
    text = GOOD.replace("\t\trequest_header -*authentik*\n", "").replace(
        "forward_auth idp:9443 {",
        "forward_auth idp:9443 {  # caddy-lint: allow lab fixture",
    )
    assert _strip(text) == []


@pytest.mark.parametrize(
    ("version", "ok"),
    [
        ("2.8.4", False),
        ("2.10.2", False),
        ("2.11.1", False),
        ("2.11.2-beta.1", False),
        ("2.11", False),  # floating
        ("v2.11.2", True),
        ("2.11.7", True),
        ("2.12.0", True),
        ("3.0.0", True),
        ("latest", False),
    ],
)
def test_version_floor(version, ok):
    assert lint.version_ok(version) is ok


REGISTRY = """\
registry_version: 1
services:
  edge-proxy:
    impl: caddy
    host: edge-core
    version: "{v}"
"""


@pytest.mark.parametrize(("v", "n"), [("2.8.4", 1), ("2.11.1", 1), ("2.11.2", 0), ("2.11.7", 0)])
def test_a_registry_caddy_pin(v, n):
    found = lint.lint_pins(REGISTRY.format(v=v), "services.yml")
    assert len(found) == n
    if n:
        assert found[0].line == 6 and found[0].rule == "pin"


def test_a_caddy_service_without_a_version_fails():
    assert len(lint.lint_pins("services:\n  edge:\n    impl: caddy\n")) == 1


@pytest.mark.parametrize(
    ("image", "n"),
    [
        ("caddy:2.8-alpine", 1),
        ("caddy:2.11.1", 1),
        ("caddy", 1),
        ("docker.io/library/caddy:2.10.2", 1),
        ("caddy:2.11.7-alpine@sha256:" + "a" * 64, 0),
        ("caddy:2.11.2", 0),
        ("ghcr.io/example/caddy-builder:1.0.0", 0),  # not the Caddy image
    ],
)
def test_a_compose_image(image, n):
    doc = f"services:\n  edge:\n    image: {image}\n"
    assert len(lint.lint_pins(doc)) == n


def test_a_caddy_version_variable():
    assert len(lint.lint_pins("caddy_version: 2.10.2\n")) == 1
    assert lint.lint_pins("caddy_version: 2.11.7\n") == []


def test_a_dockerfile_from():
    assert len(lint.lint_dockerfile("FROM caddy:2.10.2-builder AS b\n")) == 1
    assert lint.lint_dockerfile("FROM --platform=$BUILDPLATFORM caddy:2.11.7\n") == []


def test_markdown_blocks_and_files_in_the_tree(tmp_path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "edge.md").write_text(
        "Setup:\n\n   ```caddyfile\n   app.lab.example {\n   \tforward_auth idp:9443 {\n"
        "   \t\tcopy_headers X-Authentik-Username\n   \t}\n   }\n   ```\n"
    )
    (tmp_path / "Caddyfile.j2").write_text(GOOD)
    findings, counts = lint.scan(tmp_path)
    assert [(f.path, f.line) for f in findings] == [("docs/edge.md", 5)]
    assert counts["caddy_configs"] == 2


def test_generated_configs_are_checked(tmp_path, monkeypatch):
    """The generator's own output is linted, so a regression in its snippet fails the gate."""
    from homelabnext.generators import builtin

    registry = (REPO / "examples" / "services.yml").read_text(encoding="utf-8")
    (tmp_path / "services.yml").write_text(registry)
    findings, counts = lint.scan(tmp_path)
    assert findings == [] and counts["generated"] == 1

    original = builtin._forward_auth_snippet
    monkeypatch.setattr(
        builtin,
        "_forward_auth_snippet",
        lambda endpoint: original(endpoint).replace("-*authentik*", "-X-Authentik-*"),
    )
    findings, _ = lint.scan(tmp_path)
    assert {f.path for f in findings} == {"services.yml (caddy generator)"}
    assert all("X_Authentik_" in f.detail for f in findings) and len(findings) == 2


def test_main_reports_and_exits(tmp_path):
    (tmp_path / "compose.yml").write_text("services:\n  edge:\n    image: caddy:2.9.0\n")
    out, err = io.StringIO(), io.StringIO()
    assert lint.main([str(tmp_path)], out=out, err=err) == 1
    assert "compose.yml:3: [pin] caddy image tag '2.9.0'" in err.getvalue()
    out = io.StringIO()
    assert lint.main([str(tmp_path), "--json"], out=out, err=err) == 1
    assert json.loads(out.getvalue())["findings"][0]["rule"] == "pin"
    assert lint.main([str(tmp_path / "missing")], out=out, err=err) == 2


def test_this_repo_pins_a_fixed_caddy_and_strips_before_forward_auth():
    """Every Caddy pin in the tree was 2.8.4: 2.9.0-2.11.1 pass a client-sent identity header
    the IdP omits, and up to 2.11.1 the underscore spelling. The tree must stay clean."""
    out, err = io.StringIO(), io.StringIO()
    assert lint.main([str(REPO)], out=out, err=err) == 0, err.getvalue()
    assert "0 finding(s)" in out.getvalue()
