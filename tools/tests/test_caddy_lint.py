# SPDX-License-Identifier: Apache-2.0
"""tools/caddy_lint.py: forward_auth strips client identity headers first; Caddy >= 2.11.2."""

import io
import json
import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
import yaml

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
	request_header -*Authentik*
	import hnx_forward_auth
	reverse_proxy app:8080
}
"""
# The site-level strip is spelled -*Authentik* (Caddy matches it case-insensitively) so that the
# tests below that rewrite the route's -*authentik* leave it alone.


def _strip(text: str) -> list[str]:
    return [f.detail for f in lint.lint_caddy(textwrap.dedent(text))]


def _missed(header: str, *spellings: str) -> str:
    return (
        f"client-sent {header} is not deleted before forward_auth in the same route in every "
        f"spelling (missed: {', '.join(spellings)})"
    )


def _site(fragment: str, *deletes: str) -> str:
    """``fragment`` inside a site whose site-level strip deletes ``*Authentik*`` and ``deletes``,
    so a test of the route-level rule sees that rule's findings only."""
    strips = "".join(f"\trequest_header -{d}\n" for d in ("*Authentik*", *deletes))
    return f"app.lab.example {{\n{strips}{textwrap.indent(textwrap.dedent(fragment), chr(9))}}}\n"


ALL_USER = ("X-Authentik-Username", "X-Authentik_Username", "X_Authentik-Username",
            "X_Authentik_Username")  # fmt: skip


def test_the_generators_shape_passes():
    assert _strip(GOOD) == []


def test_forward_auth_outside_a_route_fails():
    # outside a route, Caddy runs forward_auth before request_header: the strip is too late
    text = GOOD.replace("\troute {\n", "\thandle {\n")
    assert _strip(text) == ["forward_auth is not directly inside a route block"]


def test_a_bare_forward_auth_in_a_site_fails():
    text = "app.lab.example {\n\trequest_header -*authentik*\n\tforward_auth idp:9443 {\n\t\tcopy_headers X-Authentik-Username\n\t}\n}\n"
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
    assert _strip(_site(text)) == [
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
    assert len(_strip(_site(text))) == 1


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
    text = _site(text, "*remote*")
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


def test_an_inline_allow_waives_only_its_own_forward_auth():
    """One allow anywhere in the file must not waive every other forward_auth in it."""
    allowed = GOOD.replace(
        "forward_auth idp:9443 {", "forward_auth idp:9443 {  # caddy-lint: allow x"
    )
    unallowed = "other.lab.example {\n\trequest_header -*authentik*\n\tforward_auth idp:9443 {\n\t\tcopy_headers X-Authentik-Username\n\t}\n}\n"
    assert _strip(allowed + unallowed) == ["forward_auth is not directly inside a route block"]


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
        # semver precedence: a pre-release sorts before its own release only
        ("v2.11.2-rc.1", False),
        ("2.12.0-beta.1", True),
        ("2.11.2+build.5", True),
    ],
)
def test_version_floor(version, ok):
    assert lint.version_ok(version) is ok


@pytest.mark.parametrize(
    ("tag", "ok"),
    [
        ("2.11.7-alpine", True),
        ("2.11.7-builder-alpine", True),
        ("2.11.7-windowsservercore-ltsc2022", True),
        ("2.11.2-rc.1", False),  # a release candidate of the first fixed release is not it
        ("2.11.2-rc.1-alpine", False),
        ("2.11.1-alpine", False),
        ("2-alpine", False),
        ("2.12.0-beta.1-builder", True),
    ],
)
def test_image_tags(tag, ok):
    assert lint.tag_ok(tag) is ok


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
        ("caddy:2.11.2-rc.1", 1),
        ("caddy:latest", 1),
        ("caddy@sha256:" + "a" * 64, 1),  # a digest says nothing a reviewer can read
        # behind any registry or pull-through prefix
        ("mirror.gcr.io/library/caddy:2.8.4", 1),
        ("public.ecr.aws/docker/library/caddy:2.8.4", 1),
        ("registry.lab.example:5000/proxy/library/caddy:2.8.4", 1),
        ("caddy/caddy:2.8.4", 1),
        ("registry.lab.example/proxy/library/caddy:2.11.7", 0),
        # an image built on Caddy: its tag is its own version, so it needs a reviewed allow
        ("ghcr.io/example/caddy-builder:1.0.0", 1),
        ("example/caddy-docker-proxy:2.8", 1),
        # compose interpolation: a default is what gets pulled when nothing overrides it
        ("caddy:${CADDY_TAG:-2.8.4}", 1),
        ("caddy:${CADDY_TAG:-2.11.7}", 0),
        ("caddy:${CADDY_TAG-2.11.7}", 0),
        ('"caddy:$CADDY_TAG"', 1),
        ("caddy:${CADDY_TAG}", 1),
        ("caddy:${CADDY_TAG:?set it}", 1),
        ("${EDGE_IMAGE:-caddy:2.8.4}", 1),
        ('"{{ caddy_image }}"', 1),
        ("python:3.12", 0),
        ('"{{ app_image }}"', 0),  # nothing says this one is Caddy
    ],
)
def test_a_compose_image(image, n):
    doc = f"services:\n  edge:\n    image: {image}\n"
    assert len(lint.lint_pins(doc)) == n


def test_the_same_image_twice_is_two_findings_on_their_own_lines():
    doc = "services:\n  a:\n    image: caddy:2.8.4\n  b:\n    image: caddy:2.8.4\n"
    assert [f.line for f in lint.lint_pins(doc)] == [3, 5]


def test_an_inline_allow_waives_only_its_own_line():
    doc = (
        "services:\n  a:\n    image: caddy:2.8.4  # caddy-lint: allow throwaway fixture\n"
        "  b:\n    image: caddy:2.8.4\n"
    )
    assert [f.line for f in lint.lint_pins(doc)] == [5]


def test_an_allowed_service_does_not_waive_one_whose_name_it_contains():
    doc = (
        "registry_version: 1\nservices:\n  edge-proxy:\n    impl: caddy\n"
        '    version: "2.8.4"  # caddy-lint: allow lab fixture\n'
        '  proxy:\n    impl: caddy\n    version: "2.8.4"\n'
    )
    found = lint.lint_pins(doc)
    assert [(f.line, f.detail.split(" caddy ")[0]) for f in found] == [(8, "service proxy")]


@pytest.mark.parametrize(
    ("doc", "lines"),
    [
        ("caddy_image_tag: 2.8.4\ncaddy_release: v2.8.4\n", [1, 2]),
        ("CADDY_VERSION: 2.10.2\ncaddy_builder_tag: 2.11.7\n", [1]),
        ('caddy_image: "caddy:2.8.4"\n', [1]),
        ('caddy_image: "{{ edge_image }}"\n', [1]),
        ("caddy_image: registry.lab.example/edge:1.0\n", [1]),  # cannot tell which Caddy
        ('edge_image: "caddy:2.8.4"\n', [1]),
        ('image:\n  repository: caddy\n  tag: "2.8.4"\n', [3]),
        ("image:\n  repository: docker.io/library/caddy\n", [2]),
        ("image:\n  repository: caddy\n  tag: 2.11.7\n", []),
        ("x: !vault |\n  abc\ncaddy_version: 2.11.7\n", []),  # an Ansible tag is not an error
        ("x: !vault |\n  abc\ncaddy_version: 2.8.4\n", [3]),
        ("impl: caddy\nversion: 2.11.7\nnote: run xcaddy build v2.8.4 first\n", [3]),
    ],
)
def test_yaml_pins(doc, lines):
    assert [f.line for f in lint.lint_pins(doc)] == lines


def test_a_caddy_version_variable():
    assert len(lint.lint_pins("caddy_version: 2.10.2\n")) == 1
    assert lint.lint_pins("caddy_version: 2.11.7\n") == []


def test_a_dockerfile_from():
    assert len(lint.lint_dockerfile("FROM caddy:2.10.2-builder AS b\n")) == 1
    assert lint.lint_dockerfile("FROM --platform=$BUILDPLATFORM caddy:2.11.7\n") == []


@pytest.mark.parametrize(
    ("text", "lines"),
    [
        # review SF5: COPY --from an image (the usual way to put Caddy on another base)
        ("FROM alpine\nCOPY --from=caddy:2.8.4 /usr/bin/caddy /usr/bin/caddy\n", [2]),
        ("FROM alpine\nCOPY --from=docker.io/library/caddy:2.8.4 /usr/bin/caddy /x\n", [2]),
        ("FROM caddy:2.11.7-builder AS b\nFROM alpine\nCOPY --from=b /usr/bin/caddy /x\n", []),
        ("FROM alpine\nCOPY --from=0 /x /x\n", []),
        ("ARG IMG=caddy:2.8.4\nFROM alpine\nCOPY --from=${IMG} /x /x\n", [3]),
        ("FROM alpine\nRUN --mount=type=bind,from=caddy:2.8.4,source=/usr/bin/caddy,target=/c cp /c /x\n", [2]),
        # a CADDY_VERSION set on the command itself overrides the builder image's
        ("FROM caddy:2.11.7-builder AS b\nRUN CADDY_VERSION=v2.8.4 xcaddy build --with example.test/x\n", [2]),
        ("FROM golang:1.23\nRUN CADDY_VERSION=\"v2.11.7\" xcaddy build\n", []),
        # a quoted version, the exec form, a branch name
        ('FROM caddy:2.11.7-builder AS b\nRUN xcaddy build "v2.8.4"\n', [2]),
        ("FROM caddy:2.11.7-builder AS b\nRUN xcaddy build 'v2.8.4'\n", [2]),
        ('FROM caddy:2.11.7-builder AS b\nRUN ["xcaddy", "build", "v2.8.4"]\n', [2]),
        ('FROM caddy:2.11.7-builder AS b\nRUN ["xcaddy", "build", "--with", "example.test/x"]\n', []),
        ("FROM caddy:2.11.7-builder AS b\nRUN xcaddy build master\n", [2]),
        ("FROM caddy:2.11.7-builder AS b\nRUN xcaddy build && cp caddy /x\n", []),
        # review N2: distro packages, and the escape parser directive
        ("FROM alpine\nRUN apk add caddy=2.8.4-r0\n", [2]),
        ("FROM debian\nRUN apt-get install -y caddy=2.8.4-1 curl\n", [2]),
        ("FROM alpine\nRUN apk add caddy=2.11.2-r0\n", []),
        ("# escape=`\nFROM `\n  caddy:2.8.4\n", [2]),
        # review N1: nested defaults, to any depth
        ("FROM caddy:${A:-${B:-2.8.4}}\n", [1]),
        ("FROM caddy:${A:-${B:-${C:-2.8.4}}}\n", [1]),
        ("FROM caddy:${A:-${B:-${C:-2.11.7}}}\n", []),
    ],
)  # fmt: skip
def test_review_dockerfile_pin_shapes(text, lines):
    assert [f.line for f in lint.lint_dockerfile(text)] == lines


@pytest.mark.parametrize(
    ("value", "env", "got"),
    [
        ("caddy:${A:-${B:-2.8.4}}", {}, "caddy:2.8.4"),
        ("caddy:${A:-${B:-${C:-2.8.4}}}", {"B": "2.11.7"}, "caddy:2.11.7"),
        ("caddy:${A:-${B}}", {}, None),  # no value anywhere
        ("caddy:${A:-$B}", {"B": "2.11.7"}, "caddy:2.11.7"),
        ("caddy:${A", {}, None),  # never closed
        ("caddy:$$A", {}, None),  # a $ left over
    ],
)
def test_resolve_nested_defaults(value, env, got):
    assert lint.resolve(value, env) == got


def test_a_nested_default_in_compose():
    doc = "services:\n  edge:\n    image: caddy:${A:-${B:-2.8.4}}\n"
    assert [f.line for f in lint.lint_pins(doc)] == [3]
    assert lint.lint_pins(doc.replace("2.8.4", "2.11.7")) == []


@pytest.mark.parametrize(
    ("text", "lines"),
    [
        # an ARG default resolves into FROM
        ("ARG V=2.8.4\nFROM caddy:${V}\n", [2]),
        ("ARG V=2.11.7\nFROM caddy:$V-alpine\n", []),
        ("ARG CADDY_VERSION=2.8.4\nFROM caddy:${CADDY_VERSION}\n", [1, 2]),
        ("ARG V\nFROM caddy:${V}\n", [2]),  # no default: unpinned
        ("ARG CADDY_IMAGE=caddy:2.8.4\nFROM ${CADDY_IMAGE}\n", [1, 2]),
        ("ARG BASE\nFROM ${BASE}\n", [2]),  # could be Caddy
        ("ARG BASE=python:3.12\nFROM ${BASE}\n", []),
        # xcaddy builds the binary that ships, whatever the builder image's tag
        ("FROM caddy:2.11.7-builder AS b\nRUN xcaddy build v2.8.4 \\\n  --with example.test/x\n", [2]),
        ("FROM caddy:2.11.7-builder AS b\nRUN xcaddy build --with example.test/x\n", []),
        ("FROM golang:1.23 AS b\nRUN xcaddy build --with example.test/x\n", [2]),
        ("FROM golang:1.23 AS b\nENV CADDY_VERSION=v2.11.7\nRUN xcaddy build\n", []),
        ("ARG V=v2.8.4\nFROM golang:1.23\nRUN xcaddy build $V\n", [3]),
        # a later stage built FROM an earlier one is not an image
        ("FROM caddy:2.11.7-builder AS b\nFROM b\n", []),
        ("FROM caddy:2.8.4  # caddy-lint: allow fixture\nFROM caddy:2.8.4\n", [2]),
        ("FROM caddy:2.11.7\nRUN curl -LO https://github.com/caddyserver/caddy/releases/download/v2.8.4/x\n", [2]),
    ],
)  # fmt: skip
def test_dockerfile_pins(text, lines):
    assert [f.line for f in lint.lint_dockerfile(text)] == lines


@pytest.mark.parametrize(
    ("text", "lines"),
    [
        ("CADDY_VERSION=2.8.4\nCADDY_IMAGE=caddy:2.8.4\n", [1, 2]),  # .env
        ("export CADDY_VERSION=v2.11.7\n", []),
        ("module x\n\nrequire github.com/caddyserver/caddy/v2 v2.8.4\n", [3]),  # go.mod
        ("go get github.com/caddyserver/caddy/v2@v2.10.2\n", [1]),
        ("curl -LO .../caddy_2.8.4_linux_amd64.tar.gz\n", [1]),
        ("services:\n  edge:\n    image: {{ caddy_image }}:2.8.4\n", [3]),  # a compose template
        ("Caddy is the edge; tools/caddy_lint.py:40 reads caddy configs.\n", []),  # prose
        ("pin `caddy:2.11.7` or later\n", []),
        ("Dockerfile `FROM` and `xcaddy build` with ARG defaults\n", []),  # markdown prose
        ("RUN xcaddy build\n", [1]),
    ],
)
def test_text_pins(text, lines):
    pins = lint._Pins("f", text)
    pins.text()
    assert [f.line for f in pins.findings] == lines


@pytest.mark.parametrize(
    ("text", "lines"),
    [
        ('REG = {"edge": {"impl": "caddy", "version": "2.11.7"}}\n', []),
        ('svc = {}\nREG = {"edge": {**svc, "impl": "caddy",\n  "version": "2.8.4"}}\n', [3]),
        ('REG = {"edge": {"impl": "caddy", "version": VERSION}}\n', [1]),
        ('REG = {"edge": {"impl": "caddy"}}\n', [1]),
        ('IMAGE = "caddy:2.8.4"\nNAME = "caddy"\n', [1]),
        ('CMD = "xcaddy build v2.8.4"\n', [1]),
    ],
)
def test_python_pins(text, lines):
    assert [f.line for f in lint.lint_python(text)] == lines


def test_the_allowlist(tmp_path):
    (tmp_path / "compose.yml").write_text("services:\n  edge:\n    image: caddy:2.9.0\n")
    (tmp_path / "other.yml").write_text("services:\n  edge:\n    image: caddy:2.9.0\n")
    allow = tmp_path / "allow.yml"
    allow.write_text(
        "allow:\n  - path: compose.yml\n    reason: a fixture\n"
        "  - path: gone/*.yml\n    reason: nothing there\n"
    )
    found, _ = lint.scan(tmp_path, lint.load_allowlist(allow))
    assert [(f.path, f.rule) for f in found] == [
        ("other.yml", "pin"),
        ("tools/caddy_lint.allow.yml", "allowlist"),
    ]
    assert "'gone/*.yml' excuses nothing" in found[1].detail
    out, err = io.StringIO(), io.StringIO()
    assert lint.main([str(tmp_path), "--allowlist", str(allow)], out=out, err=err) == 1
    allow.write_text("allow:\n  - path: compose.yml\n")
    assert lint.main([str(tmp_path), "--allowlist", str(allow)], out=out, err=err) == 2
    assert "has no 'reason'" in err.getvalue()
    assert lint.main([str(tmp_path), "--allowlist", str(tmp_path / "no")], out=out, err=err) == 2


def test_markdown_blocks_and_files_in_the_tree(tmp_path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "edge.md").write_text(
        "Setup:\n\n   ```caddyfile\n   app.lab.example {\n   \trequest_header -*authentik*\n"
        "   \tforward_auth idp:9443 {\n"
        "   \t\tcopy_headers X-Authentik-Username\n   \t}\n   }\n   ```\n"
    )
    (tmp_path / "Caddyfile.j2").write_text(GOOD)
    findings, counts = lint.scan(tmp_path)
    assert [(f.path, f.line) for f in findings] == [("docs/edge.md", 6)]
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
    the IdP omits, and up to 2.11.1 the underscore spelling. The tree must stay clean, and the
    generated configs must stay covered: a generator change that made every registry fail
    would otherwise read as a clean run with nothing generated."""
    out, err = io.StringIO(), io.StringIO()
    assert lint.main([str(REPO), "--json"], out=out, err=err) == 0, out.getvalue()
    doc = json.loads(out.getvalue())
    assert doc["findings"] == [] and doc["discovery"] == "git"
    assert doc["generated"] >= 6


# ---------------------------------------------------------------- a path past the auth route

PAST = """\
app.lab.example {
	%s
	route%s {
		request_header -*authentik*
		forward_auth idp:9443 {
			uri /outpost.goauthentik.io/auth/caddy
			copy_headers X-Authentik-Username X-Authentik-Groups
		}
	}
	%s
	reverse_proxy app:8080
}
"""


@pytest.mark.parametrize(
    ("matcher", "beside"),
    [
        # Caddy sorts handle before route: /api/x never reaches forward_auth, and the client's
        # X-Authentik-Groups reached the upstream live on 2.11.7 (review probe a02)
        ("", "handle /api/* {\n\t\treverse_proxy api:8080\n\t}"),
        # a matcher on the route: every other path skips it (a03)
        (" /admin/*", ""),
        ("", "handle_path /static/* {\n\t\treverse_proxy files:8080\n\t}"),
    ],
)
def test_a_path_past_the_auth_route_needs_the_site_level_strip(matcher, beside):
    found = lint.lint_caddy(PAST % ("", matcher, beside))
    assert [(f.line, f.rule) for f in found] == [(1, "strip")]
    assert found[0].detail.startswith(
        "site app.lab.example runs forward_auth but has no matcherless site-level "
        "request_header deleting *authentik*:"
    )
    # a site-level request_header runs before every handle and route (verified live on 2.11.1
    # and 2.11.7: /api/x and / reach the upstream with no identity header, /admin/ with alice's)
    assert lint.lint_caddy(PAST % ("request_header -*authentik*", matcher, beside)) == []


@pytest.mark.parametrize(
    "site",
    [
        "request_header /admin/* -*authentik*",  # a matcher: the other paths keep the headers
        "request_header @api -*authentik*",
        "request_header -X-Authentik-*",  # misses the _ and mixed spellings
        "handle {\n\t\trequest_header -*authentik*\n\t}",  # not site level
    ],
)
def test_only_a_matcherless_site_level_strip_of_every_spelling_counts(site):
    found = lint.lint_caddy(PAST % (site, "", "handle /api/* {\n\t\treverse_proxy api:8080\n\t}"))
    assert [f.rule for f in found] == ["strip"] and found[0].detail.startswith("site ")


def test_the_site_level_strip_covers_a_renamed_copy_too():
    text = (
        (PAST % ("request_header -*authentik*", "", ""))
        .replace(
            "copy_headers X-Authentik-Username X-Authentik-Groups",
            "copy_headers X-Authentik-Username>Remote-User",
        )
        .replace("\t\trequest_header -*authentik*", "\t\trequest_header -Remote*")
    )
    found = lint.lint_caddy(text)
    assert [f.rule for f in found] == ["strip"]
    assert "deleting Remote-User, Remote_User:" in found[0].detail
    assert (
        lint.lint_caddy(
            text.replace(
                "\trequest_header -*authentik*",
                "\trequest_header -*authentik*\n\trequest_header -remote*",
                1,
            )
        )
        == []
    )


def test_a_named_route_is_not_a_route_and_its_invoker_needs_the_strip():
    """Caddy 2.11.1 and 2.11.7 adapt only the first directive of a named route (observed: of
    request_header, forward_auth and reverse_proxy only the strip survives), so a forward_auth
    directly in one is not in a route; inside a route block in it, it is."""
    named = """\
&(authed) {
	route {
		request_header -*authentik*
		forward_auth idp:9443 {
			copy_headers X-Authentik-Username
		}
		reverse_proxy app:8080
	}
}
app.lab.example {
	%s
	invoke authed
}
"""
    assert [(f.line, f.rule) for f in lint.lint_caddy(named % "")] == [(10, "strip")]
    assert lint.lint_caddy(named % "request_header -*authentik*") == []
    flat = named.replace("\troute {\n", "").replace("\t\treverse_proxy app:8080\n\t}\n", "")
    flat = flat.replace("\t\t", "\t")
    found = lint.lint_caddy(flat % "request_header -*authentik*")
    assert [f.detail for f in found] == ["forward_auth is not directly inside a route block"]


def test_the_generated_sites_need_their_site_level_strip():
    golden = (REPO / "tests/generators/golden/caddy/sites.caddy").read_text(encoding="utf-8")
    assert lint.lint_caddy(golden) == []
    without = golden.replace("\trequest_header -*authentik*\n\timport", "\timport")
    assert [(f.line, f.rule) for f in lint.lint_caddy(without)] == [(14, "strip"), (25, "strip")]


# ---------------------------------------------------------------- an identity header set later

AUTHED = """\
app.lab.example {
	request_header -*authentik*
	route {
		request_header -*authentik*
		forward_auth idp:9443 {
			uri /outpost.goauthentik.io/auth/caddy
			copy_headers X-Authentik-Username X-Authentik-Groups
		}
		%s
	}
	reverse_proxy app:8080 {
		%s
	}
	%s
}
"""


def _resets(route: str = "", proxy: str = "", site: str = "") -> list[tuple[int, str]]:
    return [
        (f.line, f.detail.split(" names ")[0])
        for f in lint.lint_caddy(AUTHED % (route, proxy, site))
        if f.rule == "reset"
    ]


def test_the_authed_shape_passes():
    assert lint.lint_caddy(AUTHED % ("", "", "")) == []


@pytest.mark.parametrize(
    ("route", "proxy", "site", "expected"),
    [
        # reverse_proxy sets it from a client header after forward_auth ran
        ("", "header_up X-Authentik-Groups {http.request.header.X-Evil}", "", [(12, "header_up")]),
        ("", "header_up +X-Authentik-Groups admins", "", [(12, "header_up")]),
        ("", "header_up X-Authentik-Groups admins users", "", [(12, "header_up")]),
        # set again inside the route, after forward_auth
        ("request_header X-Authentik-Groups {http.request.header.X-Evil}", "", "", [(9, "request_header")]),
        ("request_header +x_authentik_groups admins", "", "", [(9, "request_header")]),
        # a second route
        ("", "", "route {\n\t\trequest_header X-Authentik-Username {header.X-Evil}\n\t}", [(15, "request_header")]),
        # copied from the client's own header into another one before the route runs
        ("", "", "request_header X-Remote-User {http.request.header.X-Authentik-Username}", [(14, "request_header")]),
        # a header block
        ("", "", "header {\n\t\t+X-Authentik_Groups admins\n\t}", [(15, "header")]),
        # deletes are not a reset, and other headers are not identity headers
        ("request_header -X-Authentik-Groups", "header_up -X_Authentik_*", "header {\n\t\t-Server\n\t}", []),
        ("", "header_up Host {upstream_hostport}", "", []),
    ],
)  # fmt: skip
def test_an_identity_header_set_anywhere_but_copy_headers_fails(route, proxy, site, expected):
    assert _resets(route, proxy, site) == expected


def test_a_renamed_target_is_an_identity_header_too():
    text = (AUTHED % ("", "header_up Remote-User alice", "")).replace(
        "copy_headers X-Authentik-Username X-Authentik-Groups",
        "copy_headers X-Authentik-Username>Remote-User",
    )
    findings = lint.lint_caddy(
        text.replace("-*authentik*", "-*authentik*\n\trequest_header -Remote*", 1).replace(
            "\t\trequest_header -*authentik*",
            "\t\trequest_header -*authentik*\n\t\trequest_header -Remote*",
        )
    )
    assert [(f.line, f.rule) for f in findings] == [(14, "reset")]
    assert "Remote-User" in findings[0].detail


def test_the_authentik_uri_path_is_not_a_header():
    assert lint.lint_caddy(AUTHED % ("", "", "redir /outpost.goauthentik.io/start /")) == []


def test_an_inline_allow_waives_one_reset():
    proxy = "header_up X-Authentik-Groups admins  # caddy-lint: allow fixture"
    assert _resets("request_header X-Authentik-Groups x", proxy) == [(9, "request_header")]


# Authentik's own Caddy layout (its documentation's Caddy guide): the IdP's own site, the outpost
# passthrough and a matcher named after it. None of these names a header the upstream receives.
AUTHENTIK_LAYOUT = """\
(hnx_forward_auth) {
	route {
		request_header -*authentik*
		forward_auth http://authentik-server:9000 {
			uri /outpost.goauthentik.io/auth/caddy
			copy_headers X-Authentik-Username X-Authentik-Groups
		}
	}
}

authentik.lab.example {
	reverse_proxy authentik-server:9000
}

app.lab.example {
	request_header -*authentik*
	reverse_proxy /outpost.goauthentik.io/* http://authentik-server:9000
	import hnx_forward_auth
	reverse_proxy app:8080
}

wiki.lab.example {
	request_header -*authentik*
	@authentik path /outpost.goauthentik.io/*
	handle @authentik {
		reverse_proxy authentik-outpost:9000
	}
	@admins header X-Authentik-Groups *admins*
	@editors expression `{http.request.header.X-Authentik-Groups}.contains("editors")`
	@authentik_api {
		header X-Authentik-Username *
		path /api/*
	}
	route {
		request_header -*authentik*
		forward_auth authentik-outpost:9000 {
			uri /outpost.goauthentik.io/auth/caddy
			copy_headers X-Authentik-Username X-Authentik-Groups
		}
	}
	handle @admins {
		reverse_proxy wiki-admin:8080
	}
	reverse_proxy wiki:8080
}
"""


def test_authentiks_own_caddy_layout_passes():
    """Review SF3: every token carrying authentik was a reset, so the IdP's own vhost, the
    outpost passthrough, the default authentik-server service name and an @authentik matcher
    were all refused; only header field names and header placeholders are judged now."""
    assert lint.lint_caddy(AUTHENTIK_LAYOUT) == []


def test_a_header_matcher_is_not_a_header_set_but_a_header_directive_still_is():
    text = AUTHENTIK_LAYOUT.replace(
        "\thandle @admins {", "\theader X-Authentik-Role admin\n\thandle @admins {"
    )
    assert [(f.rule, f.detail.split(" other ")[0]) for f in lint.lint_caddy(text)] == [
        ("reset", "header names the identity header X-Authentik-Role")
    ]


def test_a_snippet_definition_is_judged_where_it_is_imported():
    """Review SF4: a snippet holding the strip and forward_auth, imported inside a route, was a
    strip finding at its definition (whose parent is the snippet, not a route)."""
    text = """\
(auth) {
	request_header -*authentik*
	forward_auth idp:9443 {
		uri /outpost.goauthentik.io/auth/caddy
		copy_headers X-Authentik-Username X-Authentik-Groups
	}
}

app.lab.example {
	request_header -*authentik*
	route {
		import auth
	}
	reverse_proxy app:8080
}
"""
    assert lint.lint_caddy(text) == []
    # imported outside a route, its copy is a finding where it lands (on the snippet's line)
    found = lint.lint_caddy(text.replace("\troute {\n\t\timport auth\n\t}", "\timport auth"))
    assert [(f.line, f.rule) for f in found] == [(3, "strip")]
    # and an unused snippet is not judged at all: Caddy ignores it
    assert lint.lint_caddy(text.split("app.lab.example")[0]) == []


def test_a_copied_name_is_an_identity_header_only_in_its_own_site():
    """Review N5: a copy_headers ...>Remote-User in one site made a basic_auth site's own
    Remote-User a reset."""
    text = """\
app.lab.example {
	request_header -*authentik*
	request_header -remote*
	route {
		request_header -*authentik*
		request_header -remote*
		forward_auth idp:9443 {
			copy_headers X-Authentik-Username>Remote-User
		}
	}
	reverse_proxy app:8080
}
legacy.lab.example {
	basic_auth {
		bob $2a$14$Zkx19XLiW6VYouLHR5NmfOFU0z2GTNmpkT/5qqR7hx4IjWJPDhjvG
	}
	reverse_proxy legacy:8080 {
		header_up Remote-User {http.auth.user.id}
	}
}
"""
    assert lint.lint_caddy(text) == []
    same_site = text.replace(
        "\treverse_proxy app:8080\n",
        "\treverse_proxy app:8080 {\n\t\theader_up Remote-User bob\n\t}\n",
    )
    assert [(f.line, f.rule) for f in lint.lint_caddy(same_site)] == [(12, "reset")]


# ---------------------------------------------------------------- syntax the lint cannot model


def _rules(text: str) -> list[tuple[int, str, str]]:
    return [(f.line, f.rule, f.detail) for f in lint.lint_caddy(textwrap.dedent(text))]


def test_a_heredoc_fails_closed_and_hides_what_caddy_hides():
    # Caddy reads both deletes as the heredoc's text: on 2.11.1 every forged spelling passed
    text = GOOD.replace(
        "\t\trequest_header -*authentik*\n",
        "\t\tvars note <<TXT\n\t\trequest_header -*authentik*\n\t\tTXT\n",
    )
    found = _rules(text)
    assert found[0] == (4, "parse", "a heredoc (<<TXT) hides lines from the lint")
    assert [r for _, r, _ in found].count("strip") == 2


def test_a_heredoc_line_cannot_open_a_phantom_block():
    text = """\
    app.lab.example {
        request_header -*authentik*
        route {
            request_header -*authentik*
            vars note <<TXT
            route {
            TXT
        }
        forward_auth idp:9443 {
            copy_headers X-Authentik-Username
        }
    }
    """
    assert [(ln, r) for ln, r, _ in _rules(text)] == [(5, "parse"), (9, "strip")]
    assert "not directly inside a route" in _rules(text)[1][2]


def test_a_quoted_token_spanning_lines_fails_closed():
    text = 'app.lab.example {\n\trequest_header -*authentik*\n\troute {\n\t\trequest_header -*authentik*\n\t\tvars note "a {\n"\n\t}\n\tforward_auth idp:9443 {\n\t\tcopy_headers X-Authentik-Username\n\t}\n}\n'
    assert [(ln, r) for ln, r, _ in _rules(text)] == [(5, "parse"), (8, "strip")]


def test_an_unclosed_quote_fails_closed():
    assert _rules('app.lab.example {\n\trespond "never closed\n}\n')[0][1:] == (
        "parse",
        "a quoted token is never closed",
    )


def test_a_brace_sharing_a_line_closes_the_block_as_caddy_does():
    text = GOOD.replace("request_header -*authentik*\n", "request_header -*authentik* }\n\t")
    found = _rules(text)
    assert found[0] == (4, "parse", "a { or } shares its line with a directive")
    assert any("not directly inside a route" in d for _, _, d in found)


def test_quoted_braces_and_comments_are_not_blocks():
    text = GOOD.replace(
        "\t\tforward_auth", '\t\trespond "a { b }" 200 # } {\n\t\tvars x#y "}"\n\t\tforward_auth'
    )
    assert _rules(text) == []


@pytest.mark.parametrize(
    ("line", "detail"),
    [
        ("{$AUTH_DIRECTIVE}", "{$AUTH_DIRECTIVE} in directive position hides a directive"),
        ("{{ auth_block }}", "{{ in directive position hides a directive"),
        ("{args[0]} idp:9443", "{args[0]} in directive position hides a directive"),
        ("respond ok \\", "a line ends in \\ (a continued line)"),
    ],
)
def test_a_hidden_directive_fails_closed(line, detail):
    assert (2, "parse", detail) in _rules(
        f"app.lab.example {{\n\t{line}\n\treverse_proxy app:8080\n}}\n"
    )


def test_an_env_site_address_and_the_global_block_are_fine():
    assert _rules("{\n\tadmin off\n}\n{$SITE} {\n\treverse_proxy app:8080\n}\n") == []


@pytest.mark.parametrize(
    ("text", "detail"),
    [
        ("app.lab.example {\n\treverse_proxy app:8080\n", "a block is never closed"),
        ("app.lab.example\n}\n", "a } closes no block"),
        ("app.lab.example\n{\n\treverse_proxy app:8080\n}\n", "a { on a line of its own"),
    ],
)
def test_unbalanced_braces_fail_closed(text, detail):
    assert detail in [d for _, r, d in _rules(text) if r == "parse"]


def test_a_matcher_on_forward_auth_fails():
    text = GOOD.replace("forward_auth idp:9443", "forward_auth @api idp:9443")
    assert _strip(text) == ["forward_auth @api: a request its matcher skips is never authenticated"]


# ---------------------------------------------------------------- import


def test_a_snippet_import_is_expanded_in_place():
    text = """\
    (strip) {
        request_header -*authentik*
    }
    app.lab.example {
        request_header -*authentik*
        route {
            import strip
            forward_auth idp:9443 {
                copy_headers X-Authentik-Username
            }
        }
    }
    """
    assert _rules(text) == []
    assert len(_rules(text.replace("import strip", "import other"))) == 2  # unresolved + strip


def test_the_generated_snippet_resolves_where_it_is_not_defined():
    # a documented site imports the generated snippet without defining it
    assert (
        _rules(
            "app.lab.example {\n\trequest_header -*authentik*\n\timport hnx_forward_auth\n"
            "\treverse_proxy app:8080\n}\n"
        )
        == []
    )


def test_a_file_import_is_followed_and_a_glob_fails_closed(tmp_path):
    (tmp_path / "conf.d").mkdir()
    (tmp_path / "conf.d" / "auth.conf").write_text(
        "forward_auth idp:9443 {\n\tcopy_headers X-Authentik-Username\n}\n"
    )
    site = "app.lab.example {\n\trequest_header -*authentik*\n\timport %s\n\treverse_proxy app:8080\n}\n"
    ctx = lint.CaddyContext(tmp_path)
    found = lint.lint_caddy(site % "conf.d/auth.conf", "Caddyfile", base=tmp_path, ctx=ctx)
    assert [(f.path, f.line, f.rule) for f in found] == [("conf.d/auth.conf", 1, "strip")]
    assert ctx.parsed == {"conf.d/auth.conf"}
    # Caddy expands a glob: even a file literally named *.conf does not stand for what it matches
    (tmp_path / "conf.d" / "*.conf").write_text("reverse_proxy app:8080\n")
    for target in ("conf.d/*.conf", "missing.conf", "../outside.conf", "{$CONF}"):
        found = lint.lint_caddy(site % target, "Caddyfile", base=tmp_path, ctx=ctx)
        assert [(f.line, f.rule) for f in found] == [(3, "parse")], target
        assert "cannot be followed" in found[0].detail
    # a markdown block has no directory to resolve a file against
    assert [f.rule for f in lint.lint_caddy(site % "conf.d/auth.conf")] == ["parse"]


def test_a_snippet_that_imports_itself_terminates():
    found = _rules("(a) {\n\timport a\n}\napp.lab.example {\n\timport a\n}\n")
    assert found and {r for _, r, _ in found} == {"parse"}


# ---------------------------------------------------------------- a header name the lint cannot read

NAMED_LATER = """\
(setid) {
	request_header {args[0]} {http.request.header.X-Evil}
}
app.lab.example {
	request_header -*authentik*
	route {
		request_header -*authentik*
		forward_auth idp:9443 {
			copy_headers X-Authentik-Username X-Authentik-Groups
		}
		%s
	}
	reverse_proxy app:8080%s
}
"""


@pytest.mark.parametrize(
    ("route", "proxy", "expected"),
    [
        # review SF1: each passed the lint, adapted on 2.11.7 and, live, delivered
        # X-Authentik-Groups: forged-evil with the IdP answering alice/users (a finding in an
        # expanded snippet is reported on the snippet's own line)
        ("import setid X-Authentik-Groups", "", ("reset", 2, "request_header names the identity header X-Authentik-Groups")),
        ("request_header {vars.a}{vars.b} {http.request.header.X-Evil}", "", ("parse", 11, "request_header {vars.a}{vars.b}: a header name taken from a placeholder")),
        ("request_header {$IDH} {http.request.header.X-Evil}", "", ("parse", 11, "request_header {$IDH}: a header name")),
        ("request_header {http.request.header.X-Name} {http.request.header.X-Evil}", "", ("parse", 11, "request_header {http.request.header.X-Name}: a header")),
        ("", " {\n\t\theader_up {http.request.header.X-Name} {http.request.header.X-Evil}\n\t}", ("parse", 14, "header_up {http.request.header.X-Name}: a header")),
        ("request_header @m +{header.X-Name} x", "", ("parse", 11, "request_header +{header.X-Name}: a header")),
        # an argument the lint cannot substitute literally is refused at the import
        ("import setid {$IDH}", "", ("parse", 11, "import setid: argument {$IDH} is a placeholder, not a literal")),
        ("import setid", "", ("parse", 11, "import setid: {args[0]} is past the 0 argument(s) given")),
    ],
)  # fmt: skip
def test_a_header_name_that_is_not_literal_fails_closed(route, proxy, expected):
    found = lint.lint_caddy(NAMED_LATER % (route, proxy))
    assert [(f.rule, f.line) for f in found] == [expected[:2]]
    assert found[0].detail.startswith(expected[2]), found[0].detail


def test_import_arguments_are_substituted():
    text = NAMED_LATER % ("import setid X-Request-Id", "")
    assert lint.lint_caddy(text) == []
    ranged = text.replace("{args[0]}", "{args[:]}")
    assert [f.detail for f in lint.lint_caddy(ranged)] == [
        "import setid: {args[:]} cannot be substituted (an argument range)"
    ]


BLOCK = """\
(proxied) {
	reverse_proxy {args[0]} {
		{block}
	}
}
app.lab.example {
	request_header -*authentik*
	route {
		request_header -*authentik*
		forward_auth idp:9443 {
			copy_headers X-Authentik-Username X-Authentik-Groups
		}
	}
	import proxied app:8080 {
		%s
	}
}
"""


def test_an_import_block_lands_where_the_snippet_says_block():
    """Review N4: {block} (Caddy 2.9+) was a parse finding; the import's block is expanded into
    it, and what it carries is judged."""
    assert lint.lint_caddy(BLOCK % "header_up Host {upstream_hostport}") == []
    found = lint.lint_caddy(BLOCK % "header_up X-Authentik-Groups admins")
    assert [(f.line, f.rule) for f in found] == [(15, "reset")]
    # outside a snippet it is still a directive the lint cannot see
    assert [f.rule for f in lint.lint_caddy("app.lab.example {\n\t{block}\n}\n")] == ["parse"]


def test_a_snippet_is_available_only_after_its_definition():
    """Review N6: Caddy refuses a snippet imported above its definition ("File to import not
    found"); the lint expanded it anyway."""
    text = (
        "app.lab.example {\n\timport auth\n\treverse_proxy app:8080\n}\n"
        "(auth) {\n\trequest_header -*authentik*\n}\n"
    )
    assert [(f.line, f.rule) for f in lint.lint_caddy(text)] == [(2, "parse")]
    moved = text.split("(auth)")[1]
    assert lint.lint_caddy("(auth)" + moved + text.split("(auth)")[0]) == []


# ---------------------------------------------------------------- discovery and coverage

BARE = (
    "app.lab.example {\n\trequest_header -*authentik*\n\tforward_auth idp:9443 {\n"
    "\t\tcopy_headers X-Authentik-Username\n\t}\n}\n"
)


def _found(root) -> list[tuple[str, int, str]]:
    findings, _ = lint.scan(root)
    return sorted((f.path, f.line, f.rule) for f in findings)


def _git(root, *args):
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)


def test_discovery_follows_git(tmp_path):
    _git(tmp_path, "init", "-q")
    (tmp_path / ".gitignore").write_text("ignored/\n")
    for rel in ("build/Caddyfile", "ignored/Caddyfile", "new/Caddyfile"):
        (tmp_path / rel).parent.mkdir(exist_ok=True)
        (tmp_path / rel).write_text(BARE)
    _git(tmp_path, "add", "-f", "build/Caddyfile")
    findings, counts = lint.scan(tmp_path)
    # a tracked build/ file is read (the old walk skipped build/, dist/, venv/); an untracked
    # file is read before it is committed; an ignored one is not
    assert sorted(f.path for f in findings) == ["build/Caddyfile", "new/Caddyfile"]
    assert counts["discovery"] == "git"


def test_discovery_outside_git_reads_every_file_but_virtualenvs(tmp_path, monkeypatch):
    monkeypatch.setattr(lint, "_git_files", lambda root: None)
    for rel in ("build/Caddyfile", "dist/x/Caddyfile", "env/Caddyfile", "env/pyvenv.cfg"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(BARE)
    findings, counts = lint.scan(tmp_path)
    assert sorted(f.path for f in findings) == ["build/Caddyfile", "dist/x/Caddyfile"]
    assert counts["discovery"] == "walk"
    err = io.StringIO()
    lint.main([str(tmp_path)], out=io.StringIO(), err=err)
    assert "is not a git work tree" in err.getvalue()


@pytest.mark.parametrize(
    "fence",
    [
        "~~~caddyfile\n%s~~~\n",
        "````caddyfile\n%s````\n",
        '```caddyfile title="Caddyfile"\n%s```\n',
        "```\n%s```\n",
        "```text\n%s```\n",
        "```nginx\n%s```\n",
        "- a list item:\n\n      ```caddy\n      %s      ```\n",
    ],
)
def test_every_markdown_fence_holding_forward_auth_is_read(tmp_path, fence):
    (tmp_path / "doc.md").write_text("Intro.\n\n" + fence % BARE)
    found = _found(tmp_path)
    assert [r for _, _, r in found] == ["strip"]


def test_a_fence_closes_only_on_its_own_kind_and_length(tmp_path):
    (tmp_path / "doc.md").write_text("~~~~caddyfile\n~~~\n" + BARE + "~~~~\n")
    assert [r for _, _, r in _found(tmp_path)] == ["strip"]


def test_markdown_prose_and_other_code_are_not_configs(tmp_path):
    (tmp_path / "doc.md").write_text(
        "Run `forward_auth` in a route.\n\n```python\nprint('caddy')\n```\n"
    )
    assert _found(tmp_path) == []


def test_an_indented_code_block_fails_closed(tmp_path):
    (tmp_path / "doc.md").write_text("Example:\n\n    forward_auth idp:9443\n")
    assert _found(tmp_path) == [("doc.md", 3, "coverage")]


@pytest.mark.parametrize(
    ("name", "text"),
    [
        ("edge.conf", BARE),
        ("caddy_site.tmpl", BARE),
        ("gen_site.py", f'SITE = """\n{BARE}"""\n'),
        ("gen_inline.py", 'SITE = "app.lab.example {\\n\\tforward_auth idp:9443\\n}"\n'),
    ],
)
def test_forward_auth_in_a_file_the_lint_does_not_read_fails(tmp_path, name, text):
    (tmp_path / name).write_text(text)
    assert [(p, r) for p, _, r in _found(tmp_path)] == [(name, "coverage")]


def test_a_prose_mention_is_not_coverage(tmp_path):
    (tmp_path / "Makefile").write_text("# F-23: strip identity headers before forward_auth\n")
    (tmp_path / "x.py").write_text('assert ln.startswith("forward_auth ")\n')
    assert _found(tmp_path) == []


def test_an_imported_file_is_read_as_a_config(tmp_path):
    (tmp_path / "conf.d").mkdir()
    (tmp_path / "conf.d" / "auth.conf").write_text(
        "route {\n\trequest_header -*authentik*\n\tforward_auth idp:9443 {\n"
        "\t\tcopy_headers X-Authentik-Username\n\t}\n}\n"
    )
    (tmp_path / "Caddyfile").write_text(
        "app.lab.example {\n\trequest_header -*authentik*\n\timport conf.d/auth.conf\n}\n"
    )
    assert _found(tmp_path) == []


def test_a_caddyfile_embedded_in_yaml_is_read(tmp_path):
    (tmp_path / "task.yml").write_text(
        "- name: edge config\n  copy:\n    content: |\n"
        + "".join(f"      {ln}\n" for ln in BARE.splitlines())
    )
    assert _found(tmp_path) == [("task.yml", 6, "strip")]
    (tmp_path / "task.yml").write_text("- name: forward_auth strips identity headers first\n")
    assert _found(tmp_path) == []


def test_a_generator_failure_is_a_finding(tmp_path, monkeypatch):
    from homelabnext.generators import builtin

    (tmp_path / "services.yml").write_text(
        (REPO / "examples" / "services.yml").read_text(encoding="utf-8")
    )

    def broken(endpoint):
        raise RuntimeError("a generator bug")

    monkeypatch.setattr(builtin, "_forward_auth_snippet", broken)
    findings, counts = lint.scan(tmp_path)
    assert [(f.path, f.rule) for f in findings] == [("services.yml", "generate")]
    assert counts["generated"] == 0


def test_a_registry_that_does_not_load_is_skipped(tmp_path):
    (tmp_path / "bad.yml").write_text("registry_version: 1\nservices: {edge: {impl: caddy}}\n")
    findings, counts = lint.scan(tmp_path)
    assert [f.rule for f in findings] == ["pin"] and counts["generated"] == 0


def test_a_missing_dependency_exits_2(tmp_path, monkeypatch):
    (tmp_path / "services.yml").write_text(
        (REPO / "examples" / "services.yml").read_text(encoding="utf-8")
    )
    out, err = io.StringIO(), io.StringIO()
    monkeypatch.setitem(sys.modules, "homelabnext.generators", None)
    assert lint.main([str(tmp_path)], out=out, err=err) == 2
    assert "missing dependency: homelabnext" in err.getvalue()
    monkeypatch.setattr(lint, "yaml", None)
    assert lint.main([str(tmp_path)], out=out, err=err) == 2
    assert "missing dependency: PyYAML" in err.getvalue()


@pytest.mark.parametrize(
    ("change", "expected"),
    [
        # a matcher on the delete: the strip runs only for requests it matches (review probe p10)
        (("request_header -*authentik*", "request_header @api -*authentik*"), ["strip", "strip"]),
        # a value after a delete still deletes in Caddy (p14)
        (("request_header -*authentik*", "request_header -*authentik* x"), []),
        # a copy_headers taken from the environment cannot be checked (p12)
        (("copy_headers X-Authentik-Username X-Authentik-Groups", "copy_headers {$IDENTITY}"), ["strip"]),
    ],
)  # fmt: skip
def test_review_probes(change, expected):
    assert [f.rule for f in lint.lint_caddy(GOOD.replace(*change))] == expected


# ---------------------------------------------------------------- Caddy's own JSON (semantic)


def _fa(*copied: str, dial: str = "idp:9443") -> dict:
    """A forward_auth as caddy adapt writes it: a reverse_proxy whose handle_response copies."""
    sets = [
        {
            "handle": [
                {
                    "handler": "headers",
                    "request": {"set": {h: [f"{{http.reverse_proxy.header.{h}}}"]}},
                }
            ]
        }
        for h in copied
    ]
    return {
        "handler": "reverse_proxy",
        "upstreams": [{"dial": dial}],
        "handle_response": [{"match": {"status_code": [2]}, "routes": sets}],
    }


def _del(*patterns: str) -> dict:
    return {"handler": "headers", "request": {"delete": list(patterns)}}


def _proxy(dial: str = "app:8080", **request) -> dict:
    h: dict = {"handler": "reverse_proxy", "upstreams": [{"dial": dial}]}
    if request:
        h["headers"] = {"request": request}
    return h


def _sub(*routes: dict) -> dict:
    return {"handler": "subroute", "routes": list(routes)}


def _route(*handle: dict, **kw) -> dict:
    return {"handle": list(handle), **kw}


def _config(*routes: dict, **server) -> dict:
    return {
        "apps": {
            "http": {"servers": {"srv0": {"listen": [":443"], "routes": list(routes), **server}}}
        }
    }


IDS = ("X-Authentik-Username", "X-Authentik-Groups")
AUTH_ROUTE = _route(_sub(_route(_del("*authentik*"), _fa(*IDS))))


def _judged(doc: dict) -> list[tuple[str, str]]:
    return [
        (rule, detail.split(": ", 1)[0]) for rule, detail in lint.judge_json(doc)
    ]  # (rule, where)


def test_the_generated_shape_passes_the_semantic_check():
    site = _route(_sub(_route(_del("*authentik*")), _route(_sub(_route(_del("*authentik*"), _fa(*IDS)))), _route(_proxy())),
                  match=[{"host": ["app.lab.example"]}], terminal=True)  # fmt: skip
    idp = _route(
        _sub(_route(_proxy("idp:9443"))), match=[{"host": ["login.lab.example"]}], terminal=True
    )
    assert lint.judge_json(_config(site, idp)) == []


@pytest.mark.parametrize(
    ("routes", "expected"),
    [
        # a handle group beside the auth route: Caddy sorts it first (review a02)
        ([_route(_sub(_route(_proxy("api:8080"))), match=[{"path": ["/api/*"]}], group="group0"), AUTH_ROUTE, _route(_proxy())],
         [("semantic", "srv0 routes[0]/handle[0]/routes[0]/handle[0]")]),
        # a matcher on the auth route (a03): the other paths skip it
        ([{**AUTH_ROUTE, "match": [{"path": ["/admin/*"]}]}, _route(_proxy())], [("semantic", "srv0 routes[1]/handle[0]")]),
        # the strip after forward_auth deletes the IdP's answer, not the client's headers
        ([_route(_sub(_route(_fa(*IDS), _del("*authentik*")))), _route(_proxy())],
         [("semantic", "srv0 routes[0]/handle[0]/routes[0]/handle[0]")]),
        # a delete only some requests run (a matcher on the strip's route), before a forward_auth
        # whose route does not strip again
        ([_route(_del("*authentik*"), match=[{"path": ["/x"]}]), _route(_sub(_route(_fa(*IDS)))), _route(_proxy())],
         [("semantic", "srv0 routes[1]/handle[0]/routes[0]/handle[0]"), ("semantic", "srv0 routes[2]/handle[0]")]),
        # a site-level strip covers every path
        ([_route(_del("*authentik*")), _route(_sub(_route(_proxy("api:8080"))), match=[{"path": ["/api/*"]}], group="g"), AUTH_ROUTE, _route(_proxy())], []),
        # an upstream's own header_up delete counts for that upstream
        ([_route(_sub(_route(_proxy("api:8080", delete=["*authentik*"]))), match=[{"path": ["/api/*"]}], group="g"), AUTH_ROUTE, _route(_proxy())], []),
    ],
)  # fmt: skip
def test_every_upstream_is_reached_with_the_identity_headers_deleted(routes, expected):
    assert _judged(_config(*routes)) == expected


@pytest.mark.parametrize(
    ("request_ops", "expected"),
    [
        ({"set": {"X-Authentik-Groups": ["{http.request.header.X-Evil}"]}}, "reset"),  # p04
        ({"add": {"x_authentik_groups": ["admins"]}}, "reset"),
        ({"replace": {"X-Authentik-Groups": [{"search_regexp": "^.*$", "replace": "admins"}]}}, "reset"),  # a08
        ({"set": {"X-Remote-User": ["{header.X-Authentik-Username}"]}}, "reset"),
        ({"set": {"{http.request.header.X-Name}": ["{http.request.header.X-Evil}"]}}, "semantic"),  # a06b
        ({"set": {"{http.vars.a}{http.vars.b}": [""]}}, "semantic"),  # a04
        ({"set": {"Host": ["{upstream_hostport}"]}, "delete": ["X-Authentik-Groups"]}, None),
    ],
)  # fmt: skip
def test_an_identity_header_set_after_the_strip_is_a_finding(request_ops, expected):
    doc = _config(_route(_del("*authentik*")), AUTH_ROUTE, _route(_proxy(**request_ops)))
    assert [rule for rule, _ in lint.judge_json(doc)] == ([expected] if expected else [])


def test_only_the_auth_answer_may_set_an_identity_header_in_handle_response():
    fa = _fa(*IDS)
    fa["handle_response"][0]["routes"].append(
        {
            "handle": [
                {
                    "handler": "headers",
                    "request": {"set": {"X-Authentik-Groups": ["{http.request.header.X-Evil}"]}},
                }
            ]
        }
    )
    doc = _config(
        _route(_del("*authentik*")), _route(_sub(_route(_del("*authentik*"), fa))), _route(_proxy())
    )
    assert [rule for rule, _ in lint.judge_json(doc)] == ["reset"]


def test_the_idps_own_site_and_another_sites_copied_name_are_not_held_to_the_rule():
    renamed = _route(_sub(_route(_del("*authentik*", "remote*")), _route(_sub(_route(_del("*authentik*", "remote*"), _fa("Remote-User")))), _route(_proxy())),
                     match=[{"host": ["app.lab.example"]}], terminal=True)  # fmt: skip
    legacy = _route(_sub(_route(_proxy("legacy:8080", set={"Remote-User": ["{http.auth.user.id}"]}))),
                    match=[{"host": ["legacy.lab.example"]}], terminal=True)  # fmt: skip
    idp = _route(
        _sub(_route(_proxy("authentik-server:9000"))),
        match=[{"host": ["authentik.lab.example"]}],
        terminal=True,
    )
    assert lint.judge_json(_config(renamed, legacy, idp)) == []
    # without a host matcher keeping it apart, the legacy proxy is in the auth site
    legacy.pop("match")
    assert {rule for rule, _ in lint.judge_json(_config(renamed, legacy))} == {"reset", "semantic"}


def test_handle_errors_starts_from_what_the_site_deleted_first():
    api = _route(
        _sub(_route(_proxy("api:8080", delete=["*authentik*"]))),
        match=[{"path": ["/api/*"]}],
        group="g",
    )
    site = _route(_sub(_route(_del("*authentik*")), api, AUTH_ROUTE, _route(_proxy())),
                  match=[{"host": ["app.lab.example"]}], terminal=True)  # fmt: skip
    errors = {
        "routes": [
            _route(
                _sub(_route(_proxy("errors:8080"))),
                match=[{"host": ["app.lab.example"]}],
                terminal=True,
            )
        ]
    }
    assert lint.judge_json(_config(site, errors=errors)) == []
    site["handle"][0]["routes"].pop(0)  # no site-level strip: the error path proxies the forgery
    assert _judged(_config(site, errors=errors)) == [
        ("semantic", "srv0 errors[0]/handle[0]/routes[0]/handle[0]")
    ]


def test_a_named_route_and_an_unknown_handler():
    named = {"authed": _route(_sub(_route(_del("*authentik*"), _fa(*IDS))), _proxy())}
    invoke = {"handler": "invoke", "name": "authed"}
    assert lint.judge_json(_config(_route(invoke), named_routes=named)) == []
    missing = _config(_route({"handler": "invoke", "name": "nope"}, _proxy()), _route(_fa(*IDS)))
    assert ("semantic", "srv0 routes[0]/handle[0]") in _judged(missing)
    plugin = _config(
        _route(_del("*authentik*"), {"handler": "set_identity"}), AUTH_ROUTE, _route(_proxy())
    )
    assert _judged(plugin) == [("semantic", "srv0 routes[0]/handle[1]")]


def _fake_caddy(tmp_path: Path, doc: object | None, error: str = "") -> str:
    """A stand-in caddy binary, beside (not in) the tree under test, that answers `version` and
    prints ``doc`` for `adapt`."""
    script = tmp_path.parent / f"{tmp_path.name}-fake-caddy"
    body = json.dumps(doc) if doc is not None else ""
    script.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = version ]; then echo v2.11.7 fake; exit 0; fi\n'
        f"cat <<'JSON'\n{body}\nJSON\n"
        + (f"echo '{json.dumps({'level': 'error', 'msg': error})}' >&2\nexit 1\n" if error else "")
    )
    script.chmod(0o755)
    return str(script)


def test_scan_judges_what_caddy_adapt_returns(tmp_path):
    (tmp_path / "Caddyfile").write_text(GOOD)
    (tmp_path / "doc.md").write_text("```caddyfile\n" + GOOD + "```\n")
    bypass = _config(
        _route(_sub(_route(_proxy("api:8080"))), match=[{"path": ["/api/*"]}], group="g"),
        AUTH_ROUTE,
        _route(_proxy()),
    )
    adapter = lint.Adapter(_fake_caddy(tmp_path, bypass))
    findings, counts = lint.scan(tmp_path, adapter=adapter)
    assert sorted({(f.path, f.rule) for f in findings}) == [
        ("Caddyfile", "semantic"),
        ("doc.md", "semantic"),
    ]
    assert counts["adapted"] == 2 and counts["caddy"] == "v2.11.7"
    # Caddy refusing a Caddyfile is a finding; refusing a markdown example leaves it to the text lint
    adapter = lint.Adapter(_fake_caddy(tmp_path, None, "File to import not found: auth"))
    findings, counts = lint.scan(tmp_path, adapter=adapter)
    assert [(f.path, f.rule, f.detail) for f in findings] == [
        (
            "Caddyfile",
            "semantic",
            "caddy adapt refuses it (File to import not found: auth): the semantic check cannot judge it",
        )
    ]
    assert counts["text_only"] == 2 and counts["adapted"] == 0


def test_the_ci_run_requires_caddy_and_a_local_run_says_what_it_skipped(tmp_path, monkeypatch):
    (tmp_path / "Caddyfile").write_text(GOOD)
    monkeypatch.delenv("HNX_CADDY", raising=False)
    monkeypatch.setattr(lint.shutil, "which", lambda name: None)
    out, err = io.StringIO(), io.StringIO()
    assert lint.main([str(tmp_path)], out=out, err=err) == 0
    assert "the semantic check (caddy adapt) did not run" in err.getvalue()
    assert "caddy adapt not run, 1 text only" in out.getvalue()
    monkeypatch.setenv("HNX_CADDY_REQUIRED", "1")
    err = io.StringIO()
    assert lint.main([str(tmp_path)], out=io.StringIO(), err=err) == 2
    assert "HNX_CADDY_REQUIRED is set and no caddy binary was found" in err.getvalue()
    assert (
        lint.main(
            [str(tmp_path), "--caddy", _fake_caddy(tmp_path, _config(AUTH_ROUTE))],
            out=out,
            err=err,
        )
        == 0
    )


def test_a_caddy_json_or_yaml_config_in_the_tree_is_judged(tmp_path):
    """Review SF6: caddy adapt of p04 saved as edge/caddy.json (and as YAML) spoofed live on
    2.11.7, and the scan neither read it nor counted it."""
    p04 = _config(
        _route(_sub(_route(_del("X-Authentik-*"), _fa(*IDS)))),
        _route(_proxy(set={"X-Authentik-Groups": ["{http.request.header.X-Evil}"]})),
    )
    (tmp_path / "edge").mkdir()
    (tmp_path / "edge" / "caddy.json").write_text(json.dumps(p04))
    (tmp_path / "edge" / "caddy.yaml").write_text(yaml.safe_dump(p04))
    (tmp_path / "edge" / "route.json").write_text(
        json.dumps({"routes": [_route(_proxy())]})
    )  # a fragment
    (tmp_path / "other.json").write_text('{"handler": "file", "level": "info"}')  # not Caddy
    findings, counts = lint.scan(tmp_path)
    got = sorted({(f.path, f.rule) for f in findings})
    assert got == [("edge/caddy.json", "reset"), ("edge/caddy.json", "semantic"),
                   ("edge/caddy.yaml", "reset"), ("edge/caddy.yaml", "semantic"),
                   ("edge/route.json", "coverage")]  # fmt: skip
    assert counts["json_configs"] == 2


def test_a_global_order_option_fails_closed():
    text = "{\n\torder request_header after reverse_proxy\n}\n" + GOOD
    assert [(f.line, f.rule) for f in lint.lint_caddy(text)] == [(2, "parse")]


CADDY_BIN = os.environ.get("HNX_CADDY") or shutil.which("caddy")
live = pytest.mark.skipif(
    CADDY_BIN is None, reason="caddy not installed (set HNX_CADDY or put caddy on PATH)"
)


@live
@pytest.mark.parametrize(
    ("text", "rules"),
    [
        (PAST % ("", "", "handle /api/* {\n\t\treverse_proxy api:8080\n\t}"), {"semantic"}),
        (PAST % ("", " /admin/*", ""), {"semantic"}),
        (PAST % ("request_header -*authentik*", "", "handle /api/* {\n\t\treverse_proxy api:8080\n\t}"), set()),
        (AUTHENTIK_LAYOUT, set()),
        ((NAMED_LATER % ("import setid X-Authentik-Groups", "")).replace("\t\t\tcopy", "\t\t\turi /auth\n\t\t\tcopy"), {"reset"}),
    ],
)  # fmt: skip
def test_live_caddy_adapt(text, rules):
    doc, err = lint.Adapter(CADDY_BIN).adapt(text, None)
    assert err == "" and {rule for rule, _ in lint.judge_json(doc)} == rules


@live
def test_live_the_tree_passes_the_semantic_check():
    out, err = io.StringIO(), io.StringIO()
    assert lint.main([str(REPO), "--json", "--caddy", CADDY_BIN], out=out, err=err) == 0, (
        out.getvalue()
    )
    doc = json.loads(out.getvalue())
    assert doc["adapted"] >= 7 and doc["findings"] == []
