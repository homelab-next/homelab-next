# SPDX-License-Identifier: Apache-2.0
"""A version written in more than one place says the same thing everywhere.

Dependabot, or a person, moves the copy it can see: the ruff rev in ``.pre-commit-config.yaml``
and not ``constraints/ci-tools.in``, the NATS image and not CI's ``NATS_SERVER_VERSION``, one
workflow's action SHA and not the example overlay's.  Each "bump these together" comment was
honour-system; here a one-sided bump fails CI instead, as ``test_constraints_bootstrap.py`` does
for pip."""

from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path

import pytest
import yaml

from homelabnext._version import VERSION

ROOT = Path(__file__).resolve().parents[2]
CI = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())
COMPOSE = ROOT / "compose" / "lab-in-a-box" / "docker-compose.yml"


def read(rel: str) -> str:
    return (ROOT / rel).read_text()


def job_env(job: str, key: str) -> str:
    return str(CI["jobs"][job]["env"][key])


# --- ruff: the pre-commit hook, the CI tools input and the hashed constraints -----------------


def ruff_versions(root: Path = ROOT) -> dict[str, str]:
    pre = (root / ".pre-commit-config.yaml").read_text()
    m = re.search(
        r"repo: https://github\.com/astral-sh/ruff-pre-commit\n\s+rev: \S+\s+#\s*v(\S+)", pre
    )
    tools = re.search(r"^ruff==(\S+)$", (root / "constraints/ci-tools.in").read_text(), re.M)
    ci = re.search(r"^ruff==(\S+) \\$", (root / "constraints/ci.txt").read_text(), re.M)
    return {
        ".pre-commit-config.yaml": m.group(1) if m else "",
        "constraints/ci-tools.in": tools.group(1) if tools else "",
        "constraints/ci.txt": ci.group(1) if ci else "",
    }


def test_ruff_is_one_version_in_pre_commit_ci_tools_and_ci_constraints():
    got = ruff_versions()
    assert all(got.values()), f"a ruff pin was not found: {got}"
    assert len(set(got.values())) == 1, f"ruff differs: {got} (bump all three; `make constraints`)"


def test_ruff_check_reads_the_three_places(tmp_path):
    (tmp_path / "constraints").mkdir()
    (tmp_path / ".pre-commit-config.yaml").write_text(
        "repos:\n  - repo: https://github.com/astral-sh/ruff-pre-commit\n"
        "    rev: " + "a" * 40 + "  # v0.2.0\n"
    )
    (tmp_path / "constraints/ci-tools.in").write_text("ruff==0.1.0\n")
    (tmp_path / "constraints/ci.txt").write_text("ruff==0.1.0 \\\n    --hash=sha256:aa\n")
    assert ruff_versions(tmp_path) == {
        ".pre-commit-config.yaml": "0.2.0",
        "constraints/ci-tools.in": "0.1.0",
        "constraints/ci.txt": "0.1.0",
    }


# --- images: the lab's NATS and the CI nats-server; one pin per image repository ---------------


# a registry host may carry a port (host:5000/name); a pin may be a tag, a digest or both; a
# Dockerfile FROM may take flags; a FROM naming an earlier stage (no tag, no digest) is not a pin
IMAGE_RE = re.compile(
    r"^\s*(?:image:|FROM(?:\s+--\S+)*|[a-z0-9_]+_image:)\s+[\"']?"
    r"(?P<repo>(?:[a-z0-9.-]+:[0-9]+/)?[a-z0-9._/-]+)"
    r"(?::(?P<tag>[A-Za-z0-9._-]+))?(?:@(?P<digest>sha256:[0-9a-f]{64}))?(?=[\"'\s]|$)",
    re.M,
)


def image_pins(text: str) -> list[tuple[str, str, str | None]]:
    return [
        (m["repo"], m["tag"], m["digest"])
        for m in IMAGE_RE.finditer(text)
        if m["tag"] or m["digest"]
    ]


def test_the_ci_nats_server_is_the_lab_image_version():
    (tag,) = {t for r, t, _ in image_pins(COMPOSE.read_text()) if r == "nats"}
    ci = job_env("external-tools", "NATS_SERVER_VERSION")
    assert ci.removeprefix("v") == tag.split("-")[0], (
        f"compose runs nats {tag}, CI builds nats-server {ci}: bump NATS_SERVER_VERSION and "
        "NATS_SERVER_SUM_SHA256 with the image"
    )


def _image_sources() -> list[Path]:
    return [
        COMPOSE,
        *sorted((ROOT / "compose").rglob("Dockerfile")),
        *sorted((ROOT / "ansible" / "roles").glob("*/defaults/main.yml")),
        *sorted((ROOT / "ansible" / "roles").glob("*/meta/argument_specs.yml")),
    ]


def test_an_image_repository_is_pinned_to_one_tag_and_digest_everywhere():
    seen: dict[str, set[tuple[str | None, str | None]]] = defaultdict(set)
    where: dict[str, set[str]] = defaultdict(set)
    for path in _image_sources():
        for repo, tag, digest in image_pins(path.read_text()):
            if tag == "local":  # built by the compose file, never pulled
                continue
            seen[repo].add((tag, digest))
            where[repo].add(path.relative_to(ROOT).as_posix())
    split = {r: (sorted(map(str, p)), sorted(where[r])) for r, p in seen.items() if len(p) > 1}
    assert split == {}, f"one image, several pins: {split}"


def test_the_image_parser_reads_compose_dockerfiles_and_role_defaults():
    text = (
        "    image: nats:2.10.22-alpine@sha256:" + "a" * 64 + "\n"
        "FROM python:3.12-slim-bookworm@sha256:" + "b" * 64 + "\n"
        'open_webui_image: "ghcr.io/open-webui/open-webui:v0.11.4@sha256:' + "c" * 64 + '"\n'
        "    image: hnx-lab-fakes:local\n"
        "    image: registry.example.test:5000/team/app:1.2\n"
        "    image: registry.example.test/team/tool@sha256:" + "d" * 64 + "\n"
        "FROM --platform=$BUILDPLATFORM base:1 AS build\n"
        "FROM build\n"
    )
    assert image_pins(text) == [
        ("nats", "2.10.22-alpine", "sha256:" + "a" * 64),
        ("python", "3.12-slim-bookworm", "sha256:" + "b" * 64),
        ("ghcr.io/open-webui/open-webui", "v0.11.4", "sha256:" + "c" * 64),
        ("hnx-lab-fakes", "local", None),
        ("registry.example.test:5000/team/app", "1.2", None),
        ("registry.example.test/team/tool", None, "sha256:" + "d" * 64),
        ("base", "1", None),
    ]


def test_the_lake_query_rehearsal_flips_to_the_trino_the_lab_runs():
    (tag,) = {t for r, t, _ in image_pins(COMPOSE.read_text()) if r == "trinodb/trino"}
    rehearsal = re.search(
        r'^CANDIDATE = \{[^}]*"impl": "trino", "version": "([^"]+)"',
        read("homelabnext/swap/rehearsal.py"),
        re.M,
    )
    script = set(
        re.findall(
            r"--to-impl trino --to-version (\S+)",
            read("compose/lab-in-a-box/rehearsals/swap-lake-query.sh"),
        )
    )
    want = f"{tag}.0"
    assert rehearsal and rehearsal.group(1) == want, f"compose runs trino {tag}: swap/rehearsal.py"
    assert script == {want}, (
        f"compose runs trino {tag}: rehearsals/swap-lake-query.sh says {script}"
    )


def test_the_open_webui_docs_name_the_role_default():
    defaults = yaml.safe_load(read("ansible/roles/open_webui/defaults/main.yml"))
    specs = yaml.safe_load(read("ansible/roles/open_webui/meta/argument_specs.yml"))
    image = defaults["open_webui_image"]
    assert specs["argument_specs"]["main"]["options"]["open_webui_image"]["default"] == image
    repo_tag, digest = image.split("@sha256:")
    m = re.search(
        r"`(ghcr\.io/open-webui/open-webui:[^@`]+)@sha256:([0-9a-f]+)…`",
        read("docs/model-serving.md"),
    )
    assert m, "docs/model-serving.md no longer names the open_webui image"
    assert m.group(1) == repo_tag and digest.startswith(m.group(2)), (m.groups(), image)


# --- caddy: the CI binary the lint adapts with, and the version the example registries run ------


def _caddy_versions(doc) -> list[str]:
    out: list[str] = []
    if isinstance(doc, dict):
        if doc.get("impl") == "caddy" and "version" in doc:
            out.append(str(doc["version"]))
        for v in doc.values():
            out += _caddy_versions(v)
    elif isinstance(doc, list):
        for v in doc:
            out += _caddy_versions(v)
    return out


def test_the_example_registries_run_the_caddy_ci_checks_with():
    ci = job_env("schemas", "CADDY_VERSION")
    found: dict[str, list[str]] = {}
    for path in sorted((ROOT / "examples").rglob("services.yml")):
        versions = _caddy_versions(yaml.safe_load(path.read_text()))
        if versions:
            found[path.relative_to(ROOT).as_posix()] = versions
    assert found, "no example registry runs caddy"
    # every caddy service of a registry, not the last one read
    assert {p: vs for p, vs in found.items() if set(vs) != {ci}} == {}, f"CI caddy is {ci}"
    page = read("docs/systems/edge-proxy.md")
    assert f"- Implementation: `caddy` {ci}\n" in page, "regenerate docs/systems (make docs)"


# --- metrics: the scrape target each pinned version really serves -------------------------------

ISSUES = "https://github.com/homelab-next/homelab-next/issues/"
#: the example registry's controller row: this repository's controller, at this repository's
#: version (ADR-0026 decisions 15 and 16), so its facts are read from this checkout's source
ORCHESTRATOR_ROW = "examples/services.yml"
#: the route table the controller's GET /metrics is served from (nil Metrics: not served)
ORCHESTRATOR_ROUTES = "orchestrator/internal/api/server.go"

# What each product serves for Prometheus, read from its own source at the versions listed; a
# registry metrics block for another version fails until that version is read and added here.
# `port` "own" is the service's own port; "listener" is a separate listener whose port is
# configurable (so a block must name it, and never the service port), `default_port` what it is
# when nothing sets it.  `paths` None is any path but those in `not`.  `served` False: no
# Prometheus endpoint at the listed versions, so the registry declares no metrics block.
#   lakekeeper: its own plain-HTTP listener, default 9000, configurable via
#     LAKEKEEPER__METRICS_PORT (crates/lakekeeper/src/config.rs, `impl Default for Metrics`, at
#     v0.14.1; docs/docs/configuration.md at v0.5.2), bound by metrics-exporter-prometheus, which
#     renders every path but /health (http_listener.rs, handle_http_request, at 0.15.3 and
#     0.17.2, the versions those tags lock).  The example registries scrape it only once a
#     metrics block can say plain HTTP on an https service (metrics.scheme, issue 250).
#   trino: the coordinator's own HTTP(S) port, /metrics (Server.java installs airlift's
#     JmxOpenMetricsModule at 450 and 484, whose MetricsResource is @Path("/metrics");
#     docs admin/openmetrics.md), behind the server's authentication: the generated job sends no
#     credentials, so it gets 401 until scrape auth exists (issue 251)
#   orchestrator: this repository's controller at this repository's version (homelabnext
#     VERSION): GET /metrics on its own port (ORCHESTRATOR_ROUTES, `handle("GET /metrics", ...)`),
#     behind the job API's metrics scope, so the generated job, which sends no credentials, gets
#     401 until scrape auth exists (issue 251), and the example row declares no metrics block
METRICS_SERVED: dict[str, dict] = {
    "lakekeeper": {
        "versions": {"0.5.2", "0.14.1"},
        "port": "listener",
        "default_port": 9000,
        "paths": None,
        "not": {"/health"},
    },
    "trino": {"versions": {"450.0", "484.0"}, "port": "own", "paths": {"/metrics"}},
    "orchestrator": {"versions": {VERSION}, "port": "own", "paths": {"/metrics"}},
}
FACTS = "METRICS_SERVED in tools/tests/test_pin_consistency.py"


def metrics_mismatches(doc: dict, src: str = "<registry>") -> list[str]:
    """Each metrics block of a registry document that its product does not serve."""
    out: list[str] = []
    for name, s in sorted((doc.get("services") or {}).items()):
        fact = METRICS_SERVED.get(s.get("impl", ""))
        m = s.get("metrics")
        if fact is None or m is None:
            continue  # serving metrics is not an obligation to scrape them
        where = f"{src}: {name} ({s['impl']} {s.get('version')})"
        if str(s.get("version")) not in fact["versions"]:
            out.append(
                f"{where}: {FACTS} has no fact for this version; read what it serves in its "
                f"source at that version and add it (known: {sorted(fact['versions'])})"
            )
            continue
        if not fact.get("served", True):
            out.append(f"{where}: declares metrics {m}, but serves no Prometheus endpoint")
            continue
        port = m.get("port", s["port"])
        if fact["port"] == "own" and port != s["port"]:
            out.append(f"{where}: metrics on port {port}, served on {s['port']}")
        if fact["port"] == "listener" and port == s["port"]:
            out.append(
                f"{where}: metrics on the service port {port}, served on a listener of its own "
                f"(default {fact['default_port']})"
            )
        path = m["path"]
        allowed = fact["paths"]
        if path in fact.get("not", ()) or (allowed is not None and path not in allowed):
            out.append(f"{where}: metrics path {path} is not served")
    return out


def listener_clashes(doc: dict, src: str = "<registry>") -> list[str]:
    """Two listeners (service ports and metrics ports) on one host, port and transport."""
    seen: dict[tuple, list[str]] = defaultdict(list)
    for name, s in sorted((doc.get("services") or {}).items()):
        transport = "udp" if s.get("protocol") == "udp" else "tcp"
        seen[(s["host"], transport, s["port"])].append(name)
        m = s.get("metrics")
        if m and m.get("port") not in (None, s["port"]):
            seen[(s["host"], "tcp", m["port"])].append(f"{name} metrics")
    return [
        f"{src}: {host} {transport}/{port} is claimed by {', '.join(sorted(names))}"
        for (host, transport, port), names in seen.items()
        if len(names) > 1
    ]


def _registries() -> list[tuple[str, dict]]:
    # the schema negatives are not: each exists to be rejected, so no generator reads one
    out = []
    for path in [
        *sorted((ROOT / "examples").rglob("services.yml")),
        *sorted((ROOT / "schemas" / "platform" / "examples").glob("service.*.yml")),
    ]:
        doc = yaml.safe_load(path.read_text())
        if isinstance(doc, dict) and isinstance(doc.get("services"), dict):
            out.append((path.relative_to(ROOT).as_posix(), doc))
    return out


def test_every_registry_scrapes_what_its_product_serves():
    found = [bad for src, doc in _registries() for bad in metrics_mismatches(doc, src)]
    assert found == [], "\n".join(["metrics blocks a product does not serve:", *found])


def test_no_two_listeners_share_a_host_and_port():
    found = [bad for src, doc in _registries() for bad in listener_clashes(doc, src)]
    assert found == [], "\n".join(["one host port, several listeners:", *found])


def test_the_lab_runs_the_metrics_facts_versions_on_their_default_ports():
    compose = COMPOSE.read_text()
    where = COMPOSE.relative_to(ROOT).as_posix()
    tags = {r: t for r, t, _ in image_pins(compose)}
    lake = tags["quay.io/lakekeeper/catalog"].removeprefix("v")
    trino = f"{tags['trinodb/trino']}.0"
    for product, version in (("lakekeeper", lake), ("trino", trino)):
        assert version in METRICS_SERVED[product]["versions"], (
            f"{where} runs {product} {version}: read what it serves for metrics at that version "
            f"and add it to {FACTS}"
        )
    # the lakekeeper fact's port is the default; the lab sets none
    assert "METRICS_PORT" not in compose and "METRICS__PORT" not in compose, (
        f"{where} sets the metrics port; {FACTS} assumes the default"
    )
    # the controller is this repository's: its row carries this repository's version, and the
    # fact is this checkout's route table
    row = yaml.safe_load(read(ORCHESTRATOR_ROW))["services"]["orchestrator"]
    assert (row["impl"], row["version"]) == ("orchestrator", VERSION), (
        f"{ORCHESTRATOR_ROW}: the orchestrator row is this repository's controller, at {VERSION}"
    )
    assert 'handle("GET /metrics"' in read(ORCHESTRATOR_ROUTES), (
        f"{ORCHESTRATOR_ROUTES} no longer serves GET /metrics: update the orchestrator entry of "
        f"{FACTS}"
    )


def test_the_unscraped_metrics_link_their_issues():
    text = read("examples/services.yml")
    assert f"{ISSUES}250" in text and f"{ISSUES}251" in text


@pytest.mark.parametrize(
    ("service", "want"),
    [
        ({"impl": "lakekeeper", "version": "0.14.1", "port": 8181}, []),
        (
            {"impl": "lakekeeper", "version": "0.14.1", "port": 8181, "metrics": {"path": "/x"}},
            ["on the service port 8181"],
        ),
        (
            {
                "impl": "lakekeeper",
                "version": "0.14.1",
                "port": 8181,
                "metrics": {"path": "/metrics", "port": 9100},
            },
            [],
        ),
        (
            {
                "impl": "lakekeeper",
                "version": "0.14.1",
                "port": 8181,
                "metrics": {"path": "/health", "port": 9000},
            },
            ["path /health is not served"],
        ),
        (
            {"impl": "trino", "version": "484.0", "port": 8443, "metrics": {"path": "/metrics"}},
            [],
        ),
        (
            {
                "impl": "trino",
                "version": "484.0",
                "port": 8443,
                "metrics": {"path": "/metrics", "port": 9091},
            },
            ["port 9091, served on 8443"],
        ),
        (
            {"impl": "trino", "version": "999.0", "port": 8443, "metrics": {"path": "/metrics"}},
            ["has no fact for this version"],
        ),
        ({"impl": "trino", "version": "999.0", "port": 8443}, []),
        (
            {"impl": "orchestrator", "version": VERSION, "port": 8088, "metrics": {"path": "/m"}},
            ["path /m is not served"],
        ),
        (
            {
                "impl": "orchestrator",
                "version": VERSION,
                "port": 8088,
                "metrics": {"path": "/metrics"},
            },
            [],
        ),
        (
            # the private controller's version: no fact here any more (decision 15)
            {"impl": "orchestrator", "version": "0.3.0", "port": 8088, "metrics": {"path": "/m"}},
            ["has no fact for this version"],
        ),
        ({"impl": "unknown-product", "version": "1", "port": 1, "metrics": {"path": "/m"}}, []),
    ],
)
def test_the_metrics_check(service, want):
    got = metrics_mismatches({"services": {"svc": service}})
    assert len(got) == len(want) and all(w in g for w, g in zip(want, got, strict=True)), got


def test_the_listener_check():
    services = {
        "store": {"host": "a", "protocol": "https", "port": 9000},
        "catalog": {
            "host": "a",
            "protocol": "https",
            "port": 8181,
            "metrics": {"path": "/m", "port": 9000},
        },
        "dns": {"host": "a", "protocol": "udp", "port": 8181},
        "other": {"host": "b", "protocol": "http", "port": 9000},
        "same": {
            "host": "b",
            "protocol": "http",
            "port": 80,
            "metrics": {"path": "/m", "port": 80},
        },
    }
    assert listener_clashes({"services": services}) == [
        "<registry>: a tcp/9000 is claimed by catalog metrics, store"
    ]


# --- tools whose version a document names --------------------------------------------------


def test_the_private_overlay_doc_names_the_zizmor_ci_runs():
    v = job_env("external-tools", "ZIZMOR_VERSION")
    doc = read("docs/private-overlay.md")
    named = set(re.findall(r"`zizmor --offline`; checked\s+with ([0-9.]+)\)", doc))
    assert named == {v}, f"docs/private-overlay.md says {named}, CI runs zizmor {v}"
    assert set(
        re.findall(r"zizmor ([0-9]+\.[0-9]+\.[0-9]+)", read(".github/workflows/ci.yml"))
    ) <= {v}


def test_the_private_overlay_doc_names_the_pinned_tailscale_action():
    deploy = read("examples/private-overlay/.github/workflows/deploy.yml")
    (pinned,) = set(re.findall(r"uses: tailscale/github-action@[0-9a-f]{40}\s+#\s*(v\S+)", deploy))
    named = set(
        re.findall(r"`tailscale/github-action`\s+\(?(v[0-9.]+)", read("docs/private-overlay.md"))
    )
    assert named == {pinned}, f"docs/private-overlay.md says {named}, the template pins {pinned}"


# --- actions: one action, one commit, one version comment, in every workflow tree ---------------


# a `uses:` step key at the start of its line, so a commented-out step is not read
USES_RE = re.compile(
    r"^[ \t]*(?:-[ \t]+)?uses:[ \t]+(?P<action>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)(?:/[^@\s]*)?@(?P<ref>\S+)"
    r"(?:[ \t]+#[ \t]*(?P<comment>\S+))?",
    re.M,
)


def action_pins(text: str) -> list[tuple[str, str, str | None]]:
    return [(m["action"], m["ref"], m["comment"]) for m in USES_RE.finditer(text)]


def _workflow_files() -> list[Path]:
    """Workflows and composite actions only (not dependabot.yml or other .github config)."""
    out: list[Path] = []
    for gh in (ROOT / ".github", ROOT / "examples" / "private-overlay" / ".github"):
        out += [*(gh / "workflows").glob("*.yml"), *(gh / "workflows").glob("*.yaml")]
        out += [*(gh / "actions").rglob("action.yml"), *(gh / "actions").rglob("action.yaml")]
    return sorted(out)


def test_every_action_is_one_full_sha_with_one_version_comment_everywhere():
    pins: dict[str, set[tuple[str, str | None]]] = defaultdict(set)
    bad = []
    for path in _workflow_files():
        for action, ref, comment in action_pins(path.read_text()):
            if not re.fullmatch(r"[0-9a-f]{40}", ref) or not comment:
                bad.append(f"{path.relative_to(ROOT)}: {action}@{ref} {comment or ''}")
            pins[action].add((ref, comment))
    assert bad == [], "pin actions by full SHA with a `# vX.Y.Z` comment"
    split = {a: sorted(map(str, p)) for a, p in pins.items() if len(p) > 1}
    assert split == {}, f"one action at several pins: {split}"


@pytest.mark.parametrize(
    ("line", "want"),
    [
        (
            "      - uses: actions/checkout@" + "a" * 40 + "  # v7.0.1",
            [("actions/checkout", "a" * 40, "v7.0.1")],
        ),
        (
            "      - uses: github/codeql-action/init@" + "b" * 40 + "  # v4.39.1",
            [("github/codeql-action", "b" * 40, "v4.39.1")],
        ),
        ("      - uses: ./.github/actions/python-deps", []),
        ("        uses: owner/repo@main", [("owner/repo", "main", None)]),
        ("      # - uses: owner/repo@main  # disabled", []),
        ("      - run: echo uses: owner/repo@main", []),
    ],
)
def test_the_uses_parser(line, want):
    assert action_pins(line) == want
