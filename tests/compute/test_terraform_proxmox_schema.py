# SPDX-License-Identifier: Apache-2.0
"""The terraform-proxmox render stays within the bpg/proxmox provider schema.

The schema fixture is a trimmed snapshot of ``terraform providers schema -json`` for
``registry.terraform.io/bpg/proxmox`` (resources ``proxmox_virtual_environment_vm`` and
``proxmox_virtual_environment_container``).  The test parses every rendered ``.tf`` file and
checks that every attribute and block name is a name the real provider accepts, at the right
position in the schema.  Unknown names fail the test with the file, line and identifier.

This is a CI-safe shape check: it needs no network and no live Proxmox.  Regenerate the
fixture (and bump ``provider_version``) when the pinned provider version is updated:

    cd /tmp/scratch && terraform init && terraform providers schema -json > schema.json

bpg/proxmox exposes some multi-instance children (``network_device`` on vms, ``ipv4`` /
``user_account`` inside ``initialization``, ...) as list-nested-type attributes rather than
block types; Terraform accepts the "attribute as block" HCL syntax for those, so the test
accepts both.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from homelabnext.compute import render
from homelabnext.compute.loader import load_fleet
from homelabnext.compute.model import ZoneInfo
from homelabnext.compute.zones import MappingZones

HERE = Path(__file__).resolve().parent
FIXTURE = HERE / "fixtures" / "bpg_proxmox_schema.json"
FLEET = HERE / "fleet"
KEYS = HERE / "keys.yml"

RE_RESOURCE = re.compile(r'^resource\s+"([^"]+)"\s+"[^"]+"\s*\{\s*$')
RE_ATTR = re.compile(r"^\s*([a-z_][a-z0-9_]*)\s*=\s*")
RE_BLOCK = re.compile(r"^\s*([a-z_][a-z0-9_]*)\s*\{\s*$")

# Blocks native to HCL (not the provider schema): allowed anywhere.
META_BLOCKS = frozenset({"lifecycle"})


def _schema() -> dict:
    return json.loads(FIXTURE.read_text())


def _nested_object_attrs(attr_type) -> dict | None:
    """If ``attr_type`` is a list/set of object, return the object's attribute dict; else None."""
    # Schema JSON types are nested arrays: e.g. ["list", ["object", {k: ty}]] or
    # ["set", ["object", {k: ty}]] or ["object", {k: ty}].
    if not isinstance(attr_type, list):
        return None
    if attr_type and attr_type[0] in ("list", "set") and len(attr_type) >= 2:
        inner = attr_type[1]
        if (
            isinstance(inner, list)
            and inner
            and inner[0] == "object"
            and isinstance(inner[1], dict)
        ):
            return inner[1]
        return None
    if attr_type and attr_type[0] == "object" and isinstance(attr_type[1], dict):
        return attr_type[1]
    return None


def _resolve_child(parent_block: dict, name: str) -> tuple[str, dict | None]:
    """Resolve ``name`` as a child of ``parent_block`` from the provider schema.

    Returns ``(kind, descent)`` where kind is ``"attr"``, ``"block"``, ``"attr-as-block"``
    or ``"unknown"``.  ``descent`` is the schema to descend into for sub-children when
    the name opened a block / attr-as-block, else ``None``.
    """
    attrs = parent_block.get("attributes") or {}
    blocks = parent_block.get("block_types") or {}
    if name in blocks:
        return "block", blocks[name].get("block", {}) or {}
    if name in attrs:
        inner = _nested_object_attrs(attrs[name].get("type"))
        if inner is not None:
            # object/list-of-object: an attribute-as-block is legal; its children are the
            # object's own attributes, which we wrap into a block-shaped schema so the
            # recursion stays uniform.
            return "attr-as-block", {
                "attributes": {k: {"type": t} for k, t in inner.items()},
                "block_types": {},
            }
        return "attr", None
    return "unknown", None


def _parse_hcl(text: str):
    """Yield (kind, name, line_no, path) tokens for the one resource in the file.

    ``kind`` is ``"resource"`` for the opening line (name is the resource type), ``"open"``
    for a block header (name is the block name) and ``"attr"`` for an attribute assignment.
    """
    stack: list[str] = []
    rtype = ""
    for i, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        m = RE_RESOURCE.match(line)
        if m:
            rtype = m.group(1)
            yield "resource", rtype, i, []
            continue
        if s == "}":
            if stack:
                stack.pop()
            continue
        mb = RE_BLOCK.match(line)
        if mb:
            yield "open", mb.group(1), i, list(stack)
            stack.append(mb.group(1))
            continue
        ma = RE_ATTR.match(line)
        if ma:
            yield "attr", ma.group(1), i, list(stack)
    assert not stack, f"unbalanced blocks in HCL (stack remainder: {stack})"


def _tf_files():
    fleet = load_fleet(FLEET, _stub_zones(), keys_path=KEYS)
    rendered = render(fleet, "terraform-proxmox")
    return [
        (name, text)
        for name, text in sorted(rendered.items())
        if name.endswith(".tf") and name not in ("providers.tf", "variables.tf")
    ]


def _stub_zones() -> MappingZones:
    return MappingZones(
        [
            ZoneInfo("mgmt", "192.0.2.0/24", "192.0.2.1", None, 10),
            ZoneInfo(
                "data", "198.51.100.0/25", "198.51.100.1", ("198.51.100.100", "198.51.100.126"), 20
            ),
            ZoneInfo("compute", "198.51.100.128/25", "198.51.100.129", None, 30),
            ZoneInfo("edge", "203.0.113.0/24", "203.0.113.1", None, 40),
        ]
    )


@pytest.mark.parametrize("name,text", _tf_files(), ids=lambda v: v if isinstance(v, str) else "x")
def test_resource_shape_matches_provider_schema(name, text):
    rtype = ""
    # Each stack entry is a dict (block schema) we descend into for subsequent children.
    schema_stack: list[dict] = []
    schemas = _schema()["resource_schemas"]

    for kind, token, line_no, path in _parse_hcl(text):
        if kind == "resource":
            rtype = token
            assert rtype in schemas, (
                f"{name}:{line_no}: resource type {rtype!r} not in provider schema"
            )
            schema_stack = [schemas[rtype]["block"]]
            continue

        # Realign schema_stack with the parser's path depth (parser pops on "}" but
        # does not yield a close event, so we drop stale frames here).
        target_depth = len(path) + 1  # 1 for the resource root + path frames
        while len(schema_stack) > target_depth:
            schema_stack.pop()
        parent = schema_stack[-1]
        # Meta blocks (lifecycle) are HCL grammar, not provider schema
        if kind == "open" and token in META_BLOCKS:
            # Push a permissive stub so inner lines don't fail
            schema_stack.append(
                {
                    "attributes": {
                        "ignore_changes": {},
                        "create_before_destroy": {},
                        "prevent_destroy": {},
                        "replace_triggered_by": {},
                    },
                    "block_types": {},
                }
            )
            continue

        child_kind, descent = _resolve_child(parent, token)
        if child_kind == "unknown":
            raise AssertionError(
                f"{name}:{line_no}: {kind} {token!r} not accepted by {rtype} at "
                f"path /{'/'.join(path) or '<root>'}"
            )
        if kind == "open":
            # Opening a block must map to a schema block or an attr-as-block
            if child_kind == "attr":
                raise AssertionError(
                    f"{name}:{line_no}: {token!r} is an attribute, not a block, in {rtype} at "
                    f"/{'/'.join(path) or '<root>'}"
                )
            schema_stack.append(descent or {"attributes": {}, "block_types": {}})
        else:
            # It's an attribute assignment; must be a known attribute
            if child_kind == "block":
                raise AssertionError(
                    f"{name}:{line_no}: {token!r} is a block, not an attribute, in {rtype} at "
                    f"/{'/'.join(path) or '<root>'}"
                )
            # 'attr' or 'attr-as-block' both accept attribute assignment (the latter rarely).


def test_fixture_has_expected_resources():
    rs = _schema()["resource_schemas"]
    assert "proxmox_virtual_environment_vm" in rs
    assert "proxmox_virtual_environment_container" in rs
    assert _schema()["provider_version"] == "0.116.1"
