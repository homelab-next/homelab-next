# SPDX-License-Identifier: Apache-2.0
"""Minimal secret lookup used by the reference roles: a role names a secret, never holds it.

    {{ lookup('hnx_secret', 'secret:siem/enrollment-password') }}

A reference ``secret:<name>`` resolves, on the controller, from the environment variable the
registry delivers it in (``HNX_SECRET_<NAME>``: ``homelabnext.registry.model.secret_env_name``),
else from the file ``<hnx_secrets_dir>/<name>`` (inventory variable), else the lookup fails: an
empty or missing secret is never read as "no secret".  A task that uses the value must carry
``no_log: true`` (tools/role_lint.py RL011).  This stand-in is meant to be replaced by the
secrets capability's resolver behind the same lookup name and arguments.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from ansible.errors import AnsibleLookupError

from ansible.plugins.lookup import LookupBase

DOCUMENTATION = r"""
name: hnx_secret
short_description: Resolve a secret reference (secret:<name>) to its value on the controller
options:
  _terms:
    description: Secret references, each secret:<name>.
    required: true
"""

NAME = re.compile(r"^[a-z0-9][a-z0-9._-]*(?:/[a-z0-9][a-z0-9._-]*)*$")


def env_name(ref: str) -> str:
    """``secret:siem/enrollment-password`` -> ``HNX_SECRET_SIEM_ENROLLMENT_PASSWORD`` (the rule
    of ``homelabnext.registry.model.secret_env_name``)."""
    return "HNX_SECRET_" + re.sub(r"[^A-Za-z0-9]", "_", ref.removeprefix("secret:")).upper()


class LookupModule(LookupBase):
    def run(self, terms, variables=None, **kwargs):
        secrets_dir = (variables or {}).get("hnx_secrets_dir")
        out = []
        for ref in terms:
            name = ref.removeprefix("secret:") if isinstance(ref, str) else ""
            if not isinstance(ref, str) or not ref.startswith("secret:") or not NAME.match(name):
                raise AnsibleLookupError(
                    f"hnx_secret: {ref!r} is not a secret reference (secret:<name>)"
                )
            value = os.environ.get(env_name(ref), "")
            if not value and secrets_dir:
                p = Path(secrets_dir) / name
                try:
                    value = p.read_text(encoding="utf-8").strip() if p.is_file() else ""
                except OSError as exc:
                    raise AnsibleLookupError(f"hnx_secret: cannot read {ref}: {exc}") from exc
            if not value:
                raise AnsibleLookupError(
                    f"hnx_secret: {ref} is not set ({env_name(ref)} or hnx_secrets_dir/{name})"
                )
            out.append(value)
        return out
