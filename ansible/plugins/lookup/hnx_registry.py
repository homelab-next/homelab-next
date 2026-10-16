# SPDX-License-Identifier: Apache-2.0
"""Minimal service-registry lookup used by the reference roles.

    {{ lookup('hnx_registry', 'query-core', field='url') }}

The registry file path comes from the inventory variable ``hnx_registry_file``.
The registry (the registry task owns the real file) is the
single source of truth for names and ports; roles never carry them in defaults.
This stub understands only the minimal shape below and is meant to be replaced
by the full registry resolver behind the same lookup name and arguments.

    services:
      <logical-id>: {host: <fqdn>, port: <int>, scheme: <http|https|tcp>}
"""

from __future__ import annotations

import yaml
from ansible.errors import AnsibleLookupError

from ansible.plugins.lookup import LookupBase

DOCUMENTATION = r"""
name: hnx_registry
short_description: Resolve a logical service id to host, port or url
options:
  _terms:
    description: Logical service ids.
    required: true
  field:
    description: One of host, port, url.
    default: url
"""


class LookupModule(LookupBase):
    def run(self, terms, variables=None, **kwargs):
        field = kwargs.get("field", "url")
        if field not in ("host", "port", "url"):
            raise AnsibleLookupError(f"hnx_registry: unknown field '{field}'")
        path = (variables or {}).get("hnx_registry_file")
        if not path:
            raise AnsibleLookupError(
                "hnx_registry: inventory variable hnx_registry_file is not set"
            )
        try:
            with open(path, encoding="utf-8") as fh:
                services = (yaml.safe_load(fh) or {}).get("services", {})
        except OSError as exc:
            raise AnsibleLookupError(f"hnx_registry: cannot read registry: {exc}") from exc
        out = []
        for term in terms:
            row = services.get(term)
            if row is None:
                raise AnsibleLookupError(f"hnx_registry: unknown service id '{term}'")
            if field == "url":
                out.append(f"{row.get('scheme', 'https')}://{row['host']}:{row['port']}")
            else:
                out.append(row[field])
        return out
