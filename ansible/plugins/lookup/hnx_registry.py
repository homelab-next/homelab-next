# SPDX-License-Identifier: Apache-2.0
"""Minimal service-registry lookup used by the reference roles.

    {{ lookup('hnx_registry', 'query-core', field='url') }}

The registry file path comes from the inventory variable ``hnx_registry_file``.
The registry (the registry task owns the real file) is the
single source of truth for names and ports; roles never carry them in defaults.
This stub understands only the minimal shape below and is meant to be replaced
by the full registry resolver behind the same lookup name and arguments.

    services:
      <logical-id>: {host: <fqdn>, port: <int>, scheme: <name>, capability: <name>}

A registry in the platform shape (the one ``homelabnext.registry.model`` loads: a ``lab:`` block,
a ``hosts:`` map, and rows carrying ``protocol:`` and ``tls:`` instead of ``scheme:``) is read the
way the model reads it, because a row's ``host`` there is a logical host id, never an address:

* the scheme is ``Service.scheme``: ``protocol: http`` is ``https`` only with ``tls`` internal,
  public or mtls, ``https`` is always ``https``, any other protocol is its own scheme;
* the host is the name the row answers by (``Registry.address_of``, ADR-0002), which is
  ``<capability>.<svc_label>.<domain>`` for a primary and ``<row>.<svc_label>.<domain>`` for an
  ``eval`` or ``retiring`` row; a ``legacy`` row answers by no name and is refused.  A client names
  the alias, never an address, so a cutover changes DNS only.  The row's host id must still be in
  ``hosts:``, or the row is refused by name.

``scheme`` (stub shape) is free text (``https``, ``http``, ``tcp``, ``udp``, ``ldaps``, ``ssh`` in the example
registry) and defaults to ``https`` in a url; ``host`` and ``port`` are required for ``url`` and
for the field asked, and a row without one is refused by name.

``field='capability'`` is what the service provides (empty when the row does not say), so a role
can refuse an id that resolves to the wrong kind of service.  ``field='public_hostname'`` is the
name clients use for the service through the edge (the platform registry's ``public_hostname``),
refused by name when the row has none.
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
    description: One of host, port, url, capability, public_hostname.
    default: url
"""


def _platform_scheme(row: dict) -> str:
    """``homelabnext.registry.model.Service.scheme``, restated so the plugin needs only PyYAML
    (a parity test pins the two together)."""
    protocol = row["protocol"]
    if protocol in ("http", "https"):
        upgraded = protocol == "https" or row.get("tls") in ("internal", "public", "mtls")
        return "https" if upgraded else "http"
    return protocol


def _platform_name(term: str, row: dict, doc: dict) -> str:
    """The name the row answers by (``Registry.address_of``), after checking its host id."""
    for key in ("protocol", "host", "capability"):
        if row.get(key) in (None, ""):
            raise AnsibleLookupError(f"hnx_registry: service '{term}' has no {key}")
    if row["host"] not in (doc.get("hosts") or {}):
        raise AnsibleLookupError(
            f"hnx_registry: service '{term}' names host '{row['host']}', which is not in the "
            "registry's hosts map"
        )
    lab = doc.get("lab") or {}
    if not lab.get("domain"):
        raise AnsibleLookupError("hnx_registry: the registry has no lab.domain")
    tier = (row.get("standing") or {}).get("tier", "primary")
    if tier == "primary":
        label = row["capability"]
    elif tier in ("eval", "retiring"):
        label = term
    else:
        raise AnsibleLookupError(
            f"hnx_registry: service '{term}' is a {tier} row: it answers by no name"
        )
    return f"{label}.{lab.get('svc_label', 'svc')}.{lab['domain']}"


class LookupModule(LookupBase):
    def run(self, terms, variables=None, **kwargs):
        field = kwargs.get("field", "url")
        if field not in ("host", "port", "url", "capability", "public_hostname"):
            raise AnsibleLookupError(f"hnx_registry: unknown field '{field}'")
        path = (variables or {}).get("hnx_registry_file")
        if isinstance(path, str) and "{{" in path and self._templar is not None:
            # an inventory sets it relative to itself ("{{ inventory_dir }}/..."); a lookup is
            # handed the variable as written, so it is templated here
            path = self._templar.template(path)
        if not path:
            raise AnsibleLookupError(
                "hnx_registry: inventory variable hnx_registry_file is not set"
            )
        try:
            with open(path, encoding="utf-8") as fh:
                doc = yaml.safe_load(fh) or {}
            services = doc.get("services", {})
        except OSError as exc:
            raise AnsibleLookupError(f"hnx_registry: cannot read registry: {exc}") from exc
        out = []
        for term in terms:
            row = services.get(term)
            if row is None:
                raise AnsibleLookupError(f"hnx_registry: unknown service id '{term}'")
            if not isinstance(row, dict):
                raise AnsibleLookupError(f"hnx_registry: service '{term}' is not a mapping")
            if field == "capability":
                out.append(str(row.get("capability", "")))
                continue
            if "hosts" in doc and field in ("url", "host"):  # the platform shape
                name = _platform_name(term, row, doc)
                if row.get("port") in (None, ""):
                    raise AnsibleLookupError(f"hnx_registry: service '{term}' has no port")
                if field == "host":
                    out.append(name)
                else:
                    out.append(f"{_platform_scheme(row)}://{name}:{row['port']}")
                continue
            needs = ("host", "port") if field == "url" else (field,)
            missing = [k for k in needs if row.get(k) in (None, "")]
            if missing:
                raise AnsibleLookupError(
                    f"hnx_registry: service '{term}' has no {' or '.join(missing)}"
                )
            if field == "url":
                out.append(f"{row.get('scheme', 'https')}://{row['host']}:{row['port']}")
            else:
                out.append(row[field])
        return out
