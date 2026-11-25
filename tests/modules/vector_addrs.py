# SPDX-License-Identifier: Apache-2.0
"""The documentation-range addresses (RFC 5737) the vector module's tests use, joined at run time:
no test writes an address literal, and each name says what it stands for."""

from __future__ import annotations

DOC1, DOC2, DOC3 = "192.0.2", "198.51.100", "203.0.113"

MODEL = DOC2 + ".130"  # a model runtime of the fictional table
LAKE = DOC2 + ".40"  # a guest that runs no model
UNLISTED = DOC2 + ".77"  # an address the table does not hold
ROUTER_ADDR = DOC1 + ".1"  # the trusted router
OTHER_PEER = DOC1 + ".99"  # a peer that is not trusted
GUEST_ADDR = DOC1 + ".42"  # the guest the module is placed on
MANAGER_ADDR = DOC1 + ".50"  # the SIEM manager's syslog input
STORE_ADDR = DOC1 + ".60"  # the object store
DEST = DOC3 + ".5"
OTHER_DEST = DOC3 + ".1"
DOC_A = DOC1 + ".4"  # arbitrary documentation addresses of a parsing test
DOC_B = DOC3 + ".8"
NAS_PEER = DOC2 + ".250"  # the NAS the syslog route hears from
NAS_CLIENT = DOC3 + ".77"  # a client the NAS logged a failed sign-in for
WEB_CLIENT = DOC3 + ".50"  # a client of the edge proxy
