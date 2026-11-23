# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: vector-package
#   kind: tool
#   purpose: Mark the vector module's package, the directory the sidecar and its remap are imported from on the guest.
#   owner: platform
#   trigger: [role:vector]
#   inputs: nothing (imported, never run)
#   outputs: nothing
#   exit:
#     "0": imported
"""The vector module's code (modules/vector/README.md): the enrichment sidecar the Vector
aggregator hands every event to (``sidecar``), the OCSF remap it applies (``ocsf``) and the
``log-pipeline`` conformance adapter (``log_pipeline``).

``sidecar`` and ``ocsf`` run on the guest from the standard library alone, beside a verbatim copy
of the core's label rules (``homelabnext/tlp.py`` and ``homelabnext/logpipeline/``): the rule that
labels an event on the guest is the library's own bytes, not a port."""
