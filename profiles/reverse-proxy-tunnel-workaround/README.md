<!-- SPDX-License-Identifier: Apache-2.0 -->
# reverse-proxy-tunnel-workaround

Kind `patch-overlay`. Appends a small block to the `example_service` config template.
Template overlays are addressed by role and template name; the core template is never edited,
and the overlay's content hash appears in the plan so a drifted overlay is visible.
