<!-- SPDX-License-Identifier: Apache-2.0 -->
# Shipped optional profiles

Each directory is one customization (`customization.yml`) plus the files it references. They
are `optional: true`: loaded and linted always, applied only when a deployment enables the id.
The content is synthetic and shows the pattern; copy one into your own overlay directory and
change it rather than editing it here. See [docs/customization.md](../docs/customization.md).

| Directory | Kind | What it shows |
|---|---|---|
| `board-sensor-driver/` | profile | opt-in tasks that persist a hardware-sensor kernel module on boards that need it |
| `vlan-aware-bridge-verifier/` | profile | read-only verification tasks for a VLAN-aware hypervisor bridge |
| `reverse-proxy-tunnel-workaround/` | patch-overlay | a template overlay appended to a role template for a tunnel quirk |

Enable one for named hosts:

```sh
hnx custom plan --enable custom:board-sensor-driver=host-a,host-b
```
