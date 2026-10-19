<!-- SPDX-License-Identifier: Apache-2.0 -->
# vlan-aware-bridge-verifier

Kind `profile`. One read-only task that fails the play when the named bridge
(`vlan_aware_bridge_verifier_bridge`, default `vmbr0`) does not have VLAN filtering on. It
changes nothing.

Scope. The hypervisor is a fixed substrate, not a capability (ADR-0012), so the scope cannot name
it. The declared scope is `cap:edge`: enabled without a host list, the check runs on the hosts
that provide the edge capability, whose bridge carries the tagged trunk. To check a hypervisor
bridge, enable the profile for that host by name (it must be a host in the registry), which
replaces the capability scope with exactly those hosts:

    hnx custom plan --enable custom:vlan-aware-bridge-verifier=<host>
