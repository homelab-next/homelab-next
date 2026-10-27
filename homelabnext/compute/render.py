# SPDX-License-Identifier: Apache-2.0
"""Target dispatch table for ``hnx guests render``."""

from __future__ import annotations

from collections.abc import Callable

from .gen import (
    backup_jobs,
    baseline_playbook,
    cloudinit,
    firewall_rules,
    inventory,
    libvirt,
    node_mirror,
    registry_hosts,
    runtime_labels,
    tailscale_acl,
    terraform_proxmox,
)
from .model import ComputeError, Fleet

TARGETS: dict[str, Callable[[Fleet], dict[str, str]]] = {
    "terraform-proxmox": terraform_proxmox.render,
    "libvirt": libvirt.render,
    "cloudinit": cloudinit.render,
    "inventory": inventory.render,
    "registry-hosts": registry_hosts.render,
    "backup-jobs": backup_jobs.render,
    "firewall-rules": firewall_rules.render,
    "baseline-playbook": baseline_playbook.render,
    "tailscale-acl": tailscale_acl.render,
    "node-mirror": node_mirror.render,
    "runtime-labels": runtime_labels.render,
}


def render(fleet: Fleet, target: str) -> dict[str, str]:
    try:
        fn = TARGETS[target]
    except KeyError:
        raise ComputeError(
            f"unknown target {target!r}; known: {', '.join(sorted(TARGETS))}"
        ) from None
    return fn(fleet)
