# SPDX-License-Identifier: Apache-2.0
"""Target dispatch table for ``hnx guests render``."""

from __future__ import annotations

from collections.abc import Callable

from .gen import (
    backup_jobs,
    cloudinit,
    firewall_rules,
    inventory,
    libvirt,
    registry_hosts,
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
}


def render(fleet: Fleet, target: str) -> dict[str, str]:
    try:
        fn = TARGETS[target]
    except KeyError:
        raise ComputeError(
            f"unknown target {target!r}; known: {', '.join(sorted(TARGETS))}"
        ) from None
    return fn(fleet)
