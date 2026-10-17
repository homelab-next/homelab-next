# SPDX-License-Identifier: Apache-2.0
"""Fictional lab data for the decommission tests (RFC 5737 addresses, example names)."""

FILES = {
    "inventory/hosts.yml": "all:\n  hosts:\n    app-core: {ansible_host: 192.0.2.50}\n",
    "inventory/host_vars/app-core.yml": "role: app\n",
    "playbooks/site.yml": "- import_playbook: app.yml\n- import_playbook: gone-core.yml\n",
    "playbooks/app.yml": "- hosts: app-core\n  tasks: []\n",
    "playbooks/other.yml": "- hosts: web-core\n  tasks: []\n",
    "terraform/app.tf": 'resource "x_vm" "app" {\n  name = "app-core"\n  vmid = 180\n}\n',
    "terraform/web.tf": 'resource "x_vm" "web" {\n  name = "web-core"\n  vmid = 190\n}\n',
    "config/proxy.conf": "upstream app-core:8080;\n",
    "config/notes.conf": "# was on old-core until the move\nkeep = 1\n",
    "docs/runbook.md": "The old-core host used to run this.\n",
}

SNAPSHOT = {
    "hypervisor": {
        "guest_configs": {"180": "name: app-core"},
        "firewall_files": ["180.fw", "190.fw"],
        "volumes": ["pool:vm-180-disk-0", "pool:vm-190-disk-0"],
        "backup_jobs": [{"id": "daily", "vmids": [180, 190]}],
        "ha": ["vm:180"],
    },
    "siem": {"agents": [{"name": "app-core", "ip": "192.0.2.50"}, {"name": "web-core"}]},
    "monitoring": {"targets": ["app-core:9100", "web-core:9100"]},
    "secrets": {"names": ["app_core_db_password", "web_core_token"]},
    "dns": {"records": ["app-core.example.internal A 192.0.2.50"]},
    "proxy": {"routes": [{"host": "app.example.invalid", "upstream": "app-core:8080"}]},
    "dhcp": {"reservations": [{"name": "app-core", "ip": "192.0.2.50"}]},
}
