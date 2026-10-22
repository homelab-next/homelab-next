<!-- SPDX-License-Identifier: Apache-2.0 -->
# ansible/playbooks/ (placeholder)

`site.yml` applies the hnx roles (from the pinned public checkout, `roles_path = hnx/ansible/roles`)
to the production inventory. The deploy workflow runs `ansible-playbook ansible/playbooks/site.yml`.
Start from the public `ansible/playbooks/example_service.yml`.
