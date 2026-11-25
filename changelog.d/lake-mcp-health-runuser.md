---
group: Changed
---
modules/lake-mcp: the health hook runs `hnx lake mcp --check` as the service account through `runuser`, not Ansible's `become_user`, which needs ACL tools a guest may not have (first live deploy).
