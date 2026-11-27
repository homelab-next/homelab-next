---
group: Fixed
---
ansible/roles/wazuh_agent: a drop-in gives the agent's unit `Restart=on-failure`, `RestartSec=30`, `TimeoutStartSec=120` and no start limit. The vendor unit has no `Restart=` and a 45 s start timeout, so an agent that booted before its manager was up (a whole-host power cycle) timed out once and stayed failed until restarted by hand; it now retries until the manager answers.
