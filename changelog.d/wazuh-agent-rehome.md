---
group: Added
---
role wazuh_agent: `wazuh_agent_rehome` (and the `rehome` hook) moves an agent already enrolled with another manager to the registry's manager: backups, the configured address, the enrolment password from the secret store (never an argument), an emptied key, agent-auth, start; an agent already there is left alone.
