---
group: Added
---
role `agent_rehome` (opt-in through `agent_rehome_enabled`, honoured by the SIEM agent role's main hook): moves an endpoint agent already enrolled with another manager to the registry's manager: backups, the configured address, the enrolment password from the secret store (never an argument), an emptied key, the enrolment command, start; an agent already there is left alone.
