---
group: Added
---
module `prowler` (feature, bundle soc/cloud-posture): a weekly read-only cloud-posture scan from a pinned virtualenv with the credential read from the secret store into a root-only file, writing a summary line and one flat `pw_`-prefixed line per failing check to a findings file the SIEM agent and the log pipeline tail (a failed or empty scan leaves the last findings untouched); a mutelist that demands a reason and pinned resources for every entry and whose deferred entries fail health after their review month; hooks for validate, readiness, health, backup, restore, upgrade and export.
