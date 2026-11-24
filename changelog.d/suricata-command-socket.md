---
group: Fixed
---
modules/suricata: the command socket is at the command client's default path (`/run/suricata-command.socket`), where the distribution unit's reload and stop and the HOME_NET reload look; under `/run/suricata/` it never bound.
