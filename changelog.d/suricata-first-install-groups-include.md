---
group: Fixed
---
modules/suricata: a first install no longer fails its rule fetch on the not-yet-written address-groups include (a placeholder is written when the file is missing; suricata_enroll replaces it before the gate).
