---
group: Fixed
---
modules/zeek: `zeek_retired_units`, `zeek_retired_containers` and `zeek_retired_siem_markers` retire the predecessor once the module owns the captures (its watchdog disabled first, its containers kept from restarting and stopped, its SIEM agent localfile blocks removed), so each flow event is read once.
