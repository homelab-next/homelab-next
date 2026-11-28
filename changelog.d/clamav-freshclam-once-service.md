---
group: Fixed
---
the virus scanner role masks the one-shot signature updater's service as well as its timer: the package enables the service at boot too, so it still ran beside the update daemon and failed on the log lock after every boot.
