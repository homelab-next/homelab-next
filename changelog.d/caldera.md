---
group: Added
---
module `caldera` (feature): the Caldera adversary-emulation control-validation server (release 5.3.0) built on the guest from its pinned source tag and run as one compose_app container on an isolated guest; the UI and agent contact are published on the guest's own address only, with no public route and no SSO. The admin and research-account passwords come from the secret store and are written into the server's generated configuration at every converge; the compose mounts keep the baked UI (upstream's whole-tree bind mount does not); operations, adversaries, agents and artifacts are exported as a checked object tree before a removal.
