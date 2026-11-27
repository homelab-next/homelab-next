---
summary: File analysis is a contained AssemblyLine 4 stage in the VLAN 40 research zone on pm200, no egress, staged updates, pull-only results to lake, MISP, IRIS.
summary_of: outline:sha256:45c4a04f0fa446ac
---
# ADR-0052: File analysis runs in a contained research stage on AssemblyLine 4

- **Status:** proposed (placement revised 2026-11-27: VLAN 40 on pm200, operator decision; supersedes the
  pm205 core-VLAN placement this ADR first recommended)
- **Date:** 2026-11-26 (revised 2026-11-27)
- **Related:** ADR-0008 (export hooks), ADR-0012 (the hypervisor is not modular), ADR-0049 (the SOC
  data plane), `docs/network-model.md` (one-way zones), `docs/modules/egress.md`,
  `modules/assemblyline/README.md`; the old lab's malware-zone design (homelab-infra
  `dev/architecture.md` section 6 "Malware lab in/out data contract", `ansible/roles/pve_vm_firewall`,
  `ansible/unifi_vlan40_firewall*.yml`, `scripts/cape_maintenance_window.sh`,
  `ansible/roles/cape_update_proxy`) and the pipeline plan `~/hnx-deploy/plans/2026-11-27-research-pipeline-vlan40.md`
- **Operator decisions owed:** section "Decisions the operator owns" below; nothing in this ADR is
  deployed and the overlay's guest record is a proposal.

## Context

The operator wants a file-analysis stage in the research pipeline: files the lab already collects
(sources the CTI pipeline reads, payloads the remote honeypot captured, samples a researcher drops
in) get a verdict, extracted indicators and a reproducible record, and those land where the lab
already looks for them (the lake, the threat-intelligence store, the case manager). The product
chosen is [AssemblyLine 4](https://github.com/CybercentreCanada/assemblyline) (AL4), the Canadian
Centre for Cyber Security's open-source (MIT) file-triage and malware-analysis platform. This is
lab-internal analysis and research of files the lab already holds; nothing leaves the lab.

What was read for this ADR (the project's compose repository, `assemblyline-docker-compose`, at its
default branch on 2026-11-26, and the AL4 documentation site), and what it says:

- **Two deployment shapes.** An *appliance* on one Docker host (the compose repository), and a
  *cluster* on Kubernetes (also a MicroK8s appliance). The compose appliance does not support Swarm.
  The compose repository's `.env` pins the release `AL_VERSION=4.8.0.stable4` (the same tag exists
  for every `cccs/assemblyline-*` image on Docker Hub).
- **Components** (compose profile `minimal`): Elasticsearch 8.10.2 (datastore, single node), Redis,
  MinIO (filestore: `al-storage`, `al-cache`, optional `al-archive`), `nginx` front (TLS on 443),
  `ui` and `socketio` and the web `frontend`, and the core processes (`dispatcher`, `ingester`,
  `service_server`, `expiry`, `workflow`, `alerter`, `heartbeat`, `plumber`, `statistics`; `archiver`
  under the `archive` profile), plus `scaler` and `updater`. Profile `full` adds metrics, logs, Kibana
  and APM in Elasticsearch; profile `mcp` adds an MCP server at `/mcp`.
- **The two containers that matter for containment.** `scaler` and `updater` run `privileged: true`
  with `/var/run/docker.sock` mounted (the compose file's own comment: "this is like root"). The
  scaler starts and stops the analysis-service containers on demand through that socket; the updater
  runs the services' signature and rule updaters. So **the Docker host is the trust boundary**: a
  compromise of either container is root on the guest that runs it.
- **Networks.** The appliance defines `core` (`internal: true`, no route out), `registration`
  (`internal: true`) and `external`. Only the nginx front, `ui`, `socketio`, `dispatcher` and
  `updater` join `external`. Analysis-service containers the scaler starts are attached to `core`
  (`AL_CORE_NETWORK`), so by default they cannot reach the internet; a service can be given
  "Internet Access" in its container settings. A service in its default mode reaches the core only
  through the service server (it is not privileged); a privileged-mode service pulls from Redis
  directly and is not used here.
- **What needs the internet** (without a mirror): pulling images from Docker Hub at install, at
  upgrade and whenever the scaler starts a service container it does not have; the updater's rule
  and signature sources (public Git repositories and feeds, per service, configured under Source
  Management); the services that call outside (reputation and sandbox lookups, URL download); and the
  default `submission.file_sources` entry (MalwareBazaar). The documentation has **no air-gapped
  guide**; the mechanism it does give is `$REGISTRY` (the image registry the manifests are rendered
  against), a per-service internet switch, and the updater's configurable sources. The offline
  design below is therefore ours, built from those three, and is unverified until it has run.
- **Hardware.** The appliance page gives only a minimum: 4 CPUs and 8 GB of RAM, on Ubuntu 22.04 or
  24.04 (or RHEL 8.5); the default `ELASTIC_MEM` is 2048 MB and `core.scaler.service_defaults.min_instances:
  0` means services scale from zero on demand. The lab's guests are Debian 13; the appliance is
  Docker-only, so the OS is expected to work, but that is untested here.
- **Interfaces.** REST (`/api/v4/...`) and the Python client `assemblyline_client`
  (`get_client(url, apikey=(user, key))`; `submit` for one file, `ingest` with a notification queue
  for a stream; `search.submission` and `search.stream.submission` for results; `submission(sid)` for
  the whole record). Authentication is an **API key** (per user, privileges no greater than its
  owner's, shown once, the integration method the project recommends), username and password, an
  OAuth bearer token, or a client certificate. The server can sign users in through **OpenID
  Connect** (`auth.oauth.providers.<name>`, with a discovery URL, `auto_create`, `auto_sync` and
  role mapping; Keycloak is one of the documented examples and needs a `groups` claim mapper) or LDAP.
- **Licences.** AL4 itself is MIT. The product is a framework with about fifty community services,
  each with its own manifest and licence; **the individual services' licences were not audited for this
  ADR** and each must be read before it is installed. Known cases to check first: commercial
  antivirus and reputation services need the vendor's licence and key and mostly need the
  internet (out of scope here); a sandbox service needs a sandbox host. The data tier's licences are
  not MIT either: Elasticsearch 8.10.2 and Kibana are under the Elastic licence (not an OSI licence;
  the lab uses it unmodified and does not offer it as a service), MinIO is AGPL-3.0, and Redis from
  7.4 on is not BSD (the lab pins the 7.2 line, BSD, as `modules/intelowl` does).

The lab's facts this rests on: the operator decided on 2026-11-27 that the **whole research pipeline
(the CAPE sandbox, Ghidra and this AL4 stage) lives on VLAN 40 on pm200**, under the old lab's tight
controls and its staged update process, so AL4 is one more guest of the existing malware-analysis zone
(a one-way zone in the site model; the sandbox guest's own firewall is at `policy_out DROP`). The old
lab ran that zone on a separate hypervisor (pm203, now out of the fleet and unreachable); the
controls were built and live-verified there (Proxmox per-VM firewall as the primary layer, UDR7 rules
as the second) and are the design this ADR reuses. The network model's **one-way zone** (`egress.one_way`) forbids any rule that lets traffic into it from
elsewhere except an explicit, listed flow; the per-guest hypervisor firewall (`policy_in`/`policy_out`
with `inbound_allow` and `outbound_allow`) is enforced outside the guest, so a compromised guest cannot
edit it, and Docker's published ports bypass the guest's own chains (so the hypervisor-level rule is the
only filter that counts, as other lab guests already note).

## Decision

1. **AL4 runs as the compose appliance, profile `minimal`, pinned by tag and digest, in one dedicated
   VM that runs nothing else.** The module is `modules/assemblyline` (provider of a new, provisional
   slot `file-analysis`). Kubernetes is not used: one node does not need it and the cluster guides
   add a control plane that is another thing to contain. The docker socket held by `scaler` and
   `updater` is accepted **only** because of decisions 2 to 4: the VM, not the container, is the
   boundary. The module refuses to place beside another module on the same guest.
2. **Placement (operator decision 2026-11-27): a dedicated guest on VLAN 40 on pm200, next to the CAPE
   sandbox and Ghidra, under the zone's existing containment.** The zone's contract is the old lab's
   (homelab-infra `dev/architecture.md` section 6): a per-VM hypervisor firewall at `policy_in DROP` and
   `policy_out DROP` is the primary layer (enforced outside the guest), the router's VLAN 40 rules
   (allow established/related, scoped allow of the SIEM agent port, deny-all at an index below the broad
   allow rules) are the second, and two separate one-way channels are never crossed: the trusted side
   initiates everything that goes in, the zone never initiates anything that goes out. For this guest:
   - *Inbound allow list, exactly:* SSH from the deploy workstation, the metrics scrape (9100) from the
     metrics guest, HTTPS (443) from the submitters (decision 4), nothing else. The UI is not exposed to
     the edge guest; analysts reach it through the workstation (or the edge's sign-in only if the operator
     later decides so, see O1).
   - *Outbound list: empty.* Not DNS, not NTP, not the secret store, not the lab resolver. Secrets and the
     image set arrive in (decisions 5 and 7); results are pulled out (decision 4). The zone's only
     standing outbound exception is the SIEM agent (port 1514 to the SIEM guest's one address, the
     router's scoped allow plus the guest's one `outbound_allow`), kept as the old lab's sandbox kept it
     (decision O3, now the default).
   - *Zone mechanics:* the guest takes a 192.168.40.x address and the VLAN 40 tag on pm200's bridge. The
     router has `internet_access_enabled` on this network and relies on the guest's own `policy_out DROP`
     for the internet block (a known gap in the old lab's site model), so the guest firewall file is
     mandatory, not optional, and is checked by the health hook (decision 9). Test every reachability
     claim **from the one authorised source**, never from the hypervisor (the old lab's LL-102 lesson).
   - *Gate:* **no file is submitted until a test from the guest shows an outbound connection to an
     internet address and to a lab address both fail**; the module's health hook asserts it.
   - *Not co-located with trusted services:* the research guests share pm200 with nothing that holds
     production secrets once the old lab's guests are retired; until then the VLAN 40 bridge and the
     per-VM firewall are the separation, and the plan's host-neighbour caveat applies (see the plan).
3. **Defence in depth inside the guest.** The appliance's `core` and `registration` networks stay
   `internal: true`; service containers are not given internet access (the module's service
   manifest rewrite sets it to off and the health hook lists any service with it on); the UI's
   response-rendering of hostile content is a known XSS surface, so it is reached by analysts through
   the edge's sign-in only and the guest's UI port admits the edge guest alone. No sandbox with live
   network behaviour is installed here; if a dynamic-analysis service is wanted later it is a separate
   decision and uses the lab's existing isolated-zone sandbox rather than a second one.
4. **One-way data flow: files go in, results are pulled out, the stage never calls out.**
   - *In:* the trusted side initiates, the zone never reaches out. A submitter (the CTI pipeline's file
     step, the honeypot payload hand-over, a researcher through the client) calls the AL4 API on 443
     with its own API key (`submit` for one file, `ingest` with a notification queue for a stream) and
     the file's origin, TLP and source id as submission metadata. Files stay under the lab's TLP rules
     (default `amber`). **This is a documented exception to the one-way contract**, the same shape as
     the old lab's one inbound allow for the sample intake (workstation to the sandbox on 22): each
     submitter is one allow, **source = that one address, destination = this guest's one address, port
     443**, listed in the site model's `service_exceptions` and in the guest's `inbound_allow`, never a
     zone or a range. **Move bytes, never execute**, and screen first: a submitter hashes the file
     and applies the lab's existing gates (hash lookup, TLP) before the upload, as the old lab's intake
     did for the sandbox. Files that live on other hosts reach a submitter by the old lab's one auditable
     path (DFIR collection to the collection server, then submission), not by an arbitrary host pushing
     to the zone. Raw hostile content is never returned to a submitter except as the normalised row.
   - *Out:* the SOC pulls, the zone never pushes (the old lab's egress rule: the zone is write-only to
     its outbox, the trusted side is read-only). A **result puller** (a feature module, `file-analysis-export`, PR 3) on a lake-side guest
     calls `search.stream.submission` with a high-water mark and writes one row per finished
     submission to a fresh lake table `soc.file_analysis` through the lake-writer pattern
     (`LakeClient.write_batch`, commit then checkpoint, `uid` = submission id + file sha256, a `tlp`
     column, `day(time)` partitioning): sha256 and other hashes, file type, AL4's score and its
     verdict band, the heuristics fired, the extracted tags that are indicators (domains, URIs,
     addresses, mutexes, rule names), the service versions and signature set versions that produced it
     (so a verdict is reproducible), and the submitter. The row is the OCSF file-activity class where it
     fits and the table's own columns where it does not.
   - *Onward:* indicators above a stated score and TLP go to MISP as attributes on an event for the
     submission (the MISP module's existing API, TLP carried; the puller is the old lab's "disposable
     normalizer" pattern: strict schema validation, typed fields only, no raw blobs, because *direction
     is not sanitisation*), and a case in the case manager gets
     the submission link and verdict on request, never automatically. AL4's own alerter is off.
   - *Never:* AL4 does not push, notify, fetch URLs (the `URLDownloader` service is not installed)
     or enrich from outside. Indicators it extracts are looked up afterwards by the existing
     enrichment stage, outside this guest.
5. **Secrets are in the lab's OpenBao and arrive with the deploy, not at runtime.** Names in the module's own secret namespace (`assemblyline`): `admin-password`, `elastic-password`, `filestore-password`,
   `service-api-key`, and one `apikey-<consumer>` per submitter or puller (least privilege: the
   submitters' keys can submit and read their own submissions; the puller's can search and read). The
   module reads each by name at deploy time (a lookup on the deploy side), writes the compose
   project's 0600 env files and `config.yml`, and the guest holds no secret-store credential. The
   appliance's `.env` defaults (`password_123` and the rest) are never used; a default password
   fails the module's validate hook. API keys are created by the module through the API with the
   admin account on first deploy and written to the store create-only.
6. **Sign-in.** Local accounts and API keys first (`auth: own` in the registry row, as the other
   products with their own accounts). OpenID Connect through the lab's identity provider (Keycloak)
   comes next (PR 2): `auth.oauth` with `auto_create: false`, roles mapped from a group claim, the
   local admin kept as break-glass. Auto-create against a provider the lab does not control is
   refused by the module.
7. **Offline by design, with the old lab's staged update process.** The zone has no internet and no
   standing route to anything that has. Updates are staged on the trusted side and cross in under one of
   the two mechanisms the old lab already ran; nothing is pulled by the guest on its own schedule.
   - *Big and rare (the container image set, service images, a golden image): pushed in through the
     intake channel.* The deploy imports images **by digest** from an archive built on the workstation
     (`docker save`; the pattern `llamacpp_image_archive` already sets), over the same inbound SSH the
     samples use, then sets `REGISTRY` so the scaler resolves service images locally. Digest, size and
     sha256 are recorded; the guest checks the digest before `docker load`.
   - *Small and frequent (OS packages and the updater's rule and signature sources): the supervised
     maintenance window.* The old lab's gated window (`scripts/cape_maintenance_window.sh`): steady
     state is deny; an operator-present script saves the guest's firewall file, opens a scoped,
     temporary outbound to **one pull-through proxy on a trusted host** (the old lab's squid with a
     destination allowlist and a source pinned to the client address, two independent layers agreeing),
     verifies reachability, does the work, and **restores the saved file byte for byte** in the same run
     (trap on exit; the next config-management run re-asserts the canonical file if the script is killed).
     The proxy's allowlist is exactly the package index and the named rule sources, reviewed per change;
     it is not a general internet route and not a place a payload can phone home to. Where a rule source
     can be fetched on the trusted side instead, it is staged there and pushed in with the images (no
     window needed). The old lab's update proxy ran on a guest that is being decommissioned, so the
     proxy needs a new home (decision O2).
   - Services are installed from a reviewed allow list (not "Install All"); the default MalwareBazaar
     file source is removed; the first set is the offline-capable static set (type identification, YARA
     with a pinned local ruleset, document and archive extraction, string and PE/ELF/script static
     analysis, entropy, safelisting), fixed in PR 2 after reading each manifest and licence. Each source
     the updater reads is rendered as a local file or directory or as a proxy-allowlisted URL, and is
     listed so a window can be audited afterwards.
8. **Sizing on pm200 (starting point, to be re-measured after a week; pm200's free RAM and pool space must be read before the guest is created, the numbers below were written against pm205).** One VM: **16 vCPU, 48 GiB
   RAM, 600 GB disk** on the VM pool (`vmdata`), type `host`. Budget: Elasticsearch heap 8 GiB
   (`ELASTIC_MEM=8192`, the OS keeps as much again for page cache), Redis 1 GiB, MinIO and core
   processes about 8 GiB, service containers about 16 GiB at the scaler's default scale-from-zero.
   Disk: the datastore and the filestore grow with retention; submission expiry is set to 90 days
   at first and the malware archive profile stays off until it is wanted. The figures are our
   estimate (the project publishes only the 4 CPU / 8 GB minimum), sized to the pipeline's volume
   (hundreds of files a day, not millions) with headroom for the services' memory; the ceiling is
   cheap on this host, the floor is not.
9. **Health is a containment check, not just a liveness check.** The role's health hook fails when:
   the front does not answer or an anonymous API call is not refused; any core container is not
   healthy; any installed service has internet access on; any service is privileged-mode; the
   docker socket is mounted in any container other than `scaler` and `updater`; a default
   password is in use; or (when the module is told the guest's own addresses) an outbound probe to a
   public address or a lab address succeeds.
10. **Backups.** The data to keep is the datastore (accounts, API keys, submissions, results,
    service configuration, signatures) and the filestore (the files). Export hook (ADR-0008): an
    Elasticsearch snapshot to a path on the guest's data disk plus a copy of the MinIO buckets, with a
    sha256 listing; restore takes the listing and refuses a target with data unless asked. The
    guest is in the hypervisor's nightly VM backup job like the other guests, but **the sample files
    are quarantined data**: the backup target's access is the lab's own, the VM backup is encrypted
    where the target supports it, and the sample filestore can be excluded by the operator
    (decision O5) so only verdicts are backed up. Restore drills follow the lab's drill procedure.
11. **Upgrade path.** A bump is the release tag and all its digests together (every `cccs/assemblyline-*`
    image is on one tag), validated and recorded by the upgrade hook, the export taken first, then
    converged; the datastore migrates on first start of the new release and cannot go back, so the
    hook refuses an older tag. The Elasticsearch pin moves separately and only within the major
    version the release supports. Service images move with their own tags through the scaler once
    imported (decision 7). Pins are listed in `tools/pin_freshness.py` like every other image.
12. **Sequence.** PR 1 (this ADR and the module scaffold) changes nothing running. PR 2 completes the
    module (the privileged pair, `config.yml` rendering, bootstrap, service allow list, the offline
    mirror, the health and containment checks) and is rehearsed in the throwaway staging guest with
    a deliberately hostile test file (a harmless EICAR-class sample) before the research guest
    exists. PR 3 adds the result puller and the lake table. The guest is built only after the operator
    answers the decisions below.

### Decisions the operator owns

- **O1. Placement: DECIDED 2026-11-27 (operator).** VLAN 40 on pm200, with CAPE and Ghidra, under the
  zone's existing controls (decision 2). Still open under it: (i) does pm200's bridge carry VLAN 40 and
  does the switch port trunk it (the old lab's lesson: the bridge must be VLAN-aware and the trunk is
  not assumed; verify, do not trust); (ii) analyst access to the UI: through the workstation only
  (default) or also through the edge's sign-in; (iii) sequencing against pm200's decommission (the
  research guests need pm200 up, so they are a reason it is not switched off).
- **O2. Image and rule delivery: DECIDED in shape.** The staged process of decision 7 (archive push for
  images, supervised window through the pull-through proxy for packages and rule sources). Still open:
  where the proxy lives now that infra-core is being retired (an existing guest of the new lab or a
  small dedicated one), and whether rule sources are staged on the trusted side instead of through the
  proxy.
- **O3. The SIEM agent port as the one allowed outbound: now the default** (it is the zone's one
  standing exception, as for the sandbox); the operator only needs to object.
- **O4. Which submitters are admitted** at go-live, each as a named one-address exception to the
  one-way zone (default: the pipeline guest, the honeypot receiver's guest, the research workstation).
  Each is a deliberate hole in the contract, so the list is the operator's.
- **O5. Backup scope:** include the sample filestore in the VM backup or exclude it (verdicts only).
- **O6. Sizing and the pool's declared capacity:** accept 16 vCPU / 48 GiB / 600 GB, or a smaller start,
  against **pm200's** free RAM and pool space (read them first). The pm205 declared-capacity problem found
  on 2026-11-26 (3000 GB declared, 2990 GB already declared) no longer applies to this guest.
- **O7. A dynamic-analysis (sandbox) service:** none now. CAPE is in the same zone; if AL4 should hand
  files to it, that is a zone-internal flow to design later, never a second sandbox with network behaviour.
- **O8. Sign-in:** local accounts and API keys now, the lab's identity provider in PR 2 (default yes).

## Consequences

- A new, contained stage exists for files; the rest of the lab gains verdicts, indicators and a
  reproducible record without any other guest receiving a sample.
- The guest is **not** a general-purpose host: it cannot be updated from the internet, its package
  repositories and its container registry must be fed in (staged push or a supervised window), and its
  upgrades are an operator-paced import. That is the price of containment and it is deliberate.
- The docker socket's root-equivalence is accepted for two containers; the VM and its firewall
  carry the risk, so the firewall rules and the guest's single-purpose rule are load-bearing and
  are checked by the health hook rather than trusted.
- The module is large (about a dozen core containers plus services) and `compose_app` does not yet
  express an `internal` network, the `extends` of the upstream files, the privileged pair or the
  scaler's own container spawning; PR 2 either extends `compose_app` or renders the project in the
  module's role.
- The datastore is Elasticsearch: a second search engine beside the SIEM's indexer, with its own
  upgrade cadence and licence terms.
- Results are TLP-labelled and enter the lake as a fresh table; a retention and expiry decision is
  owed for both the filestore and the table.

## Alternatives

- **Kubernetes (MicroK8s or a cluster).** The cluster shape AL4 is built for; rejected for one
  node: a control plane to contain and upgrade for no scaling the lab needs. Pods would also not
  remove the need for the node boundary.
- **Run AL4 on an existing guest** (the pipeline or the SIEM guest). Rejected: the scaler's docker
  socket makes any co-tenant's secrets one container escape away.
- **Place it in an LXC.** Rejected: nested container-runtime privileges and a shared kernel are the
  wrong shape for the stage that handles hostile files.
- **A dedicated guest on pm205's core VLAN** (this ADR's first recommendation, 2026-11-26, VM 148).
  Superseded by the operator's 2026-11-27 decision to run the whole research pipeline in one contained
  zone; it had one router-less layer (the per-guest firewall) where VLAN 40 adds the router's rules, and
  it split the pipeline across two hypervisors.
- **A new research zone instead of VLAN 40.** Not needed: VLAN 40 already exists as the research
  network; the one-way contract gets named per-submitter exceptions instead.
- **Another analysis product** (the lab's sandbox alone, an enrichment-only service, a hash-lookup
  pipeline). The sandbox answers a different question (dynamic behaviour of one sample) and the
  enrichment product looks up observables it is given; neither unpacks, extracts and scores
  an arbitrary file with a reproducible service set. They stay as stages around this one.
- **Internet-connected services for better verdicts.** Rejected for the lab's own files: submitting
  a file or its hash to a third party is a disclosure decision per file, not a default; the
  existing enrichment stage already covers hash and indicator reputation from outside, after the fact,
  under the pipeline's TLP rules.
