---
summary: File analysis is a contained research stage on AssemblyLine 4 in its own guest, no egress, pull-only results; verdicts reach the lake, MISP and IRIS.
summary_of: outline:sha256:45c4a04f0fa446ac
---
# ADR-0052: File analysis runs in a contained research stage on AssemblyLine 4

- **Status:** proposed
- **Date:** 2026-11-26
- **Related:** ADR-0008 (export hooks), ADR-0012 (the hypervisor is not modular), ADR-0049 (the SOC
  data plane), `docs/network-model.md` (one-way zones), `docs/modules/egress.md`,
  `modules/assemblyline/README.md`
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

The lab's facts this rests on: the new lab runs on a single hypervisor (pm205: 256 threads, about 1
TiB of RAM, of which a few hundred GiB are unallocated at the time of writing) with guests on the
core VLAN; the old lab's malware-analysis zone (VLAN 40, a one-way zone in the site model, its sandbox
guest's own firewall at `policy_out DROP`) is on another hypervisor that is being decommissioned; the
network model's **one-way zone** (`egress.one_way`) forbids any rule that lets traffic into it from
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
2. **Placement (recommended now): a dedicated guest on pm205 on the core VLAN, `policy_in DROP` and
   `policy_out DROP`, no route to any lab service.** Inbound is an allow list of exactly: SSH from the
   deploy workstation, the metrics scrape (9100) from the metrics guest, HTTPS (443) from the submitters
   (the pipeline guest, the honeypot receiver's guest, the research workstation) and from the edge guest
   (the UI), nothing else. Outbound is **empty**: not DNS, not NTP, not the secret store, not the lab
   resolver; secrets and the image set are delivered in (decisions 5 and 7), and results are pulled out
   (decision 4). One optional outbound allow is permitted only by a recorded decision: the SIEM agent's
   port to the SIEM guest's one address (the same single exception the old lab's analysis guest
   carries). The ADR's gate: **no file is submitted until a test from the guest shows an outbound
   connection to an internet address and to a lab address both fail**; the module's health hook
   asserts it (decision 9).
3. **Defence in depth inside the guest.** The appliance's `core` and `registration` networks stay
   `internal: true`; service containers are not given internet access (the module's service
   manifest rewrite sets it to off and the health hook lists any service with it on); the UI's
   response-rendering of hostile content is a known XSS surface, so it is reached by analysts through
   the edge's sign-in only and the guest's UI port admits the edge guest alone. No sandbox with live
   network behaviour is installed here; if a dynamic-analysis service is wanted later it is a separate
   decision and uses the lab's existing isolated-zone sandbox rather than a second one.
4. **One-way data flow: files go in, results are pulled out, the stage never calls out.**
   - *In:* a submitter (the CTI pipeline's file step, the honeypot payload hand-over, a researcher
     through the UI or the client) calls the AL4 API on 443 with its own API key (`submit` for one
     file, `ingest` with a notification queue for a stream) and the file's origin, TLP and source id as
     submission metadata. Files stay under the lab's TLP rules (default `amber`).
   - *Out:* a **result puller** (a feature module, `file-analysis-export`, PR 3) on a lake-side guest
     calls `search.stream.submission` with a high-water mark and writes one row per finished
     submission to a fresh lake table `soc.file_analysis` through the lake-writer pattern
     (`LakeClient.write_batch`, commit then checkpoint, `uid` = submission id + file sha256, a `tlp`
     column, `day(time)` partitioning): sha256 and other hashes, file type, AL4's score and its
     verdict band, the heuristics fired, the extracted tags that are indicators (domains, URIs,
     addresses, mutexes, rule names), the service versions and signature set versions that produced it
     (so a verdict is reproducible), and the submitter. The row is the OCSF file-activity class where it
     fits and the table's own columns where it does not.
   - *Onward:* indicators above a stated score and TLP go to MISP as attributes on an event for the
     submission (the MISP module's existing API, TLP carried), and a case in the case manager gets
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
7. **Offline by design.** Image set: the module takes images **by digest** and the deploy imports
   them from an archive built on the workstation (`docker save`; the pattern `llamacpp_image_archive`
   already sets) or from a lab-internal registry, then sets `REGISTRY` so the scaler resolves service
   images there. Services are installed from a reviewed allow list (not "Install All"), their
   container images imported in the same way. Rule and signature sources are mirrored into the lab (a
   Git mirror the updater reads over the lab network is **not** reachable from a no-egress guest, so
   the mirror is *pushed in*: the deploy renders each source as a local file or directory the updater
   reads); the default MalwareBazaar file source is removed. The first set of services is the
   offline-capable static set (type identification, YARA with a pinned local ruleset, document and
   archive extraction, string and PE/ELF/script static analysis, entropy, safelisting); the list is
   fixed in PR 2 after reading each manifest and licence.
8. **Sizing on pm205 (starting point, to be re-measured after a week).** One VM: **16 vCPU, 48 GiB
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

- **O1. Placement.** (a) *Recommended for now:* a dedicated VM on the core VLAN under the hypervisor
  firewall described in decision 2 (`policy_out DROP`, empty outbound list). (b) A dedicated VM on a
  segment of its own, which adds a second, router-level layer. The old lab's isolated VLAN 40 is the
  obvious candidate but its site model is a **one-way** zone (nothing may be admitted into it), the opposite
  of what a submitted-to service needs, so either VLAN 40 gets a documented exception (the submitters'
  HTTPS and the metrics scrape in, nothing out) or a new research zone is added to the site model. The
  lab already runs an untrusted-workload guest on a non-core VLAN of this hypervisor (the CI runner pool),
  so the bridge carries other VLANs; the switch port's trunk for the chosen VLAN was not verified. (c) Wait
  for the isolated network on the old hypervisor, the lab's stated long-term home, which is being
  decommissioned. This ADR recommends (a) now and (b) once the VLAN, its switch trunk and its router rules
  exist, and does not recommend (c): waiting leaves the pipeline without the stage.
- **O2. Image and rule delivery.** Archive import by hand (no window, one operator step per release),
  or a short supervised bring-up window with outbound open (as the GPU guests had) before the guest
  is locked. Recommended: archive import; it needs no window.
- **O3. Is the SIEM agent port an allowed outbound?** Recommended yes, one address, one port, so the
  guest is monitored like the rest; otherwise the host's own logs are pulled.
- **O4. Which submitters are admitted** at go-live (default: the pipeline guest, the honeypot
  receiver's guest, the research workstation).
- **O5. Backup scope:** include the sample filestore in the VM backup or exclude it (verdicts only).
- **O6. Sizing and the pool's declared capacity:** accept 16 vCPU / 48 GiB / 600 GB, or a smaller start.
  The lab's node record declares the guest-disk pool at 3000 GB and the guests already declare 2990 GB of it
  (the pool's real use on 2026-11-26 was about 0.5 TB, so the figure is a declared total, not a reservation),
  so any disk of this size fails the overlay's declared-capacity check: the operator either raises the declared
  figure to what the pool really holds (about 3.1 TB, still too small for 600 GB on top of 2990), accepts the
  overcommit explicitly, or trims another guest.
- **O7. A dynamic-analysis (sandbox) service:** none now. Revisit only with the lab's existing
  isolated-zone sandbox, never a second one with network behaviour.
- **O8. Sign-in:** local accounts and API keys now, the lab's identity provider in PR 2 (default yes).

## Consequences

- A new, contained stage exists for files; the rest of the lab gains verdicts, indicators and a
  reproducible record without any other guest receiving a sample.
- The guest is **not** a general-purpose host: it cannot be updated from the internet, its package
  repositories and its container registry must be fed in, and its upgrades are an operator-paced
  import. That is the price of containment and it is deliberate.
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
- **The isolated VLAN 40 now.** Stronger (a router layer on top of the guest firewall), not available today: its one-way contract forbids the inbound submissions (decision O1b).
- **Another analysis product** (the lab's sandbox alone, an enrichment-only service, a hash-lookup
  pipeline). The sandbox answers a different question (dynamic behaviour of one sample) and the
  enrichment product looks up observables it is given; neither unpacks, extracts and scores
  an arbitrary file with a reproducible service set. They stay as stages around this one.
- **Internet-connected services for better verdicts.** Rejected for the lab's own files: submitting
  a file or its hash to a third party is a disclosure decision per file, not a default; the
  existing enrichment stage already covers hash and indicator reputation from outside, after the fact,
  under the pipeline's TLP rules.
