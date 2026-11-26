# SPDX-License-Identifier: Apache-2.0
"""Load a directory of guest files, validate each against ``guest.schema.json``."""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Mapping
from fractions import Fraction
from pathlib import Path
from typing import Any

import yaml

from homelabnext import paths, shapes, sops
from homelabnext._schema_text import safe_message
from homelabnext._yaml import UniqueKeyStrDateLoader
from homelabnext.generators.safe import control_char_paths

from .baselines import BASELINES_FILE, load_baselines
from .model import ComputeError, ComputeUnreadable, Fleet, Guest, Problem, ZoneFlow, ZoneLookup

POLICIES_FILE = "_backup_policies.yml"
NODES_FILE = "_nodes.yml"
#: the problem text of a guest file that does not parse (bad input, see ComputeUnreadable)
UNREADABLE = "unreadable YAML"


# refuses duplicate keys; timestamps stay strings
_UniqueKeyLoader = UniqueKeyStrDateLoader


def schema() -> dict:
    return json.loads(
        paths.schema_file("platform", "guest.schema.json").read_text(encoding="utf-8")
    )


def schema_problems(doc: Any, where: str) -> list[Problem]:
    import jsonschema

    validator = jsonschema.Draft202012Validator(schema())
    out = []
    for err in sorted(validator.iter_errors(doc), key=lambda e: [str(p) for p in e.absolute_path]):
        path = "/".join(str(p) for p in err.absolute_path) or "<root>"
        out.append(Problem(where, f"schema: {path}: {safe_message(err)}"))
    return out


def guest_files(directory: Path) -> list[Path]:
    """``*.yml``/``*.yaml`` files that are guests (names starting with ``_`` are support files)."""
    return sorted(
        p
        for p in directory.iterdir()
        if p.suffix in (".yml", ".yaml") and not p.name.startswith("_") and p.is_file()
    )


def load_guests(directory: str | Path) -> tuple[list[Guest], list[Problem]]:
    """Parse every guest file.  Returns the guests that passed the schema and all problems."""
    d = Path(directory)
    if not d.is_dir():
        raise ComputeUnreadable(f"not a directory: {d}")
    guests: list[Guest] = []
    problems: list[Problem] = []
    for path in guest_files(d):
        where = path.name
        try:
            doc = yaml.load(sops.read_text(path), Loader=_UniqueKeyLoader)
        except (OSError, UnicodeDecodeError, yaml.YAMLError, sops.SopsError) as exc:
            problems.append(Problem(where, f"{UNREADABLE}: {exc}"))
            continue
        # Python's re lets a schema pattern's "$" match before a trailing newline, and every
        # target writes line-oriented text: refuse control characters in any key or value first
        errs = [Problem(where, f"unsafe: {m}") for m in control_char_paths(doc)]
        errs += schema_problems(doc, where)
        if errs:
            problems += errs
            continue
        g = Guest(doc, source=where)
        if path.stem != g.name:
            problems.append(Problem(where, f"file name must be {g.name}.yml to match id {g.id}"))
            continue
        guests.append(g)
    return guests, problems


def load_policies(path: str | Path) -> dict[str, Mapping[str, Any]]:
    """Read ``{policies: {name: {...}}}``; ``none`` is always implicitly defined."""
    p = Path(path)
    try:
        doc = yaml.load(sops.read_text(p), Loader=_UniqueKeyLoader)
    except (OSError, yaml.YAMLError, sops.SopsError) as exc:
        raise ComputeUnreadable(f"cannot read backup policies {p}: {exc}") from exc
    pol = (doc or {}).get("policies") if isinstance(doc, dict) else None
    if not isinstance(pol, dict):
        raise ComputeError(f"{p}: expected a mapping with a 'policies' mapping")
    return {str(k): (v or {}) for k, v in pol.items()}


def load_nodes(path: str | Path) -> dict[str, Mapping[str, Any]]:
    """Read ``{nodes: {name: {firewall: enabled|disabled, power: {...}, capacity: {...},
    pools: {...}, mirror: {...}, notify: {...}}}}``: what each hypervisor enforces, what feeds it
    (``power``, checked against the site by :func:`homelabnext.power.fleet_problems`), what it
    holds (``capacity`` and ``pools``, checked against its guests by
    :func:`homelabnext.compute.validate.validate`), where it copies its guests' traffic for a
    network sensor (``mirror``, rendered by the ``node-mirror`` target), and where its own
    notifications go (``notify``, rendered by the ``node-notify`` target), and which sources may
    reach its own SSH, web and API ports (``host_firewall``, rendered by the ``pve-host-firewall``
    target)."""
    p = Path(path)
    try:
        doc = yaml.load(sops.read_text(p), Loader=_UniqueKeyLoader)
    except (OSError, yaml.YAMLError, sops.SopsError) as exc:
        raise ComputeUnreadable(f"cannot read nodes {p}: {exc}") from exc
    nodes = (doc or {}).get("nodes") if isinstance(doc, dict) else None
    if not isinstance(nodes, dict):
        raise ComputeError(f"{p}: expected a mapping with a 'nodes' mapping")
    out: dict[str, Mapping[str, Any]] = {}
    for name, spec in nodes.items():
        spec = spec or {}
        fw = spec.get("firewall", "enabled") if isinstance(spec, dict) else None
        if fw not in ("enabled", "disabled"):
            raise ComputeError(f"{p}: node {name!r}: firewall must be 'enabled' or 'disabled'")
        out[str(name)] = {"firewall": fw}
        if isinstance(spec, dict) and "power" in spec:
            out[str(name)]["power"] = spec["power"]
        if isinstance(spec, dict) and "capacity" in spec:
            out[str(name)]["capacity"] = _capacity(p, name, spec["capacity"])
        if isinstance(spec, dict) and "pools" in spec:
            out[str(name)]["pools"] = _pools(p, name, spec["pools"])
        if isinstance(spec, dict) and "mirror" in spec:
            out[str(name)]["mirror"] = _mirror(p, name, spec["mirror"])
        if isinstance(spec, dict) and "notify" in spec:
            out[str(name)]["notify"] = _notify(p, name, spec["notify"])
        if isinstance(spec, dict) and "native_vlans" in spec:
            out[str(name)]["native_vlans"] = _native_vlans(p, name, spec["native_vlans"])
        if isinstance(spec, dict) and "host_firewall" in spec:
            out[str(name)]["host_firewall"] = _host_firewall(p, name, spec["host_firewall"])
    return out


def _native_vlans(p: Path, name: Any, raw: Any) -> dict[str, int]:
    """``{bridge: vlan id}``: the VLAN each VLAN-aware bridge of the node carries untagged (its
    native VLAN: the switch port's untagged VLAN).  A bridge has one, so a mapping, and the
    bridge is a name (``default`` for the site's default bridge)."""
    where = f"{p}: node {name!r}: native_vlans"
    if not isinstance(raw, dict) or not raw:
        raise ComputeError(f"{where} must be a mapping of bridge name to VLAN id")
    out: dict[str, int] = {}
    for bridge, vid in raw.items():
        if not isinstance(bridge, str) or not re.fullmatch(
            r"default|[a-z][a-z0-9_.-]{0,14}", bridge
        ):
            raise ComputeError(f"{where}: {bridge!r} is not a bridge name")
        if not _count(vid) or vid > 4094:
            raise ComputeError(f"{where}: bridge {bridge!r} needs a VLAN id from 1 to 4094")
        out[bridge] = vid
    return out


def _count(v: Any, *, low: int = 1) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= low


def _capacity(p: Path, name: Any, raw: Any) -> dict[str, Any]:
    """``{threads, memory_mb, reserve: {threads, memory_mb}, cpu_overcommit}``: the logical CPUs
    and memory the hypervisor schedules, what it keeps for itself (the hypervisor, a ZFS ARC),
    and how many guest vCPUs it may place on each thread it gives out (default 1.0)."""
    where = f"{p}: node {name!r}: capacity"
    if not isinstance(raw, dict) or set(raw) - {
        "threads",
        "memory_mb",
        "reserve",
        "cpu_overcommit",
    }:
        raise ComputeError(f"{where} takes threads, memory_mb, reserve and cpu_overcommit")
    if not (_count(raw.get("threads")) and _count(raw.get("memory_mb"))):
        raise ComputeError(f"{where}: threads and memory_mb are positive whole numbers")
    reserve = raw.get("reserve", {})
    if (
        not isinstance(reserve, dict)
        or set(reserve) - {"threads", "memory_mb"}
        or not all(_count(v, low=0) for v in reserve.values())
    ):
        raise ComputeError(f"{where}.reserve: threads and memory_mb, whole numbers >= 0")
    ratio = raw.get("cpu_overcommit", 1.0)
    if isinstance(ratio, bool) or not isinstance(ratio, (int, float)) or not 1 <= ratio <= 16:
        raise ComputeError(f"{where}.cpu_overcommit: a number from 1 to 16")
    left = {
        "threads": raw["threads"] - reserve.get("threads", 0),
        "memory_mb": raw["memory_mb"] - reserve.get("memory_mb", 0),
    }
    if left["threads"] < 1 or left["memory_mb"] < 1:
        raise ComputeError(f"{where}: the reserve leaves no threads or memory for guests")
    # the vCPU budget, once: an exact ratio (1.15 is 23/20, not 1.149999...), floored
    left["vcpus"] = int(Fraction(str(ratio)) * left["threads"])
    return {**raw, "reserve": reserve, "cpu_overcommit": float(ratio), "for_guests": left}


def _pools(p: Path, name: Any, raw: Any) -> dict[str, dict[str, Any]]:
    """``{pool: {size_gb, media}}``: the storage pools a guest's disks may name on this node."""
    where = f"{p}: node {name!r}: pools"
    if not isinstance(raw, dict) or not raw:
        raise ComputeError(f"{where}: a mapping of pool name to {{size_gb, media}}")
    out = {}
    for pool, spec in raw.items():
        # the names a guest's disk may use (guest schema: disks[].pool)
        if not isinstance(pool, str) or not _POOL_RE.match(pool):
            raise ComputeError(f"{where}: pool name {pool!r} is not one a disk can name")
        if not isinstance(spec, dict) or set(spec) - {"size_gb", "media"}:
            raise ComputeError(f"{where}.{pool}: takes size_gb and media")
        if not _count(spec.get("size_gb")):
            raise ComputeError(f"{where}.{pool}: size_gb is a positive whole number")
        if spec.get("media", "ssd") not in ("nvme", "ssd", "hdd"):
            raise ComputeError(f"{where}.{pool}: media is nvme, ssd or hdd")
        out[pool] = dict(spec)
    return out


_POOL_RE = re.compile(r"^[a-z][a-z0-9_-]*\Z")
# a Linux interface name: at most 15 bytes (IFNAMSIZ less the NUL), and a word a shell script can
# carry without quoting surprises
_IFNAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,14}\Z")


def _mirror(p: Path, name: Any, raw: Any) -> dict[str, Any]:
    """``{to: <nic>, bridges: [<bridge>, ...]}``: copy every frame the node's guests send into
    these bridges to ``to``, a NIC cabled to the sensor's capture port and carrying nothing else.
    A switch mirror never sees traffic between two guests of one node; this does."""
    where = f"{p}: node {name!r}: mirror"
    if not isinstance(raw, dict) or set(raw) != {"to", "bridges"}:
        raise ComputeError(f"{where}: takes to (a NIC) and bridges (a list), both required")
    to, bridges = raw["to"], raw["bridges"]
    if not isinstance(to, str) or not _IFNAME_RE.match(to):
        raise ComputeError(f"{where}.to: {to!r} is not an interface name")
    if not isinstance(bridges, list) or not bridges:
        raise ComputeError(f"{where}.bridges: a non-empty list of bridge names")
    for br in bridges:
        if not isinstance(br, str) or not _IFNAME_RE.match(br):
            raise ComputeError(f"{where}.bridges: {br!r} is not an interface name")
    if len(set(bridges)) != len(bridges):
        raise ComputeError(f"{where}.bridges: a bridge is listed twice")
    if to in bridges:
        raise ComputeError(f"{where}: to {to!r} is one of the bridges it copies")
    if to == "lo":
        raise ComputeError(f"{where}.to: the loopback interface cannot carry a mirror")
    return {"to": to, "bridges": list(bridges)}


#: a notify server: http(s), an ASCII host name (dot-separated labels) or IPv4 address, an optional
#: port and base path; no user, query or fragment
_NOTIFY_URL_RE = re.compile(
    r"^https?://(?P<host>[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*)"
    r"(?::(?P<port>[0-9]{1,5}))?(?P<path>(?:/[A-Za-z0-9._~-]+)*)/?\Z"
)
#: an ntfy topic name (ntfy's own rule)
_NOTIFY_TOPIC_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}\Z")
#: the severities a Proxmox notification matcher can match
PVE_SEVERITIES = ("info", "notice", "warning", "error", "unknown")
#: a publish credential: a reference to a secret by name, never its value.  The name becomes the
#: webhook target's secret name, read back by Proxmox as ``{{ secrets.<name> }}`` (a template
#: path, so no ``-`` or ``.``)
_NOTIFY_CREDENTIAL_RE = re.compile(r"^secret:(?P<name>[a-z][a-z0-9_]{0,31})\Z")


def _notify(p: Path, name: Any, raw: Any) -> dict[str, Any]:
    """``{url, topic, severities, priority, default_mail, credential}``: send the node's own
    Proxmox notifications of these severities (default warning, error and unknown, which is the
    mail the node forwards to root) to an ntfy topic at priority 1 to 5 (default 4).
    ``default_mail`` (default false) keeps Proxmox's built-in matcher that mails everything to
    root@pam.  ``credential`` (optional, ``secret:<name>``) names the publish token: its value is
    given to the generated script when it runs, never written here."""
    where = f"{p}: node {name!r}: notify"
    keys = {"url", "topic", "severities", "priority", "default_mail", "credential"}
    if not isinstance(raw, dict) or set(raw) - keys or not {"url", "topic"} <= set(raw):
        raise ComputeError(
            f"{where}: takes url and topic (required), severities, priority, default_mail and "
            "credential"
        )
    url, topic = raw["url"], raw["topic"]
    m = _NOTIFY_URL_RE.match(url) if isinstance(url, str) else None
    if (
        m is None
        or not 1 <= int(m["port"] or 80) <= 65535
        or any(seg in (".", "..") for seg in m["path"].split("/"))
    ):
        raise ComputeError(f"{where}.url: {url!r} is not an http(s) server URL (no query, no user)")
    if not isinstance(topic, str) or not _NOTIFY_TOPIC_RE.match(topic):
        raise ComputeError(f"{where}.topic: {topic!r} is not a topic ([A-Za-z0-9_-], 1-64)")
    sev = raw.get("severities", ["warning", "error", "unknown"])
    if (
        not isinstance(sev, list)
        or not sev
        or not all(isinstance(s, str) and s in PVE_SEVERITIES for s in sev)
    ):
        raise ComputeError(f"{where}.severities: a non-empty list of {', '.join(PVE_SEVERITIES)}")
    if len(set(sev)) != len(sev):
        raise ComputeError(f"{where}.severities: a severity is listed twice")
    prio = raw.get("priority", 4)
    if isinstance(prio, bool) or not isinstance(prio, int) or not 1 <= prio <= 5:
        raise ComputeError(f"{where}.priority: a whole number from 1 to 5")
    mail = raw.get("default_mail", False)
    if not isinstance(mail, bool):
        raise ComputeError(f"{where}.default_mail: true or false")
    out = {
        "url": url if url.endswith("/") else url + "/",
        "topic": topic,
        "severities": list(sev),
        "priority": prio,
        "default_mail": mail,
    }
    if "credential" in raw:
        cred = raw["credential"]
        m = _NOTIFY_CREDENTIAL_RE.match(cred) if isinstance(cred, str) else None
        if m is None:
            # never echo the value: a token pasted here by mistake must not reach a log
            raise ComputeError(
                f"{where}.credential: a secret reference, secret:<name> ([a-z][a-z0-9_], up to "
                "32), never a value"
            )
        out["credential"] = m["name"]
    return out


#: a ``host_firewall`` source: ``any``, ``zone:<id>`` or a CIDR (the guest firewall rules' forms)
_HF_ZONE_RE = re.compile(r"^zone:[a-z][a-z0-9-]{0,31}\Z")
_HF_KEYS = {
    "management",
    "icmp",
    "console",
    "spice",
    "cluster",
    "allow_any_management",
    "rollback_minutes",
}
#: the management ports the lock-out guard is about: ``management.ssh`` and ``management.web``
HF_MANAGEMENT = {"ssh": 22, "web": 8006}
HF_ROLLBACK_DEFAULT = 5


def hf_is_wildcard(source: str) -> bool:
    """``any``, or a CIDR that matches every address of its family."""
    if source == "any":
        return True
    try:
        return ipaddress.ip_network(source, strict=False).prefixlen == 0
    except ValueError:
        return False


def _hf_sources(where: str, raw: Any) -> list[str]:
    if not isinstance(raw, list) or not raw:
        raise ComputeError(f"{where}: a non-empty list of sources (any, zone:<id> or a CIDR)")
    out: list[str] = []
    for src in raw:
        if not isinstance(src, str):
            raise ComputeError(f"{where}: {src!r} is not a source (any, zone:<id> or a CIDR)")
        if src == "any" or _HF_ZONE_RE.match(src):
            norm = src
        else:
            try:
                if "/" not in src:
                    raise ValueError(src)
                norm = str(ipaddress.ip_network(src, strict=True))
            except ValueError:
                raise ComputeError(
                    f"{where}: {src!r} is not a source (any, zone:<id> or a network address "
                    "with a prefix length, host bits clear)"
                ) from None
        if norm in out:
            raise ComputeError(f"{where}: {norm!r} is listed twice")
        out.append(norm)
    return out


def _host_firewall(p: Path, name: Any, raw: Any) -> dict[str, Any]:
    """``{management: {ssh, web}, icmp, console, spice, cluster: {peers}, allow_any_management,
    rollback_minutes}``: the sources the node's own ``host.fw`` lets in (target
    ``pve-host-firewall``).  Everything else inbound is dropped by the datacenter policy.

    ``management.ssh`` (port 22) and ``management.web`` (the web interface and API, 8006) are the
    way back in: a node declaring neither is refused (the lock-out guard), and ``any`` or a /0 for
    either, or for ``console``/``spice``, is refused unless ``allow_any_management: true``.
    ``console`` is 5900-5999 (VNC), ``spice`` is 3128; each is allowed only when declared.
    ``cluster.peers`` are the other nodes of a multi-node cluster (corosync, 5405-5412/udp); a
    standalone node declares none.  ``rollback_minutes`` (default 5) is the apply script's dead
    man's switch."""
    where = f"{p}: node {name!r}: host_firewall"
    if not isinstance(raw, dict) or set(raw) - _HF_KEYS:
        raise ComputeError(f"{where}: takes {', '.join(sorted(_HF_KEYS))}")
    out: dict[str, Any] = {}
    mgmt = raw.get("management")
    if not isinstance(mgmt, dict) or set(mgmt) - set(HF_MANAGEMENT):
        raise ComputeError(f"{where}.management: takes ssh (port 22) and web (port 8006)")
    out["management"] = {k: _hf_sources(f"{where}.management.{k}", v) for k, v in mgmt.items()}
    if not out["management"]:
        raise ComputeError(
            f"{where}.management: declares no source for ssh (22) or web (8006); the node "
            "would be unreachable once the file is on (lock-out guard)"
        )
    for key in ("icmp", "console", "spice"):
        if key in raw:
            out[key] = _hf_sources(f"{where}.{key}", raw[key])
    if "cluster" in raw:
        cl = raw["cluster"]
        if not isinstance(cl, dict) or set(cl) != {"peers"}:
            raise ComputeError(f"{where}.cluster: takes peers (the other nodes), nothing else")
        peers = _hf_sources(f"{where}.cluster.peers", cl["peers"])
        if any(hf_is_wildcard(x) for x in peers):
            raise ComputeError(f"{where}.cluster.peers: the cluster's nodes, never any or /0")
        out["cluster"] = {"peers": peers}
    anyok = raw.get("allow_any_management", False)
    if not isinstance(anyok, bool):
        raise ComputeError(f"{where}.allow_any_management: true or false")
    out["allow_any_management"] = anyok
    mins = raw.get("rollback_minutes", HF_ROLLBACK_DEFAULT)
    if isinstance(mins, bool) or not isinstance(mins, int) or not 1 <= mins <= 60:
        raise ComputeError(f"{where}.rollback_minutes: a whole number of minutes from 1 to 60")
    out["rollback_minutes"] = mins
    if not anyok:
        for key in ("ssh", "web"):
            if any(hf_is_wildcard(x) for x in out["management"].get(key, [])):
                raise ComputeError(
                    f"{where}.management.{key}: any (or a /0) opens port {HF_MANAGEMENT[key]} to "
                    "every address; name the sources, or set allow_any_management: true"
                )
        for key in ("console", "spice"):
            if any(hf_is_wildcard(x) for x in out.get(key, [])):
                raise ComputeError(
                    f"{where}.{key}: any (or a /0) opens a console port to every address; name "
                    "the sources, or set allow_any_management: true"
                )
    return out


#: one OpenSSH public key line: a known key type, base64 material, an optional comment
PUBLIC_KEY_LINE = re.compile(
    r"(?:ssh-(?:ed25519|rsa|dss)|ecdsa-sha2-nistp(?:256|384|521)"
    r"|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)"
    r" [A-Za-z0-9+/]{8,}={0,2}(?: [ -~]*)?"
)


_KEY_NAME = re.compile(r"[A-Za-z0-9_.-]{1,64}")


def _yaml_where(exc: Exception) -> str:
    """Where a YAML error is, never the snippet: the keys file can hold private key material."""
    mark = getattr(exc, "problem_mark", None)
    what = str(getattr(exc, "problem", None) or "not valid YAML")[:80]
    return f"{what} at line {mark.line + 1}, column {mark.column + 1}" if mark else what


def load_keys(path: str | Path) -> dict[str, str]:
    """Read ``{keys: {name: public-key-line}}`` (public keys only; never private material)."""
    p = Path(path)
    try:
        doc = yaml.load(sops.read_text(p), Loader=_UniqueKeyLoader)
    except yaml.YAMLError as exc:
        # PyYAML's message quotes the offending source lines, which may be key material
        raise ComputeUnreadable(f"cannot read keys {p}: {_yaml_where(exc)}") from exc
    except (OSError, sops.SopsError) as exc:
        raise ComputeUnreadable(f"cannot read keys {p}: {exc}") from exc
    keys = (doc or {}).get("keys") if isinstance(doc, dict) else None
    if not isinstance(keys, dict):
        raise ComputeError(f"{p}: expected a mapping with a 'keys' mapping")
    out: dict[str, str] = {}
    for k, v in keys.items():
        if not isinstance(k, str) or not _KEY_NAME.fullmatch(k):
            # a name can itself be pasted key material or carry control characters
            raise ComputeError(f"{p}: a key name must match [A-Za-z0-9_.-]{{1,64}}")
        name = k
        # never echo the value: a refused value may be private key material
        if not isinstance(v, str) or re.search(shapes.PRIVATE_KEY_HEADER, v):
            raise ComputeError(
                f"{p}: keys.{name} is not an OpenSSH public key line"
                + (" (private key material is refused)" if isinstance(v, str) else "")
            )
        if not PUBLIC_KEY_LINE.fullmatch(v.strip()):
            raise ComputeError(f"{p}: keys.{name} is not a single-line OpenSSH public key")
        out[name] = v.strip()
    return out


def load_fleet(
    directory: str | Path,
    zones: ZoneLookup,
    *,
    domain: str = "example.internal",
    policies_path: str | Path | None = None,
    keys_path: str | Path | None = None,
    nodes_path: str | Path | None = None,
    baselines_path: str | Path | None = None,
    require_baselines: bool = True,
    flows: tuple[ZoneFlow, ...] = (),
    power: Mapping[str, Any] | None = None,
    deploy: Mapping[str, Any] | None = None,
    site_addresses: Mapping[str, tuple[str, ...]] | None = None,
    delegated6: Any = None,
    placement: Mapping[str, frozenset[str]] | None = None,
    lenient: list[Problem] | None = None,
) -> Fleet:
    """Load, schema- and semantically validate; raise ComputeError listing every problem.

    ``lenient``: a list that receives the semantic problems (:func:`validate`) instead of
    raising for them, so a page that shows the lab as it is (the status hub's maps) still draws a
    guest set that breaks a policy; a file that cannot be read or does not fit the schema, and an
    unusable baseline set, still raise.

    ``baselines_path`` defaults to ``DIRECTORY/_baselines.yml``; without that file there is no
    baseline set and no guest needs a baseline.  ``require_baselines=False`` tolerates guests
    that declare none (for the coverage report, which lists them).  ``flows``: the zone-to-zone
    flows the site allows (:func:`homelabnext.compute.zones.site_flows`), for the targets that
    follow them (``tailscale-acl``).  ``power``: the site's power facts
    (:func:`homelabnext.compute.zones.site_power`); with them, every hypervisor and physical
    host must say what feeds it.  ``deploy``: the deploy's tailnet access
    (:func:`homelabnext.compute.zones.site_deploy`), for ``tailscale-acl``.  ``site_addresses``:
    the addresses the site names something other than a guest
    (:func:`homelabnext.compute.zones.site_addresses`), which no extra address may claim.
    ``delegated6``: the site's ``delegated_prefixes6`` as read
    (:func:`homelabnext.compute.zones.site_delegated6`), the global IPv6 prefixes it declares its
    own.  ``placement``: the service registry's capabilities per host
    (:func:`registry_placement`), which widen the capabilities a guest on that host may declare."""
    from .validate import validate

    d = Path(directory)
    guests, problems = load_guests(d)
    unreadable = [p for p in problems if p.message.startswith(UNREADABLE + ":")]
    if unreadable:  # a file that does not parse is bad input, not a guest that fails validation
        raise ComputeUnreadable(f"unreadable guest files in {d}", unreadable)
    pol_path = Path(policies_path) if policies_path else d / POLICIES_FILE
    policies = load_policies(pol_path) if pol_path.is_file() else {}
    nodes_file = Path(nodes_path) if nodes_path else d / NODES_FILE
    bl_file = Path(baselines_path) if baselines_path else d / BASELINES_FILE
    baselines = None
    if baselines_path or bl_file.is_file():
        baselines, bl_problems = load_baselines(bl_file)
        if baselines is None:  # never read an unusable set as "no set": stop here
            raise ComputeError(f"invalid guest set in {d}", problems + bl_problems)
    fleet = Fleet(
        tuple(guests),
        zones,
        domain=domain,
        keys=load_keys(keys_path) if keys_path else {},
        policies=policies,
        nodes=load_nodes(nodes_file) if nodes_file.is_file() else {},
        baselines=baselines,
        flows=tuple(flows),
        power=power,
        deploy=deploy,
        site_addresses=dict(site_addresses or {}),
        delegated6=delegated6,
        placement=dict(placement or {}),
    )
    found = validate(fleet, require_baselines=require_baselines)
    if lenient is not None and not problems:
        lenient.extend(found)
        return fleet
    problems += found
    if problems:
        raise ComputeError(f"invalid guest set in {d}", problems)
    return fleet


def registry_path(site_path: str | Path, explicit: str | Path | None = None) -> Path | None:
    """The service registry the guests are judged against: ``explicit`` when given (it must
    exist), else ``services.yml`` beside the site file when there is one, else None."""
    if explicit:
        return Path(explicit)
    beside = Path(site_path).parent / "services.yml"
    return beside if beside.is_file() else None


def load_registry_for(site_path: str | Path, explicit: str | Path | None = None) -> Any:
    """The registry of :func:`registry_path`, loaded, or None.  Unreadable is
    :class:`ComputeUnreadable`, invalid :class:`ComputeError`."""
    from homelabnext.network.loader import SiteError, SiteUnreadable, load_registry

    path = registry_path(site_path, explicit)
    if path is None:
        return None
    try:
        return load_registry(path)
    except SiteUnreadable as exc:
        raise ComputeUnreadable(str(exc)) from exc
    except SiteError as exc:
        raise ComputeError(str(exc)) from exc


def registry_placement(reg: Any) -> dict[str, frozenset[str]]:
    """Registry host -> the capabilities a guest on it may declare: those its rows serve, every
    standing (ADR-0039 decision 7), and a row-less host's own ``role`` (the runner's role on any
    host), which ``registry_hosts.capability_problems`` accepts by name."""
    from homelabnext.registry.model import STANDINGS

    out: dict[str, set[str]] = {}
    for r in [] if reg is None else reg.rows(*STANDINGS):
        out.setdefault(r.host, set()).add(r.capability)
    for name, h in ({} if reg is None else reg.hosts).items():
        if h.role and (name not in out or h.role == "agent-runtime"):
            out.setdefault(name, set()).add(h.role)
    return {h: frozenset(c) for h, c in out.items()}
