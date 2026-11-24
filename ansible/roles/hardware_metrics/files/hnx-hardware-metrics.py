#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: hardware-metrics
#   kind: job
#   purpose: Write a host's hardware state (pool health and capacity, board sensors and event log, GPU temperature, power and load, guest run state) as node-exporter textfile metrics.
#   owner: platform
#   trigger: [timer:hardware_metrics/hnx-hardware-metrics, role:hardware_metrics]
#   inputs: the role's JSON configuration (the collectors and the commands and paths each reads), and those commands' read-only output
#   outputs: hardware_metrics.prom in the textfile directory, written atomically
#   installs_to: /usr/local/libexec/homelabnext/hnx-hardware-metrics
#   exit:
#     "0": metrics written (a collector that failed says so in hw_collector_up, it does not fail the run)
#     "2": the configuration could not be read or the metrics could not be written
"""Managed by homelabnext (role hardware_metrics, control hardware-metrics); local changes are overwritten.

Every collector only reads: the pool tool's list and status, the board controller's sensor list
and event log (in-band, through the local device), the GPU tool's query, the GPU driver's sysfs
files, and the hypervisor's guest list. A collector that fails or times out is reported as
``hw_collector_up{collector="x"} 0`` and its families are left out; the others are still written.

Families (the metrics service's hardware rules read them):
  hw_collector_up{collector}                       1 when the collector read its source
  hw_collector_last_run_timestamp_seconds          when this run wrote the file (a stale value alerts)
  pools:   hw_zfs_pool_{size,allocated,free}_bytes, hw_zfs_pool_capacity_percent, hw_zfs_pool_healthy,
           hw_zfs_pool_health_info{health}, hw_zfs_pool_device_errors{kind=read|write|checksum},
           hw_zfs_pool_data_errors
  board:   hw_ipmi_sensor_state{sensor,kind} (0 ok, 1 non-critical, 2 critical, 3 non-recoverable),
           hw_ipmi_temperature_celsius, hw_ipmi_fan_rpm, hw_ipmi_voltage_volts, hw_ipmi_power_watts,
           hw_ipmi_sel_entries, hw_ipmi_sel_critical_events_total, hw_ipmi_sel_last_critical_info{sensor,event}
  gpus:    hw_gpu_temperature_celsius, hw_gpu_power_watts, hw_gpu_power_limit_watts,
           hw_gpu_energy_joules_total, hw_gpu_utilization_percent, hw_gpu_idle_residency_seconds_total{gt},
           hw_gpu_memory_{used,total}_bytes, hw_gpu_fan_percent, hw_gpu_fan_rpm  (labels gpu, bus, driver)
  guests:  hw_guest_running{vmid,name,type}, hw_guest_onboot{vmid,name,type}
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import subprocess
import sys
import time

COLLECTORS = ("zfs", "ipmi", "nvidia", "xe", "hypervisor")
TIMEOUT = 25


class Out:
    """Prometheus text format, one HELP/TYPE per family, families in first-seen order."""

    def __init__(self):
        self.fams: dict[str, tuple[str, str, list[str]]] = {}

    def add(self, name, value, labels=None, help_="", type_="gauge"):
        if value is None:
            return
        fam = self.fams.setdefault(name, (help_ or name, type_, []))
        lbl = ""
        if labels:
            lbl = "{" + ",".join(f'{k}="{esc(v)}"' for k, v in labels.items()) + "}"
        fam[2].append(f"{name}{lbl} {fmt(value)}")

    def text(self):
        lines = []
        for name, (help_, type_, samples) in self.fams.items():
            lines += [f"# HELP {name} {help_}", f"# TYPE {name} {type_}", *samples]
        return "\n".join(lines) + "\n"


def esc(v):
    return str(v).replace("\\", "\\\\").replace("\n", " ").replace('"', '\\"')


def fmt(v):
    if isinstance(v, bool):
        return "1" if v else "0"
    if isinstance(v, int):
        return str(v)
    v = float(v)
    return str(int(v)) if v.is_integer() and abs(v) < 2**63 else repr(v)


def run(argv, tolerant=False):
    """-> stdout, or raise RuntimeError (never a shell; a bounded wait). ``tolerant``: a non-zero
    exit still returns what was printed (a GPU tool that lists the cards it can reach and fails
    on the one it cannot), stdout and stderr together."""
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=TIMEOUT)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise RuntimeError(f"{argv[0]}: {type(e).__name__}") from None
    if tolerant:
        return r.stdout + "\n" + r.stderr
    if r.returncode != 0:
        raise RuntimeError(f"{argv[0]}: exit {r.returncode}")
    return r.stdout


def num(s):
    try:
        return float(s)
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------------- pools

ROW = re.compile(r"^\s+(\S+)\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)(\s.*)?$")


def parse_zpool_list(text):
    pools = {}
    for line in text.splitlines():
        f = line.split("\t")
        if len(f) != 6:
            continue
        name, size, alloc, free, cap, health = f
        pools[name] = {
            "size": num(size),
            "alloc": num(alloc),
            "free": num(free),
            "cap": num(cap.rstrip("%")),
            "health": health,
        }
    return pools


def parse_zpool_status(text):
    """-> {pool: {"read": n, "write": n, "checksum": n, "data_errors": n}} summed over every row
    of the pool's config table (the pool row, its vdevs and their devices)."""
    out, pool, in_cfg = {}, None, False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("pool:"):
            pool = s.split(":", 1)[1].strip()
            out[pool] = {"read": 0, "write": 0, "checksum": 0, "data_errors": 0}
            in_cfg = False
        elif pool is None:
            continue
        elif s.startswith("NAME") and "CKSUM" in s:
            in_cfg = True
        elif s.startswith("errors:"):
            in_cfg = False
            m = re.match(r"errors:\s+(\d+) data errors", s)
            out[pool]["data_errors"] = int(m.group(1)) if m else 0
        elif in_cfg:
            m = ROW.match(line)
            if m:
                out[pool]["read"] += int(m.group(3))
                out[pool]["write"] += int(m.group(4))
                out[pool]["checksum"] += int(m.group(5))
    return out


def collect_zfs(cfg, o):
    zpool = cfg.get("zpool_cli", "zpool")
    pools = parse_zpool_list(run([zpool, "list", "-Hp", "-o", "name,size,alloc,free,cap,health"]))
    status = parse_zpool_status(run([zpool, "status", "-p"]))
    for name, p in pools.items():
        lb = {"pool": name}
        o.add("hw_zfs_pool_size_bytes", p["size"], lb, "pool size")
        o.add("hw_zfs_pool_allocated_bytes", p["alloc"], lb, "pool space allocated")
        o.add("hw_zfs_pool_free_bytes", p["free"], lb, "pool space free")
        o.add("hw_zfs_pool_capacity_percent", p["cap"], lb, "pool capacity used, percent")
        o.add(
            "hw_zfs_pool_healthy", p["health"] == "ONLINE", lb, "1 when the pool's health is ONLINE"
        )
        o.add("hw_zfs_pool_health_info", 1, {**lb, "health": p["health"]}, "the pool's health word")
        st = status.get(name)
        if st:
            for kind in ("read", "write", "checksum"):
                o.add(
                    "hw_zfs_pool_device_errors",
                    st[kind],
                    {**lb, "kind": kind},
                    "error counters of the pool's devices since the last clear, summed",
                )
            o.add(
                "hw_zfs_pool_data_errors", st["data_errors"], lb, "files with permanent data errors"
            )


# ---------------------------------------------------------------------------------- board

STATE = {
    "ok": 0,
    "nc": 1,
    "lnc": 1,
    "unc": 1,
    "cr": 2,
    "lcr": 2,
    "ucr": 2,
    "nr": 3,
    "lnr": 3,
    "unr": 3,
}
UNITS = {
    "degrees C": ("temperature", "hw_ipmi_temperature_celsius", "board temperature sensor"),
    "RPM": ("fan", "hw_ipmi_fan_rpm", "board fan speed"),
    "Volts": ("voltage", "hw_ipmi_voltage_volts", "board voltage sensor"),
    "Watts": ("power", "hw_ipmi_power_watts", "board power sensor"),
}
# a discrete sensor (power supply, processor, ...) whose asserted state names a fault
FAULT = re.compile(
    r"failure|fault|predictive|ac lost|non-recoverable|thermal trip|(?<!non-)critical", re.I
)
SEL_CRITICAL = re.compile(
    r"(?<!non-)critical|non-recoverable|thermal trip|failure detected|uncorrectable|ac lost|predictive failure",
    re.I,
)


def parse_sdr(text):
    """`ipmitool sdr elist` rows: name | id | status | entity | reading. 'ns' (no reading) is left out."""
    rows = []
    for line in text.splitlines():
        f = [x.strip() for x in line.split("|")]
        if len(f) != 5:
            continue
        name, _id, status, _ent, reading = f
        status = status.lower()
        if status == "ns" or status not in STATE:
            continue
        kind, metric, value = "discrete", None, None
        for unit, (k, m, _h) in UNITS.items():
            if reading.endswith(" " + unit):
                kind, metric, value = k, m, num(reading[: -len(unit)].strip())
                break
        state = STATE[status]
        if kind == "discrete" and FAULT.search(reading):
            state = max(state, 2)
        rows.append(
            {"sensor": name, "kind": kind, "state": state, "metric": metric, "value": value}
        )
    return rows


def parse_sel(text):
    """`ipmitool sel elist`: -> (entries, critical asserted events, (sensor, event) of the last one)."""
    entries, crit, last = 0, 0, None
    for line in text.splitlines():
        f = [x.strip() for x in line.split("|")]
        if len(f) < 5:
            continue
        entries += 1
        sensor, event = f[3], f[4]
        asserted = len(f) < 6 or f[5].lower().startswith("asserted")
        if asserted and SEL_CRITICAL.search(event):
            crit += 1
            last = (sensor, event)
    return entries, crit, last


def collect_ipmi(cfg, o):
    ipmitool = cfg.get("ipmitool_cli", "ipmitool")
    for r in parse_sdr(run([ipmitool, "sdr", "elist"])):
        lb = {"sensor": r["sensor"]}
        o.add(
            "hw_ipmi_sensor_state",
            r["state"],
            {**lb, "kind": r["kind"]},
            "board sensor state: 0 ok, 1 non-critical, 2 critical, 3 non-recoverable",
        )
        if r["metric"] and r["value"] is not None:
            o.add(r["metric"], r["value"], lb, UNITS_HELP[r["metric"]])
    entries, crit, last = parse_sel(run([ipmitool, "sel", "elist"]))
    o.add("hw_ipmi_sel_entries", entries, None, "entries in the board's event log")
    o.add(
        "hw_ipmi_sel_critical_events_total",
        crit,
        None,
        "critical, non-recoverable or failure events asserted in the board's event log",
        "counter",
    )
    if last:
        o.add(
            "hw_ipmi_sel_last_critical_info",
            1,
            {"sensor": last[0], "event": last[1]},
            "the newest critical event in the board's event log",
        )


UNITS_HELP = {m: h for (_k, m, h) in UNITS.values()}


# ---------------------------------------------------------------------------------- GPUs

NV_FIELDS = "index,pci.bus_id,temperature.gpu,power.draw,power.limit,utilization.gpu,memory.used,memory.total,fan.speed"
# a card the tool cannot reach (fallen off the bus, needs a reset, lost its firmware link)
NV_LOST = re.compile(
    r"unable to determine the device handle|unknown error|requires reset|gpu is lost", re.I
)
# the kernel driver's own error reports (Xid: a fault the driver recorded for a card)
KERNEL_ERRORS = {
    "nvidia": r"NVRM: Xid ",
    "xe": r"xe [0-9a-f:.]+: .*(wedged|reset failed|\*ERROR\*|GuC .*(fail|timed out))",
}
# a process holding at least this much device memory is computing on the card (not merely probing it)
PROCESS_MIN_BYTES = 64 * 1048576


def parse_nvidia(text):
    """-> (rows, lost): the cards the tool listed, and how many it reported it could not reach."""
    gpus, lost = [], 0
    for line in text.splitlines():
        if NV_LOST.search(line):
            lost += 1
            continue
        f = [x.strip() for x in line.split(",")]
        if len(f) != 9 or not f[0].isdigit():
            continue
        g = dict(
            zip(
                ["index", "bus", "temp", "power", "limit", "util", "mused", "mtotal", "fan"],
                [f[0], f[1].lower(), *map(num, f[2:])],
                strict=True,
            )
        )
        if g["temp"] is None and g["power"] is None:
            lost += 1  # listed, but every reading is an error word
            continue
        gpus.append(g)
    return gpus, lost


def parse_compute_apps(text):
    """`--query-compute-apps=gpu_bus_id,pid,used_memory`: -> {bus: (processes over the floor, bytes)}."""
    out = {}
    for line in text.splitlines():
        f = [x.strip() for x in line.split(",")]
        if len(f) != 3:
            continue
        mib = num(f[2])
        if mib is None:
            continue
        n, b = out.get(f[0].lower(), (0, 0))
        out[f[0].lower()] = (n + (mib * 1048576 >= PROCESS_MIN_BYTES), b + mib * 1048576)
    return out


def pci_gpus(cfg, vendor):
    """Display-class PCI functions of a vendor, whatever driver holds them (or none): what the
    host was given, to compare with what the driver can still reach."""
    n = 0
    for d in glob.glob(os.path.join(cfg.get("pci_dir", "/sys/bus/pci/devices"), "*")):
        if read_or(os.path.join(d, "vendor")) == vendor and (
            read_or(os.path.join(d, "class")) or ""
        ).startswith("0x03"):
            n += 1
    return n


def kernel_errors(cfg, driver):
    """Driver error lines in the kernel log of this boot (a count since boot: alerts use its increase)."""
    text = run(
        [
            cfg.get("journal_cli", "journalctl"),
            "-k",
            "-b",
            "-o",
            "cat",
            "--no-pager",
            "--grep",
            KERNEL_ERRORS[driver],
        ],
        tolerant=True,
    )  # no match exits 1: that is zero
    return sum(1 for ln in text.splitlines() if re.search(KERNEL_ERRORS[driver], ln))


def gpu_common(cfg, o, driver, listed, lost, pci_vendor):
    lb = {"driver": driver}
    o.add("hw_gpu_count", listed, lb, "GPUs the driver can reach")
    o.add("hw_gpu_lost", lost, lb, "GPUs the driver reports it cannot reach")
    o.add(
        "hw_gpu_pci_devices",
        pci_gpus(cfg, pci_vendor),
        lb,
        "display-class PCI functions of the GPU vendor on this host",
    )
    try:
        o.add(
            "hw_gpu_driver_errors_total",
            kernel_errors(cfg, driver),
            lb,
            "GPU driver error reports in the kernel log since boot",
            "counter",
        )
    except RuntimeError as e:
        print(f"hardware-metrics: kernel log: {e}", file=sys.stderr)
    if cfg.get("expect_gpu_processes"):
        o.add(
            "hw_gpu_processes_expected",
            1,
            lb,
            "1 when a workload is expected to compute on this host's GPUs",
        )


def collect_nvidia(cfg, o):
    smi = cfg.get("nvidia_smi_cli", "nvidia-smi")
    gpus, lost = parse_nvidia(
        run([smi, f"--query-gpu={NV_FIELDS}", "--format=csv,noheader,nounits"], tolerant=True)
    )
    if not gpus and not lost:
        raise RuntimeError("no GPU listed")
    apps = (
        parse_compute_apps(
            run(
                [
                    smi,
                    "--query-compute-apps=gpu_bus_id,pid,used_memory",
                    "--format=csv,noheader,nounits",
                ],
                tolerant=True,
            )
        )
        if gpus
        else {}
    )
    for g in gpus:
        lb = {"gpu": g["index"], "bus": g["bus"], "driver": "nvidia"}
        o.add("hw_gpu_temperature_celsius", g["temp"], lb, "GPU core temperature")
        o.add("hw_gpu_power_watts", g["power"], lb, "GPU board power draw")
        o.add("hw_gpu_power_limit_watts", g["limit"], lb, "GPU power limit in force")
        o.add("hw_gpu_utilization_percent", g["util"], lb, "GPU busy, percent")
        if g["mused"] is not None:
            o.add("hw_gpu_memory_used_bytes", g["mused"] * 1048576, lb, "GPU memory used")
        if g["mtotal"] is not None:
            o.add("hw_gpu_memory_total_bytes", g["mtotal"] * 1048576, lb, "GPU memory total")
        o.add("hw_gpu_fan_percent", g["fan"], lb, "GPU fan duty, percent")
        n, b = apps.get(g["bus"], (0, 0))
        o.add(
            "hw_gpu_compute_processes",
            n,
            lb,
            "processes holding at least 64 MiB of the GPU's memory",
        )
        o.add("hw_gpu_process_memory_bytes", b, lb, "GPU memory held by processes")
    gpu_common(cfg, o, "nvidia", len(gpus), lost, "0x10de")


def read(path):
    with open(path) as f:
        return f.read().strip()


def collect_xe(cfg, o):
    drm = cfg.get("drm_dir", "/sys/class/drm")
    found = 0
    for card in sorted(glob.glob(os.path.join(drm, "card[0-9]*"))):
        if "-" in os.path.basename(card):
            continue  # a connector (card0-DP-1), not a card
        dev = os.path.join(card, "device")
        hw = [
            h
            for h in glob.glob(os.path.join(dev, "hwmon", "hwmon*"))
            if read_or(h + "/name") == "xe"
        ]
        if not hw:
            continue
        found += 1
        h = hw[0]
        bus = os.path.basename(os.path.realpath(dev)).lower()
        lb = {"gpu": os.path.basename(card).removeprefix("card"), "bus": bus, "driver": "xe"}
        for t in glob.glob(os.path.join(h, "temp*_label")):
            if read_or(t) == "pkg":
                v = num(read_or(t.replace("_label", "_input")))
                o.add(
                    "hw_gpu_temperature_celsius",
                    None if v is None else v / 1000,
                    lb,
                    "GPU core temperature",
                )
        cap = num(read_or(os.path.join(h, "power1_cap")))
        o.add(
            "hw_gpu_power_limit_watts",
            None if cap is None else cap / 1e6,
            lb,
            "GPU power limit in force",
        )
        for e in glob.glob(os.path.join(h, "energy*_label")):
            if read_or(e) == "card":
                v = num(read_or(e.replace("_label", "_input")))
                o.add(
                    "hw_gpu_energy_joules_total",
                    None if v is None else v / 1e6,
                    lb,
                    "GPU board energy used",
                    "counter",
                )
        fan = num(read_or(os.path.join(h, "fan1_input")))
        o.add("hw_gpu_fan_rpm", fan, lb, "GPU fan speed")
        for idle in sorted(
            glob.glob(os.path.join(dev, "tile*", "gt*", "gtidle", "idle_residency_ms"))
        ):
            gt = os.path.basename(os.path.dirname(os.path.dirname(idle)))
            v = num(read_or(idle))
            o.add(
                "hw_gpu_idle_residency_seconds_total",
                None if v is None else v / 1000,
                {**lb, "gt": gt},
                "time the GPU's engine group spent idle",
                "counter",
            )
        n, b = xe_clients(cfg, bus)
        o.add(
            "hw_gpu_compute_processes",
            n,
            lb,
            "processes holding at least 64 MiB of the GPU's memory",
        )
        o.add("hw_gpu_process_memory_bytes", b, lb, "GPU memory held by processes")
    lost = max(0, pci_gpus(cfg, "0x8086") - found)
    if not found and not lost:
        raise RuntimeError("no xe GPU found")
    gpu_common(cfg, o, "xe", found, lost, "0x8086")


def xe_clients(cfg, bus):
    """The DRM clients of the card (/proc/<pid>/fdinfo, one per client id): -> (processes whose
    clients hold at least the floor of device memory, bytes held)."""
    per_pid, seen = {}, set()
    for fd in glob.glob(os.path.join(cfg.get("proc_dir", "/proc"), "[0-9]*", "fdinfo", "*")):
        try:
            with open(fd) as f:
                info = dict(ln.rstrip("\n").split(":\t", 1) for ln in f if ":\t" in ln)
        except OSError:
            continue
        if info.get("drm-driver") != "xe" or info.get("drm-pdev", "").lower() != bus:
            continue
        pid = fd.split(os.sep)[-3]
        if (pid, info.get("drm-client-id")) in seen:
            continue
        seen.add((pid, info.get("drm-client-id")))
        b = 0
        for k, v in info.items():
            if k.startswith("drm-total-vram"):
                parts = v.split()
                val = num(parts[0]) or 0
                b += val * {"KiB": 1024, "MiB": 1048576, "GiB": 1073741824}.get(
                    parts[1] if len(parts) > 1 else "", 1
                )
        per_pid[pid] = per_pid.get(pid, 0) + b
    return sum(1 for b in per_pid.values() if b >= PROCESS_MIN_BYTES), sum(per_pid.values())


def read_or(path):
    try:
        return read(path)
    except OSError:
        return None


# ---------------------------------------------------------------------------------- guests


def onboot(conf_dirs, vmid):
    for d in conf_dirs:
        p = os.path.join(d, f"{vmid}.conf")
        try:
            with open(p) as f:
                for line in f:
                    if line.startswith("["):
                        break  # a snapshot section: the live config ends here
                    if re.match(r"^onboot:\s*1\s*$", line):
                        return 1
            return 0
        except OSError:
            continue
    return 0


def collect_hypervisor(cfg, o):
    pvesh = cfg.get("guests_cli", "pvesh")
    node = cfg.get("node") or os.uname().nodename
    conf_dirs = cfg.get("guest_conf_dirs", ["/etc/pve/qemu-server", "/etc/pve/lxc"])
    rows = json.loads(
        run([pvesh, "get", "/cluster/resources", "--type", "vm", "--output-format", "json"])
    )
    for r in rows:
        if r.get("node") != node or r.get("template"):
            continue
        lb = {
            "vmid": str(r.get("vmid")),
            "name": str(r.get("name", "")),
            "type": str(r.get("type", "")),
        }
        o.add("hw_guest_running", r.get("status") == "running", lb, "1 when the guest is running")
        o.add(
            "hw_guest_onboot",
            onboot(conf_dirs, r.get("vmid")),
            lb,
            "1 when the guest is set to start at boot",
        )


FUNCS = {
    "zfs": collect_zfs,
    "ipmi": collect_ipmi,
    "nvidia": collect_nvidia,
    "xe": collect_xe,
    "hypervisor": collect_hypervisor,
}


def build(cfg):
    o = Out()
    ups = []
    for c in cfg["collectors"]:
        part = Out()
        try:
            FUNCS[c](cfg, part)
            ok = 1
        except Exception as e:
            print(f"hardware-metrics: collector {c} failed: {e}", file=sys.stderr)
            ok = 0
        if ok:
            for name, fam in part.fams.items():
                cur = o.fams.setdefault(name, (fam[0], fam[1], []))
                cur[2].extend(fam[2])
        ups.append((c, ok))
    for c, ok in ups:
        o.add("hw_collector_up", ok, {"collector": c}, "1 when the collector read its source")
    o.add(
        "hw_collector_last_run_timestamp_seconds",
        int(time.time()),
        None,
        "when the hardware metrics were written",
    )
    return o.text()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--config", required=True)
    a = ap.parse_args(argv)
    try:
        with open(a.config) as f:
            cfg = json.load(f)
        bad = [c for c in cfg.get("collectors", []) if c not in COLLECTORS]
        if bad or not cfg.get("collectors") or not cfg.get("textfile_dir"):
            raise ValueError(
                f"collectors must be a non-empty list of {', '.join(COLLECTORS)}, with a textfile_dir"
            )
    except (OSError, ValueError) as e:
        print(f"hardware-metrics: configuration: {e}", file=sys.stderr)
        return 2
    text = build(cfg)
    out = os.path.join(cfg["textfile_dir"], "hardware_metrics.prom")
    tmp = out + ".tmp"
    # the exporter's own user reads the file: a world-readable file by the process mask (no secret in it)
    os.umask(0o022)
    try:
        with open(tmp, "w") as f:
            f.write(text)
        os.replace(tmp, out)
    except OSError as e:
        print(f"hardware-metrics: cannot write {out}: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
