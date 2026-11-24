# SPDX-License-Identifier: Apache-2.0
"""The role ``hardware_metrics`` (control hardware-metrics) and its collector.

* The collector (run as a subprocess against fake commands and a fake sysfs tree) writes the pool,
  board, GPU and guest families the metrics service's hardware rules read; a collector that fails
  is ``hw_collector_up 0`` and never hides the others; a board sensor with no reading is left out,
  a discrete sensor that asserts a fault is critical, and only critical event-log entries count.
* ``config`` installs the collector, its configuration and its units, runs it once and is
  idempotent; ``validate`` refuses a value that could add a line; ``readiness`` refuses a collector
  whose command the host lacks; ``health`` fails on a stale file or a collector that is down.
Nothing here reads real hardware.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from rolerun import calls, fake, last_run_vars, logging_fake, run_cases, run_role

pytestmark = pytest.mark.requires_tool("ansible-playbook")

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "ansible/roles/hardware_metrics/files/hnx-hardware-metrics.py"

ZPOOL_LIST = "fast\t1000\t900\t100\t90\tONLINE\nbulk\t5000\t500\t4500\t10\tDEGRADED\n"
ZPOOL_STATUS = """\
  pool: bulk
 state: DEGRADED
config:

\tNAME        STATE     READ WRITE CKSUM
\tbulk        DEGRADED     0     0     0
\t  mirror-0  DEGRADED     0     0     0
\t    disk-a  ONLINE       0     0     0
\t    disk-b  FAULTED      3     1     0  too many errors

errors: No known data errors

  pool: fast
 state: ONLINE
status: One or more devices has experienced an error resulting in data
\tcorruption.  Applications may be affected.
config:

\tNAME        STATE     READ WRITE CKSUM
\tfast        ONLINE       0     0     0
\t  disk-c    ONLINE       0     0     2

errors: 1 data errors, use '-v' for a list
"""
SDR = """\
Watchdog         | EBh | ok  |  6.1 |
CPU0_TEMP        | 01h | ok  | 65.1 | 40 degrees C
DIMM1_TEMP       | 05h | cr  | 66.2 | 88 degrees C
CPU0_FAN         | B8h | ok  | 29.1 | 1500 RPM
SYS_FAN3         | BCh | ns  | 29.5 | No Reading
SYS_FAN4         | BDh | lcr | 29.6 | 0 RPM
PS1_Status       | E6h | ok  | 10.1 | Presence detected
PS2_Status       | E7h | ok  | 10.2 | Presence detected, Failure detected
P_12V            | 40h | ok  |  7.1 | 12.09 Volts
SYS_POWER        | E9h | ns  | 19.1 | No Reading
"""
SEL = """\
   1 | 09/18/2026 | 07:18:59 PM CDT | Event Logging Disabled SEL | Log area reset/cleared | Asserted
   2 | 11/11/2026 | 11:48:22 PM CST | Processor CPU0_Status | Thermal Trip | Asserted
   3 | 11/12/2026 | 12:06:12 AM CST | Processor CPU0_Status | Thermal Trip | Deasserted
   4 | 11/23/2026 | 08:02:53 PM CST | Temperature DIMM1_TEMP | Upper Critical going high | Asserted
   5 | 11/23/2026 | 08:41:18 PM CST | Temperature DIMM1_TEMP | Upper Non-critical going high | Asserted
"""
NVIDIA = "0, 00000000:01:00.0, 50, 113.04, 200.00, 30, 19524, 65536, [N/A]\n1, 00000000:02:00.0, 93, 210.5, 250.00, 99, 1, 8192, 40\n"
# the server on card 0 holds its weights; a probe on card 1 holds next to nothing
APPS = "00000000:01:00.0, 3613, 19512\n00000000:02:00.0, 4000, 2\n"
# one card fell off the bus: the tool lists the others and names the one it cannot reach
NVIDIA_LOST = (
    "Unable to determine the device handle for GPU0000:03:00.0: Unknown Error\n"
    "0, 00000000:01:00.0, 50, 113.04, 200.00, 30, 19524, 65536, [N/A]\n"
)
KERNEL = (
    "NVRM: GPU at PCI:0000:03:00: GPU-0000\n"
    "NVRM: Xid (PCI:0000:03:00): 79, GPU has fallen off the bus.\n"
    "NVRM: Xid (PCI:0000:01:00): 154, GPU recovery action changed\n"
)
GUESTS = [
    {
        "vmid": 101,
        "name": "app-01",
        "type": "qemu",
        "node": "node1",
        "status": "running",
        "template": 0,
    },
    {
        "vmid": 102,
        "name": "app-02",
        "type": "qemu",
        "node": "node1",
        "status": "stopped",
        "template": 0,
    },
    {
        "vmid": 103,
        "name": "ct-03",
        "type": "lxc",
        "node": "node1",
        "status": "stopped",
        "template": 0,
    },
    {
        "vmid": 900,
        "name": "tmpl",
        "type": "qemu",
        "node": "node1",
        "status": "stopped",
        "template": 1,
    },
    {
        "vmid": 201,
        "name": "other",
        "type": "qemu",
        "node": "node2",
        "status": "running",
        "template": 0,
    },
]


def _printer(text: str) -> str:
    return f"import sys\nsys.stdout.write({text!r})\n"


def _fakes(tmp_path: Path) -> dict[str, str]:
    """Stand-ins for the four commands, each answering only the read the collector makes."""
    b = tmp_path / "bin"
    b.mkdir(exist_ok=True)
    zpool = fake(b / "zpool", "import sys\n"
                 f"sys.stdout.write({ZPOOL_LIST!r} if sys.argv[1] == 'list' else {ZPOOL_STATUS!r})\n")  # fmt: skip
    ipmi = fake(b / "ipmitool", "import sys\n"
                f"sys.stdout.write({SDR!r} if sys.argv[1] == 'sdr' else {SEL!r})\n")  # fmt: skip
    smi = fake(b / "gpu-query", "import os, sys\n"
               f"lost = os.path.exists({str(tmp_path / 'lost')!r})\n"
               f"sys.stdout.write({APPS!r} if 'compute-apps' in sys.argv[1] else ({NVIDIA_LOST!r} if lost else {NVIDIA!r}))\n"
               "sys.exit(15 if lost else 0)\n")  # fmt: skip
    journal = fake(b / "journal", "import sys, re\n"
                   f"lines = [ln for ln in {KERNEL!r}.splitlines() if re.search(sys.argv[-1], ln)]\n"
                   "print('\\n'.join(lines)); sys.exit(0 if lines else 1)\n")  # fmt: skip
    guests = fake(b / "guest-list", _printer(json.dumps(GUESTS)))
    qemu, lxc = tmp_path / "conf/qemu", tmp_path / "conf/lxc"
    qemu.mkdir(parents=True, exist_ok=True)
    lxc.mkdir(parents=True, exist_ok=True)
    (qemu / "101.conf").write_text("cores: 2\nonboot: 1\n")
    (qemu / "102.conf").write_text("onboot: 1\nmemory: 512\n[snap1]\nonboot: 0\n")
    (lxc / "103.conf").write_text("onboot: 0\n")
    pci = tmp_path / "pcidev"
    for addr, vendor, cls in (("0000:01:00.0", "0x10de", "0x030200"), ("0000:02:00.0", "0x10de", "0x030200"),
                              ("0000:03:00.0", "0x10de", "0x030200"), ("0000:05:00.0", "0x8086", "0x030000"),
                              ("0000:00:1f.0", "0x8086", "0x060100")):  # fmt: skip
        (pci / addr).mkdir(parents=True, exist_ok=True)
        (pci / addr / "vendor").write_text(vendor + "\n")
        (pci / addr / "class").write_text(cls + "\n")
    proc = tmp_path / "proc"
    for pid, fd, client, vram in (
        ("3357", "4", "3", "0"),
        ("3357", "8", "4", "21949176 KiB"),
        ("77", "3", "9", "512 KiB"),
    ):
        d = proc / pid / "fdinfo"
        d.mkdir(parents=True, exist_ok=True)
        (d / fd).write_text(f"pos:\t0\ndrm-driver:\txe\ndrm-client-id:\t{client}\ndrm-pdev:\t0000:05:00.0\n"
                            f"drm-total-vram0:\t{vram}\n")  # fmt: skip
    return {"zpool": zpool, "ipmitool": ipmi, "smi": smi, "guests": guests, "journal": journal,
            "conf": [str(qemu), str(lxc)], "pci": str(pci), "proc": str(proc)}  # fmt: skip


def _sysfs(tmp_path: Path) -> Path:
    """A DRM tree with one xe card (plus a connector entry and a non-xe card the collector skips)."""
    drm = tmp_path / "drm"
    if drm.exists():
        return drm
    dev = tmp_path / "pci/0000:05:00.0"
    hw = dev / "hwmon/hwmon3"
    hw.mkdir(parents=True)
    for name, val in {"name": "xe", "temp2_label": "pkg", "temp2_input": "44000", "temp3_label": "vram",
                      "temp3_input": "60000", "power1_cap": "200000000", "energy1_label": "card",
                      "energy1_input": "16000000000000", "energy2_label": "pkg", "energy2_input": "5",
                      "fan1_input": "971"}.items():  # fmt: skip
        (hw / name).write_text(val + "\n")
    for gt, ms in (("gt0", "2000000"), ("gt1", "3000000")):
        p = dev / "tile0" / gt / "gtidle"
        p.mkdir(parents=True)
        (p / "idle_residency_ms").write_text(ms + "\n")
    other = tmp_path / "pci/0000:06:00.0/hwmon/hwmon4"
    other.mkdir(parents=True)
    (other / "name").write_text("something-else\n")
    drm.mkdir()
    (drm / "card0").mkdir()
    (drm / "card0" / "device").symlink_to(dev)
    (drm / "card1").mkdir()
    (drm / "card1" / "device").symlink_to(other.parent.parent)
    (drm / "card0-DP-1").mkdir()
    return drm


def _collect(tmp_path: Path, collectors, **over) -> tuple[subprocess.CompletedProcess, str]:
    f = _fakes(tmp_path)
    out = tmp_path / "textfile"
    out.mkdir(exist_ok=True)
    cfg = {"collectors": collectors, "textfile_dir": str(out), "zpool_cli": f["zpool"],
           "ipmitool_cli": f["ipmitool"], "nvidia_smi_cli": f["smi"], "guests_cli": f["guests"],
           "guest_conf_dirs": f["conf"], "drm_dir": str(_sysfs(tmp_path)), "node": "node1",
           "pci_dir": f["pci"], "proc_dir": f["proc"], "journal_cli": f["journal"]}  # fmt: skip
    cfg.update(over)
    (tmp_path / "cfg.json").write_text(json.dumps(cfg))
    r = subprocess.run([sys.executable, str(SCRIPT), "--config", str(tmp_path / "cfg.json")],
                       capture_output=True, text=True, timeout=60)  # fmt: skip
    prom = out / "hardware_metrics.prom"
    return r, prom.read_text() if prom.exists() else ""


# ----------------------------------------------------------------------------- the collector


def test_the_pool_collector_writes_capacity_health_and_error_counters(tmp_path):
    r, prom = _collect(tmp_path, ["zfs"])
    assert r.returncode == 0, r.stderr
    assert 'hw_zfs_pool_capacity_percent{pool="fast"} 90' in prom
    assert 'hw_zfs_pool_size_bytes{pool="bulk"} 5000' in prom
    assert 'hw_zfs_pool_healthy{pool="fast"} 1' in prom
    assert 'hw_zfs_pool_healthy{pool="bulk"} 0' in prom
    assert 'hw_zfs_pool_health_info{pool="bulk",health="DEGRADED"} 1' in prom
    assert 'hw_zfs_pool_device_errors{pool="bulk",kind="read"} 3' in prom
    assert 'hw_zfs_pool_device_errors{pool="bulk",kind="write"} 1' in prom
    assert 'hw_zfs_pool_device_errors{pool="fast",kind="checksum"} 2' in prom
    assert 'hw_zfs_pool_data_errors{pool="fast"} 1' in prom
    assert 'hw_zfs_pool_data_errors{pool="bulk"} 0' in prom
    assert 'hw_collector_up{collector="zfs"} 1' in prom


def test_the_board_collector_reads_sensors_and_counts_only_critical_events(tmp_path):
    r, prom = _collect(tmp_path, ["ipmi"])
    assert r.returncode == 0, r.stderr
    assert 'hw_ipmi_temperature_celsius{sensor="CPU0_TEMP"} 40' in prom
    assert 'hw_ipmi_sensor_state{sensor="DIMM1_TEMP",kind="temperature"} 2' in prom
    assert 'hw_ipmi_fan_rpm{sensor="CPU0_FAN"} 1500' in prom
    assert 'hw_ipmi_sensor_state{sensor="SYS_FAN4",kind="fan"} 2' in prom
    assert 'hw_ipmi_voltage_volts{sensor="P_12V"} 12.09' in prom
    # no reading: left out, never a permanent alert
    assert "SYS_FAN3" not in prom and "SYS_POWER" not in prom
    # a discrete sensor asserting a fault is critical; one that only reports presence is ok
    assert 'hw_ipmi_sensor_state{sensor="PS2_Status",kind="discrete"} 2' in prom
    assert 'hw_ipmi_sensor_state{sensor="PS1_Status",kind="discrete"} 0' in prom
    # a thermal trip and an upper-critical crossing count; a deassertion and a NON-critical one do not
    assert "hw_ipmi_sel_entries 5" in prom
    assert "hw_ipmi_sel_critical_events_total 2" in prom
    assert "# TYPE hw_ipmi_sel_critical_events_total counter" in prom
    assert ('hw_ipmi_sel_last_critical_info{sensor="Temperature DIMM1_TEMP",'
            'event="Upper Critical going high"} 1') in prom  # fmt: skip


def test_the_gpu_query_collector_writes_temperature_power_limit_load_and_memory(tmp_path):
    r, prom = _collect(tmp_path, ["nvidia"])
    assert r.returncode == 0, r.stderr
    lb = 'gpu="1",bus="00000000:02:00.0",driver="nvidia"'
    assert f"hw_gpu_temperature_celsius{{{lb}}} 93" in prom
    assert f"hw_gpu_power_watts{{{lb}}} 210.5" in prom
    assert f"hw_gpu_power_limit_watts{{{lb}}} 250" in prom
    assert f"hw_gpu_utilization_percent{{{lb}}} 99" in prom
    assert f"hw_gpu_memory_total_bytes{{{lb}}} 8589934592" in prom
    assert f"hw_gpu_fan_percent{{{lb}}} 40" in prom
    # a field the card does not have ([N/A]) is left out, not written as zero
    assert 'hw_gpu_fan_percent{gpu="0"' not in prom


def test_the_sysfs_gpu_collector_reads_the_driver_files(tmp_path):
    r, prom = _collect(tmp_path, ["xe"])
    assert r.returncode == 0, r.stderr
    lb = 'gpu="0",bus="0000:05:00.0",driver="xe"'
    assert f"hw_gpu_temperature_celsius{{{lb}}} 44" in prom
    assert f"hw_gpu_power_limit_watts{{{lb}}} 200" in prom
    assert f"hw_gpu_energy_joules_total{{{lb}}} 16000000" in prom
    assert f"hw_gpu_fan_rpm{{{lb}}} 971" in prom
    assert f'hw_gpu_idle_residency_seconds_total{{{lb},gt="gt1"}} 3000' in prom
    assert 'gpu="1"' not in prom  # the other driver's card is not this collector's
    assert 'hw_collector_up{collector="xe"} 1' in prom


def test_the_guest_collector_lists_this_nodes_guests_without_templates(tmp_path):
    r, prom = _collect(tmp_path, ["hypervisor"])
    assert r.returncode == 0, r.stderr
    assert 'hw_guest_running{vmid="101",name="app-01",type="qemu"} 1' in prom
    assert 'hw_guest_running{vmid="102",name="app-02",type="qemu"} 0' in prom
    assert 'hw_guest_onboot{vmid="101",name="app-01",type="qemu"} 1' in prom
    # the live config's flag, not a snapshot section's
    assert 'hw_guest_onboot{vmid="102",name="app-02",type="qemu"} 1' in prom
    assert 'hw_guest_onboot{vmid="103",name="ct-03",type="lxc"} 0' in prom
    assert 'vmid="900"' not in prom and 'vmid="201"' not in prom


def test_a_failing_collector_is_reported_and_never_hides_the_others(tmp_path):
    r, prom = _collect(tmp_path, ["zfs", "nvidia"], nvidia_smi_cli=str(tmp_path / "missing"))
    assert r.returncode == 0, r.stderr
    assert 'hw_collector_up{collector="nvidia"} 0' in prom
    assert 'hw_collector_up{collector="zfs"} 1' in prom
    assert "hw_zfs_pool_healthy" in prom and "hw_gpu_" not in prom
    assert "hw_collector_last_run_timestamp_seconds " in prom
    assert "collector nvidia failed" in r.stderr


def test_an_unknown_collector_or_a_missing_directory_writes_nothing(tmp_path):
    r, prom = _collect(tmp_path, ["zfs", "everything"])
    assert r.returncode == 2 and prom == ""
    r, _ = _collect(tmp_path, ["zfs"], textfile_dir=str(tmp_path / "no" / "such"))
    assert r.returncode == 2


def test_the_file_is_valid_exposition_text_with_one_help_and_type_per_family(tmp_path):
    r, prom = _collect(tmp_path, ["zfs", "ipmi", "nvidia", "xe", "hypervisor"])
    assert r.returncode == 0, r.stderr
    mode = (tmp_path / "textfile/hardware_metrics.prom").stat().st_mode & 0o777
    assert mode == 0o644  # the exporter's own user reads it; nobody else may write it
    helps = [ln.split()[2] for ln in prom.splitlines() if ln.startswith("# HELP ")]
    assert len(helps) == len(set(helps))
    for ln in prom.splitlines():
        if not ln.startswith("#"):
            name_labels, value = ln.rsplit(" ", 1)
            float(value)
            assert name_labels.split("{")[0] in helps


def test_the_gpu_collectors_count_cards_driver_errors_and_computing_processes(tmp_path):
    r, prom = _collect(tmp_path, ["nvidia"], expect_gpu_processes=True)
    assert r.returncode == 0, r.stderr
    assert 'hw_gpu_count{driver="nvidia"} 2' in prom
    assert 'hw_gpu_pci_devices{driver="nvidia"} 3' in prom  # the host was given three
    assert 'hw_gpu_lost{driver="nvidia"} 0' in prom
    assert 'hw_gpu_driver_errors_total{driver="nvidia"} 2' in prom
    assert 'hw_gpu_compute_processes{gpu="0",bus="00000000:01:00.0",driver="nvidia"} 1' in prom
    assert 'hw_gpu_compute_processes{gpu="1",bus="00000000:02:00.0",driver="nvidia"} 0' in prom
    assert 'hw_gpu_processes_expected{driver="nvidia"} 1' in prom


def test_a_card_the_tool_cannot_reach_is_counted_lost_and_the_others_still_reported(tmp_path):
    (tmp_path / "lost").touch()
    r, prom = _collect(tmp_path, ["nvidia"])
    assert r.returncode == 0, r.stderr
    assert 'hw_collector_up{collector="nvidia"} 1' in prom
    assert 'hw_gpu_count{driver="nvidia"} 1' in prom and 'hw_gpu_lost{driver="nvidia"} 1' in prom
    assert 'hw_gpu_temperature_celsius{gpu="0"' in prom
    assert "hw_gpu_processes_expected" not in prom  # not asked for


def test_the_sysfs_gpu_collector_counts_the_processes_holding_device_memory(tmp_path):
    r, prom = _collect(tmp_path, ["xe"])
    assert r.returncode == 0, r.stderr
    lb = 'gpu="0",bus="0000:05:00.0",driver="xe"'
    assert f"hw_gpu_compute_processes{{{lb}}} 1" in prom  # pid 77's half MiB is not computing
    assert f"hw_gpu_process_memory_bytes{{{lb}}} {21949176 * 1024 + 512 * 1024}" in prom
    assert 'hw_gpu_count{driver="xe"} 1' in prom and 'hw_gpu_lost{driver="xe"} 0' in prom
    assert 'hw_gpu_driver_errors_total{driver="xe"} 0' in prom


# ----------------------------------------------------------------------------- the role


SYSTEMCTL = """
import os, sys
log = os.path.join(HERE, "calls.log")
on = os.path.join(HERE, "timer.on")
open(log, "a").write("systemctl " + " ".join(sys.argv[1:]) + "\\n")
if sys.argv[1] == "enable":
    open(on, "w").close()
elif sys.argv[1] in ("is-enabled", "is-active"):
    print(("enabled" if sys.argv[1] == "is-enabled" else "active") if os.path.exists(on) else "inactive")
"""


def _systemctl(tmp_path: Path) -> str:
    """A fake systemctl: logs every call; the timer is enabled and active once `enable` ran."""
    return fake(tmp_path / "systemctl", f"HERE = {str(tmp_path)!r}\n" + SYSTEMCTL)


def _vars(tmp_path: Path, **kw) -> dict:
    f = _fakes(tmp_path)
    d = {
        **last_run_vars(tmp_path, "hardware_metrics"),
        "hardware_metrics_collectors": ["zfs", "ipmi"],
        "hardware_metrics_textfile_dir": str(tmp_path / "textfile"),
        "hardware_metrics_conf_dir": str(tmp_path / "etc"),
        "hardware_metrics_libexec_dir": str(tmp_path / "libexec"),
        "hardware_metrics_systemd_dir": str(tmp_path / "systemd"),
        "hardware_metrics_systemctl_cli": _systemctl(tmp_path),
        "hardware_metrics_zpool_cli": f["zpool"],
        "hardware_metrics_ipmitool_cli": f["ipmitool"],
        "hardware_metrics_guest_conf_dirs": f["conf"],
        "hardware_metrics_node": "node1",
        "hardware_metrics_pci_dir": f["pci"],
        "hardware_metrics_proc_dir": f["proc"],
        "hardware_metrics_journal_cli": f["journal"],
    }
    (tmp_path / "systemd").mkdir(exist_ok=True)
    d.update(kw)
    return d


def test_config_installs_the_collector_its_units_runs_it_once_and_is_idempotent(tmp_path):
    v = _vars(tmp_path)
    r = run_role(tmp_path, "hardware_metrics", "config", v)
    assert r.returncode == 0, r.stdout + r.stderr
    cfg = json.loads((tmp_path / "etc/hardware-metrics.json").read_text())
    assert cfg["collectors"] == ["zfs", "ipmi"] and cfg["textfile_dir"] == str(
        tmp_path / "textfile"
    )
    svc = (tmp_path / "systemd/hnx-hardware-metrics.service").read_text()
    assert (
        f"ExecStart=/usr/local/libexec/homelabnext/hnx-hardware-metrics --config {tmp_path}/etc/hardware-metrics.json"
        in svc
    )
    assert "ProtectSystem=strict" in svc
    assert f"ReadWritePaths={tmp_path}/textfile {tmp_path}/last-run" in svc
    assert "--job timer:hardware_metrics/hnx-hardware-metrics" in svc
    assert (
        "OnCalendar=*-*-* *:*:00 UTC"
        in (tmp_path / "systemd/hnx-hardware-metrics.timer").read_text()
    )
    prom = (tmp_path / "textfile/hardware_metrics.prom").read_text()
    assert (
        'hw_collector_up{collector="zfs"} 1' in prom
        and 'hw_collector_up{collector="ipmi"} 1' in prom
    )
    timer = "hnx-hardware-metrics.timer"
    assert [c for c in calls(tmp_path) if " is-" not in c] == [
        "systemctl daemon-reload", f"systemctl enable --now {timer}"]  # fmt: skip
    r2 = run_role(tmp_path, "hardware_metrics", "config", v)
    assert r2.returncode == 0, r2.stdout + r2.stderr
    assert "changed=0" in r2.stdout, r2.stdout
    # no second reload, and an enabled, active timer is left alone
    assert [c for c in calls(tmp_path) if " is-" not in c] == [
        "systemctl daemon-reload", f"systemctl enable --now {timer}"]  # fmt: skip


def test_config_under_check_on_a_fresh_host_asks_nothing_it_cannot_answer(tmp_path):
    """The dry run of a first install: the unit does not exist, so the timer is neither enabled
    nor started, and the run does not fail on it."""
    v = _vars(tmp_path)
    r = run_role(tmp_path, "hardware_metrics", "config", v, check=True)
    assert r.returncode == 0, r.stdout + r.stderr
    assert not any(c.startswith("systemctl enable") for c in calls(tmp_path))


def test_a_setting_that_could_add_a_line_or_name_no_collector_is_refused(tmp_path):
    cases = [
        {"hardware_metrics_collectors": []},
        {"hardware_metrics_collectors": "zfs"},
        {"hardware_metrics_collectors": ["zfs", "zfs"]},
        {"hardware_metrics_collectors": ["zfs", "smart"]},
        {"hardware_metrics_textfile_dir": "relative/dir"},
        {"hardware_metrics_textfile_dir": "/var/lib/../etc"},
        {"hardware_metrics_interval": "*-*-* *:*:00\nExecStart=/bin/sh"},
        {"hardware_metrics_zpool_cli": "zpool; true"},
        {"hardware_metrics_node": "node 1"},
        {"hardware_metrics_health_max_age_seconds": 10},
        {"hardware_metrics_guest_conf_dirs": ["/etc/../tmp"]},
    ]
    out = run_cases(tmp_path, "hardware_metrics", "validate", _vars(tmp_path), cases, parallel=True)
    for case, (failed, msg) in zip(cases, out, strict=True):
        assert failed, case
        assert "hardware_metrics: collectors must be" in msg, (case, msg)


def test_readiness_refuses_a_collector_whose_command_the_host_lacks(tmp_path):
    v = _vars(tmp_path, hardware_metrics_collectors=["zfs", "nvidia"],
              hardware_metrics_nvidia_smi_cli=str(tmp_path / "no-such-tool"))  # fmt: skip
    r = run_role(tmp_path, "hardware_metrics", "readiness", v)
    assert r.returncode != 0
    assert "no-such-tool" in r.stdout and "take the collector off this host's control" in r.stdout


def test_readiness_does_not_look_up_a_tool_main_installs(tmp_path):
    v = _vars(tmp_path, hardware_metrics_ipmitool_cli=str(tmp_path / "not-yet-installed"))
    r = run_role(tmp_path, "hardware_metrics", "readiness", v)
    assert r.returncode == 0, r.stdout
    r = run_role(
        tmp_path, "hardware_metrics", "readiness", {**v, "hardware_metrics_install_packages": False}
    )
    assert r.returncode != 0 and "not-yet-installed" in r.stdout


def test_health_passes_on_a_fresh_file_with_every_collector_up(tmp_path):
    v = _vars(tmp_path)
    assert run_role(tmp_path, "hardware_metrics", "config", v).returncode == 0
    r = run_role(tmp_path, "hardware_metrics", "health", v)
    assert r.returncode == 0, r.stdout


def test_health_fails_on_a_collector_that_could_not_read_its_source(tmp_path):
    v = _vars(tmp_path, hardware_metrics_collectors=["zfs", "hypervisor"],
              hardware_metrics_guests_cli=logging_fake(tmp_path, "broken-guests"))  # fmt: skip
    (tmp_path / "broken-guests.fails").touch()
    assert run_role(tmp_path, "hardware_metrics", "config", v).returncode == 0
    r = run_role(tmp_path, "hardware_metrics", "health", v)
    assert r.returncode != 0 and "source: hypervisor" in r.stdout


def test_health_fails_on_a_stale_file(tmp_path):
    v = _vars(tmp_path)
    assert run_role(tmp_path, "hardware_metrics", "config", v).returncode == 0
    old = 1_000_000_000  # a fixed instant long past: any health window has run out
    os.utime(tmp_path / "textfile/hardware_metrics.prom", (old, old))
    r = run_role(tmp_path, "hardware_metrics", "health", v)
    assert r.returncode != 0 and "is the hnx-hardware-metrics.timer running" in r.stdout
