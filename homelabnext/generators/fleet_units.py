# SPDX-License-Identifier: Apache-2.0
"""Render systemd service+timer units from a declarative list.

Rules enforced at render time (a violation raises ``FleetUnitsError``):

* Timers are ``OnCalendar=`` only. ``OnBootSec``, ``OnUnitActiveSec``,
  ``OnUnitInactiveSec``, ``OnActiveSec`` and ``OnStartupSec`` are refused. The
  pair ``OnBootSec`` + ``OnUnitActiveSec`` is refused with a dedicated message: if
  the boot trigger point is missed the unit-active anchor never starts, so the
  timer reports ``active`` forever and never fires again.
* Every calendar expression carries an explicit trailing ``UTC`` token. Missing
  or any other time zone is refused, and so are the shorthands (``daily``,
  ``hourly`` ...) because they resolve in the host's local zone.
* Output is deterministic: entries are sorted by name, line endings are ``\\n``,
  and there are no timestamps, so goldens are byte-identical.

Spec entry (YAML list item)::

    name: lake-compact              # [a-z0-9-]+, becomes hnx-<name>.service/.timer
    description: Compact lake tables
    exec: /usr/local/bin/lake-compact --all   # absolute path
    on_calendar: "*-*-* 02:30:00 UTC"         # string or list of strings
    user: svc-lake                  # optional
    persistent: true                # optional, default true
    randomized_delay_sec: 0         # optional
    timeout_start_sec: 3600         # optional
    pages_directly: false           # optional; true adds OnFailure=hnx-page@%n.service
    replaced_by: "st2:pack.workflow"  # optional; unit is rendered DISABLED and marked retired
"""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import yaml

PREFIX = "hnx-"
MONOTONIC = {
    "on_boot_sec": "OnBootSec",
    "on_unit_active_sec": "OnUnitActiveSec",
    "on_unit_inactive_sec": "OnUnitInactiveSec",
    "on_active_sec": "OnActiveSec",
    "on_startup_sec": "OnStartupSec",
}
ALLOWED = {
    "name",
    "description",
    "exec",
    "on_calendar",
    "user",
    "persistent",
    "randomized_delay_sec",
    "timeout_start_sec",
    "pages_directly",
    "replaced_by",
}
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
SHORTHANDS = {
    "minutely",
    "hourly",
    "daily",
    "weekly",
    "monthly",
    "quarterly",
    "semiannually",
    "yearly",
    "annually",
}
CAL_RE = re.compile(r"^[\w*,.:/\- ]+$")
# a timezone token at the end of the expression: UTC, or something zone-like
TZ_TOKEN = re.compile(r"\s(\S+)$")


class FleetUnitsError(ValueError):
    """The spec violates a fleet_units rule."""


def _check_calendar(name: str, cal: Any) -> str:
    if not isinstance(cal, str) or not cal.strip():
        raise FleetUnitsError(f"{name}: on_calendar entries must be non-empty strings")
    cal = cal.strip()
    if cal.lower() in SHORTHANDS:
        raise FleetUnitsError(
            f"{name}: calendar shorthand '{cal}' resolves in the host time zone; write an explicit expression ending in ' UTC'"
        )
    if not CAL_RE.match(cal):
        raise FleetUnitsError(f"{name}: calendar '{cal}' contains unsupported characters")
    if cal.upper() == "UTC":
        raise FleetUnitsError(f"{name}: calendar '{cal}' has no time expression")
    m = TZ_TOKEN.search(cal)
    if not m:
        raise FleetUnitsError(f"{name}: calendar '{cal}' has no time zone; append ' UTC'")
    tz = m.group(1)
    if not re.match(r"^[A-Za-z][A-Za-z_+\-/0-9]*$", tz):
        raise FleetUnitsError(f"{name}: calendar '{cal}' has no time zone; append ' UTC'")
    if tz != "UTC":
        raise FleetUnitsError(
            f"{name}: calendar '{cal}' uses time zone '{tz}'; only UTC is allowed"
        )
    if tz == cal:
        raise FleetUnitsError(f"{name}: calendar '{cal}' has no time expression")
    return cal


def validate(entries: Any) -> list[dict[str, Any]]:
    if not isinstance(entries, list) or not entries:
        raise FleetUnitsError("spec must be a non-empty list of unit entries")
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for i, e in enumerate(entries):
        if not isinstance(e, dict):
            raise FleetUnitsError(f"entry {i}: must be a mapping")
        name = e.get("name")
        if not isinstance(name, str) or not NAME_RE.match(name):
            raise FleetUnitsError(f"entry {i}: name must match {NAME_RE.pattern}")
        mono = [k for k in MONOTONIC if k in e]
        if "on_boot_sec" in e and "on_unit_active_sec" in e:
            raise FleetUnitsError(
                f"{name}: OnBootSec + OnUnitActiveSec is refused: a missed boot trigger leaves the timer "
                "active forever and never firing; use on_calendar"
            )
        if mono:
            raise FleetUnitsError(
                f"{name}: {', '.join(MONOTONIC[k] for k in mono)} refused; fleet_units is OnCalendar-only"
            )
        unknown = set(e) - ALLOWED
        if unknown:
            raise FleetUnitsError(f"{name}: unknown key(s) {sorted(unknown)}")
        if name in seen:
            raise FleetUnitsError(f"duplicate unit name '{name}'")
        seen.add(name)
        ex = e.get("exec")
        if not isinstance(ex, str) or not ex.startswith("/"):
            raise FleetUnitsError(f"{name}: exec must be a string starting with an absolute path")
        if "on_calendar" not in e:
            raise FleetUnitsError(f"{name}: on_calendar is required")
        cals = e["on_calendar"] if isinstance(e["on_calendar"], list) else [e["on_calendar"]]
        if not cals:
            raise FleetUnitsError(f"{name}: on_calendar is empty")
        item = dict(e)
        item["on_calendar"] = [_check_calendar(name, c) for c in cals]
        for k in ("persistent", "pages_directly"):
            if k in item and not isinstance(item[k], bool):
                raise FleetUnitsError(f"{name}: {k} must be a boolean")
        for k in ("randomized_delay_sec", "timeout_start_sec"):
            if k in item and (
                not isinstance(item[k], int) or isinstance(item[k], bool) or item[k] < 0
            ):
                raise FleetUnitsError(f"{name}: {k} must be a non-negative integer")
        if "replaced_by" in item and not (
            isinstance(item["replaced_by"], str) and item["replaced_by"].strip()
        ):
            raise FleetUnitsError(f"{name}: replaced_by must be a non-empty string")
        for k in ("description", "user"):
            if k in item and (not isinstance(item[k], str) or "\n" in item[k]):
                raise FleetUnitsError(f"{name}: {k} must be a single-line string")
        out.append(item)
    return sorted(out, key=lambda x: x["name"])


def _service(e: dict[str, Any]) -> str:
    name = e["name"]
    lines = ["# Managed by fleet_units. Do not edit."]
    if e.get("replaced_by"):
        lines.append(f"# RETIRED: replaced by {e['replaced_by']}. Timer is not enabled.")
    lines += ["[Unit]", f"Description={e.get('description', name)}"]
    if e.get("pages_directly"):
        lines.append("OnFailure=hnx-page@%n.service")
    lines += ["", "[Service]", "Type=oneshot", f"ExecStart={e['exec']}"]
    if e.get("user"):
        lines.append(f"User={e['user']}")
    if "timeout_start_sec" in e:
        lines.append(f"TimeoutStartSec={e['timeout_start_sec']}")
    return "\n".join(lines) + "\n"


def _timer(e: dict[str, Any]) -> str:
    name = e["name"]
    lines = ["# Managed by fleet_units. Do not edit."]
    if e.get("replaced_by"):
        lines.append(f"# RETIRED: replaced by {e['replaced_by']}. Timer is not enabled.")
    lines += ["[Unit]", f"Description=Timer for {PREFIX}{name}.service", "", "[Timer]"]
    lines += [f"OnCalendar={c}" for c in e["on_calendar"]]
    lines.append(f"Persistent={'true' if e.get('persistent', True) else 'false'}")
    if e.get("randomized_delay_sec"):
        lines.append(f"RandomizedDelaySec={e['randomized_delay_sec']}")
    lines.append(f"Unit={PREFIX}{name}.service")
    if not e.get("replaced_by"):
        lines += ["", "[Install]", "WantedBy=timers.target"]
    return "\n".join(lines) + "\n"


def render(entries: Any) -> dict[str, str]:
    """Return {filename: content}, including ``fleet-units.manifest`` listing enabled/retired timers."""
    items = validate(entries)
    files: dict[str, str] = {}
    manifest = ["# fleet_units manifest: <state> <timer>"]
    for e in items:
        files[f"{PREFIX}{e['name']}.service"] = _service(e)
        files[f"{PREFIX}{e['name']}.timer"] = _timer(e)
        state = "retired" if e.get("replaced_by") else "enabled"
        manifest.append(f"{state} {PREFIX}{e['name']}.timer")
    files["fleet-units.manifest"] = "\n".join(manifest) + "\n"
    return dict(sorted(files.items()))


def render_file(spec_path: Path) -> dict[str, str]:
    return render(yaml.safe_load(Path(spec_path).read_text(encoding="utf-8")))


def write(files: dict[str, str], out_dir: Path) -> list[Path]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for fname, content in files.items():
        p = out_dir / fname
        p.write_bytes(content.encode("utf-8"))
        written.append(p)
    return written


def main(argv: Iterable[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Render systemd units from a fleet_units spec")
    ap.add_argument("spec")
    ap.add_argument("out_dir")
    args = ap.parse_args(list(argv) if argv is not None else None)
    try:
        files = render_file(Path(args.spec))
    except FleetUnitsError as exc:
        print(f"fleet_units: {exc}", file=sys.stderr)
        return 1
    except (OSError, yaml.YAMLError) as exc:
        print(f"fleet_units: cannot read spec: {exc}", file=sys.stderr)
        return 2
    write(files, Path(args.out_dir))
    print(f"wrote {len(files)} files to {args.out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
