#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: prowler-export
#   kind: job
#   purpose: Run the cloud-posture scanner read-only against the account and replace the findings file (one summary line, then one flat line per failing check) the SIEM agent and the log pipeline tail.
#   owner: platform
#   trigger: [timer:prowler/scan, role:prowler]
#   inputs: "environment PROWLER_* (scan.env) and the cloud credentials in AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY (a root-only EnvironmentFile the unit loads)"
#   outputs: the findings file (JSON lines, replaced whole), last-run.json under the state directory, one line on stdout
#   installs_to: /usr/local/libexec/homelabnext/hnx-prowler-export
#   exit:
#     "0": scanned, findings written
#     "1": the scan failed or produced no usable report (the previous findings are left as they were)
#     "2": refused before any scan (a missing credential, an unsafe path)
"""Run the scanner and write a fresh JSON-lines findings file.

Two flat event shapes, both ``pw_``-prefixed:

* one ``summary`` per run: passed, failed, muted, total, score, scanner version, account;
* one ``check`` per FAILING check. A pass is counted into the summary and not emitted (the scanner's
  own report stays on disk), the signal-to-noise call every scanner feed here makes.

The fields are flattened and prefixed on purpose. The scanner's native output is deeply nested, and
a SIEM's generic JSON decoder flattens nested objects into dotted names: an ordinary leaf (status,
severity, region) can collide with a reserved field and take down the rule engine. A prefix removes
the risk by construction instead of hoping no word collides.

The scanner's exit code is not a success flag: it exits 3 when at least one check FAILED, which is
the normal outcome of a real scan. Only a code outside {0, 3} is a tool error.

A failed scan, or a report with no findings at all, writes nothing: truncating the previous findings
to zero would make a broken scanner look like an account where everything got fixed.

The cloud credentials come from the environment only. They are never read from a file by this
script, never logged, and the scanner's stderr is cut before it is printed because it can echo argv.
"""

import glob
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

OK_RETURNCODES = (0, 3)
MAX_TEXT = 500  # long prose is cut; the full report stays on disk
MAX_STDERR = 600
REPORT_NAME = "prowler-run"


class ConfigError(Exception):
    """Refused before any scan: a missing credential or an unsafe path."""


class ReportError(Exception):
    """The scanner's report is missing, unparsable or holds no findings."""


@dataclass
class Config:
    prowler_bin: str
    output_dir: Path
    findings: Path
    mutelist: Path | None
    regions: list
    state_dir: Path
    mode: int
    timeout: int


@dataclass
class Result:
    rows: list
    passed: int
    failed: int
    muted: int
    total: int
    account: str


def config_from_env(env) -> Config:
    def need(name):
        v = env.get(name, "")
        if not v:
            raise ConfigError(f"{name} is not set")
        return v

    mute = env.get("PROWLER_MUTELIST", "")
    return Config(
        prowler_bin=need("PROWLER_BIN"),
        output_dir=Path(need("PROWLER_OUTPUT_DIR")),
        findings=Path(need("PROWLER_FINDINGS")),
        mutelist=Path(mute) if mute else None,
        regions=[r for r in env.get("PROWLER_REGIONS", "").split() if r],
        state_dir=Path(need("PROWLER_STATE_DIR")),
        mode=int(env.get("PROWLER_FINDINGS_MODE", "0640"), 8),
        timeout=int(env.get("PROWLER_TIMEOUT_S", "3600")),
    )


def require_credentials(env) -> None:
    # the names only: a value never reaches a message
    for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"):
        if not env.get(name):
            raise ConfigError(f"{name} is not set (the unit's credential file did not load)")


def _safe_dir(path: Path) -> Path:
    """Refuse a relative, shallow, dotted or symlinked directory before anything in it is deleted."""
    s = str(path)
    if not path.is_absolute() or ".." in path.parts or len(path.parts) < 4:
        raise ConfigError(f"unsafe output directory {s!r}")
    if path.is_symlink() or path.resolve() != path:
        raise ConfigError(f"output directory {s!r} is or passes through a symlink")
    return path


def clean_output(directory: Path) -> None:
    """Remove the previous run's report files (only the scanner's own names, only directly inside
    the directory), so a stale report can never be re-read as this week's."""
    d = _safe_dir(directory)
    for old in glob.glob(str(d / f"{REPORT_NAME}.*")):
        p = Path(old)
        if p.is_file() and not p.is_symlink():
            p.unlink()


def version_number(text: str) -> str:
    """The number only: the scanner appends chatter to a changing string for an unchanged binary."""
    m = re.search(r"(\d+\.\d+\.\d+)", text or "")
    return m.group(1) if m else "unknown"


def _text(val) -> str:
    return "" if val is None else str(val).replace("\n", " ").strip()[:MAX_TEXT]


def _account(f: dict) -> str:
    return _text(((f.get("cloud") or {}).get("account") or {}).get("uid"))


def parse_findings(report: Path) -> Result:
    try:
        raw = json.loads(Path(report).read_text() or "null")
    except (OSError, ValueError) as e:
        raise ReportError(f"report unreadable: {type(e).__name__}") from None
    if isinstance(raw, dict):  # some versions wrap the list
        raw = raw.get("findings")
    if not isinstance(raw, list) or not any(isinstance(f, dict) for f in raw):
        raise ReportError(
            "report holds no findings (an empty scan is an error, not a clean account)"
        )

    passed = failed = muted = total = 0
    account = ""
    rows = []
    for f in raw:
        if not isinstance(f, dict):
            continue
        total += 1
        account = account or _account(f)
        # A muted finding is `status: Suppressed` with status_code LEFT AT FAIL: the mutelist must be
        # read before the status code, or it appears to work and changes nothing in this file.
        if (f.get("status") or "").lower() == "suppressed":
            muted += 1
            continue
        status = (f.get("status_code") or "").upper()
        if status == "PASS":
            passed += 1
            continue
        if status != "FAIL":
            continue  # MANUAL, INFO, anything else: in the total only
        failed += 1
        meta = f.get("metadata") or {}
        info = f.get("finding_info") or {}
        cloud = f.get("cloud") or {}
        res = f.get("resources") or []
        resource = res[0] if res and isinstance(res[0], dict) else {}
        rows.append(
            {
                "pw_finding": True,
                "pw_kind": "check",
                "pw_check_id": _text(meta.get("event_code") or info.get("uid")),
                "pw_title": _text(info.get("title") or meta.get("event_code")),
                "pw_status": "fail",
                "pw_severity": _text(f.get("severity") or "unknown").lower(),
                "pw_service": _text((resource.get("group") or {}).get("name")),
                "pw_region": _text(resource.get("region") or cloud.get("region")),
                "pw_account": _account(f),
                "pw_resource_uid": _text(resource.get("uid")),
                "pw_resource_type": _text(resource.get("type")),
                "pw_risk": _text(f.get("risk_details")),
                "pw_remediation": _text((f.get("remediation") or {}).get("desc")),
            }
        )
    return Result(rows, passed, failed, muted, total, account)


def summary_event(res: Result, version: str, now: datetime) -> dict:
    acted = res.passed + res.failed
    return {
        "pw_finding": True,
        "pw_kind": "summary",
        "pw_status": "summary",
        "pw_severity": "informational",
        "pw_title": f"Prowler AWS scan: {res.failed} failed / {res.passed} passed / "
        f"{res.muted} muted of {res.total} checks",
        "pw_passed": res.passed,
        "pw_failed": res.failed,
        # Muted is reported, never silent: an accepted risk that stops being counted is how a
        # mutelist rots into a blind spot.
        "pw_muted": res.muted,
        "pw_total": res.total,
        # muted findings are on neither side: accepted, not failed and not fixed; nothing acted on
        # scores 0.0, never a division by zero
        "pw_score": round(100.0 * res.passed / acted, 2) if acted else 0.0,
        "pw_account": res.account,
        "pw_version": version,
        "pw_scanned_at": now.isoformat(),
    }


def render_findings(summary: dict, rows: list) -> str:
    return "".join(json.dumps(line) + "\n" for line in [summary, *rows])


def replace_file(path: Path, text: str, mode: int) -> None:
    """Write beside, then rename into place: a reader tailing the file never sees half of it."""
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as out:
        out.write(text)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def write_findings(path: Path, summary: dict, rows: list, mode: int) -> None:
    replace_file(path, render_findings(summary, rows), mode)


def record_run(directory: Path, doc: dict) -> None:
    """The last-run record the health hook reads (a torn one reads as not ok until the next run)."""
    record = directory / "last-run.json"
    record.parent.mkdir(parents=True, exist_ok=True)
    record.write_text(json.dumps(doc) + "\n")


def _fail(cfg: Config, now: datetime, reason: str) -> int:
    print(f"prowler-export: {reason}", file=sys.stderr)
    record_run(cfg.state_dir, {"ok": False, "at": now.isoformat(), "reason": reason[:300]})
    return 1


def run(cfg: Config, env, runner=subprocess.run, now: datetime | None = None) -> int:
    now = now or datetime.now(UTC)
    try:
        require_credentials(env)
        clean_output(cfg.output_dir)
    except ConfigError as e:
        print(f"prowler-export: refused: {e}", file=sys.stderr)
        return 2
    cfg.output_dir.mkdir(parents=True, exist_ok=True)
    version = _version(cfg, env, runner)

    cmd = [
        cfg.prowler_bin, "aws",
        "--output-formats", "json-ocsf",
        "--output-directory", str(cfg.output_dir),
        "--output-filename", REPORT_NAME,
        "--no-banner",
    ]  # fmt: skip
    if cfg.regions:
        cmd += ["--region", *cfg.regions]
    if cfg.mutelist is not None and cfg.mutelist.exists():
        cmd += ["--mutelist-file", str(cfg.mutelist)]

    try:
        proc = runner(cmd, capture_output=True, text=True, env=dict(env), timeout=cfg.timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        return _fail(cfg, now, f"scanner did not run: {type(e).__name__}")
    if proc.returncode not in OK_RETURNCODES:
        tail = (proc.stderr or "").strip()[:MAX_STDERR]
        for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"):
            if env.get(name):
                tail = tail.replace(env[name], "***")
        return _fail(cfg, now, f"scanner exited {proc.returncode}: {tail}")
    reports = sorted(glob.glob(str(cfg.output_dir / f"{REPORT_NAME}*.ocsf.json")))
    if not reports:
        return _fail(cfg, now, f"scanner wrote no report in {cfg.output_dir}")
    try:
        res = parse_findings(Path(reports[-1]))
    except ReportError as e:
        return _fail(cfg, now, str(e))

    summary = summary_event(res, version, now)
    write_findings(cfg.findings, summary, res.rows, cfg.mode)
    record_run(
        cfg.state_dir,
        {"ok": True, "at": now.isoformat(), "failed": res.failed, "passed": res.passed,
         "muted": res.muted, "total": res.total, "version": version},
    )  # fmt: skip
    print(
        f"prowler {version}: {res.failed} failed / {res.passed} passed / {res.muted} muted "
        f"of {res.total} checks -> {cfg.findings}"
    )
    return 0


def _version(cfg: Config, env, runner) -> str:
    try:
        r = runner([cfg.prowler_bin, "--version"], capture_output=True, text=True,
                   env=dict(env), timeout=60)  # fmt: skip
        return version_number((r.stdout or r.stderr or "").strip().splitlines()[0])
    except Exception:
        return "unknown"


def main() -> int:
    try:
        cfg = config_from_env(os.environ)
    except (ConfigError, ValueError) as e:
        print(f"prowler-export: refused: {e}", file=sys.stderr)
        return 2
    try:
        return run(cfg, os.environ)
    except Exception as e:  # never interpolate more than the type: scanner errors can echo argv
        print(f"prowler-export failed: {type(e).__name__}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
