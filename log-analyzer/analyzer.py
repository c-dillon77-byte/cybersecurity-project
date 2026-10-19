#!/usr/bin/env python3
"""Linux auth log analyzer (Python 3.10+, standard library only).

Parse Debian/Ubuntu /var/log/auth.log, RHEL /var/log/secure, and
`journalctl -u ssh -o short-iso` style lines. Detect brute force, password
spraying, success-after-failures, root attempts, invalid-user enumeration,
new-IP logins, and off-hours access. Findings carry severity and MITRE ATT&CK
IDs where they fit.

Credentials and real hostnames are never required — ship and demo with synthetic
sample_logs/ only.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

__version__ = "1.0.0"

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AuthEvent:
    timestamp: datetime
    host: str
    program: str
    pid: int | None
    event_type: str
    raw: str
    user: str = ""
    source_ip: str = ""
    port: int | None = None
    method: str = ""  # password | publickey | ""
    success: bool | None = None
    command: str = ""
    invalid_user: bool = False


@dataclass
class Finding:
    severity: str  # low | medium | high
    title: str
    detail: str
    mitre: str  # e.g. T1110.001
    mitre_name: str
    source_ip: str = ""
    user: str = ""
    count: int = 0
    first_seen: str = ""
    last_seen: str = ""


@dataclass
class AnalysisReport:
    files: list[str]
    events_parsed: int
    events_ignored: int
    findings: list[Finding] = field(default_factory=list)
    top_ips: list[tuple[str, int]] = field(default_factory=list)
    top_users: list[tuple[str, int]] = field(default_factory=list)
    failure_count: int = 0
    success_count: int = 0
    sudo_count: int = 0
    block_candidates: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


class AnalyzerError(Exception):
    """User-facing error; printed without a traceback; exit code 2."""


# ---------------------------------------------------------------------------
# Timestamp / file I/O
# ---------------------------------------------------------------------------

SYSLOG_TS = re.compile(
    r"^(?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<prog>[a-zA-Z0-9_/\-]+)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<msg>.*)$"
)

ISO_TS = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<prog>[a-zA-Z0-9_/\-]+)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<msg>.*)$"
)

MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}


def parse_syslog_timestamp(mon: str, day: str, time_s: str, year: int) -> datetime:
    """Build a naive datetime; syslog lines have no year or timezone."""
    return datetime(
        year,
        MONTHS[mon],
        int(day),
        *map(int, time_s.split(":")),
    )


def open_log(path: Path):
    """Open a plain or gzip-rotated log for text reading."""
    if path.suffix == ".gz" or path.name.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return path.open("rt", encoding="utf-8", errors="replace")


def read_log_lines(path: Path) -> list[str]:
    try:
        with open_log(path) as fh:
            return fh.read().splitlines()
    except OSError as exc:
        raise AnalyzerError(f"cannot read {path}: {exc}") from None


# ---------------------------------------------------------------------------
# Line parsers
# ---------------------------------------------------------------------------

# sshd failure / success / invalid / closed / pam authentication failure
RE_FAILED = re.compile(
    r"Failed password for (?:(?P<invalid>invalid user) )?(?P<user>\S+) "
    r"from (?P<ip>\S+)(?: port (?P<port>\d+))?",
    re.IGNORECASE,
)
RE_ACCEPTED = re.compile(
    r"Accepted (?P<method>password|publickey) for (?P<user>\S+) "
    r"from (?P<ip>\S+)(?: port (?P<port>\d+))?",
    re.IGNORECASE,
)
RE_INVALID = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>\S+)(?: port (?P<port>\d+))?",
    re.IGNORECASE,
)
RE_CLOSED = re.compile(
    r"Connection closed by authenticating user (?P<user>\S+) (?P<ip>\S+)(?: port (?P<port>\d+))?",
    re.IGNORECASE,
)
RE_PAM_FAIL = re.compile(
    r"authentication failure;.*\brhost=(?P<ip>\S+)(?:\s+user=(?P<user>\S+))?",
    re.IGNORECASE,
)
RE_SUDO_CMD = re.compile(r"^(?P<user>\S+)\s*:\s*(?P<body>.+);\s*COMMAND=(?P<cmd>.+)$")
RE_SUDO_NOT = re.compile(
    r"^(?P<user>\S+)\s*:\s*user NOT in sudoers\s*;.*COMMAND=(?P<cmd>.+)$",
    re.IGNORECASE,
)
RE_SUDO_BADPASS = re.compile(
    r"^(?P<user>\S+)\s*:\s*\d+ incorrect password attempts?\s*;.*COMMAND=(?P<cmd>.+)$",
    re.IGNORECASE,
)


def parse_message(
    *,
    timestamp: datetime,
    host: str,
    program: str,
    pid: int | None,
    msg: str,
    raw: str,
) -> AuthEvent | None:
    """Classify one syslog message body into an AuthEvent, or None if uninteresting."""
    prog = program.split("/")[-1].lower()

    if prog.startswith("sshd") or prog == "sshd":
        m = RE_ACCEPTED.search(msg)
        if m:
            return AuthEvent(
                timestamp,
                host,
                prog,
                pid,
                "ssh_accepted",
                raw,
                user=m.group("user"),
                source_ip=m.group("ip"),
                port=int(m.group("port")) if m.group("port") else None,
                method=m.group("method").lower(),
                success=True,
            )
        m = RE_FAILED.search(msg)
        if m:
            return AuthEvent(
                timestamp,
                host,
                prog,
                pid,
                "ssh_failed",
                raw,
                user=m.group("user"),
                source_ip=m.group("ip"),
                port=int(m.group("port")) if m.group("port") else None,
                method="password",
                success=False,
                invalid_user=bool(m.group("invalid")),
            )
        m = RE_INVALID.search(msg)
        if m:
            return AuthEvent(
                timestamp,
                host,
                prog,
                pid,
                "ssh_invalid_user",
                raw,
                user=m.group("user"),
                source_ip=m.group("ip"),
                port=int(m.group("port")) if m.group("port") else None,
                success=False,
                invalid_user=True,
            )
        m = RE_CLOSED.search(msg)
        if m:
            return AuthEvent(
                timestamp,
                host,
                prog,
                pid,
                "ssh_closed",
                raw,
                user=m.group("user"),
                source_ip=m.group("ip"),
                port=int(m.group("port")) if m.group("port") else None,
                success=False,
            )
        m = RE_PAM_FAIL.search(msg)
        if m:
            return AuthEvent(
                timestamp,
                host,
                prog,
                pid,
                "ssh_auth_failure",
                raw,
                user=(m.group("user") or ""),
                source_ip=m.group("ip"),
                success=False,
            )

    if prog == "sudo":
        m = RE_SUDO_NOT.match(msg.strip())
        if m:
            return AuthEvent(
                timestamp,
                host,
                prog,
                pid,
                "sudo_not_in_sudoers",
                raw,
                user=m.group("user"),
                success=False,
                command=m.group("cmd").strip(),
            )
        m = RE_SUDO_BADPASS.match(msg.strip())
        if m:
            return AuthEvent(
                timestamp,
                host,
                prog,
                pid,
                "sudo_bad_password",
                raw,
                user=m.group("user"),
                success=False,
                command=m.group("cmd").strip(),
            )
        m = RE_SUDO_CMD.match(msg.strip())
        if m and "COMMAND=" in msg:
            body = m.group("body")
            ok = "NOT in sudoers" not in body and "incorrect password" not in body
            return AuthEvent(
                timestamp,
                host,
                prog,
                pid,
                "sudo_command" if ok else "sudo_other",
                raw,
                user=m.group("user"),
                success=ok,
                command=m.group("cmd").strip(),
            )

    return None


def parse_line(line: str, *, year: int) -> AuthEvent | None:
    """Parse one log line (syslog or short-iso). Blank / noise → None."""
    line = line.rstrip("\n")
    if not line.strip() or line.lstrip().startswith("#"):
        return None

    m = ISO_TS.match(line)
    if m:
        ts_raw = m.group("ts")
        # fromisoformat handles 2026-10-18T11:00:00+00:00 and ...Z (3.11+);
        # normalize Z for 3.10.
        ts_norm = ts_raw.replace("Z", "+00:00")
        try:
            ts = datetime.fromisoformat(ts_norm)
        except ValueError as exc:
            raise AnalyzerError(f"bad ISO timestamp {ts_raw!r}: {exc}") from None
        if ts.tzinfo is not None:
            ts = ts.replace(tzinfo=None)  # keep naive for window math
        pid = int(m.group("pid")) if m.group("pid") else None
        return parse_message(
            timestamp=ts,
            host=m.group("host"),
            program=m.group("prog"),
            pid=pid,
            msg=m.group("msg"),
            raw=line,
        )

    m = SYSLOG_TS.match(line)
    if m:
        ts = parse_syslog_timestamp(m.group("mon"), m.group("day"), m.group("time"), year)
        pid = int(m.group("pid")) if m.group("pid") else None
        return parse_message(
            timestamp=ts,
            host=m.group("host"),
            program=m.group("prog"),
            pid=pid,
            msg=m.group("msg"),
            raw=line,
        )

    return None


def parse_lines(lines: list[str], *, year: int) -> tuple[list[AuthEvent], int]:
    events: list[AuthEvent] = []
    ignored = 0
    for line in lines:
        try:
            ev = parse_line(line, year=year)
        except AnalyzerError:
            ignored += 1
            continue
        if ev is None:
            ignored += 1
        else:
            events.append(ev)
    events.sort(key=lambda e: e.timestamp)
    return events, ignored


def parse_files(paths: list[Path], *, year: int) -> tuple[list[AuthEvent], int]:
    all_events: list[AuthEvent] = []
    ignored = 0
    for path in paths:
        evs, ign = parse_lines(read_log_lines(path), year=year)
        all_events.extend(evs)
        ignored += ign
    all_events.sort(key=lambda e: e.timestamp)
    return all_events, ignored


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


@dataclass
class DetectConfig:
    fail_threshold: int = 5
    fail_window_minutes: int = 10
    spray_user_threshold: int = 5
    spray_window_minutes: int = 10
    enum_threshold: int = 5
    enum_window_minutes: int = 15
    off_hours_start: int = 22  # inclusive, 24h clock
    off_hours_end: int = 6  # exclusive; wraps past midnight
    known_ips: dict[str, set[str]] = field(default_factory=dict)
    # known_ips: user -> set of IPs already considered "seen"


def _in_off_hours(ts: datetime, start: int, end: int) -> bool:
    hour = ts.hour
    if start == end:
        return False
    if start < end:
        return start <= hour < end
    # wraps midnight, e.g. 22..6
    return hour >= start or hour < end


def _window_hits(
    events: list[AuthEvent],
    *,
    threshold: int,
    window: timedelta,
    key_fn,
) -> list[tuple[object, list[AuthEvent]]]:
    """Sliding-window: return groups where >= threshold events share a key."""
    # Group by key first, then scan each timeline.
    by_key: dict[object, list[AuthEvent]] = defaultdict(list)
    for ev in events:
        by_key[key_fn(ev)].append(ev)
    hits: list[tuple[object, list[AuthEvent]]] = []
    for key, evs in by_key.items():
        if key in (None, "", ("", "")):
            continue
        evs = sorted(evs, key=lambda e: e.timestamp)
        left = 0
        best: list[AuthEvent] = []
        for right, ev in enumerate(evs):
            while ev.timestamp - evs[left].timestamp > window:
                left += 1
            span = evs[left : right + 1]
            if len(span) >= threshold and len(span) >= len(best):
                best = span
        if len(best) >= threshold:
            hits.append((key, best))
    return hits


def detect(events: list[AuthEvent], cfg: DetectConfig | None = None) -> list[Finding]:
    """Run all detectors; return findings sorted by severity then title."""
    cfg = cfg or DetectConfig()
    findings: list[Finding] = []

    failures = [
        e for e in events if e.event_type in {"ssh_failed", "ssh_auth_failure"} and e.source_ip
    ]
    accepts = [e for e in events if e.event_type == "ssh_accepted" and e.source_ip]
    invalids = [
        e for e in events if (e.event_type == "ssh_invalid_user" or e.invalid_user) and e.source_ip
    ]

    # --- Brute force: many failures, same IP (optionally same user) ---
    bf_window = timedelta(minutes=cfg.fail_window_minutes)
    for ip, hit in _window_hits(
        failures,
        threshold=cfg.fail_threshold,
        window=bf_window,
        key_fn=lambda e: e.source_ip,
    ):
        users = sorted({e.user for e in hit if e.user})
        findings.append(
            Finding(
                severity="high",
                title="SSH brute force",
                detail=(
                    f"{len(hit)} failed authentications from {ip} within "
                    f"{cfg.fail_window_minutes}m"
                    + (f" (users: {', '.join(users)})" if users else "")
                ),
                mitre="T1110.001",
                mitre_name="Brute Force: Password Guessing",
                source_ip=str(ip),
                user=users[0] if len(users) == 1 else "",
                count=len(hit),
                first_seen=hit[0].timestamp.isoformat(sep=" "),
                last_seen=hit[-1].timestamp.isoformat(sep=" "),
            )
        )

    # --- Password spraying: one IP, many distinct usernames failing ---
    spray_window = timedelta(minutes=cfg.spray_window_minutes)
    by_ip: dict[str, list[AuthEvent]] = defaultdict(list)
    for e in failures:
        by_ip[e.source_ip].append(e)
    for ip, evs in by_ip.items():
        evs = sorted(evs, key=lambda e: e.timestamp)
        left = 0
        best_users: set[str] = set()
        best_span: list[AuthEvent] = []
        for right, ev in enumerate(evs):
            while ev.timestamp - evs[left].timestamp > spray_window:
                left += 1
            span = evs[left : right + 1]
            users = {e.user for e in span if e.user}
            if len(users) >= cfg.spray_user_threshold and len(users) >= len(best_users):
                best_users = users
                best_span = span
        if len(best_users) >= cfg.spray_user_threshold:
            findings.append(
                Finding(
                    severity="high",
                    title="Password spraying",
                    detail=(
                        f"{ip} tried {len(best_users)} usernames within "
                        f"{cfg.spray_window_minutes}m: "
                        + ", ".join(sorted(best_users)[:8])
                        + ("…" if len(best_users) > 8 else "")
                    ),
                    mitre="T1110.003",
                    mitre_name="Brute Force: Password Spraying",
                    source_ip=ip,
                    count=len(best_span),
                    first_seen=best_span[0].timestamp.isoformat(sep=" "),
                    last_seen=best_span[-1].timestamp.isoformat(sep=" "),
                )
            )

    # --- Success after repeated failures from same IP ---
    fails_by_ip: dict[str, list[AuthEvent]] = defaultdict(list)
    for e in failures:
        fails_by_ip[e.source_ip].append(e)
    for e in accepts:
        prior = [
            f
            for f in fails_by_ip.get(e.source_ip, [])
            if f.timestamp < e.timestamp
            and e.timestamp - f.timestamp <= timedelta(minutes=cfg.fail_window_minutes)
        ]
        if len(prior) >= max(3, cfg.fail_threshold - 2):
            findings.append(
                Finding(
                    severity="high",
                    title="Successful login after failures",
                    detail=(
                        f"{e.user} logged in from {e.source_ip} via {e.method} after "
                        f"{len(prior)} recent failures — possible compromise"
                    ),
                    mitre="T1078",
                    mitre_name="Valid Accounts",
                    source_ip=e.source_ip,
                    user=e.user,
                    count=len(prior) + 1,
                    first_seen=prior[0].timestamp.isoformat(sep=" "),
                    last_seen=e.timestamp.isoformat(sep=" "),
                )
            )

    # --- Invalid-user enumeration ---
    enum_window = timedelta(minutes=cfg.enum_window_minutes)
    for ip, hit in _window_hits(
        invalids,
        threshold=cfg.enum_threshold,
        window=enum_window,
        key_fn=lambda e: e.source_ip,
    ):
        users = sorted({e.user for e in hit if e.user})
        findings.append(
            Finding(
                severity="medium",
                title="Invalid-user enumeration",
                detail=(
                    f"{ip} probed {len(users)} invalid usernames within {cfg.enum_window_minutes}m"
                ),
                mitre="T1589.001",
                mitre_name="Gather Victim Identity Information: Credentials",
                source_ip=str(ip),
                count=len(hit),
                first_seen=hit[0].timestamp.isoformat(sep=" "),
                last_seen=hit[-1].timestamp.isoformat(sep=" "),
            )
        )

    # --- Root login attempts (failed or accepted) ---
    root_events = [
        e
        for e in events
        if e.user == "root"
        and e.event_type in {"ssh_failed", "ssh_accepted", "ssh_invalid_user", "ssh_auth_failure"}
    ]
    root_by_ip: dict[str, list[AuthEvent]] = defaultdict(list)
    for e in root_events:
        if e.source_ip:
            root_by_ip[e.source_ip].append(e)
    for ip, evs in root_by_ip.items():
        accepted = any(e.success for e in evs)
        findings.append(
            Finding(
                severity="high" if accepted else "medium",
                title="Root SSH login attempt" + (" (succeeded)" if accepted else "s"),
                detail=f"{len(evs)} root auth event(s) from {ip}",
                mitre="T1078.003" if accepted else "T1110.001",
                mitre_name=(
                    "Valid Accounts: Local Accounts"
                    if accepted
                    else "Brute Force: Password Guessing"
                ),
                source_ip=ip,
                user="root",
                count=len(evs),
                first_seen=evs[0].timestamp.isoformat(sep=" "),
                last_seen=evs[-1].timestamp.isoformat(sep=" "),
            )
        )

    # --- New IP for user (first success from an IP not in known set / prior successes) ---
    seen: dict[str, set[str]] = {u: set(ips) for u, ips in cfg.known_ips.items()}
    for e in accepts:
        prior_ips = seen.setdefault(e.user, set())
        if prior_ips and e.source_ip not in prior_ips:
            findings.append(
                Finding(
                    severity="medium",
                    title="Login from new IP",
                    detail=(
                        f"{e.user} accepted from new IP {e.source_ip} "
                        f"(previously seen: {', '.join(sorted(prior_ips)[:5])})"
                    ),
                    mitre="T1078",
                    mitre_name="Valid Accounts",
                    source_ip=e.source_ip,
                    user=e.user,
                    count=1,
                    first_seen=e.timestamp.isoformat(sep=" "),
                    last_seen=e.timestamp.isoformat(sep=" "),
                )
            )
        prior_ips.add(e.source_ip)

    # --- Off-hours successful logins ---
    for e in accepts:
        if _in_off_hours(e.timestamp, cfg.off_hours_start, cfg.off_hours_end):
            findings.append(
                Finding(
                    severity="low",
                    title="Off-hours login",
                    detail=(
                        f"{e.user} logged in from {e.source_ip} at "
                        f"{e.timestamp.strftime('%H:%M:%S')} "
                        f"(off-hours {cfg.off_hours_start:02d}:00–{cfg.off_hours_end:02d}:00)"
                    ),
                    mitre="T1078",
                    mitre_name="Valid Accounts",
                    source_ip=e.source_ip,
                    user=e.user,
                    count=1,
                    first_seen=e.timestamp.isoformat(sep=" "),
                    last_seen=e.timestamp.isoformat(sep=" "),
                )
            )

    # --- Sudo failures ---
    for e in events:
        if e.event_type in {"sudo_not_in_sudoers", "sudo_bad_password"}:
            findings.append(
                Finding(
                    severity="medium",
                    title="Sudo failure",
                    detail=f"{e.user}: {e.event_type.replace('_', ' ')} — {e.command}",
                    mitre="T1548.003",
                    mitre_name="Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
                    user=e.user,
                    count=1,
                    first_seen=e.timestamp.isoformat(sep=" "),
                    last_seen=e.timestamp.isoformat(sep=" "),
                )
            )

    severity_order = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda f: (severity_order.get(f.severity, 9), f.title, f.source_ip))
    return findings


# ---------------------------------------------------------------------------
# Report building / output
# ---------------------------------------------------------------------------


def analyze(
    events: list[AuthEvent],
    *,
    files: list[str],
    ignored: int,
    cfg: DetectConfig | None = None,
) -> AnalysisReport:
    cfg = cfg or DetectConfig()
    findings = detect(events, cfg)
    fail_ips = Counter(e.source_ip for e in events if e.success is False and e.source_ip)
    target_users = Counter(e.user for e in events if e.success is False and e.user)
    block = sorted({f.source_ip for f in findings if f.severity == "high" and f.source_ip})
    return AnalysisReport(
        files=files,
        events_parsed=len(events),
        events_ignored=ignored,
        findings=findings,
        top_ips=fail_ips.most_common(10),
        top_users=target_users.most_common(10),
        failure_count=sum(1 for e in events if e.success is False),
        success_count=sum(1 for e in events if e.success is True),
        sudo_count=sum(1 for e in events if e.program == "sudo"),
        block_candidates=block,
    )


def format_summary(report: AnalysisReport, *, include_blocklist: bool = True) -> str:
    lines = [
        f"Files            : {', '.join(report.files) or '(stdin)'}",
        f"Events parsed    : {report.events_parsed}",
        f"Lines ignored    : {report.events_ignored}",
        f"Failures         : {report.failure_count}",
        f"Successes        : {report.success_count}",
        f"Sudo events      : {report.sudo_count}",
        f"Findings         : {len(report.findings)}",
    ]
    for note in report.notes:
        lines.append(f"Note             : {note}")
    lines.append("")
    lines.append("=== Top offending IPs (by failures) ===")
    if not report.top_ips:
        lines.append("(none)")
    else:
        lines.append(f"{'IP':<18} {'Failures':>8}")
        lines.append("-" * 28)
        for ip, n in report.top_ips:
            lines.append(f"{ip:<18} {n:>8}")
    lines.append("")
    lines.append("=== Top targeted users ===")
    if not report.top_users:
        lines.append("(none)")
    else:
        lines.append(f"{'User':<16} {'Failures':>8}")
        lines.append("-" * 26)
        for user, n in report.top_users:
            lines.append(f"{user:<16} {n:>8}")
    lines.append("")
    lines.append("=== Findings ===")
    if not report.findings:
        lines.append("(none)")
    else:
        header = f"{'Sev':<7} {'MITRE':<12} {'Title':<32} Detail"
        lines.append(header)
        lines.append("-" * len(header))
        for f in report.findings:
            lines.append(f"{f.severity:<7} {f.mitre:<12} {f.title:<32} {f.detail}")
    if include_blocklist and report.block_candidates:
        lines.append("")
        lines.append("=== Suggested block list (high severity IPs) ===")
        lines.append("# Review before applying. Printed only — nothing is executed.")
        for ip in report.block_candidates:
            lines.append(f"# fail2ban / iptables candidate: {ip}")
            lines.append(f"iptables -A INPUT -s {ip} -j DROP")
    return "\n".join(lines)


def report_to_dict(report: AnalysisReport) -> dict:
    return {
        "files": report.files,
        "events_parsed": report.events_parsed,
        "events_ignored": report.events_ignored,
        "failure_count": report.failure_count,
        "success_count": report.success_count,
        "sudo_count": report.sudo_count,
        "top_ips": [{"ip": ip, "failures": n} for ip, n in report.top_ips],
        "top_users": [{"user": u, "failures": n} for u, n in report.top_users],
        "findings": [asdict(f) for f in report.findings],
        "block_candidates": report.block_candidates,
        "notes": report.notes,
    }


def write_csv(report: AnalysisReport, path: Path) -> None:
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(
            [
                "severity",
                "mitre",
                "mitre_name",
                "title",
                "detail",
                "source_ip",
                "user",
                "count",
                "first_seen",
                "last_seen",
            ]
        )
        for f in report.findings:
            writer.writerow(
                [
                    f.severity,
                    f.mitre,
                    f.mitre_name,
                    f.title,
                    f.detail,
                    f.source_ip,
                    f.user,
                    f.count,
                    f.first_seen,
                    f.last_seen,
                ]
            )


def render_html(report: AnalysisReport) -> str:
    """Standalone HTML report with inline CSS (no external assets)."""

    def esc(s: object) -> str:
        return (
            str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )

    sev_colors = {"high": "#b91c1c", "medium": "#c2410c", "low": "#a16207"}
    finding_rows = []
    for f in report.findings:
        color = sev_colors.get(f.severity, "#334155")
        finding_rows.append(
            "<tr>"
            f"<td><span class='sev' style='background:{color}'>{esc(f.severity)}</span></td>"
            f"<td><code>{esc(f.mitre)}</code><br><small>{esc(f.mitre_name)}</small></td>"
            f"<td>{esc(f.title)}</td>"
            f"<td>{esc(f.detail)}</td>"
            f"<td>{esc(f.source_ip)}</td>"
            f"<td>{esc(f.user)}</td>"
            f"<td>{esc(f.count)}</td>"
            "</tr>"
        )
    ip_rows = (
        "".join(f"<tr><td>{esc(ip)}</td><td>{n}</td></tr>" for ip, n in report.top_ips)
        or "<tr><td colspan='2'>(none)</td></tr>"
    )
    user_rows = (
        "".join(f"<tr><td>{esc(u)}</td><td>{n}</td></tr>" for u, n in report.top_users)
        or "<tr><td colspan='2'>(none)</td></tr>"
    )
    blocks = "".join(f"<li><code>{esc(ip)}</code></li>" for ip in report.block_candidates)
    block_section = (
        f"<h2>Suggested block list</h2><ul>{blocks}</ul>"
        "<p class='muted'>Printed for review only — this tool never applies firewall rules.</p>"
        if report.block_candidates
        else ""
    )
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def card(n: object, label: str) -> str:
        return (
            f'<div class="card"><div class="n">{esc(n)}</div>'
            f'<div class="l">{esc(label)}</div></div>'
        )

    cards = "\n".join(
        [
            "    " + card(report.events_parsed, "Events"),
            "    " + card(report.failure_count, "Failures"),
            "    " + card(report.success_count, "Successes"),
            "    " + card(len(report.findings), "Findings"),
            "    " + card(len(report.block_candidates), "Block IPs"),
        ]
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>Auth Log Analysis Report</title>
<style>
  :root {{ font-family: "Segoe UI", system-ui, sans-serif; color: #0f172a; }}
  body {{ margin: 0; background: #f1f5f9; }}
  main {{ max-width: 1100px; margin: 2rem auto; background: #fff;
         padding: 2rem; border-radius: 12px; box-shadow: 0 8px 24px #0f172a22; }}
  h1 {{ margin-top: 0; }}
  h2 {{ border-bottom: 2px solid #e2e8f0; padding-bottom: .3rem; }}
  .cards {{ display: grid; grid-template-columns: repeat(auto-fit,minmax(140px,1fr));
            gap: 1rem; margin: 1.2rem 0 2rem; }}
  .card {{ background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px;
           padding: 1rem; text-align: center; }}
  .card .n {{ font-size: 1.8rem; font-weight: 700; }}
  .card .l {{ color: #64748b; font-size: .85rem; }}
  table {{ width: 100%; border-collapse: collapse; font-size: .92rem; }}
  th, td {{ text-align: left; padding: .55rem .6rem; border-bottom: 1px solid #e2e8f0;
            vertical-align: top; }}
  th {{ background: #0f172a; color: #fff; }}
  tr:nth-child(even) {{ background: #f8fafc; }}
  .sev {{ color: #fff; padding: .15rem .5rem; border-radius: 999px; font-size: .75rem;
          text-transform: uppercase; letter-spacing: .03em; }}
  code {{ background: #e2e8f0; padding: .1rem .35rem; border-radius: 4px; }}
  .muted {{ color: #64748b; font-size: .9rem; }}
  .grid2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; }}
  @media (max-width: 800px) {{ .grid2 {{ grid-template-columns: 1fr; }} }}
</style>
</head>
<body>
<main>
  <h1>Auth Log Analysis Report</h1>
  <p class="muted">Generated {esc(generated)} · files: {esc(", ".join(report.files) or "stdin")}</p>
  <div class="cards">
{cards}
  </div>
  <div class="grid2">
    <div>
      <h2>Top offending IPs</h2>
      <table><tr><th>IP</th><th>Failures</th></tr>{ip_rows}</table>
    </div>
    <div>
      <h2>Top targeted users</h2>
      <table><tr><th>User</th><th>Failures</th></tr>{user_rows}</table>
    </div>
  </div>
  <h2>Findings</h2>
  <table>
    <tr><th>Sev</th><th>MITRE</th><th>Title</th><th>Detail</th><th>IP</th><th>User</th><th>Count</th></tr>
    {"".join(finding_rows) or '<tr><td colspan="7">(none)</td></tr>'}
  </table>
  {block_section}
  <p class="muted">Synthetic / lab use. Sample IPs are RFC 1918 or RFC 5737.</p>
</main>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Demo / CLI
# ---------------------------------------------------------------------------


def sample_dir() -> Path:
    return Path(__file__).resolve().parent / "sample_logs"


def run_demo(output_dir: Path | None = None) -> tuple[AnalysisReport, Path]:
    out = output_dir or (Path(__file__).resolve().parent / "demo_output")
    out.mkdir(parents=True, exist_ok=True)
    auth = sample_dir() / "auth.log"
    events, ignored = parse_files([auth], year=2026)
    # Seed known IPs so alice's later login from 203.0.113.80 is "new"
    # while 10.20.30.40 is known from the first success in-file (detector learns
    # as it goes — first success establishes baseline).
    cfg = DetectConfig(
        fail_threshold=5,
        fail_window_minutes=10,
        spray_user_threshold=5,
        known_ips={"alice": {"10.20.30.40"}},
        off_hours_start=22,
        off_hours_end=6,
    )
    report = analyze(events, files=[str(auth.name)], ignored=ignored, cfg=cfg)
    report.notes.append("demo mode — synthetic sample_logs/auth.log")
    html_path = out / "report.html"
    html_path.write_text(render_html(report), encoding="utf-8")
    json_path = out / "report.json"
    json_path.write_text(json.dumps(report_to_dict(report), indent=2) + "\n", encoding="utf-8")
    csv_path = out / "findings.csv"
    write_csv(report, csv_path)
    report.notes.append(f"HTML report: {html_path}")
    report.notes.append(f"JSON report: {json_path}")
    report.notes.append(f"CSV findings: {csv_path}")
    return report, html_path


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="analyzer",
        description="Analyze Linux auth logs for brute force, spraying, and suspicious logins.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument(
        "files",
        nargs="*",
        type=Path,
        help="auth.log / secure / journalctl export (.gz OK)",
    )
    p.add_argument(
        "--year",
        type=int,
        default=None,
        help="year for syslog timestamps (default: current)",
    )
    p.add_argument("--fail-threshold", type=int, default=5)
    p.add_argument("--fail-window", type=int, default=10, help="minutes")
    p.add_argument("--spray-threshold", type=int, default=5, help="distinct usernames")
    p.add_argument("--spray-window", type=int, default=10, help="minutes")
    p.add_argument("--off-hours", default="22-6", help="e.g. 22-6 or 0-0 to disable")
    p.add_argument("--json", type=Path, metavar="FILE")
    p.add_argument("--csv", type=Path, metavar="FILE")
    p.add_argument("--html", type=Path, metavar="FILE")
    p.add_argument(
        "--blocklist",
        action="store_true",
        help="include suggested fail2ban/iptables lines for high-severity IPs",
    )
    p.add_argument("--demo", action="store_true", help="analyze bundled sample + write HTML")
    p.add_argument(
        "-o",
        "--output-dir",
        type=Path,
        default=None,
        help="with --demo: directory for report.html (default: demo_output/)",
    )
    return p


def _parse_off_hours(text: str) -> tuple[int, int]:
    try:
        a, b = text.split("-", 1)
        start, end = int(a), int(b)
    except ValueError as exc:
        raise AnalyzerError(f"bad --off-hours {text!r}; expected START-END") from exc
    if not (0 <= start <= 23 and 0 <= end <= 23):
        raise AnalyzerError("--off-hours values must be 0-23")
    return start, end


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.demo:
            report, html_path = run_demo(args.output_dir)
            print(format_summary(report))
            print(f"\nWrote HTML report: {html_path}")
            return 0

        if not args.files:
            raise AnalyzerError("pass one or more log files, or use --demo")

        year = args.year or datetime.now().year
        start, end = _parse_off_hours(args.off_hours)
        cfg = DetectConfig(
            fail_threshold=args.fail_threshold,
            fail_window_minutes=args.fail_window,
            spray_user_threshold=args.spray_threshold,
            spray_window_minutes=args.spray_window,
            off_hours_start=start,
            off_hours_end=end,
        )
        events, ignored = parse_files(args.files, year=year)
        if not events:
            raise AnalyzerError("no auth events parsed from the given file(s)")
        report = analyze(
            events,
            files=[str(p) for p in args.files],
            ignored=ignored,
            cfg=cfg,
        )
        print(format_summary(report, include_blocklist=args.blocklist))

        if args.json:
            args.json.write_text(
                json.dumps(report_to_dict(report), indent=2) + "\n", encoding="utf-8"
            )
            print(f"Wrote JSON: {args.json}")
        if args.csv:
            write_csv(report, args.csv)
            print(f"Wrote CSV: {args.csv}")
        if args.html:
            args.html.write_text(render_html(report), encoding="utf-8")
            print(f"Wrote HTML: {args.html}")
        return 0
    except AnalyzerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("error: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
