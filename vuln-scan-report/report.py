#!/usr/bin/env python3
"""Nmap vulnerability scan reporter (Python 3.10+, standard library).

Parse nmap XML (-oX), apply editable risk rules, emit HTML/Markdown/JSON/CSV,
optionally diff two scans, and (outside tests) wrap a safe nmap invocation.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

__version__ = "1.0.0"

SAFE_NETWORKS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
    )
)

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class ReportError(Exception):
    """User-facing error; no traceback; exit code 2."""


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class ScriptOutput:
    id: str
    output: str


@dataclass
class Port:
    protocol: str
    port_id: int
    state: str
    service: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    scripts: list[ScriptOutput] = field(default_factory=list)


@dataclass
class Host:
    ip: str
    status: str
    hostnames: list[str] = field(default_factory=list)
    mac: str = ""
    vendor: str = ""
    os_guess: str = ""
    ports: list[Port] = field(default_factory=list)


@dataclass
class ScanResult:
    path: str
    scanner: str
    args: str
    started: str
    hosts: list[Host] = field(default_factory=list)

    @property
    def hosts_up(self) -> list[Host]:
        return [h for h in self.hosts if h.status == "up"]


@dataclass
class Finding:
    host: str
    hostname: str
    severity: str
    rule_id: str
    title: str
    detail: str
    remediation: str
    port: int | None = None
    protocol: str = ""
    cvss: float | None = None
    cve: str = ""


@dataclass
class DiffReport:
    baseline: str
    current: str
    new_hosts: list[str] = field(default_factory=list)
    gone_hosts: list[str] = field(default_factory=list)
    ports_opened: list[str] = field(default_factory=list)
    ports_closed: list[str] = field(default_factory=list)
    new_findings: list[Finding] = field(default_factory=list)
    resolved_findings: list[Finding] = field(default_factory=list)


@dataclass
class AnalysisReport:
    scan: ScanResult
    findings: list[Finding]
    severity_counts: dict[str, int]
    notes: list[str] = field(default_factory=list)
    diff: DiffReport | None = None


# ---------------------------------------------------------------------------
# XML parsing
# ---------------------------------------------------------------------------


def parse_nmap_xml(path: Path) -> ScanResult:
    """Parse an nmap -oX XML file into structured hosts/ports/scripts."""
    try:
        tree = ET.parse(path)
    except ET.ParseError as exc:
        raise ReportError(f"malformed XML in {path}: {exc}") from None
    except OSError as exc:
        raise ReportError(f"cannot read {path}: {exc}") from None

    root = tree.getroot()
    if root.tag != "nmaprun":
        raise ReportError(f"{path}: expected root <nmaprun>, got <{root.tag}>")

    scan = ScanResult(
        path=str(path),
        scanner=root.attrib.get("scanner", "nmap"),
        args=root.attrib.get("args", ""),
        started=root.attrib.get("startstr", ""),
    )

    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        status = status_el.attrib.get("state", "unknown") if status_el is not None else "unknown"
        ip = ""
        mac = ""
        vendor = ""
        for addr in host_el.findall("address"):
            if addr.attrib.get("addrtype") == "ipv4":
                ip = addr.attrib.get("addr", "")
            elif addr.attrib.get("addrtype") == "mac":
                mac = addr.attrib.get("addr", "")
                vendor = addr.attrib.get("vendor", "")
        if not ip:
            continue
        hostnames = [
            hn.attrib.get("name", "")
            for hn in host_el.findall("./hostnames/hostname")
            if hn.attrib.get("name")
        ]
        os_guess = ""
        osmatch = host_el.find("./os/osmatch")
        if osmatch is not None:
            os_guess = osmatch.attrib.get("name", "")

        ports: list[Port] = []
        for port_el in host_el.findall("./ports/port"):
            state_el = port_el.find("state")
            svc_el = port_el.find("service")
            scripts = [
                ScriptOutput(id=s.attrib.get("id", ""), output=s.attrib.get("output", ""))
                for s in port_el.findall("script")
            ]
            ports.append(
                Port(
                    protocol=port_el.attrib.get("protocol", "tcp"),
                    port_id=int(port_el.attrib.get("portid", "0")),
                    state=state_el.attrib.get("state", "") if state_el is not None else "",
                    service=svc_el.attrib.get("name", "") if svc_el is not None else "",
                    product=svc_el.attrib.get("product", "") if svc_el is not None else "",
                    version=svc_el.attrib.get("version", "") if svc_el is not None else "",
                    extrainfo=svc_el.attrib.get("extrainfo", "") if svc_el is not None else "",
                    scripts=scripts,
                )
            )
        scan.hosts.append(
            Host(
                ip=ip,
                status=status,
                hostnames=hostnames,
                mac=mac,
                vendor=vendor,
                os_guess=os_guess,
                ports=ports,
            )
        )
    return scan


# ---------------------------------------------------------------------------
# Rules / findings
# ---------------------------------------------------------------------------


def load_rules(path: Path | None = None) -> dict:
    rules_path = path or (Path(__file__).resolve().parent / "rules" / "risk_rules.json")
    try:
        return json.loads(rules_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReportError(f"cannot load rules from {rules_path}: {exc}") from None


def severity_from_cvss(score: float, bands: dict) -> str:
    for name in ("critical", "high", "medium", "low"):
        lo, hi = bands[name]
        if lo <= score <= hi:
            return name
    return "info"


def _port_open(port: Port) -> bool:
    return port.state.startswith("open")


def _script_blob(port: Port, script_id: str | None = None) -> str:
    parts = []
    for s in port.scripts:
        if script_id and s.id != script_id:
            continue
        parts.append(s.output)
    return "\n".join(parts)


def _match_service_rule(host: Host, port: Port, rule: dict) -> Finding | None:
    if rule.get("ports") and port.port_id not in rule["ports"]:
        return None
    if rule.get("services"):
        svc = port.service.lower()
        matched = any(s.lower() == svc or s.lower() in svc for s in rule["services"])
        # allow match by port alone when services listed but empty service name
        if not matched and port.service:
            return None
    if rule.get("product_contains"):
        prod = f"{port.product} {port.version}".lower()
        if not any(p.lower() in prod for p in rule["product_contains"]):
            return None
    if (
        rule.get("version_regex")
        and rule.get("product_contains")
        and not re.search(rule["version_regex"], port.version or "")
    ):
        return None
    blob = _script_blob(port, rule.get("script_id"))
    if (
        rule.get("script_id")
        and rule.get("script_contains")
        and not any(needle in blob for needle in rule["script_contains"])
    ):
        return None
    if rule.get("script_contains") and not rule.get("script_id"):
        all_blob = _script_blob(port)
        if not any(needle in all_blob for needle in rule["script_contains"]):
            return None
    if rule.get("script_contains_any_script"):
        all_blob = _script_blob(port).lower()
        if not any(n.lower() in all_blob for n in rule["script_contains_any_script"]):
            return None

    # If rule only has ports/services and no script constraints, require open port
    detail = f"{port.protocol}/{port.port_id} {port.service} {port.product} {port.version}".strip()
    if port.scripts and rule.get("script_id"):
        detail += f" [{rule['script_id']}]"
    return Finding(
        host=host.ip,
        hostname=host.hostnames[0] if host.hostnames else "",
        severity=rule.get("severity", "medium"),
        rule_id=rule["id"],
        title=rule["title"],
        detail=detail,
        remediation=rule.get("remediation", ""),
        port=port.port_id,
        protocol=port.protocol,
    )


_CVE_LINE = re.compile(
    r"(?P<cve>CVE-\d{4}-\d+)\s+(?P<cvss>\d+(?:\.\d+)?)",
    re.IGNORECASE,
)


def extract_vulners_findings(host: Host, port: Port, bands: dict) -> list[Finding]:
    findings: list[Finding] = []
    for script in port.scripts:
        if script.id != "vulners":
            continue
        for m in _CVE_LINE.finditer(script.output):
            cvss = float(m.group("cvss"))
            cve = m.group("cve").upper()
            sev = severity_from_cvss(cvss, bands)
            findings.append(
                Finding(
                    host=host.ip,
                    hostname=host.hostnames[0] if host.hostnames else "",
                    severity=sev,
                    rule_id="VULNERS_CVE",
                    title=f"{cve} (CVSS {cvss})",
                    detail=(
                        f"{port.protocol}/{port.port_id} {port.product} {port.version} "
                        f"— sample CVE from vulners NSE (lab data)"
                    ).strip(),
                    remediation=(
                        f"Patch or upgrade the affected service; review {cve} advisory "
                        "and apply vendor fixes."
                    ),
                    port=port.port_id,
                    protocol=port.protocol,
                    cvss=cvss,
                    cve=cve,
                )
            )
    return findings


def apply_rules(scan: ScanResult, rules: dict | None = None) -> list[Finding]:
    rules = rules or load_rules()
    bands = rules.get("cvss_bands", {})
    findings: list[Finding] = []
    for host in scan.hosts_up:
        for port in host.ports:
            if not _port_open(port):
                continue
            for rule in rules.get("service_rules", []):
                hit = _match_service_rule(host, port, rule)
                if hit:
                    findings.append(hit)
            findings.extend(extract_vulners_findings(host, port, bands))
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.host, f.rule_id, f.cve))
    return findings


def count_severities(findings: list[Finding]) -> dict[str, int]:
    counts = {k: 0 for k in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def analyze(scan: ScanResult, rules: dict | None = None) -> AnalysisReport:
    findings = apply_rules(scan, rules)
    return AnalysisReport(
        scan=scan,
        findings=findings,
        severity_counts=count_severities(findings),
    )


# ---------------------------------------------------------------------------
# Diff
# ---------------------------------------------------------------------------


def _port_key(host_ip: str, port: Port) -> str:
    return f"{host_ip}:{port.protocol}/{port.port_id}"


def _finding_key(f: Finding) -> str:
    return f"{f.host}|{f.rule_id}|{f.cve}|{f.port}|{f.title}"


def diff_scans(
    baseline: ScanResult,
    current: ScanResult,
    *,
    baseline_findings: list[Finding],
    current_findings: list[Finding],
) -> DiffReport:
    base_ips = {h.ip for h in baseline.hosts_up}
    cur_ips = {h.ip for h in current.hosts_up}
    base_ports = {_port_key(h.ip, p) for h in baseline.hosts_up for p in h.ports if _port_open(p)}
    cur_ports = {_port_key(h.ip, p) for h in current.hosts_up for p in h.ports if _port_open(p)}
    base_f = {_finding_key(f): f for f in baseline_findings}
    cur_f = {_finding_key(f): f for f in current_findings}
    return DiffReport(
        baseline=baseline.path,
        current=current.path,
        new_hosts=sorted(cur_ips - base_ips),
        gone_hosts=sorted(base_ips - cur_ips),
        ports_opened=sorted(cur_ports - base_ports),
        ports_closed=sorted(base_ports - cur_ports),
        new_findings=[cur_f[k] for k in sorted(set(cur_f) - set(base_f))],
        resolved_findings=[base_f[k] for k in sorted(set(base_f) - set(cur_f))],
    )


# ---------------------------------------------------------------------------
# Target safety / optional nmap wrapper
# ---------------------------------------------------------------------------


def is_safe_target(spec: str) -> bool:
    """True if IP/CIDR is in private/loopback/documentation ranges."""
    try:
        if "/" in spec:
            net = ipaddress.ip_network(spec, strict=False)
            if not isinstance(net, ipaddress.IPv4Network):
                return False
            return any(net.subnet_of(s) for s in SAFE_NETWORKS)
        addr = ipaddress.ip_address(spec)
        return any(addr in s for s in SAFE_NETWORKS)
    except ValueError:
        return False


def validate_scan_targets(targets: list[str], *, i_own_this: bool) -> None:
    bad = [t for t in targets if not is_safe_target(t)]
    if bad and not i_own_this:
        raise ReportError(
            f"refusing non-private targets {bad}; pass --i-own-this-network "
            "only if you own them or have written authorization"
        )


def run_nmap(
    targets: list[str],
    output: Path,
    *,
    i_own_this: bool = False,
    profile: str = "safe",
    extra_args: list[str] | None = None,
) -> Path:
    """Run nmap and write XML. Not used by tests/CI."""
    if shutil.which("nmap") is None:
        raise ReportError("nmap is not installed or not on PATH")
    validate_scan_targets(targets, i_own_this=i_own_this)
    profiles = {
        "safe": ["-sV", "-T3", "--top-ports", "100"],
        "default": ["-sV", "-sC", "-T3"],
        "vuln": [
            "-sV",
            "-sC",
            "--script",
            "vulners,ssl-enum-ciphers,smb-security-mode,ftp-anon,http-title",
            "-T3",
        ],
    }
    if profile not in profiles:
        raise ReportError(f"unknown profile {profile!r}; choose {', '.join(profiles)}")
    cmd = ["nmap", *profiles[profile], "-oX", str(output), *targets]
    if extra_args:
        cmd[1:1] = extra_args
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as exc:
        raise ReportError(f"nmap exited with status {exc.returncode}") from None
    return output


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def format_summary(report: AnalysisReport) -> str:
    scan = report.scan
    lines = [
        f"Scan file        : {scan.path}",
        f"Nmap args        : {scan.args or '(unknown)'}",
        f"Started          : {scan.started or '(unknown)'}",
        f"Hosts (up)       : {len(scan.hosts_up)} / {len(scan.hosts)}",
        f"Findings         : {len(report.findings)}",
    ]
    for sev in SEVERITY_ORDER:
        lines.append(f"  {sev:<10} : {report.severity_counts.get(sev, 0)}")
    for note in report.notes:
        lines.append(f"Note             : {note}")
    lines.append("")
    lines.append("=== Hosts ===")
    lines.append(f"{'IP':<16} {'Hostname':<28} {'OS':<28} Open ports")
    lines.append("-" * 90)
    for h in scan.hosts_up:
        open_ports = ", ".join(f"{p.port_id}/{p.protocol}" for p in h.ports if _port_open(p))
        hn = h.hostnames[0] if h.hostnames else "-"
        lines.append(f"{h.ip:<16} {hn:<28} {(h.os_guess or '-'):<28} {open_ports or '-'}")
    lines.append("")
    lines.append("=== Findings ===")
    if not report.findings:
        lines.append("(none)")
    else:
        for f in report.findings:
            loc = f"{f.protocol}/{f.port}" if f.port else "-"
            lines.append(f"[{f.severity.upper():8}] {f.host} {loc}  {f.title}")
            lines.append(f"           {f.detail}")
            lines.append(f"           Fix: {f.remediation}")
    if report.diff:
        d = report.diff
        lines.append("")
        lines.append("=== Diff ===")
        lines.append(f"Baseline : {d.baseline}")
        lines.append(f"Current  : {d.current}")
        lines.append(f"New hosts     : {', '.join(d.new_hosts) or '(none)'}")
        lines.append(f"Gone hosts    : {', '.join(d.gone_hosts) or '(none)'}")
        lines.append(f"Ports opened  : {', '.join(d.ports_opened) or '(none)'}")
        lines.append(f"Ports closed  : {', '.join(d.ports_closed) or '(none)'}")
        lines.append(f"New findings  : {len(d.new_findings)}")
        lines.append(f"Resolved      : {len(d.resolved_findings)}")
        for f in d.new_findings[:8]:
            lines.append(f"  + [{f.severity}] {f.host} {f.title}")
        for f in d.resolved_findings[:8]:
            lines.append(f"  - [{f.severity}] {f.host} {f.title}")
    return "\n".join(lines)


def report_to_dict(report: AnalysisReport) -> dict:
    payload: dict = {
        "scan": {
            "path": report.scan.path,
            "args": report.scan.args,
            "started": report.scan.started,
            "hosts_up": len(report.scan.hosts_up),
            "hosts_total": len(report.scan.hosts),
        },
        "severity_counts": report.severity_counts,
        "findings": [asdict(f) for f in report.findings],
        "hosts": [
            {
                "ip": h.ip,
                "status": h.status,
                "hostnames": h.hostnames,
                "os_guess": h.os_guess,
                "ports": [
                    {
                        "protocol": p.protocol,
                        "port": p.port_id,
                        "state": p.state,
                        "service": p.service,
                        "product": p.product,
                        "version": p.version,
                        "scripts": [asdict(s) for s in p.scripts],
                    }
                    for p in h.ports
                ],
            }
            for h in report.scan.hosts
        ],
        "notes": report.notes,
    }
    if report.diff:
        payload["diff"] = {
            "baseline": report.diff.baseline,
            "current": report.diff.current,
            "new_hosts": report.diff.new_hosts,
            "gone_hosts": report.diff.gone_hosts,
            "ports_opened": report.diff.ports_opened,
            "ports_closed": report.diff.ports_closed,
            "new_findings": [asdict(f) for f in report.diff.new_findings],
            "resolved_findings": [asdict(f) for f in report.diff.resolved_findings],
        }
    return payload


def write_csv(report: AnalysisReport, path: Path) -> None:
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(
            [
                "severity",
                "host",
                "hostname",
                "port",
                "protocol",
                "rule_id",
                "cve",
                "cvss",
                "title",
                "detail",
                "remediation",
            ]
        )
        for f in report.findings:
            writer.writerow(
                [
                    f.severity,
                    f.host,
                    f.hostname,
                    f.port or "",
                    f.protocol,
                    f.rule_id,
                    f.cve,
                    f.cvss if f.cvss is not None else "",
                    f.title,
                    f.detail,
                    f.remediation,
                ]
            )


def render_markdown(report: AnalysisReport) -> str:
    lines = [
        "# Vulnerability Scan Report",
        "",
        f"- **Scan:** `{report.scan.path}`",
        f"- **Args:** `{report.scan.args or 'n/a'}`",
        f"- **Hosts up:** {len(report.scan.hosts_up)} / {len(report.scan.hosts)}",
        f"- **Findings:** {len(report.findings)}",
        "",
        "## Severity summary",
        "",
        "| Severity | Count |",
        "|----------|------:|",
    ]
    for sev in SEVERITY_ORDER:
        lines.append(f"| {sev} | {report.severity_counts.get(sev, 0)} |")
    lines += [
        "",
        "## Hosts",
        "",
        "| IP | Hostname | OS | Open ports |",
        "|----|----------|----|------------|",
    ]
    for h in report.scan.hosts_up:
        ports = ", ".join(f"{p.port_id}/{p.protocol}" for p in h.ports if _port_open(p))
        hn = h.hostnames[0] if h.hostnames else "-"
        lines.append(f"| {h.ip} | {hn} | {h.os_guess or '-'} | {ports or '-'} |")
    lines += ["", "## Findings", ""]
    for f in report.findings:
        loc = f"{f.protocol}/{f.port}" if f.port else "-"
        lines.append(f"### [{f.severity.upper()}] {f.title}")
        lines.append(f"- Host: `{f.host}` ({f.hostname or 'n/a'}) `{loc}`")
        if f.cve:
            lines.append(f"- CVE: `{f.cve}` CVSS {f.cvss}")
        lines.append(f"- Detail: {f.detail}")
        lines.append(f"- Remediation: {f.remediation}")
        lines.append("")
    if report.diff:
        d = report.diff
        lines += [
            "## Diff",
            f"- New hosts: {', '.join(d.new_hosts) or 'none'}",
            f"- Gone hosts: {', '.join(d.gone_hosts) or 'none'}",
            f"- Ports opened: {', '.join(d.ports_opened) or 'none'}",
            f"- Ports closed: {', '.join(d.ports_closed) or 'none'}",
            f"- New findings: {len(d.new_findings)}; resolved: {len(d.resolved_findings)}",
            "",
        ]
    lines.append("_Synthetic lab sample. CVE IDs attached for demonstration only._")
    return "\n".join(lines) + "\n"


def render_html(report: AnalysisReport) -> str:
    def esc(s: object) -> str:
        return (
            str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )

    sev_colors = {
        "critical": "#7f1d1d",
        "high": "#b91c1c",
        "medium": "#c2410c",
        "low": "#a16207",
        "info": "#334155",
    }

    def card(n: object, label: str) -> str:
        return (
            f'<div class="card"><div class="n">{esc(n)}</div>'
            f'<div class="l">{esc(label)}</div></div>'
        )

    cards = "\n".join(
        [
            "    " + card(len(report.scan.hosts_up), "Hosts up"),
            "    " + card(len(report.findings), "Findings"),
            *[
                "    " + card(report.severity_counts.get(s, 0), s.capitalize())
                for s in ("critical", "high", "medium", "low")
            ],
        ]
    )
    host_rows = []
    for h in report.scan.hosts_up:
        ports = ", ".join(f"{p.port_id}/{p.protocol}" for p in h.ports if _port_open(p))
        host_rows.append(
            "<tr>"
            f"<td>{esc(h.ip)}</td>"
            f"<td>{esc(h.hostnames[0] if h.hostnames else '-')}</td>"
            f"<td>{esc(h.os_guess or '-')}</td>"
            f"<td>{esc(ports or '-')}</td>"
            "</tr>"
        )
    finding_rows = []
    for f in report.findings:
        color = sev_colors.get(f.severity, "#334155")
        loc = f"{f.protocol}/{f.port}" if f.port else "-"
        finding_rows.append(
            "<tr>"
            f"<td><span class='sev' style='background:{color}'>{esc(f.severity)}</span></td>"
            f"<td>{esc(f.host)}<br><small>{esc(f.hostname)}</small></td>"
            f"<td>{esc(loc)}</td>"
            f"<td>{esc(f.title)}"
            + (f"<br><code>{esc(f.cve)}</code> CVSS {esc(f.cvss)}" if f.cve else "")
            + f"<br><small>{esc(f.detail)}</small></td>"
            f"<td>{esc(f.remediation)}</td>"
            "</tr>"
        )
    diff_html = ""
    if report.diff:
        d = report.diff
        diff_html = f"""
  <h2>Diff vs baseline</h2>
  <ul>
    <li>New hosts: {esc(", ".join(d.new_hosts) or "none")}</li>
    <li>Gone hosts: {esc(", ".join(d.gone_hosts) or "none")}</li>
    <li>Ports opened: {esc(", ".join(d.ports_opened) or "none")}</li>
    <li>Ports closed: {esc(", ".join(d.ports_closed) or "none")}</li>
    <li>New findings: {len(d.new_findings)}; resolved: {len(d.resolved_findings)}</li>
  </ul>
"""
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>Vulnerability Scan Report</title>
<style>
  body {{
    margin: 0; background: #f1f5f9; color: #0f172a;
    font-family: "Segoe UI", system-ui, sans-serif;
  }}
  main {{
    max-width: 1100px; margin: 2rem auto; background: #fff;
    padding: 2rem; border-radius: 12px; box-shadow: 0 8px 24px #0f172a22;
  }}
  h1 {{ margin-top: 0; }}
  h2 {{ border-bottom: 2px solid #e2e8f0; padding-bottom: .3rem; }}
  .cards {{
    display: grid; gap: 1rem; margin: 1rem 0 1.5rem;
    grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
  }}
  .card {{
    background: #f8fafc; border: 1px solid #e2e8f0;
    border-radius: 8px; padding: .9rem; text-align: center;
  }}
  .card .n {{ font-size: 1.6rem; font-weight: 700; }}
  .card .l {{ color: #64748b; font-size: .8rem; }}
  table {{ width: 100%; border-collapse: collapse; font-size: .9rem; }}
  th, td {{
    text-align: left; padding: .5rem .55rem;
    border-bottom: 1px solid #e2e8f0; vertical-align: top;
  }}
  th {{ background: #0f172a; color: #fff; }}
  tr:nth-child(even) {{ background: #f8fafc; }}
  .sev {{
    color: #fff; padding: .12rem .45rem; border-radius: 999px;
    font-size: .72rem; text-transform: uppercase;
  }}
  code {{ background: #e2e8f0; padding: .1rem .3rem; border-radius: 4px; }}
  .muted {{ color: #64748b; font-size: .9rem; }}
  .banner {{
    background: #eff6ff; border-left: 4px solid #1d4ed8;
    padding: .75rem 1rem; margin-bottom: 1rem;
  }}
</style>
</head>
<body>
<main>
  <h1>Vulnerability Scan Report</h1>
  <p class="muted">Generated {esc(generated)}</p>
  <div class="banner">
    Synthetic lab sample (RFC 1918 / RFC 5737). CVE IDs are well-known examples
    attached for demonstration — not evidence of a real compromise.
  </div>
  <p class="muted">Scan: <code>{esc(report.scan.path)}</code><br/>
  Args: <code>{esc(report.scan.args or "n/a")}</code></p>
  <div class="cards">
{cards}
  </div>
  <h2>Hosts</h2>
  <table>
    <tr><th>IP</th><th>Hostname</th><th>OS</th><th>Open ports</th></tr>
    {"".join(host_rows) or "<tr><td colspan='4'>(none)</td></tr>"}
  </table>
  <h2>Findings</h2>
  <table>
    <tr><th>Sev</th><th>Host</th><th>Port</th><th>Finding</th><th>Remediation</th></tr>
    {"".join(finding_rows) or "<tr><td colspan='5'>(none)</td></tr>"}
  </table>
  {diff_html}
</main>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Demo / CLI
# ---------------------------------------------------------------------------


def sample_dir() -> Path:
    return Path(__file__).resolve().parent / "sample_scans"


def run_demo(output_dir: Path | None = None) -> tuple[AnalysisReport, Path]:
    out = output_dir or (Path(__file__).resolve().parent / "demo_output")
    out.mkdir(parents=True, exist_ok=True)
    s1 = parse_nmap_xml(sample_dir() / "lab_scan1.xml")
    s2 = parse_nmap_xml(sample_dir() / "lab_scan2.xml")
    r1 = analyze(s1)
    r2 = analyze(s2)
    r2.diff = diff_scans(s1, s2, baseline_findings=r1.findings, current_findings=r2.findings)
    r2.notes.append("demo — baseline lab_scan1.xml vs current lab_scan2.xml")
    html_path = out / "report.html"
    html_path.write_text(render_html(r2), encoding="utf-8")
    (out / "report.md").write_text(render_markdown(r2), encoding="utf-8")
    (out / "report.json").write_text(
        json.dumps(report_to_dict(r2), indent=2) + "\n", encoding="utf-8"
    )
    write_csv(r2, out / "findings.csv")
    # Also write baseline-only summary artifact
    (out / "baseline_summary.txt").write_text(format_summary(r1) + "\n", encoding="utf-8")
    r2.notes.append(f"HTML: {html_path}")
    r2.notes.append(f"Markdown: {out / 'report.md'}")
    return r2, html_path


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="report",
        description="Parse nmap XML, score risks, and write HTML/Markdown/JSON/CSV reports.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--rules", type=Path, default=None, help="risk_rules.json path")
    common.add_argument("--json", type=Path, metavar="FILE")
    common.add_argument("--csv", type=Path, metavar="FILE")
    common.add_argument("--html", type=Path, metavar="FILE")
    common.add_argument("--md", type=Path, metavar="FILE", help="Markdown report")

    pa = sub.add_parser("analyze", parents=[common], help="analyze an nmap XML file")
    pa.add_argument("xml", type=Path, help="nmap -oX file")
    pa.add_argument("--diff", type=Path, metavar="BASELINE_XML", help="diff against baseline")

    demo = sub.add_parser("demo", help="analyze sample scans + write reports")
    demo.add_argument("-o", "--output-dir", type=Path, default=None)

    sc = sub.add_parser("scan", help="run nmap (requires nmap; not used in tests)")
    sc.add_argument("targets", nargs="+", help="IP/CIDR targets")
    sc.add_argument("-o", "--output", type=Path, required=True, help="output XML path")
    sc.add_argument(
        "--profile",
        choices=["safe", "default", "vuln"],
        default="safe",
        help="nmap argument profile (default: safe)",
    )
    sc.add_argument(
        "--i-own-this-network",
        action="store_true",
        help="allow non-private targets (authorized use only)",
    )
    sc.add_argument(
        "--analyze",
        action="store_true",
        help="analyze the XML after the scan finishes",
    )
    return p


def _emit_files(report: AnalysisReport, args: argparse.Namespace) -> None:
    if getattr(args, "json", None):
        args.json.write_text(json.dumps(report_to_dict(report), indent=2) + "\n", encoding="utf-8")
        print(f"Wrote JSON: {args.json}")
    if getattr(args, "csv", None):
        write_csv(report, args.csv)
        print(f"Wrote CSV: {args.csv}")
    if getattr(args, "html", None):
        args.html.write_text(render_html(report), encoding="utf-8")
        print(f"Wrote HTML: {args.html}")
    if getattr(args, "md", None):
        args.md.write_text(render_markdown(report), encoding="utf-8")
        print(f"Wrote Markdown: {args.md}")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "demo":
            report, html_path = run_demo(args.output_dir)
            print(format_summary(report))
            print(f"\nWrote HTML report: {html_path}")
            return 0

        if args.command == "scan":
            out = run_nmap(
                args.targets,
                args.output,
                i_own_this=args.i_own_this_network,
                profile=args.profile,
            )
            print(f"Wrote nmap XML: {out}")
            if args.analyze:
                report = analyze(parse_nmap_xml(out))
                print(format_summary(report))
            return 0

        if args.command == "analyze":
            rules = load_rules(args.rules) if args.rules else load_rules()
            scan = parse_nmap_xml(args.xml)
            report = analyze(scan, rules)
            if args.diff:
                base = parse_nmap_xml(args.diff)
                base_rep = analyze(base, rules)
                report.diff = diff_scans(
                    base,
                    scan,
                    baseline_findings=base_rep.findings,
                    current_findings=report.findings,
                )
            print(format_summary(report))
            _emit_files(report, args)
            return 0

        raise ReportError(f"unknown command {args.command}")
    except ReportError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("error: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
