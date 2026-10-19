"""Tests for vuln-scan-report (parser, rules, severity, diff, safety, bad XML)."""

from __future__ import annotations

from pathlib import Path

import pytest

import report as rp

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "sample_scans"
SCAN1 = SAMPLES / "lab_scan1.xml"
SCAN2 = SAMPLES / "lab_scan2.xml"


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def test_parse_lab_scan1_hosts_and_ports():
    scan = rp.parse_nmap_xml(SCAN1)
    assert scan.scanner == "nmap"
    assert "192.168.10.0/28" in scan.args
    ups = {h.ip: h for h in scan.hosts_up}
    assert set(ups) == {
        "192.168.10.1",
        "192.168.10.10",
        "192.168.10.20",
        "192.168.10.30",
        "192.168.10.40",
    }
    win = ups["192.168.10.10"]
    assert "win-dc01.lab.local" in win.hostnames
    assert "Windows" in win.os_guess
    open_ports = {(p.protocol, p.port_id) for p in win.ports if p.state.startswith("open")}
    assert ("tcp", 445) in open_ports
    assert ("tcp", 3389) in open_ports
    smb = next(p for p in win.ports if p.port_id == 445)
    assert any(s.id == "smb-security-mode" for s in smb.scripts)


def test_parse_scripts_vulners_and_os():
    scan = rp.parse_nmap_xml(SCAN1)
    web = next(h for h in scan.hosts if h.ip == "192.168.10.20")
    ssh = next(p for p in web.ports if p.port_id == 22)
    assert ssh.product == "OpenSSH"
    assert any(s.id == "vulners" for s in ssh.scripts)
    assert "CVE-2016-10009" in next(s.output for s in ssh.scripts if s.id == "vulners")


def test_parse_down_host_counted():
    scan = rp.parse_nmap_xml(SCAN1)
    assert len(scan.hosts) > len(scan.hosts_up)
    downs = [h for h in scan.hosts if h.status != "up"]
    assert downs


# ---------------------------------------------------------------------------
# Bad / malformed XML
# ---------------------------------------------------------------------------


def test_malformed_xml_raises(tmp_path: Path):
    bad = tmp_path / "bad.xml"
    bad.write_text("<nmaprun><host></nmaprun>", encoding="utf-8")
    with pytest.raises(rp.ReportError, match="malformed XML"):
        rp.parse_nmap_xml(bad)


def test_wrong_root_raises(tmp_path: Path):
    bad = tmp_path / "wrong.xml"
    bad.write_text("<scan><host/></scan>", encoding="utf-8")
    with pytest.raises(rp.ReportError, match="nmaprun"):
        rp.parse_nmap_xml(bad)


def test_missing_file_raises(tmp_path: Path):
    with pytest.raises(rp.ReportError, match="cannot read"):
        rp.parse_nmap_xml(tmp_path / "nope.xml")


# ---------------------------------------------------------------------------
# Rules / findings
# ---------------------------------------------------------------------------


def test_rules_flag_telnet_rdp_ftp_anon_smb():
    findings = rp.apply_rules(rp.parse_nmap_xml(SCAN1))
    ids = {f.rule_id for f in findings}
    assert "TELNET_OPEN" in ids
    assert "RDP_EXPOSED" in ids
    assert "FTP_ANON" in ids
    assert "SMB_SIGNING_NOT_REQUIRED" in ids
    assert "SMBv1_HINT" in ids
    assert "SNMP_EXPOSED" in ids
    assert "WEAK_TLS" in ids
    assert "HTTP_ADMIN_TITLE" in ids
    assert "OLD_OPENSSH" in ids


def test_vulners_cves_with_cvss():
    findings = rp.apply_rules(rp.parse_nmap_xml(SCAN1))
    cves = [f for f in findings if f.rule_id == "VULNERS_CVE"]
    assert cves
    by_cve = {f.cve: f for f in cves}
    assert "CVE-2016-10009" in by_cve
    assert by_cve["CVE-2016-10009"].cvss == 7.5
    assert by_cve["CVE-2016-10009"].severity == "high"
    assert by_cve["CVE-2018-15473"].severity == "medium"
    assert all(f.remediation for f in cves)


def test_each_finding_has_remediation_and_severity():
    findings = rp.apply_rules(rp.parse_nmap_xml(SCAN2))
    assert findings
    for f in findings:
        assert f.severity in rp.SEVERITY_ORDER
        assert f.remediation
        assert f.title
        assert f.host.startswith("192.168.")


def test_mysql_only_in_scan2():
    f1 = {f.rule_id for f in rp.apply_rules(rp.parse_nmap_xml(SCAN1))}
    f2 = {f.rule_id for f in rp.apply_rules(rp.parse_nmap_xml(SCAN2))}
    assert "MYSQL_EXPOSED" not in f1
    assert "MYSQL_EXPOSED" in f2


# ---------------------------------------------------------------------------
# Severity banding
# ---------------------------------------------------------------------------


def test_severity_from_cvss_bands():
    bands = rp.load_rules()["cvss_bands"]
    assert rp.severity_from_cvss(9.8, bands) == "critical"
    assert rp.severity_from_cvss(9.0, bands) == "critical"
    assert rp.severity_from_cvss(8.9, bands) == "high"
    assert rp.severity_from_cvss(7.0, bands) == "high"
    assert rp.severity_from_cvss(5.0, bands) == "medium"
    assert rp.severity_from_cvss(4.0, bands) == "medium"
    assert rp.severity_from_cvss(3.9, bands) == "low"
    assert rp.severity_from_cvss(0.1, bands) == "low"
    assert rp.severity_from_cvss(0.0, bands) == "info"


# ---------------------------------------------------------------------------
# Diff
# ---------------------------------------------------------------------------


def test_diff_new_host_ports_and_findings():
    s1 = rp.parse_nmap_xml(SCAN1)
    s2 = rp.parse_nmap_xml(SCAN2)
    r1 = rp.analyze(s1)
    r2 = rp.analyze(s2)
    d = rp.diff_scans(s1, s2, baseline_findings=r1.findings, current_findings=r2.findings)
    assert "192.168.10.60" in d.new_hosts
    assert any("3306" in p for p in d.ports_opened)
    assert any(p == "192.168.10.1:tcp/23" for p in d.ports_closed)
    assert d.new_findings
    assert d.resolved_findings
    assert any("Telnet" in f.title for f in d.resolved_findings)


# ---------------------------------------------------------------------------
# Target safety (nmap wrapper never runs in tests)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "spec,ok",
    [
        ("192.168.10.1", True),
        ("10.0.0.5", True),
        ("172.16.5.1", True),
        ("127.0.0.1", True),
        ("192.0.2.10", True),
        ("198.51.100.1", True),
        ("203.0.113.50", True),
        ("192.168.10.0/28", True),
        ("10.0.0.0/8", True),
        ("8.8.8.8", False),
        ("1.1.1.1", False),
        ("8.8.8.0/24", False),
        ("not-an-ip", False),
        ("example.com", False),
    ],
)
def test_is_safe_target(spec: str, ok: bool):
    assert rp.is_safe_target(spec) is ok


def test_validate_scan_targets_refuses_public():
    with pytest.raises(rp.ReportError, match="refusing non-private"):
        rp.validate_scan_targets(["8.8.8.8"], i_own_this=False)
    rp.validate_scan_targets(["8.8.8.8"], i_own_this=True)  # allowed with flag


def test_run_nmap_not_invoked_without_binary(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setattr(rp.shutil, "which", lambda _: None)
    with pytest.raises(rp.ReportError, match="nmap is not installed"):
        rp.run_nmap(["192.168.1.1"], tmp_path / "out.xml")


def test_run_nmap_refuses_public_before_exec(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setattr(rp.shutil, "which", lambda _: "/usr/bin/nmap")
    called = []

    def fake_run(*a, **k):
        called.append(a)
        raise AssertionError("nmap must not run for public targets")

    monkeypatch.setattr(rp.subprocess, "run", fake_run)
    with pytest.raises(rp.ReportError, match="refusing non-private"):
        rp.run_nmap(["1.2.3.4"], tmp_path / "out.xml")
    assert called == []


# ---------------------------------------------------------------------------
# Reports / demo smoke
# ---------------------------------------------------------------------------


def test_render_html_and_markdown_contain_summary():
    report = rp.analyze(rp.parse_nmap_xml(SCAN2))
    html = rp.render_html(report)
    md = rp.render_markdown(report)
    assert "Vulnerability Scan Report" in html
    assert "<style>" in html
    assert "Findings" in md
    assert "Severity summary" in md


def test_demo_writes_artifacts(tmp_path: Path):
    report, html_path = rp.run_demo(tmp_path)
    assert html_path.is_file()
    assert (tmp_path / "report.md").is_file()
    assert (tmp_path / "report.json").is_file()
    assert (tmp_path / "findings.csv").is_file()
    assert report.diff is not None
    assert report.findings


def test_cli_analyze_exit_zero(capsys: pytest.CaptureFixture[str]):
    code = rp.main(["analyze", str(SCAN1)])
    assert code == 0
    out = capsys.readouterr().out
    assert "Findings" in out
    assert "192.168.10.10" in out


def test_cli_demo_exit_zero(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    code = rp.main(["demo", "-o", str(tmp_path)])
    assert code == 0
    assert "Diff" in capsys.readouterr().out
