"""Tests for the auth log analyzer. Offline — uses bundled synthetic samples."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import analyzer as az

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "sample_logs"


# ---------------------------------------------------------------- parsing


class TestParseLines:
    def test_accepted_password(self):
        line = (
            "Oct 18 08:15:03 lab sshd[10]: Accepted password for bob "
            "from 192.168.10.50 port 49821 ssh2"
        )
        ev = az.parse_line(line, year=2026)
        assert ev is not None
        assert ev.event_type == "ssh_accepted"
        assert ev.user == "bob" and ev.source_ip == "192.168.10.50"
        assert ev.method == "password" and ev.success is True
        assert ev.timestamp == datetime(2026, 10, 18, 8, 15, 3)

    def test_accepted_publickey(self):
        line = (
            "Oct 18 08:01:12 lab sshd[1]: Accepted publickey for alice "
            "from 10.20.30.40 port 51234 ssh2: RSA SHA256:ABC"
        )
        ev = az.parse_line(line, year=2026)
        assert ev is not None and ev.method == "publickey"

    def test_failed_and_invalid(self):
        fail = az.parse_line(
            "Oct 18 11:00:00 lab sshd[1]: Failed password for root "
            "from 198.51.100.20 port 41001 ssh2",
            year=2026,
        )
        inv = az.parse_line(
            "Oct 18 10:12:01 lab sshd[1]: Invalid user oracle from 203.0.113.50 port 40001",
            year=2026,
        )
        fail_inv = az.parse_line(
            "Oct 18 10:12:02 lab sshd[1]: Failed password for invalid user oracle "
            "from 203.0.113.50 port 40001 ssh2",
            year=2026,
        )
        assert fail and fail.event_type == "ssh_failed" and fail.user == "root"
        assert inv and inv.invalid_user and inv.event_type == "ssh_invalid_user"
        assert fail_inv and fail_inv.invalid_user

    def test_connection_closed(self):
        ev = az.parse_line(
            "Oct 18 11:00:40 lab sshd[1]: Connection closed by authenticating user "
            "root 198.51.100.20 port 41008 [preauth]",
            year=2026,
        )
        assert ev and ev.event_type == "ssh_closed"

    def test_pam_auth_failure(self):
        ev = az.parse_line(
            "Oct 19 02:10:00 lab sshd[1]: pam_unix(sshd:auth): authentication failure; "
            "logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.50 user=alice",
            year=2026,
        )
        assert ev and ev.event_type == "ssh_auth_failure"
        assert ev.source_ip == "203.0.113.50" and ev.user == "alice"

    def test_sudo_events(self):
        ok = az.parse_line(
            "Oct 18 08:05:44 lab sudo:     alice : TTY=pts/0 ; PWD=/home/alice ; "
            "USER=root ; COMMAND=/usr/bin/systemctl status ssh",
            year=2026,
        )
        nosudo = az.parse_line(
            "Oct 18 14:22:11 lab sudo:      bob : user NOT in sudoers ; TTY=pts/2 ; "
            "PWD=/home/bob ; USER=root ; COMMAND=/bin/bash",
            year=2026,
        )
        badpw = az.parse_line(
            "Oct 18 14:22:30 lab sudo:      bob : 3 incorrect password attempts ; "
            "TTY=pts/2 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/apt update",
            year=2026,
        )
        assert ok and ok.event_type == "sudo_command" and ok.success
        assert nosudo and nosudo.event_type == "sudo_not_in_sudoers"
        assert badpw and badpw.event_type == "sudo_bad_password"

    def test_iso_journalctl(self):
        line = (
            "2026-10-18T11:00:00+00:00 lab-jump sshd[3001]: Failed password for root "
            "from 198.51.100.20 port 53001 ssh2"
        )
        ev = az.parse_line(line, year=2026)
        assert ev and ev.timestamp == datetime(2026, 10, 18, 11, 0, 0)
        assert ev.source_ip == "198.51.100.20"

    def test_noise_ignored(self):
        assert (
            az.parse_line(
                "Oct 18 09:00:01 lab CRON[1]: pam_unix(cron:session): "
                "session opened for user root by (uid=0)",
                year=2026,
            )
            is None
        )
        assert az.parse_line("", year=2026) is None
        assert az.parse_line("# comment", year=2026) is None

    def test_year_matters(self):
        line = "Oct 18 08:00:00 lab sshd[1]: Accepted password for a from 10.0.0.1 port 1 ssh2"
        assert az.parse_line(line, year=2025).timestamp.year == 2025
        assert az.parse_line(line, year=2026).timestamp.year == 2026


class TestFiles:
    def test_auth_log_sample(self):
        events, ignored = az.parse_files([SAMPLES / "auth.log"], year=2026)
        assert len(events) >= 40
        assert ignored >= 1
        assert any(e.event_type == "ssh_accepted" for e in events)

    def test_secure_sample(self):
        events, _ = az.parse_files([SAMPLES / "secure"], year=2026)
        assert any(e.host == "lab-rhel" for e in events)

    def test_journal_sample(self):
        events, _ = az.parse_files([SAMPLES / "journalctl_ssh_short_iso.txt"], year=2026)
        assert len(events) == 6

    def test_gzip(self):
        events, _ = az.parse_files([SAMPLES / "auth.log.1.gz"], year=2026)
        plain, _ = az.parse_files([SAMPLES / "auth.log"], year=2026)
        assert len(events) == len(plain)


# ---------------------------------------------------------------- detections


def _events_from(lines: list[str], year: int = 2026):
    evs, _ = az.parse_lines(lines, year=year)
    return evs


class TestDetections:
    def test_brute_force_window(self):
        lines = [
            f"Oct 18 11:00:{i:02d} lab sshd[{i}]: Failed password for root "
            f"from 198.51.100.20 port {41000 + i} ssh2"
            for i in range(0, 50, 5)  # 10 failures over ~45s
        ]
        findings = az.detect(_events_from(lines), az.DetectConfig(fail_threshold=5))
        bf = [f for f in findings if f.title == "SSH brute force"]
        assert bf and bf[0].source_ip == "198.51.100.20"
        assert bf[0].mitre == "T1110.001"
        assert bf[0].severity == "high"

    def test_brute_force_outside_window(self):
        lines = [
            "Oct 18 11:00:00 lab sshd[1]: Failed password for root from 198.51.100.20 port 1 ssh2",
            "Oct 18 11:00:01 lab sshd[2]: Failed password for root from 198.51.100.20 port 2 ssh2",
            "Oct 18 12:00:00 lab sshd[3]: Failed password for root from 198.51.100.20 port 3 ssh2",
            "Oct 18 12:00:01 lab sshd[4]: Failed password for root from 198.51.100.20 port 4 ssh2",
            "Oct 18 13:00:00 lab sshd[5]: Failed password for root from 198.51.100.20 port 5 ssh2",
        ]
        findings = az.detect(
            _events_from(lines),
            az.DetectConfig(fail_threshold=5, fail_window_minutes=10),
        )
        assert not any(f.title == "SSH brute force" for f in findings)

    def test_password_spray(self):
        users = ["alice", "bob", "carol", "dave", "erin", "frank"]
        lines = [
            f"Oct 18 10:00:{i:02d} lab sshd[{i}]: Failed password for {u} "
            f"from 203.0.113.50 port {40000 + i} ssh2"
            for i, u in enumerate(users)
        ]
        findings = az.detect(
            _events_from(lines),
            az.DetectConfig(spray_user_threshold=5, fail_threshold=99),
        )
        spray = [f for f in findings if f.title == "Password spraying"]
        assert spray and spray[0].mitre == "T1110.003"

    def test_success_after_failures(self):
        lines = [
            f"Oct 18 11:30:{i:02d} lab sshd[{i}]: Failed password for alice "
            f"from 203.0.113.80 port {i} ssh2"
            for i in range(5)
        ] + [
            "Oct 18 11:30:50 lab sshd[9]: Accepted password for alice from 203.0.113.80 port 9 ssh2"
        ]
        findings = az.detect(_events_from(lines), az.DetectConfig(fail_threshold=5))
        hit = [f for f in findings if "Successful login after failures" in f.title]
        assert hit and hit[0].mitre == "T1078"

    def test_new_ip(self):
        lines = [
            "Oct 18 08:00:00 lab sshd[1]: Accepted publickey for alice "
            "from 10.20.30.40 port 1 ssh2",
            "Oct 18 09:00:00 lab sshd[2]: Accepted password for alice "
            "from 203.0.113.80 port 2 ssh2",
        ]
        findings = az.detect(
            _events_from(lines),
            az.DetectConfig(known_ips={"alice": {"10.20.30.40"}}, fail_threshold=99),
        )
        assert any(f.title == "Login from new IP" for f in findings)

    def test_off_hours(self):
        lines = [
            "Oct 18 23:15:00 lab sshd[1]: Accepted password for alice from 10.20.30.40 port 1 ssh2",
        ]
        findings = az.detect(
            _events_from(lines),
            az.DetectConfig(off_hours_start=22, off_hours_end=6, fail_threshold=99),
        )
        assert any(f.title == "Off-hours login" for f in findings)

    def test_root_attempts(self):
        lines = [
            f"Oct 18 11:00:0{i} lab sshd[{i}]: Failed password for root "
            f"from 198.51.100.20 port {i} ssh2"
            for i in range(3)
        ]
        findings = az.detect(_events_from(lines), az.DetectConfig(fail_threshold=99))
        assert any("Root SSH" in f.title for f in findings)

    def test_sample_auth_produces_high_findings(self):
        events, ignored = az.parse_files([SAMPLES / "auth.log"], year=2026)
        report = az.analyze(
            events,
            files=["auth.log"],
            ignored=ignored,
            cfg=az.DetectConfig(known_ips={"alice": {"10.20.30.40"}}),
        )
        titles = {f.title for f in report.findings}
        assert "SSH brute force" in titles
        assert "Password spraying" in titles
        assert "Successful login after failures" in titles
        assert report.block_candidates  # high-sev IPs


# ---------------------------------------------------------------- output / CLI


class TestOutputCli:
    def test_html_and_json(self, tmp_path):
        events, ignored = az.parse_files([SAMPLES / "auth.log"], year=2026)
        report = az.analyze(events, files=["auth.log"], ignored=ignored)
        html = az.render_html(report)
        assert "Auth Log Analysis Report" in html
        assert "T1110" in html
        assert "<style>" in html  # inline CSS
        data = az.report_to_dict(report)
        assert "findings" in data
        csv_path = tmp_path / "f.csv"
        az.write_csv(report, csv_path)
        assert "severity,mitre" in csv_path.read_text().splitlines()[0]

    def test_demo_cli(self, tmp_path, capsys):
        assert az.main(["--demo", "-o", str(tmp_path)]) == 0
        out = capsys.readouterr().out
        assert "SSH brute force" in out
        assert (tmp_path / "report.html").is_file()
        assert (tmp_path / "report.json").is_file()

    def test_analyze_file_cli(self, tmp_path, capsys):
        html = tmp_path / "out.html"
        js = tmp_path / "out.json"
        rc = az.main(
            [
                str(SAMPLES / "auth.log"),
                "--year",
                "2026",
                "--html",
                str(html),
                "--json",
                str(js),
                "--blocklist",
            ]
        )
        assert rc == 0
        assert "iptables" in capsys.readouterr().out
        assert html.is_file() and json.loads(js.read_text())["events_parsed"] > 0

    def test_missing_file(self, capsys):
        assert az.main(["nope.log"]) == 2
        assert "error:" in capsys.readouterr().err

    def test_no_files(self, capsys):
        assert az.main([]) == 2

    def test_empty_file(self, tmp_path, capsys):
        empty = tmp_path / "empty.log"
        empty.write_text("\n# only comments\n")
        assert az.main([str(empty), "--year", "2026"]) == 2
        assert "no auth events" in capsys.readouterr().err
