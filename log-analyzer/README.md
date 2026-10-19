# Auth Log Analyzer

A Python tool that parses Linux **SSH / sudo auth logs** and flags brute force,
password spraying, success-after-failures, root attempts, invalid-user
enumeration, new-IP logins, and off-hours access.

Stdlib only (Python 3.10+). Findings carry a **severity** and a **MITRE ATT&CK**
technique ID where one fits — the kind of detail SOC and cybersecurity hiring
managers look for.

## What it reads

| Source | Format |
|--------|--------|
| Debian/Ubuntu | `/var/log/auth.log` classic syslog (`Oct 18 11:00:00 host sshd[pid]: …`) |
| RHEL/CentOS/Rocky | `/var/log/secure` (same syslog shape) |
| journalctl | `journalctl -u ssh -o short-iso` (`2026-10-18T11:00:00+00:00 host sshd[pid]: …`) |
| Rotated logs | `.gz` gzip files (e.g. `auth.log.1.gz`) |

Syslog lines have no year — pass `--year 2026` or the tool uses the current year.

### Event types parsed

- sshd: `Failed password`, `Invalid user`, `Accepted password` / `Accepted publickey`,
  `authentication failure` (pam), `Connection closed by authenticating user`
- sudo: successful `COMMAND=`, `user NOT in sudoers`, incorrect password attempts

## Detections

| Finding | Default logic | Severity | MITRE |
|---------|---------------|----------|-------|
| SSH brute force | ≥5 failures from one IP in 10 minutes | high | T1110.001 |
| Password spraying | ≥5 distinct usernames failing from one IP in 10 minutes | high | T1110.003 |
| Success after failures | Accepted login after several recent failures from same IP | high | T1078 |
| Invalid-user enumeration | ≥5 invalid-user events from one IP in 15 minutes | medium | T1589.001 |
| Root SSH attempts | Any root auth from an IP | medium / high if accepted | T1110.001 / T1078.003 |
| Login from new IP | Success from an IP not in the known set for that user | medium | T1078 |
| Off-hours login | Success between `--off-hours` (default 22–06) | low | T1078 |
| Sudo failure | NOT in sudoers / bad password | medium | T1548.003 |

Thresholds and windows are configurable on the CLI.

## Quick start (Linux)

```bash
# Nothing to install for runtime — stdlib only.
python3 analyzer.py --demo

# Against a real (or copied) auth log:
sudo cp /var/log/auth.log /tmp/auth.log   # optional; needs read permission
python3 analyzer.py /tmp/auth.log --year 2026

# journalctl export:
journalctl -u ssh -o short-iso --since "1 week ago" > ssh.journal.txt
python3 analyzer.py ssh.journal.txt --html report.html --json report.json --blocklist

# Gzip-rotated:
python3 analyzer.py /var/log/auth.log.1.gz --year 2026
```

`--blocklist` prints suggested `iptables` / fail2ban candidate lines for
**high-severity IPs**. They are printed for review only — this tool never
executes firewall commands.

## Demo

The bundled `sample_logs/auth.log` mixes normal activity with a brute-force
burst, a password spray, a successful login after failures, sudo abuse, and
off-hours logins (all synthetic RFC 1918 / RFC 5737 addresses and fake users).

```text
$ python3 analyzer.py --demo
Files            : auth.log
Events parsed    : 45
Lines ignored    : 6
Failures         : 37
Successes        : 8
Sudo events      : 3
Findings         : 14
Note             : demo mode — synthetic sample_logs/auth.log
Note             : HTML report: demo_output/report.html
Note             : JSON report: demo_output/report.json
Note             : CSV findings: demo_output/findings.csv

=== Top offending IPs (by failures) ===
IP                 Failures
----------------------------
203.0.113.50             14
198.51.100.20             9
203.0.113.80              5
203.0.113.99              5
10.50.0.99                2

=== Top targeted users ===
User             Failures
--------------------------
root                   14
alice                   7
bob                     4
oracle                  2
postgres                2
admin                   2
test                    2
ubuntu                  2
pi                      2

=== Findings ===
Sev     MITRE        Title                            Detail
------------------------------------------------------------
high    T1110.003    Password spraying                203.0.113.50 tried 6 usernames within 10m: admin, oracle, pi, postgres, test, ubuntu
high    T1110.001    SSH brute force                  8 failed authentications from 198.51.100.20 within 10m (users: root)
high    T1110.001    SSH brute force                  6 failed authentications from 203.0.113.50 within 10m (users: admin, oracle, pi, postgres, test, ubuntu)
high    T1110.001    SSH brute force                  5 failed authentications from 203.0.113.80 within 10m (users: alice)
high    T1110.001    SSH brute force                  5 failed authentications from 203.0.113.99 within 10m (users: root)
high    T1078        Successful login after failures  alice logged in from 203.0.113.80 via password after 5 recent failures — possible compromise
medium  T1589.001    Invalid-user enumeration         203.0.113.50 probed 6 invalid usernames within 15m
medium  T1078        Login from new IP                alice accepted from new IP 203.0.113.80 (previously seen: 10.20.30.40)
medium  T1110.001    Root SSH login attempts          8 root auth event(s) from 198.51.100.20
medium  T1110.001    Root SSH login attempts          5 root auth event(s) from 203.0.113.99
medium  T1548.003    Sudo failure                     bob: sudo not in sudoers — /bin/bash
medium  T1548.003    Sudo failure                     bob: sudo bad password — /usr/bin/apt update
low     T1078        Off-hours login                  alice logged in from 10.20.30.40 at 22:15:33 (off-hours 22:00–06:00)
low     T1078        Off-hours login                  eve logged in from 198.51.100.77 at 01:05:00 (off-hours 22:00–06:00)

=== Suggested block list (high severity IPs) ===
# Review before applying. Printed only — nothing is executed.
# fail2ban / iptables candidate: 198.51.100.20
iptables -A INPUT -s 198.51.100.20 -j DROP
# fail2ban / iptables candidate: 203.0.113.50
iptables -A INPUT -s 203.0.113.50 -j DROP
# fail2ban / iptables candidate: 203.0.113.80
iptables -A INPUT -s 203.0.113.80 -j DROP
# fail2ban / iptables candidate: 203.0.113.99
iptables -A INPUT -s 203.0.113.99 -j DROP

Wrote HTML report: demo_output/report.html
```

Open `demo_output/report.html` (or the copy at `demo_report.html`) in a browser
for a screenshot-ready report with inline CSS and no external assets.

## Sample data

| File | Purpose |
|------|---------|
| `sample_logs/auth.log` | Debian-style auth.log (main demo) |
| `sample_logs/secure` | RHEL-style secure snippet |
| `sample_logs/journalctl_ssh_short_iso.txt` | short-iso journal export |
| `sample_logs/auth.log.1.gz` | gzip-rotated copy of auth.log |

## Development

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pytest
ruff check . && ruff format --check .
```

Layout:

```text
analyzer.py          # parsers, detections, CLI, HTML renderer
sample_logs/         # synthetic auth / secure / journal samples
tests/               # parser + detection + CLI tests
demo_output/         # created by --demo (gitignored)
demo_report.html     # checked-in screenshot-ready copy of the demo report
```

## Skills demonstrated

- Parsing real-world Linux auth log formats (syslog + journald short-iso, gzip)
- Time-window correlation for brute force and password spraying
- Mapping detections to **MITRE ATT&CK** (T1110.001, T1110.003, T1078, …)
- SOC-style reporting: terminal summary, JSON/CSV, standalone HTML
- Safe automation hygiene (suggest block lists, never apply them)
- Stdlib-only Python, pytest, ruff, GitHub Actions CI on 3.10–3.12

## Resume bullet

- Built a Python auth-log analyzer that parses Linux sshd/sudo logs (syslog and
  journalctl short-iso, including .gz), detects brute force, password spraying,
  success-after-failures, and related behaviors, and tags findings with severity
  plus MITRE ATT&CK IDs (T1110.001, T1110.003, T1078).
- Added JSON/CSV/HTML reporting and a suggested fail2ban/iptables block list
  (print-only), with synthetic sample logs, an offline demo, pytest coverage, ruff,
  and GitHub Actions CI across Python 3.10–3.12.

## License

MIT
