# Vulnerability Scan Report

Parse **nmap XML** (`-oX`), apply editable risk rules, and emit
HTML / Markdown / JSON / CSV reports — plus an optional safe `nmap` wrapper and
a scan **diff** mode for change monitoring.

Stdlib only (Python 3.10+). Uses `xml.etree.ElementTree`.

## Responsible use

- Only scan networks you **own** or have **written authorization** to assess.
- The `scan` subcommand refuses non-private targets unless you pass
  `--i-own-this-network`.
- Sample XML and CVE IDs are **synthetic lab data** (RFC 1918 / RFC 5737).
  Real CVE numbers are attached for demonstration only.
- `scan` is never invoked by tests or CI.

## Quick start (Linux)

```bash
# Runtime needs no pip packages.
python3 report.py demo

# Analyze your own nmap -oX file:
python3 report.py analyze scan.xml --html report.html --md report.md --json out.json

# Diff two scans (baseline first via --diff):
python3 report.py analyze lab_scan2.xml --diff lab_scan1.xml --html delta.html

# Optional: run nmap yourself (private/RFC5737 only by default):
python3 report.py scan 192.168.10.0/28 -o scan_output/lab.xml --profile safe
python3 report.py scan 192.168.10.0/28 -o scan_output/lab.xml --profile vuln --analyze
```

## Demo

Bundled synthetic scans cover a small lab (~5–6 hosts): router, Windows DC
(SMB/RDP), Linux web server (vulners CVEs), printer (Telnet/SNMP), NAS
(anonymous FTP), and (in scan2) an IoT camera. Diff shows Telnet closed on the
router, MySQL opened on the web host, and a new camera.

```text
$ python3 report.py demo
Scan file        : .../sample_scans/lab_scan2.xml
Hosts (up)       : 6 / 7
Findings         : 18
  critical   : 1
  high       : 10
  medium     : 7
Note             : demo — baseline lab_scan1.xml vs current lab_scan2.xml

=== Hosts ===
IP               Hostname                     OS                           Open ports
192.168.10.1     r1-core.lab.local            Cisco IOS 15.X               22/tcp, 80/tcp
192.168.10.10    win-dc01.lab.local           Microsoft Windows Server 2016 135/tcp, 139/tcp, 445/tcp, 3389/tcp, 5985/tcp
192.168.10.20    linux-web01.lab.local        Linux 4.4 - 4.15             22/tcp, 80/tcp, 3306/tcp, 443/tcp
192.168.10.30    printer-lobby.lab.local      HP embedded                  23/tcp, 80/tcp, 9100/tcp, 161/udp
192.168.10.40    nas-backup.lab.local         Linux 4.X                    21/tcp, 22/tcp, 445/tcp, 5000/tcp
192.168.10.60    iot-cam.lab.local            -                            80/tcp, 23/tcp

=== Findings (excerpt) ===
[CRITICAL] 192.168.10.10 tcp/445  Possible SMBv1 / legacy SMB exposure
[HIGH    ] 192.168.10.10 tcp/3389  RDP exposed on the network
[HIGH    ] 192.168.10.10 tcp/445  SMB message signing not required
[HIGH    ] 192.168.10.20 tcp/22  CVE-2016-10009 (CVSS 7.5)
[HIGH    ] 192.168.10.30 tcp/23  Telnet service exposed
[HIGH    ] 192.168.10.40 tcp/21  Anonymous FTP login allowed
[MEDIUM  ] 192.168.10.20 tcp/3306  MySQL exposed to the network
[MEDIUM  ] 192.168.10.30 udp/161  SNMP service exposed

=== Diff ===
New hosts     : 192.168.10.60
Ports opened  : 192.168.10.20:tcp/3306, 192.168.10.60:tcp/23, 192.168.10.60:tcp/80
Ports closed  : 192.168.10.1:tcp/23
New findings  : 3
Resolved      : 1
  + [medium] 192.168.10.20 MySQL exposed to the network
  + [high] 192.168.10.60 Telnet service exposed
  - [high] 192.168.10.1 Telnet service exposed

Wrote HTML report: demo_output/report.html
```

Open `demo_report.html` (or `demo_output/report.html`) in a browser for a
screenshot-ready report with inline CSS.

## Risk rules

Editable JSON at `rules/risk_rules.json`:

| Rule | Idea |
|------|------|
| `TELNET_OPEN` | TCP/23 exposed |
| `FTP_ANON` | `ftp-anon` NSE: anonymous login |
| `SMB_SIGNING_NOT_REQUIRED` / `SMBv1_HINT` | `smb-security-mode` |
| `RDP_EXPOSED` | TCP/3389 |
| `SNMP_EXPOSED` | UDP/161 |
| `HTTP_ADMIN_TITLE` | plaintext HTTP admin/login titles |
| `OLD_OPENSSH` | OpenSSH ≤ 7.5 |
| `WEAK_TLS` | `ssl-enum-ciphers` weak protocols/grades |
| `MYSQL_EXPOSED` | TCP/3306 |
| `VULNERS_CVE` | CVE + CVSS from `vulners` NSE → severity bands |

CVSS bands: critical ≥ 9.0, high ≥ 7.0, medium ≥ 4.0, low ≥ 0.1.

## Sample data

| Path | Purpose |
|------|---------|
| `sample_scans/lab_scan1.xml` | Baseline synthetic nmap `-oX` (commit this) |
| `sample_scans/lab_scan2.xml` | Follow-up scan for diff demo |
| `rules/risk_rules.json` | Severity + remediation tips |

## Development

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pytest
ruff check . && ruff format --check .
```

## Skills demonstrated

- Nmap XML parsing (`xml.etree`) for hosts, ports, services, OS, and NSE scripts
- Risk rules as editable JSON with remediation tips and CVSS severity banding
- Safe nmap wrapper (private/RFC 5737 only; explicit ownership flag; no tests/CI)
- Multi-format reporting (standalone HTML with inline CSS, Markdown, JSON, CSV)
- Scan diff for change monitoring (hosts, ports, findings)
- Stdlib Python, pytest, ruff, GitHub Actions CI on 3.10–3.12

## Resume bullet

- Built a Python nmap vulnerability report tool that parses `-oX` XML, applies
  editable JSON risk rules (Telnet/FTP anon/SMBv1/RDP/weak TLS/CVEs from
  vulners), and emits HTML/Markdown/JSON/CSV with remediation tips and CVSS
  severity bands.
- Added a private-network-only nmap wrapper (`--i-own-this-network` for
  authorized exceptions), scan-diff change monitoring, synthetic RFC 1918 lab
  samples, pytest coverage, ruff, and GitHub Actions CI across Python 3.10–3.12.

## License

MIT
