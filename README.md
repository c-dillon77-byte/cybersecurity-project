# cybersecurity-project

![CI](https://github.com/c-dillon77-byte/cybersecurity-project/actions/workflows/ci.yml/badge.svg)

**Defensive security tools in Python** for tasks a SOC analyst or security-minded IT technician does:
finding suspicious login activity, checking password policy compliance, and turning scan results into a
readable report.

Each tool lives in its own folder with its own README, `requirements.txt` and `tests/`.

> ⚠️ **Ethical use:** only scan networks you own or are authorized to test. These tools are for learning,
> my own lab environment, and systems where I have explicit written permission. Unauthorized scanning or
> access can be illegal.

## Project index

| Project | What it demonstrates | Status |
|---|---|---|
| [`log-analyzer/`](log-analyzer/) | Parsing Linux SSH/sudo auth logs (`auth.log`, `secure`, journalctl, `.gz`) to flag brute force, password spraying, success-after-failures and new-IP logins, with severities and MITRE ATT&CK IDs; HTML/JSON/CSV report; tested with synthetic logs | ✅ Complete |
| [`password-auditor/`](password-auditor/) | Checking passwords against a policy (length, complexity, common-password list, optional HIBP k-anonymity breach check) with masked reports and no plaintext storage or logging | ✅ Complete |
| [`vuln-scan-report/`](vuln-scan-report/) | Converting nmap XML output into HTML/Markdown/JSON/CSV reports (hosts, open ports, services, versions) with JSON risk rules and scan-to-scan diffs; tested with synthetic lab scans | 🔵 In review |

*Status key: 🟡 Planned · 🟢 In progress · 🔵 In review · ✅ Complete*

## How to run

Requires Python 3.10+. Some tools may need external programs (for example, nmap itself for producing XML).

```bash
git clone https://github.com/c-dillon77-byte/cybersecurity-project.git
cd cybersecurity-project
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

cd <project-folder>              # e.g. log-analyzer
pip install -r requirements.txt
python <script>.py --help
```

Run the checks the same way CI does:

```bash
pip install ruff pytest
ruff check .
cd <project-folder> && python -m pytest -q
```

## Data handling

- Sample logs and scan files in this repo are synthetic or sanitized lab data.
- No real credentials, password lists from real users, or third-party scan results are committed.

## Repository layout

```text
cybersecurity-project/
├── <project>/
│   ├── README.md
│   ├── requirements.txt
│   ├── <script>.py
│   └── tests/
├── .github/workflows/ci.yml   # ruff + pytest for every project folder
├── pyproject.toml
└── LICENSE (MIT)
```

Part of my [IT portfolio](https://github.com/c-dillon77-byte/it-portfolio).
