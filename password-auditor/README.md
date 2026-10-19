# Password Auditor

A **defensive** Python tool for auditing password policy — not a cracker.

Check a single password (via `getpass`) or audit a CSV of synthetic accounts
against configurable policy presets, a bundled common-password list (with
leetspeak variants), and an **opt-in** Have I Been Pwned check that uses
k-anonymity. Reports mask secrets like `P*****d` by default.

Stdlib only (Python 3.10+).

## Responsible use

- Only audit credentials you are **authorized** to test (your lab, your org with
  written approval).
- Reports **mask** plaintext by default. Do not paste real passwords into tickets,
  git, or chat.
- Prefer `--prompt` (getpass, no echo) over `--check` on a shared shell history.
- The optional `--hibp` flag sends **only the first 5 hex characters** of a SHA-1
  hash to the public Pwned Passwords range API — never the password itself. Demo
  and tests never call the network.

## Policy presets

| Preset | Idea |
|--------|------|
| `nist` (default) | Inspired by **NIST SP 800-63B**: favor length, check common/breached lists, **no** forced composition (upper/digit/special) |
| `legacy` | Old “complexity” rules: length ≥ 8 plus upper + lower + digit + special |
| `strict` | Legacy composition with length ≥ 12 |

All presets can also reject usernames, company words, repeats (`aaaa`), sequences
(`1234` / `abcd`), and keyboard walks (`qwerty`).

## Quick start (Linux)

```bash
# Runtime needs no pip packages.
python3 auditor.py --demo

# Interactive single check (password is not echoed):
python3 auditor.py --prompt --username alice --policy nist

# Audit a CSV (columns: username,password):
python3 auditor.py --audit sample_data/accounts.csv --html report.html --json report.json --hash-demo

# Opt-in HIBP (network) — mock in CI; use only when you intend to:
python3 auditor.py --prompt --hibp
```

## Demo

Bundled synthetic accounts trigger weak, common, leetspeak, reuse, and strong
passphrases. HIBP is **not** queried in demo mode.

```text
$ python3 auditor.py --demo
Policy           : nist
Accounts         : 16
Failed           : 13 (81.2%)
Passed           : 3
Reuse groups     : 1
Note             : demo mode — synthetic sample_data/accounts.csv (HIBP not queried)
Note             : HTML report: demo_output/report.html

=== Most common weaknesses ===
    8  found in the common-password list
    6  shorter than 8 characters
    4  contains a keyboard walk
    2  contains the username
    1  contains a repeated character run
    1  contains a sequential run
    1  contains a company/lab dictionary word
    1  password reused across accounts

=== Reused passwords (usernames sharing a secret) ===
  - dave, pat

=== Per-account results (passwords masked) ===
User         Score Pass  Label      Failures
--------------------------------------------
alice          100 yes   strong     -
bob             50 no    weak       shorter than 8 characters; contains the username
carol           55 no    weak       found in the common-password list (incl. leetspeak variants)
dave            10 no    very weak  shorter than 8 characters; contains a keyboard walk (e.g. qwerty)…
erin            60 no    moderate   found in the common-password list (incl. leetspeak variants)
frank           80 no    strong     contains a repeated character run (e.g. aaaa)
grace          100 yes   strong     -
heidi           20 no    very weak  shorter than 8 characters; found in the common-password list (incl. leetspeak variants)
ivan            10 no    very weak  contains a sequential run (e.g. 1234 or abcd); contains a keyboard walk (e.g. qwerty)…
judy            85 no    strong     contains a company/lab dictionary word
karen           30 no    very weak  shorter than 8 characters; found in the common-password list (incl. leetspeak variants)
leo             40 no    weak       shorter than 8 characters; contains the username
mallory         75 no    moderate   contains a keyboard walk (e.g. qwerty)
nancy           55 no    weak       found in the common-password list (incl. leetspeak variants)
oscar          100 yes   strong     -
pat             10 no    very weak  shorter than 8 characters; contains a keyboard walk (e.g. qwerty)…

=== Hash demo (educational) ===
Educational only — not a password cracking tool.
  MD5 (unsalted): 0.0427 ms — Broken for passwords — too fast, no salt
  SHA-1 (unsalted): 0.0081 ms — Not appropriate for password storage
  PBKDF2-HMAC-SHA256 (200k iters, random salt): 34.052 ms — Acceptable slow hash when tuned; salt stops rainbow tables
  scrypt (n=2^14, r=8, p=1, random salt): 48.661 ms — Memory-hard; better resistance to GPU/ASIC guessing
  Store passwords with a unique salt and a slow KDF (PBKDF2, scrypt, bcrypt, or argon2). Fast unsalted MD5/SHA-1 make offline guessing trivial.

Wrote HTML report: demo_output/report.html
```

Open `demo_report.html` (or `demo_output/report.html`) in a browser for a
screenshot-ready report.

## Have I Been Pwned (k-anonymity)

With `--hibp`, the tool:

1. Hashes the password with SHA-1 locally.
2. Sends **only the first 5 hex characters** to
   `https://api.pwnedpasswords.com/range/{PREFIX}`.
3. Compares the remaining 35 characters against the returned list locally.

This is the [official k-anonymity model](https://haveibeenpwned.com/API/v3#PwnedPasswords).
Tests mock the HTTP call and assert the URL contains exactly those 5 characters.

## Educational hash demo (`--hash-demo`)

Compares unsalted **MD5 / SHA-1** (too fast for password storage) with salted
**PBKDF2** and **scrypt** from `hashlib`, including rough timings. This is for
learning why salting and slow KDFs matter — **not** a cracking toolkit.

## Sample data

| Path | Purpose |
|------|---------|
| `sample_data/accounts.csv` | Synthetic usernames + passwords for audit mode |
| `sample_data/passwords.txt` | One password per line |
| `wordlists/common_passwords.txt` | Small educational common-password list |
| `wordlists/README.md` | Attribution note (SecLists-style public examples) |

Point `--wordlist` at a larger public list (e.g. SecLists) for deeper audits.

## Development

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pytest          # HIBP fully mocked — no network
ruff check . && ruff format --check .
```

## Skills demonstrated

- Password policy design (NIST SP 800-63B-style vs legacy complexity)
- Common-list / leetspeak matching and entropy heuristics
- HIBP Pwned Passwords **k-anonymity** client (5-char prefix only)
- Credential hygiene: masking, getpass, no plaintext in reports
- Educational comparison of fast unsalted hashes vs PBKDF2/scrypt
- Stdlib Python, pytest (mocked HTTP), ruff, GitHub Actions CI on 3.10–3.12

## Resume bullet

- Built a defensive Python password auditor with NIST-style and legacy policy
  presets, common-list/leetspeak checks, optional Have I Been Pwned lookups via
  k-anonymity (only a 5-character SHA-1 prefix is sent), and masked JSON/CSV/HTML
  reports that never write plaintext secrets by default.
- Added an educational hashlib demo contrasting unsalted MD5/SHA-1 with salted
  PBKDF2 and scrypt, plus pytest coverage with fully mocked HIBP, ruff, and
  GitHub Actions CI across Python 3.10–3.12.

## License

MIT
