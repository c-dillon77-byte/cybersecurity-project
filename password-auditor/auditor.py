#!/usr/bin/env python3
"""Password policy auditor (Python 3.10+, standard library only).

Defensive tool for checking passwords against policy, common/breached lists,
optional HIBP Pwned Passwords (k-anonymity), and producing masked audit reports.

Never logs or prints plaintext passwords by default (mask like P*****d).
"""

from __future__ import annotations

import argparse
import csv
import getpass
import hashlib
import json
import math
import re
import secrets
import string
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

__version__ = "1.0.0"

HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Policy:
    name: str
    min_length: int = 8
    max_length: int = 128
    require_upper: bool = False
    require_lower: bool = False
    require_digit: bool = False
    require_special: bool = False
    forbid_username: bool = True
    forbid_company_words: bool = True
    forbid_repeats: bool = True
    forbid_sequences: bool = True
    forbid_keyboard_walks: bool = True
    check_common_list: bool = True
    # NIST SP 800-63B-ish: prefer length, check breached/common, avoid composition rules
    favor_length: bool = False


POLICIES: dict[str, Policy] = {
    "nist": Policy(
        name="nist",
        min_length=8,  # NIST minimum; recommend 15+ in messaging
        max_length=64,
        require_upper=False,
        require_lower=False,
        require_digit=False,
        require_special=False,
        forbid_username=True,
        forbid_company_words=True,
        forbid_repeats=True,
        forbid_sequences=True,
        forbid_keyboard_walks=True,
        check_common_list=True,
        favor_length=True,
    ),
    "legacy": Policy(
        name="legacy",
        min_length=8,
        max_length=128,
        require_upper=True,
        require_lower=True,
        require_digit=True,
        require_special=True,
        forbid_username=True,
        forbid_company_words=True,
        forbid_repeats=True,
        forbid_sequences=True,
        forbid_keyboard_walks=True,
        check_common_list=True,
        favor_length=False,
    ),
    "strict": Policy(
        name="strict",
        min_length=12,
        max_length=128,
        require_upper=True,
        require_lower=True,
        require_digit=True,
        require_special=True,
        forbid_username=True,
        forbid_company_words=True,
        forbid_repeats=True,
        forbid_sequences=True,
        forbid_keyboard_walks=True,
        check_common_list=True,
        favor_length=False,
    ),
}

DEFAULT_COMPANY_WORDS = (
    "company",
    "companyname",
    "corp",
    "corporate",
    "acme",
    "contoso",
    "lab",
    "ecpi",
)


@dataclass
class CheckResult:
    password_masked: str
    username: str
    policy: str
    score: int  # 0-100
    entropy_bits: float
    passed: bool
    failures: list[str] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)
    in_common_list: bool = False
    hibp_count: int | None = None  # None = not checked
    strength_label: str = ""


@dataclass
class AuditReport:
    policy: str
    total: int
    failed: int
    passed: int
    reuse_groups: list[list[str]]  # groups of usernames sharing a password
    weakness_counts: list[tuple[str, int]]
    results: list[CheckResult] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    hash_demo: dict = field(default_factory=dict)


class AuditorError(Exception):
    """User-facing error; no traceback; exit code 2."""


# ---------------------------------------------------------------------------
# Masking / helpers
# ---------------------------------------------------------------------------


def mask_password(password: str) -> str:
    """Mask like P*****d — never expose the full secret in reports."""
    if not password:
        return "(empty)"
    if len(password) == 1:
        return "*"
    if len(password) == 2:
        return password[0] + "*"
    return password[0] + ("*" * (len(password) - 2)) + password[-1]


def estimate_entropy(password: str) -> float:
    """Rough Shannon-style charset estimate (not a crack-time model)."""
    if not password:
        return 0.0
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"\d", password):
        pool += 10
    if re.search(r"[^A-Za-z0-9]", password):
        pool += 32  # approximate printable specials
    if pool == 0:
        pool = len(set(password)) or 1
    return round(len(password) * math.log2(pool), 1)


def strength_label(score: int) -> str:
    if score >= 80:
        return "strong"
    if score >= 60:
        return "moderate"
    if score >= 40:
        return "weak"
    return "very weak"


# ---------------------------------------------------------------------------
# Leetspeak / normalization for list checks
# ---------------------------------------------------------------------------

# Digit→letter maps omit 2/6/9 so years like 2022 stay matchable as digits.
LEET_MAP = str.maketrans(
    {
        "@": "a",
        "4": "a",
        "^": "a",
        "8": "b",
        "(": "c",
        "3": "e",
        "#": "h",
        "!": "i",
        "1": "i",
        "|": "i",
        "0": "o",
        "$": "s",
        "5": "s",
        "+": "t",
        "7": "t",
    }
)


def normalize_leetspeak(password: str) -> str:
    """Lowercase and undo common leetspeak substitutions."""
    return password.lower().translate(LEET_MAP)


def load_wordlist(path: Path) -> set[str]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise AuditorError(f"cannot read wordlist {path}: {exc}") from None
    words: set[str] = set()
    for line in text.splitlines():
        w = line.strip()
        if not w or w.startswith("#"):
            continue
        # Store lowercase only — do not leet-normalize list entries (that
        # would turn "Summer2022" into garbage via digit substitutions).
        words.add(w.lower())
    return words


# ---------------------------------------------------------------------------
# Pattern checks
# ---------------------------------------------------------------------------

KEYBOARD_ROWS = (
    "1234567890",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "!@#$%^&*()",
    "qwerty",
    "asdfgh",
    "zxcvbn",
)


def has_repeated_run(password: str, run: int = 4) -> bool:
    return bool(re.search(rf"(.)\1{{{run - 1},}}", password, re.IGNORECASE))


def has_digit_sequence(password: str, length: int = 4) -> bool:
    digits = "0123456789"
    lower = password.lower()
    for i in range(len(digits) - length + 1):
        seq = digits[i : i + length]
        if seq in lower or seq[::-1] in lower:
            return True
    # alpha sequences too
    alpha = string.ascii_lowercase
    for i in range(len(alpha) - length + 1):
        seq = alpha[i : i + length]
        if seq in lower or seq[::-1] in lower:
            return True
    return False


def has_keyboard_walk(password: str, length: int = 4) -> bool:
    lower = password.lower()
    for row in KEYBOARD_ROWS:
        for i in range(len(row) - length + 1):
            seq = row[i : i + length]
            if seq in lower or seq[::-1] in lower:
                return True
    # classic walks as whole tokens
    for walk in ("qwerty", "asdf", "zxcv", "1qaz", "2wsx", "qazwsx", "qwertyuiop"):
        if walk in lower:
            return True
    return False


def contains_username(password: str, username: str) -> bool:
    if not username or len(username) < 3:
        return False
    return username.lower() in password.lower()


def contains_company_word(password: str, words: tuple[str, ...] | list[str]) -> bool:
    norm = normalize_leetspeak(password)
    lower = password.lower()
    for w in words:
        if len(w) < 3:
            continue
        if w.lower() in lower or w.lower() in norm:
            return True
    return False


# ---------------------------------------------------------------------------
# HIBP (k-anonymity)
# ---------------------------------------------------------------------------


def sha1_hex(password: str) -> str:
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def hibp_prefix_suffix(password: str) -> tuple[str, str]:
    """Return (first 5 hex chars, remainder) — only the prefix is sent."""
    digest = sha1_hex(password)
    return digest[:5], digest[5:]


def check_hibp(
    password: str,
    *,
    opener=None,
    timeout: float = 10.0,
) -> int:
    """Query HIBP Pwned Passwords range API. Returns breach count (0 if unseen).

    Only the first 5 characters of the SHA-1 hash are transmitted (k-anonymity).
    `opener` is injectable for tests (callable like urllib.request.urlopen).
    """
    prefix, suffix = hibp_prefix_suffix(password)
    url = HIBP_RANGE_URL.format(prefix=prefix)
    open_fn = opener or urllib.request.urlopen
    req = urllib.request.Request(url, headers={"User-Agent": "password-auditor-lab/1.0"})
    try:
        with open_fn(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        raise AuditorError(f"HIBP HTTP error: {exc.code}") from None
    except urllib.error.URLError as exc:
        raise AuditorError(f"HIBP network error: {exc.reason}") from None
    except TimeoutError as exc:
        raise AuditorError("HIBP request timed out") from exc

    for line in body.splitlines():
        if not line.strip():
            continue
        parts = line.strip().split(":")
        if len(parts) != 2:
            continue
        if parts[0].upper() == suffix:
            return int(parts[1])
    return 0


# ---------------------------------------------------------------------------
# Core strength check
# ---------------------------------------------------------------------------


def check_password(
    password: str,
    *,
    username: str = "",
    policy: Policy | None = None,
    common_words: set[str] | None = None,
    company_words: tuple[str, ...] = DEFAULT_COMPANY_WORDS,
    hibp: bool = False,
    hibp_opener=None,
) -> CheckResult:
    policy = policy or POLICIES["nist"]
    failures: list[str] = []
    suggestions: list[str] = []
    score = 100
    in_common = False
    hibp_count: int | None = None

    if not password:
        return CheckResult(
            password_masked="(empty)",
            username=username,
            policy=policy.name,
            score=0,
            entropy_bits=0.0,
            passed=False,
            failures=["password is empty"],
            suggestions=["Choose a long passphrase of 4+ random words."],
            strength_label="very weak",
        )

    # Length
    if len(password) < policy.min_length:
        failures.append(f"shorter than {policy.min_length} characters")
        suggestions.append(f"Use at least {policy.min_length} characters (longer is better).")
        score -= 30
    elif policy.favor_length and len(password) < 15:
        suggestions.append(
            "NIST SP 800-63B favors length: aim for 15+ characters or a 4-word passphrase."
        )
        score -= 5

    if len(password) > policy.max_length:
        failures.append(f"longer than {policy.max_length} characters")
        score -= 10

    # Composition (legacy / strict)
    if policy.require_lower and not re.search(r"[a-z]", password):
        failures.append("missing a lowercase letter")
        suggestions.append("Add a lowercase letter.")
        score -= 10
    if policy.require_upper and not re.search(r"[A-Z]", password):
        failures.append("missing an uppercase letter")
        suggestions.append("Add an uppercase letter.")
        score -= 10
    if policy.require_digit and not re.search(r"\d", password):
        failures.append("missing a digit")
        suggestions.append("Add a digit.")
        score -= 10
    if policy.require_special and not re.search(r"[^A-Za-z0-9]", password):
        failures.append("missing a special character")
        suggestions.append("Add a special character (e.g. ! @ # ?).")
        score -= 10

    if policy.forbid_username and contains_username(password, username):
        failures.append("contains the username")
        suggestions.append("Do not include your username in the password.")
        score -= 20

    if policy.forbid_company_words and contains_company_word(password, company_words):
        failures.append("contains a company/lab dictionary word")
        suggestions.append("Avoid company names and common org words.")
        score -= 15

    if policy.forbid_repeats and has_repeated_run(password):
        failures.append("contains a repeated character run (e.g. aaaa)")
        suggestions.append("Avoid repeated characters like aaaa or 1111.")
        score -= 15

    if policy.forbid_sequences and has_digit_sequence(password):
        failures.append("contains a sequential run (e.g. 1234 or abcd)")
        suggestions.append("Avoid sequences like 1234 or abcd.")
        score -= 15

    if policy.forbid_keyboard_walks and has_keyboard_walk(password):
        failures.append("contains a keyboard walk (e.g. qwerty)")
        suggestions.append("Avoid keyboard patterns like qwerty or asdf.")
        score -= 20

    # Common list (+ leetspeak)
    if policy.check_common_list and common_words is not None:
        candidates = {password.lower(), normalize_leetspeak(password)}
        # Strip trailing punctuation / symbols for matching P@ssw0rd! or Summer2022!
        for base in list(candidates):
            stripped = re.sub(r"[^a-z0-9]+$", "", base)
            if stripped:
                candidates.add(stripped)
            # Also try removing all non-alnum (CompanyName123! → companyname123)
            compact = re.sub(r"[^a-z0-9]", "", base)
            if compact:
                candidates.add(compact)
        if candidates & common_words:
            in_common = True
            failures.append("found in the common-password list (incl. leetspeak variants)")
            suggestions.append("Choose something that is not a known common password.")
            score -= 40

    # HIBP opt-in
    if hibp:
        hibp_count = check_hibp(password, opener=hibp_opener)
        if hibp_count > 0:
            failures.append(f"seen in HIBP Pwned Passwords ({hibp_count:,} times)")
            suggestions.append("This password appears in known breaches — do not reuse it.")
            score -= 50

    # Entropy bonus/penalty
    entropy = estimate_entropy(password)
    if entropy >= 60:
        score += 5
    elif entropy < 28:
        score -= 10
        if "too little entropy" not in " ".join(failures):
            suggestions.append("Increase length and randomness to raise entropy.")

    score = max(0, min(100, score))
    passed = len(failures) == 0 and score >= 60

    if passed and not suggestions and policy.favor_length:
        suggestions.append(
            "Looks acceptable under a NIST-style policy — prefer a unique passphrase per site."
        )
    if not failures and score < 60:
        failures.append("score below pass threshold")
        suggestions.append("Lengthen the password or add more unique words.")

    # Dedupe suggestions preserving order
    seen: set[str] = set()
    uniq_suggestions = []
    for s in suggestions:
        if s not in seen:
            seen.add(s)
            uniq_suggestions.append(s)

    return CheckResult(
        password_masked=mask_password(password),
        username=username,
        policy=policy.name,
        score=score,
        entropy_bits=entropy,
        passed=passed,
        failures=failures,
        suggestions=uniq_suggestions,
        in_common_list=in_common,
        hibp_count=hibp_count,
        strength_label=strength_label(score),
    )


# ---------------------------------------------------------------------------
# Audit mode
# ---------------------------------------------------------------------------


def load_accounts_csv(path: Path) -> list[tuple[str, str]]:
    try:
        with path.open(encoding="utf-8", newline="") as fh:
            reader = csv.DictReader(fh)
            if not reader.fieldnames or "password" not in reader.fieldnames:
                raise AuditorError(f"{path}: CSV needs a 'password' column")
            rows = []
            for i, row in enumerate(reader, 1):
                pw = (row.get("password") or "").strip()
                user = (row.get("username") or row.get("user") or f"row{i}").strip()
                if pw:
                    rows.append((user, pw))
    except OSError as exc:
        raise AuditorError(f"cannot read {path}: {exc}") from None
    if not rows:
        raise AuditorError(f"{path}: no password rows found")
    return rows


def load_password_list(path: Path) -> list[tuple[str, str]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise AuditorError(f"cannot read {path}: {exc}") from None
    rows = []
    for i, line in enumerate(lines, 1):
        pw = line.strip()
        if pw and not pw.startswith("#"):
            rows.append((f"item{i}", pw))
    if not rows:
        raise AuditorError(f"{path}: no passwords found")
    return rows


def find_reuse(accounts: list[tuple[str, str]]) -> list[list[str]]:
    """Groups of usernames that share an identical password."""
    by_pw: dict[str, list[str]] = {}
    for user, pw in accounts:
        by_pw.setdefault(pw, []).append(user)
    return [users for users in by_pw.values() if len(users) > 1]


def audit_accounts(
    accounts: list[tuple[str, str]],
    *,
    policy: Policy,
    common_words: set[str],
    company_words: tuple[str, ...] = DEFAULT_COMPANY_WORDS,
    hibp: bool = False,
    hibp_opener=None,
) -> AuditReport:
    results = [
        check_password(
            pw,
            username=user,
            policy=policy,
            common_words=common_words,
            company_words=company_words,
            hibp=hibp,
            hibp_opener=hibp_opener,
        )
        for user, pw in accounts
    ]
    weakness = Counter()
    for r in results:
        for f in r.failures:
            # normalize to a short key
            key = f.split("(")[0].strip()
            weakness[key] += 1
    reuse = find_reuse(accounts)
    if reuse:
        weakness["password reused across accounts"] += len(reuse)
    failed = sum(1 for r in results if not r.passed)
    return AuditReport(
        policy=policy.name,
        total=len(results),
        failed=failed,
        passed=len(results) - failed,
        reuse_groups=reuse,
        weakness_counts=weakness.most_common(),
        results=results,
    )


# ---------------------------------------------------------------------------
# Educational hash demo (NOT a cracker)
# ---------------------------------------------------------------------------


def hash_demo(sample_password: str = "LabPassphrase-Example") -> dict:
    """Compare fast unsalted hashes vs salted slow hashes (timing + format)."""
    out: dict = {"note": "Educational only — not a password cracking tool.", "samples": []}
    pw = sample_password.encode("utf-8")

    t0 = time.perf_counter()
    md5 = hashlib.md5(pw).hexdigest()
    md5_ms = (time.perf_counter() - t0) * 1000

    t0 = time.perf_counter()
    sha1 = hashlib.sha1(pw).hexdigest()
    sha1_ms = (time.perf_counter() - t0) * 1000

    salt = secrets.token_bytes(16)
    t0 = time.perf_counter()
    pbkdf2 = hashlib.pbkdf2_hmac("sha256", pw, salt, 200_000)
    pbkdf2_ms = (time.perf_counter() - t0) * 1000

    t0 = time.perf_counter()
    scrypt = hashlib.scrypt(pw, salt=salt, n=2**14, r=8, p=1, dklen=32)
    scrypt_ms = (time.perf_counter() - t0) * 1000

    out["samples"] = [
        {
            "algorithm": "MD5 (unsalted)",
            "digest_hex_prefix": md5[:16] + "…",
            "elapsed_ms": round(md5_ms, 4),
            "verdict": "Broken for passwords — too fast, no salt",
        },
        {
            "algorithm": "SHA-1 (unsalted)",
            "digest_hex_prefix": sha1[:16] + "…",
            "elapsed_ms": round(sha1_ms, 4),
            "verdict": "Not appropriate for password storage",
        },
        {
            "algorithm": "PBKDF2-HMAC-SHA256 (200k iters, random salt)",
            "digest_hex_prefix": pbkdf2.hex()[:16] + "…",
            "elapsed_ms": round(pbkdf2_ms, 3),
            "verdict": "Acceptable slow hash when tuned; salt stops rainbow tables",
        },
        {
            "algorithm": "scrypt (n=2^14, r=8, p=1, random salt)",
            "digest_hex_prefix": scrypt.hex()[:16] + "…",
            "elapsed_ms": round(scrypt_ms, 3),
            "verdict": "Memory-hard; better resistance to GPU/ASIC guessing",
        },
    ]
    out["takeaway"] = (
        "Store passwords with a unique salt and a slow KDF (PBKDF2, scrypt, bcrypt, or argon2). "
        "Fast unsalted MD5/SHA-1 make offline guessing trivial."
    )
    return out


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


def format_check(result: CheckResult) -> str:
    lines = [
        f"Password         : {result.password_masked}",
        f"Username         : {result.username or '(none)'}",
        f"Policy           : {result.policy}",
        f"Score            : {result.score}/100 ({result.strength_label})",
        f"Entropy (est.)   : {result.entropy_bits} bits",
        f"Passed           : {'yes' if result.passed else 'no'}",
        f"Common list      : {'yes' if result.in_common_list else 'no'}",
    ]
    if result.hibp_count is not None:
        lines.append(f"HIBP count       : {result.hibp_count:,}")
    if result.failures:
        lines.append("Failures:")
        for f in result.failures:
            lines.append(f"  - {f}")
    if result.suggestions:
        lines.append("Suggestions:")
        for s in result.suggestions:
            lines.append(f"  - {s}")
    return "\n".join(lines)


def format_audit(report: AuditReport) -> str:
    pct = (report.failed / report.total * 100) if report.total else 0.0
    lines = [
        f"Policy           : {report.policy}",
        f"Accounts         : {report.total}",
        f"Failed           : {report.failed} ({pct:.1f}%)",
        f"Passed           : {report.passed}",
        f"Reuse groups     : {len(report.reuse_groups)}",
    ]
    for note in report.notes:
        lines.append(f"Note             : {note}")
    lines.append("")
    lines.append("=== Most common weaknesses ===")
    if not report.weakness_counts:
        lines.append("(none)")
    else:
        for w, n in report.weakness_counts[:12]:
            lines.append(f"  {n:3d}  {w}")
    if report.reuse_groups:
        lines.append("")
        lines.append("=== Reused passwords (usernames sharing a secret) ===")
        for group in report.reuse_groups:
            lines.append("  - " + ", ".join(group))
    lines.append("")
    lines.append("=== Per-account results (passwords masked) ===")
    header = f"{'User':<12} {'Score':>5} {'Pass':<5} {'Label':<10} Failures"
    lines.append(header)
    lines.append("-" * len(header))
    for r in report.results:
        fail = "; ".join(r.failures[:2]) if r.failures else "-"
        if len(r.failures) > 2:
            fail += "…"
        lines.append(
            f"{r.username:<12} {r.score:>5} {'yes' if r.passed else 'no':<5} "
            f"{r.strength_label:<10} {fail}"
        )
    if report.hash_demo:
        lines.append("")
        lines.append("=== Hash demo (educational) ===")
        lines.append(report.hash_demo.get("note", ""))
        for row in report.hash_demo.get("samples", []):
            lines.append(f"  {row['algorithm']}: {row['elapsed_ms']} ms — {row['verdict']}")
        lines.append("  " + report.hash_demo.get("takeaway", ""))
    return "\n".join(lines)


def report_to_dict(report: AuditReport) -> dict:
    return {
        "policy": report.policy,
        "total": report.total,
        "failed": report.failed,
        "passed": report.passed,
        "fail_percent": round(report.failed / report.total * 100, 1) if report.total else 0,
        "reuse_groups": report.reuse_groups,
        "weakness_counts": [{"weakness": w, "count": n} for w, n in report.weakness_counts],
        "results": [asdict(r) for r in report.results],
        "notes": report.notes,
        "hash_demo": report.hash_demo,
    }


def write_csv(report: AuditReport, path: Path) -> None:
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(
            [
                "username",
                "password_masked",
                "policy",
                "score",
                "entropy_bits",
                "passed",
                "strength_label",
                "in_common_list",
                "hibp_count",
                "failures",
                "suggestions",
            ]
        )
        for r in report.results:
            writer.writerow(
                [
                    r.username,
                    r.password_masked,
                    r.policy,
                    r.score,
                    r.entropy_bits,
                    r.passed,
                    r.strength_label,
                    r.in_common_list,
                    "" if r.hibp_count is None else r.hibp_count,
                    " | ".join(r.failures),
                    " | ".join(r.suggestions),
                ]
            )


def render_html(report: AuditReport) -> str:
    def esc(s: object) -> str:
        return (
            str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )

    pct = round(report.failed / report.total * 100, 1) if report.total else 0
    weak_rows = (
        "".join(f"<tr><td>{esc(w)}</td><td>{n}</td></tr>" for w, n in report.weakness_counts[:15])
        or "<tr><td colspan='2'>(none)</td></tr>"
    )
    result_rows = []
    for r in report.results:
        color = "#15803d" if r.passed else "#b91c1c"
        result_rows.append(
            "<tr>"
            f"<td>{esc(r.username)}</td>"
            f"<td><code>{esc(r.password_masked)}</code></td>"
            f"<td>{r.score}</td>"
            f"<td>{esc(r.entropy_bits)}</td>"
            f"<td><span class='pill' style='background:{color}'>"
            f"{'pass' if r.passed else 'fail'}</span></td>"
            f"<td>{esc(r.strength_label)}</td>"
            f"<td>{esc('; '.join(r.failures) or '-')}</td>"
            "</tr>"
        )
    reuse = (
        "".join(f"<li>{esc(', '.join(g))}</li>" for g in report.reuse_groups) or "<li>(none)</li>"
    )

    hash_rows = ""
    for row in report.hash_demo.get("samples", []):
        hash_rows += (
            "<tr>"
            f"<td>{esc(row['algorithm'])}</td>"
            f"<td><code>{esc(row['digest_hex_prefix'])}</code></td>"
            f"<td>{esc(row['elapsed_ms'])}</td>"
            f"<td>{esc(row['verdict'])}</td>"
            "</tr>"
        )

    def card(n: object, label: str) -> str:
        return (
            f'<div class="card"><div class="n">{esc(n)}</div>'
            f'<div class="l">{esc(label)}</div></div>'
        )

    cards = "\n".join(
        [
            "    " + card(report.total, "Accounts"),
            "    " + card(report.failed, "Failed"),
            "    " + card(f"{pct}%", "Fail rate"),
            "    " + card(report.passed, "Passed"),
            "    " + card(len(report.reuse_groups), "Reuse groups"),
        ]
    )
    if hash_rows:
        hash_section = (
            "<h2>Hash demo (why salting matters)</h2>"
            "<table><tr><th>Algorithm</th><th>Digest prefix</th>"
            "<th>ms</th><th>Verdict</th></tr>"
            + hash_rows
            + "</table><p class='muted'>"
            + esc(report.hash_demo.get("takeaway", ""))
            + "</p>"
        )
    else:
        hash_section = ""

    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>Password Audit Report</title>
<style>
  body {{
    margin: 0; background: #f1f5f9; color: #0f172a;
    font-family: "Segoe UI", system-ui, sans-serif;
  }}
  main {{
    max-width: 1050px; margin: 2rem auto; background: #fff;
    padding: 2rem; border-radius: 12px; box-shadow: 0 8px 24px #0f172a22;
  }}
  h1 {{ margin-top: 0; }}
  h2 {{ border-bottom: 2px solid #e2e8f0; padding-bottom: .3rem; }}
  .cards {{
    display: grid; gap: 1rem; margin: 1rem 0 1.5rem;
    grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
  }}
  .card {{
    background: #f8fafc; border: 1px solid #e2e8f0;
    border-radius: 8px; padding: 1rem; text-align: center;
  }}
  .card .n {{ font-size: 1.7rem; font-weight: 700; }}
  .card .l {{ color: #64748b; font-size: .85rem; }}
  table {{ width: 100%; border-collapse: collapse; font-size: .92rem; }}
  th, td {{
    text-align: left; padding: .5rem .55rem;
    border-bottom: 1px solid #e2e8f0; vertical-align: top;
  }}
  th {{ background: #0f172a; color: #fff; }}
  tr:nth-child(even) {{ background: #f8fafc; }}
  .pill {{
    color: #fff; padding: .12rem .45rem;
    border-radius: 999px; font-size: .75rem;
  }}
  code {{ background: #e2e8f0; padding: .1rem .35rem; border-radius: 4px; }}
  .muted {{ color: #64748b; font-size: .9rem; }}
  .warn {{
    background: #fff7ed; border-left: 4px solid #c2410c;
    padding: .75rem 1rem;
  }}
</style>
</head>
<body>
<main>
  <h1>Password Audit Report</h1>
  <p class="muted">Generated {esc(generated)} · policy:
    <code>{esc(report.policy)}</code></p>
  <div class="warn">Plaintext passwords are masked (e.g. <code>P*****d</code>).
  Handle real credentials only on systems you are authorized to audit.</div>
  <div class="cards">
{cards}
  </div>
  <h2>Most common weaknesses</h2>
  <table><tr><th>Weakness</th><th>Count</th></tr>{weak_rows}</table>
  <h2>Password reuse</h2>
  <ul>{reuse}</ul>
  <h2>Per-account results</h2>
  <table>
    <tr><th>User</th><th>Masked</th><th>Score</th><th>Entropy</th>
    <th>Result</th><th>Label</th><th>Failures</th></tr>
    {"".join(result_rows)}
  </table>
  {hash_section}
  <p class="muted">Synthetic lab data. HIBP uses k-anonymity
  (5-char SHA-1 prefix).</p>
</main>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Paths / demo / CLI
# ---------------------------------------------------------------------------


def default_wordlist() -> Path:
    return Path(__file__).resolve().parent / "wordlists" / "common_passwords.txt"


def sample_accounts() -> Path:
    return Path(__file__).resolve().parent / "sample_data" / "accounts.csv"


def run_demo(output_dir: Path | None = None) -> tuple[AuditReport, Path]:
    out = output_dir or (Path(__file__).resolve().parent / "demo_output")
    out.mkdir(parents=True, exist_ok=True)
    policy = POLICIES["nist"]
    words = load_wordlist(default_wordlist())
    accounts = load_accounts_csv(sample_accounts())
    # Inject one reuse pair for the demo narrative (mallory copies dave's weak pw)
    # — already distinct in CSV; add explicit reuse:
    accounts.append(("pat", "qwerty"))  # reuses dave's password

    report = audit_accounts(accounts, policy=policy, common_words=words, hibp=False)
    report.hash_demo = hash_demo("LabPassphrase-Example")
    report.notes.append("demo mode — synthetic sample_data/accounts.csv (HIBP not queried)")
    html_path = out / "report.html"
    html_path.write_text(render_html(report), encoding="utf-8")
    (out / "report.json").write_text(
        json.dumps(report_to_dict(report), indent=2) + "\n", encoding="utf-8"
    )
    write_csv(report, out / "findings.csv")
    report.notes.append(f"HTML report: {html_path}")
    return report, html_path


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="auditor",
        description="Audit passwords against policy, common lists, and optional HIBP.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument(
        "--policy",
        choices=sorted(POLICIES),
        default="nist",
        help="policy preset: nist (SP 800-63B-style) | legacy | strict",
    )
    p.add_argument("--wordlist", type=Path, default=None, help="extra/override common list")
    p.add_argument(
        "--company-word",
        action="append",
        default=[],
        help="extra company/lab word to forbid (repeatable)",
    )
    p.add_argument(
        "--hibp",
        action="store_true",
        help="opt-in: check Have I Been Pwned Pwned Passwords via k-anonymity",
    )
    p.add_argument("--json", type=Path, metavar="FILE")
    p.add_argument("--csv", type=Path, metavar="FILE")
    p.add_argument("--html", type=Path, metavar="FILE")
    p.add_argument("--hash-demo", action="store_true", help="include educational hash timing")
    p.add_argument("--demo", action="store_true", help="audit sample accounts + write HTML")
    p.add_argument("-o", "--output-dir", type=Path, default=None)

    g = p.add_mutually_exclusive_group()
    g.add_argument("--check", metavar="PASSWORD", help="check one password (prefer --prompt)")
    g.add_argument("--prompt", action="store_true", help="prompt with getpass (no echo)")
    g.add_argument("--audit", type=Path, metavar="CSV", help="CSV with username,password columns")
    g.add_argument("--passwords-file", type=Path, metavar="FILE", help="one password per line")
    p.add_argument("--username", default="", help="username for --check/--prompt context")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.demo:
            report, html_path = run_demo(args.output_dir)
            print(format_audit(report))
            print(f"\nWrote HTML report: {html_path}")
            return 0

        policy = POLICIES[args.policy]
        wl_path = args.wordlist or default_wordlist()
        common = load_wordlist(wl_path)
        company = tuple(DEFAULT_COMPANY_WORDS) + tuple(args.company_word)

        if args.prompt or args.check is not None:
            password = getpass.getpass("Password: ") if args.prompt else args.check
            result = check_password(
                password or "",
                username=args.username,
                policy=policy,
                common_words=common,
                company_words=company,
                hibp=args.hibp,
            )
            print(format_check(result))
            if args.hash_demo:
                demo = hash_demo("LabPassphrase-Example")
                print("\n=== Hash demo (educational) ===")
                for row in demo["samples"]:
                    print(f"  {row['algorithm']}: {row['elapsed_ms']} ms — {row['verdict']}")
                print("  " + demo["takeaway"])
            return 0 if result.passed else 1

        if args.audit or args.passwords_file:
            if args.audit:
                accounts = load_accounts_csv(args.audit)
            else:
                accounts = load_password_list(args.passwords_file)
            report = audit_accounts(
                accounts,
                policy=policy,
                common_words=common,
                company_words=company,
                hibp=args.hibp,
            )
            if args.hash_demo:
                report.hash_demo = hash_demo()
            print(format_audit(report))
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
            return 0 if report.failed == 0 else 1

        raise AuditorError("choose --demo, --prompt, --check, --audit CSV, or --passwords-file")
    except AuditorError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("error: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
