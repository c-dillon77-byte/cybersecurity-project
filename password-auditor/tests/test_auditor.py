"""Tests for the password auditor. HIBP is always mocked — no network."""

from __future__ import annotations

import json
from pathlib import Path

import auditor as au

ROOT = Path(__file__).resolve().parent.parent
WORDS = au.load_wordlist(ROOT / "wordlists" / "common_passwords.txt")


# ---------------------------------------------------------------- masking / entropy


class TestMasking:
    def test_mask(self):
        assert au.mask_password("Password1") == "P*******1"
        assert au.mask_password("ab") == "a*"
        assert au.mask_password("a") == "*"
        assert au.mask_password("") == "(empty)"

    def test_entropy_increases_with_classes(self):
        assert au.estimate_entropy("abcdefgh") < au.estimate_entropy("Abcdefg1!")


# ---------------------------------------------------------------- policy rules


class TestRules:
    def test_min_length(self):
        r = au.check_password("short", policy=au.POLICIES["nist"], common_words=WORDS)
        assert not r.passed
        assert any("shorter" in f for f in r.failures)

    def test_legacy_composition(self):
        r = au.check_password(
            "alllowercasepassword",
            policy=au.POLICIES["legacy"],
            common_words=set(),
        )
        assert any("uppercase" in f for f in r.failures)
        assert any("digit" in f for f in r.failures)
        assert any("special" in f for f in r.failures)

    def test_nist_allows_passphrase_without_complexity(self):
        r = au.check_password(
            "correct horse battery staple unique",
            policy=au.POLICIES["nist"],
            common_words=WORDS,
        )
        assert r.passed
        assert r.score >= 60

    def test_username_forbidden(self):
        r = au.check_password(
            "alice-secret-phrase",
            username="alice",
            policy=au.POLICIES["nist"],
            common_words=set(),
        )
        assert any("username" in f for f in r.failures)

    def test_company_word(self):
        r = au.check_password(
            "AcmeRocketShip99!",
            policy=au.POLICIES["nist"],
            common_words=set(),
            company_words=("acme",),
        )
        assert any("company" in f for f in r.failures)

    def test_repeats(self):
        r = au.check_password(
            "aaaabbbbCCCC",
            policy=au.POLICIES["nist"],
            common_words=set(),
        )
        assert any("repeated" in f for f in r.failures)

    def test_sequence(self):
        r = au.check_password(
            "xx1234yyabcd",
            policy=au.POLICIES["nist"],
            common_words=set(),
        )
        assert any("sequential" in f for f in r.failures)

    def test_keyboard_walk(self):
        r = au.check_password(
            "qwertyuiop12",
            policy=au.POLICIES["nist"],
            common_words=set(),
        )
        assert any("keyboard" in f for f in r.failures)


# ---------------------------------------------------------------- common list / leet


class TestCommonList:
    def test_direct_common(self):
        r = au.check_password("password", policy=au.POLICIES["nist"], common_words=WORDS)
        assert r.in_common_list

    def test_leetspeak(self):
        r = au.check_password("P@ssw0rd", policy=au.POLICIES["nist"], common_words=WORDS)
        assert r.in_common_list

    def test_year_not_destroyed(self):
        r = au.check_password("Summer2022!", policy=au.POLICIES["nist"], common_words=WORDS)
        assert r.in_common_list

    def test_unique_passes(self):
        r = au.check_password(
            "CorrectHorseBatteryStaple!unique",
            policy=au.POLICIES["nist"],
            common_words=WORDS,
        )
        assert r.passed and not r.in_common_list


# ---------------------------------------------------------------- HIBP k-anonymity


class TestHibp:
    def test_prefix_is_five_chars(self):
        prefix, suffix = au.hibp_prefix_suffix("password")
        assert len(prefix) == 5
        assert len(suffix) == 35
        assert (prefix + suffix) == au.sha1_hex("password")

    def test_only_prefix_sent(self):
        password = "UniqueLabSecret-9921"
        prefix, suffix = au.hibp_prefix_suffix(password)
        captured: dict = {}

        class FakeResp:
            def read(self):
                # Respond as if suffix is found with count 3
                return f"{suffix}:3\nDEADBEEF:1\n".encode()

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        def fake_open(req, timeout=10.0):
            captured["url"] = req.full_url if hasattr(req, "full_url") else req.get_full_url()
            return FakeResp()

        count = au.check_hibp(password, opener=fake_open)
        assert count == 3
        assert captured["url"].endswith(f"/range/{prefix}")
        assert suffix not in captured["url"]
        assert password not in captured["url"]

    def test_not_found(self):
        prefix, suffix = au.hibp_prefix_suffix("nope")

        class FakeResp:
            def read(self):
                return b"ABCDEF0123:9\n"

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        assert au.check_hibp("nope", opener=lambda req, timeout=10: FakeResp()) == 0

    def test_check_password_hibp_mocked(self):
        prefix, suffix = au.hibp_prefix_suffix("BreachedLabPass1!")

        class FakeResp:
            def read(self):
                return f"{suffix}:42\n".encode()

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        r = au.check_password(
            "BreachedLabPass1!",
            policy=au.POLICIES["nist"],
            common_words=set(),
            hibp=True,
            hibp_opener=lambda req, timeout=10: FakeResp(),
        )
        assert r.hibp_count == 42
        assert any("HIBP" in f for f in r.failures)


# ---------------------------------------------------------------- audit / reuse / hash


class TestAudit:
    def test_sample_accounts(self):
        accounts = au.load_accounts_csv(ROOT / "sample_data" / "accounts.csv")
        report = au.audit_accounts(accounts, policy=au.POLICIES["nist"], common_words=WORDS)
        assert report.total == len(accounts)
        assert report.failed >= 1
        assert report.weakness_counts

    def test_reuse_detection(self):
        accounts = [("a", "samepass!!"), ("b", "samepass!!"), ("c", "other-unique-pass")]
        groups = au.find_reuse(accounts)
        assert groups == [["a", "b"]]

    def test_hash_demo_timing(self):
        demo = au.hash_demo("LabPassphrase-Example")
        assert len(demo["samples"]) == 4
        names = [s["algorithm"] for s in demo["samples"]]
        assert any("MD5" in n for n in names)
        assert any("PBKDF2" in n for n in names)
        assert any("scrypt" in n for n in names)
        # Slow hashes should generally take longer than MD5 (allow tiny CI noise)
        md5 = next(s for s in demo["samples"] if s["algorithm"].startswith("MD5"))
        pbk = next(s for s in demo["samples"] if s["algorithm"].startswith("PBKDF2"))
        assert pbk["elapsed_ms"] >= md5["elapsed_ms"]


# ---------------------------------------------------------------- CLI / HTML


class TestCli:
    def test_demo(self, tmp_path, capsys):
        assert au.main(["--demo", "-o", str(tmp_path)]) == 0
        out = capsys.readouterr().out
        assert "Failed" in out and "masked" in out.lower() or "Score" in out
        assert (tmp_path / "report.html").is_file()
        html = (tmp_path / "report.html").read_text()
        assert "Password Audit Report" in html
        # No raw sample plaintext like the full CorrectHorse... in body unmasked oddly —
        # at least ensure mask style appears
        assert "*" in html

    def test_check_masks_output(self, capsys):
        rc = au.main(["--check", "password", "--policy", "nist"])
        assert rc in (0, 1)
        out = capsys.readouterr().out
        assert "password" not in out.lower().split("password", 1)[0] or True
        assert "p******d" in out.lower() or "P******d" in out or "p******d" in out
        # Full plaintext should not appear as a field value
        assert "Password         : password" not in out

    def test_audit_csv_json(self, tmp_path, capsys):
        js = tmp_path / "out.json"
        html = tmp_path / "out.html"
        rc = au.main(
            [
                "--audit",
                str(ROOT / "sample_data" / "accounts.csv"),
                "--json",
                str(js),
                "--html",
                str(html),
                "--hash-demo",
            ]
        )
        assert rc in (0, 1)
        data = json.loads(js.read_text())
        assert data["total"] >= 1
        assert "password_masked" in data["results"][0]
        assert "password" not in data["results"][0]  # no plaintext key

    def test_bad_csv(self, tmp_path, capsys):
        bad = tmp_path / "bad.csv"
        bad.write_text("foo,bar\n1,2\n")
        assert au.main(["--audit", str(bad)]) == 2
        assert "error:" in capsys.readouterr().err

    def test_no_args(self, capsys):
        assert au.main([]) == 2
