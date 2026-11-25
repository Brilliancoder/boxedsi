"""Detection must stay linear: the worst input of every rule that reads a long run, 200 KB, in under half a second of CPU."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

import boxed

BUDGET = 0.5 * float(os.environ.get("BOXED_TEST_TIME_FACTOR", "1"))  # CPU seconds; a slower machine than a fast Mac sets the factor (3 for a 2020 i5)
TIMEOUT = 15  # a rule that went quadratic or worse fails after this, instead of hanging the whole suite
SRC = str(Path(boxed.__file__).resolve().parent.parent)

# the best of up to three runs: only a close call is repeated, a hopeless one is not
CHILD = """
import sys, time
sys.path.insert(0, sys.argv[1])
from boxed.detect import detect

text = sys.stdin.buffer.read().decode()
best = float("inf")
for _ in range(3):
    start = time.process_time()
    detect(text, level=2)
    best = min(best, time.process_time() - start)
    if best < float(sys.argv[2]) or best > 4 * float(sys.argv[2]):
        break
print(best)
"""


def assert_linear(text):
    try:
        run = subprocess.run([sys.executable, "-c", CHILD, SRC, str(BUDGET)], input=text.encode(), capture_output=True, timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        pytest.fail(f"no answer for {len(text)} characters within {TIMEOUT} s")
    assert run.returncode == 0, run.stderr.decode()
    cpu = float(run.stdout)
    assert cpu < BUDGET, f"{cpu:.2f} s of CPU for {len(text)} characters"


URL_CASES = {
    "dots": "a.b." * 50_000,
    "hyphens": "a-b-" * 50_000,
    "plus signs": "a+b+" * 50_000,
    "dots, then a scheme end": "a.b." * 50_000 + "://x",
}


@pytest.mark.parametrize("text", URL_CASES.values(), ids=URL_CASES.keys())
def test_url_rules_are_linear(text):
    assert_linear(text)


RULE_CASES = {
    "env name: a chain of keywords": "KEY_" * 50_000,
    "env name: a chain of segments": "A1_" * 66_000,
    "email: a chain of percent signs": "a%" * 100_000,
    "email: only percent signs": "%" * 200_000,
    "jwt: a chain of hyphens": "eyJ-" * 50_000,
    "inn: a long gap": "ИНН" + " " * 200_000 + "x",
    "snils: a long gap": "СНИЛС" + " " * 200_000 + "x",
    "private key: unclosed blocks": "-----BEGIN RSA PRIVATE KEY-----\n" * 6_250,
    "russian name: a chain of names": "пароль " * 28_000,
    "russian name: words before the separator": "Пароль от почты " * 12_500,
    "russian name: a long gap": "Пароль" + " " * 200_000 + "x",
    "russian name: a long word after it": "пароль: " + "я" * 200_000,
    "russian name: bold": "**Пароль:** " * 16_000,
    "dash: a chain of names": "Пароль - " * 22_000,
    "login and password: a chain": "Логин / пароль " * 13_000,
    "telegram: digits": "1" * 200_000,
    "telegram: ids and colons": "123456789:" * 20_000,
    "value: commas": "password=" + ",a" * 100_000,
    "value: ampersands": "password=" + "&a" * 100_000,
    "value: semicolons and fields": "password=a;b=" * 15_000,
    "email in url credentials: many urls and many emails": "http://u:p@h.io x@y.io " * 9_000,
    "russian name: four words before the separator": "Пароль от учётной записи администратора " * 5_000,
    "russian name: a chain of names with four words": "пароль а б в г " * 13_000,
    "russian name: four words and a dash": "Пароль для входа в систему - " * 7_000,
    "table: a chain of pipes and names": "| Пароль " * 22_000,
    "table: pipes only": "|" * 200_000,
    "table: spaced pipes": "| " * 100_000,
    "table: tabs after names": "Пароль\t" * 28_000,
    "table: tabs only": "\t" * 200_000,
    "table: rows of names and values": "| Пароль | Xk9#mQ2v |\n" * 9_000,
    "table: a long gap": "| Пароль" + " " * 200_000 + "x",
    "table: a long value": "| Пароль | " + "я" * 200_000,
    "table: a long env name": "|" + "A_" * 100_000,
    "table: env names and pipes": "|A_PASSWORD" * 18_000,
    "header: many named columns, rows of one cell": "| Пароль" * 8_000 + " |\n" + "|---" * 8_000 + "|\n" + "| x |\n" * 20_000,
    "header: a long table": "| Логин | Пароль |\n|---|---|\n" + "| admin | Xk9#mQ2v |\n" * 8_000,
    "header: a header over a header": "| Пароль |\n|---|\n" * 11_800,
    "header: tabs": "Логин\tПароль\n" + "a\tXk9#mQ2v\n" * 12_000,
    "header: names under names": "Пароль\tПароль\n" * 14_000,
    "header: rows of dashes": "| Пароль |\n" + "|---|---|\n" * 20_000,
    "header: a long note in brackets": "| Пароль (" + "x" * 100_000 + ") |\n|---|\n| Xk9#mQ2v |",
    "header: a row of many cells": "| Пароль " * 14_000 + "|\n" + "|---" * 14_000 + "|\n" + "| Xk9#mQ2v " * 3_000,
    "passport: a chain of words": "паспорт " * 25_000,
    "passport: a chain of english words": "passport " * 22_000,
    "passport: a series without a number": "паспорт 4510 " * 15_000,
    "passport: a long gap after a series": "паспорт 4510" + " " * 200_000 + "x",
    "passport: a long gap before a series": "паспорт" + " " * 200_000 + "4510 123456",
    "passport: a long gap after the label": "паспорт 4510 №" + " " * 200_000 + "x",
    "passport: digits": "паспорт " + "1" * 200_000,
    "passport: series and labels": "серия 4510 № " * 15_000,
    "passport: a word and a digit": "паспорт 1 " * 20_000,
    "passport: gaps of 60 characters": ("паспорт " + "а" * 59 + " ") * 3_000,
    "passport: line breaks": "паспорт\n" * 25_000,
    "passport: english labels": "passport no " * 16_000,
    "passport: other countries, a long gap": "passport" + " :#=.-" * 40_000 + "x",
    "passport: other countries, tokens": "passport A1234567 " * 11_000,
    "ssn: a chain of words": "SSN " * 50_000,
    "ssn: a long gap after the word": "SSN" + " " * 200_000 + "123456789",
    "ssn: the word and nine digits, many times": "SSN 123456789 " * 14_000,
    "ssn: groups of dashes": "123-" * 50_000,
    "ssn: almost a number, many times": "123-45-678 " * 18_000,
    "ssn: dashes and digits": "1-" * 100_000,
    "ssn: digits": "1" * 200_000,
    "ssn: words of social security": "social security " * 12_000,
    "ssn: spaced groups": "SSN 123 45 " * 18_000,
    "ssn: a number with a dot": "123-45-6789.5 " * 15_000,
    "vat: country codes": "DE" * 100_000,
    "vat: a code and a digit": "DE1" * 66_000,
    "vat: a code and spaced digits": "DE 1 " * 40_000,
    "vat: a code and a long run of digits": "DE" + "1" * 200_000,
    "vat: a code and a long run of separators": "DE" + " 1" * 100_000,
    "vat: a chain of words": "VAT " * 50_000,
    "vat: a long gap after the word": "VAT" + " " * 200_000 + "DK12345678",
    "vat: words and numbers": "VAT DK12345678 " * 13_000,
    "vat: numbers with a valid checksum": "DE111111125 " * 16_000,
    "vat: numbers of other countries": "DK12345678 " * 18_000,
    "vat: windows of 40 characters": ("VAT " + "x" * 40 + " ") * 4_300,
    "vat: words of tax": "tax id " * 28_000,
    "vat: Dutch numbers": "NL123456789B" * 16_000,
    "vat: Irish numbers": "IE1A" * 50_000,
    "vat: Spanish numbers": "ESA1234567" * 20_000,
    "vat: French keys": "FR1A" * 50_000,
    "crypto: a run of ones": "1" * 200_000,
    "crypto: base58 tokens of 26 characters": ("1" + "A" * 25 + " ") * 7_400,
    "crypto: base58 tokens of 34 characters": ("3" + "A" * 33 + " ") * 5_700,
    "crypto: bech32 tokens": ("bc1" + "q" * 30 + " ") * 6_000,
    "crypto: the shortest bech32 tokens": ("bc1" + "q" * 11 + " ") * 13_000,
    "crypto: a long bech32 run": "bc1" + "q" * 200_000,
    "crypto: ethereum, one case": ("0x" + "a" * 40 + " ") * 4_700,
    "crypto: ethereum, mixed case, one address": "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed " * 4_600,
    "crypto: ethereum, mixed case, all different": " ".join("0xAbCdEf" + f"{i:034x}" for i in range(4_500)),
    "crypto: a long run of hex": "0x" + "a" * 200_000,
    "entropy: one long token of a short pattern": "Ab1" * 70_000,
    "entropy: one long random-looking token": "aB3xK9mQ2vLp7RtN4aB8cDeFgHiJkLmN" * 6_300,
    "entropy: many tokens of 20 characters": "aB3xK9mQ2vLp7RtN4aB8 " * 9_500,
    "entropy: many tokens of 19 characters": "aB3xK9mQ2vLp7RtN4aB " * 10_000,
    "entropy: dashes": "a-B3-" * 40_000,
    "entropy: words and digits": "Word1Word2" * 20_000,
    "entropy: padding": "aB3xK9mQ2vLp7RtN4aB8cD== " * 8_000,
    "entropy: a dot after each token": "aB3xK9mQ2vLp7RtN4aB8cD.x " * 8_000,
    "entropy: a scheme after each token": "aB3xK9mQ2vLp7RtN4aB8cD://x " * 7_000,
    "entropy: plus signs": "a+B3" * 50_000,
    "entropy: data uris": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB " * 3_800,
    # the shield of data uris looks for the end of a media type at each "data:": the token after the chain makes it run
    "entropy: a chain of data: before a token": "data:" * 40_000 + " u8jzPde0IgxLd6GncfBAepfJBd0Kh8oOOL8dKLzd",
    "entropy: a chain of DATA: with slashes before a token": "DATA:a/" * 28_000 + " u8jzPde0IgxLd6GncfBAepfJBd0Kh8oOOL8dKLzd",
    "entropy: a media type with no base64 after it": ("data:" + "a" * 120 + ";x ") * 1_500 + " u8jzPde0IgxLd6GncfBAepfJBd0Kh8oOOL8dKLzd",
    "entropy: digests": "sha256=aB3xK9mQ2vLp7RtN4aB8cDeFgHiJkLmNoPq " * 4_800,
    "entropy: digests with slashes": "sha512-aB3/K9mQ2vLp7RtN4aB8cD/FgHiJkLmNoPq== " * 4_400,
    "entropy: unclosed pem blocks": "-----BEGIN CERTIFICATE-----\n" * 7_000,
    "entropy: closed pem blocks": ("-----BEGIN CERTIFICATE-----\n" + "aB3xK9mQ2vLp7RtN4aB8cDeFgHiJkLmNoPqRsTuVwXyZ0123456789+/\n" * 3 + "-----END CERTIFICATE-----\n") * 1_200,
    "entropy: a long ssh key": "ssh-rsa " + "AAAAB3Nza" * 22_000,
    "entropy: many ssh keys": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOo " * 3_800,
    "entropy: sha words": "sha256- " * 25_000,
    "entropy: many tokens of 32 characters": "6wzGkWlEB5FL81rqxvse1c1A2dj3tUGk " * 6_000,
    "entropy: a word of credentials before each token": "clientSecretKey 6wzGkWlEB5FL81rqxvse1c1A2dj3tUGk " * 4_100,
    "entropy: a word of public things before each token": "walletAddressPubkey 6wzGkWlEB5FL81rqxvse1c1A2dj3tUGk " * 3_800,
    "entropy: a slash before each token": "/6wzGkWlEB5FL81rqxvse1c1A2dj3tUGk " * 5_800,
    "entropy: a slash after each token": "6wzGkWlEB5FL81rqxvse1c1A2dj3tUGk/ " * 5_800,
    "entropy: the path of a webhook before each token": "/hooks/a/b/c/6wzGkWlEB5FL81rqxvse1c1A2dj3tUGk " * 4_300,
    "entropy: the path of a slack webhook before each token": "/services/T0/B0/6wzGkWlEB5FL81rqxvse1c1A2dj3tUGk " * 4_000,
    "entropy: hooks and slashes": "/hooks/" * 28_000 + " 6wzGkWlEB5FL81rqxvse1c1A2dj3tUGk",
    "entropy: a long line of words before a token": ("word " * 60 + "6wzGkWlEB5FL81rqxvse1c1A2dj3tUGk\n") * 600,
    "entropy: tokens past the limit of 128 characters": ("aB3xK9mQ2vLp7RtN4aB8cDeFgHiJkLmN" * 5 + " ") * 1_200,
    "entropy: a token and a long run of hyphens": "aB3xK9mQ2vLp7RtN4aB8cD" + "-" * 200_000,
    "entropy: only hyphens": "-" * 200_000,
    "entropy: hyphens between tokens": ("aB3xK9mQ2vLp7RtN4aB8cD" + "-" * 30 + " ") * 3_800,
    "entropy: hyphens before a dot": ("aB3xK9mQ2vLp7RtN4aB8cD" + "-" * 10 + ".x ") * 6_000,
}


@pytest.mark.parametrize("text", RULE_CASES.values(), ids=RULE_CASES.keys())
def test_rules_are_linear(text):
    assert_linear(text)


def test_dropping_months_from_a_name_model_is_linear():
    """A name model that calls every month of 200 KB a person: each one is looked up in a small window of its own."""
    import re
    import time

    from boxed.detect.ner import GlinerDetector

    class EveryMonth:
        def predict_entities(self, text, labels, threshold):
            return [{"start": m.start(), "end": m.end(), "text": m.group(), "label": "person", "score": 0.9} for m in re.finditer("March", text)]

    detector = GlinerDetector(model=EveryMonth())
    for text, kept in [("5 March " * 25_000, 0), ("until March " * 18_000, 18_000)]:  # every month in a date, and none in one
        start = time.process_time()
        found = detector.find(text)
        cpu = time.process_time() - start
        assert len(found) == kept and cpu < BUDGET, f"{cpu:.2f} s of CPU for {len(text)} characters"


def test_cutting_a_name_that_crosses_the_cells_of_a_huge_table_is_linear():
    """A name model that takes 200 KB of cells for one person: the span is cut at every pipe and tab once."""
    import time

    from boxed.detect.ner import GlinerDetector

    text = "ab|\t" * 50_000

    class Everything:
        def predict_entities(self, text, labels, threshold):
            return [{"start": 0, "end": len(text), "text": text, "label": "person", "score": 0.9}]

    start = time.process_time()
    found = GlinerDetector(model=Everything()).find(text)
    cpu = time.process_time() - start
    assert len(found) == 50_000 and cpu < BUDGET, f"{cpu:.2f} s of CPU for {len(text)} characters"


def test_cutting_a_name_model_span_around_thousands_of_findings_is_linear():
    """A name model that takes 200 KB of e-mail addresses and words for one person (and a second model that does the same): each
    span is cut around every address once, and what lies between them stays."""
    import time

    from boxed.detect import DetectConfig, Detection, detect

    text = "ab ivan@acme.com " * 12_000

    class Everything:
        def find(self, text):
            return [Detection(0, len(text), "PERSON", text, "ner:stub")]

    start = time.process_time()
    found = detect(text, 2, DetectConfig(ner=[Everything(), Everything()]))
    cpu = time.process_time() - start
    assert len(found) == 24_000 and cpu < BUDGET, f"{cpu:.2f} s of CPU for {len(text)} characters"
