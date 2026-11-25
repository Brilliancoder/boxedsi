import hashlib
import hmac
import os
import sys
import threading

import pytest

from boxed.detect import DetectConfig
from boxed.journal import Journal
from boxed.keys import default_keystore
from boxed.observe import observe, observed_journal


@pytest.fixture
def journals(boxed_env):
    """The main journal and the observation journal of one boxed home, signed by the same device key."""
    boxed_env.mkdir(parents=True, exist_ok=True)
    keys = default_keystore()
    return Journal(boxed_env / "journal.jsonl", keys), observed_journal(boxed_env, keys)


def keyed(payload: bytes) -> str:
    """What an observed record holds as the hash of a text: HMAC-SHA256 under the device's own "observe-hmac" key."""
    return hmac.new(default_keystore().get_or_create("observe-hmac", 32), payload, hashlib.sha256).hexdigest()


def test_observe_records_counts_not_text(boxed_env, journals):
    _, observed = journals
    text = "please mail ivan.petrov@acme.com about the key AKIAIOSFODNN7EXAMPLE"
    found = observe(text, "chatgpt", "checked", observed, DetectConfig())
    assert found == {"EMAIL": 1, "SECRET": 1}
    (record,) = observed.entries()
    assert (record["channel"], record["provider"], record["account_type"], record["level"]) == ("observed", "chatgpt", "unknown", 0)
    assert (record["status"], record["coverage"], record["scope"]) == ("sent", "checked", "")
    assert record["markers_by_kind"] == {"EMAIL": 1, "SECRET": 1}
    assert record["payload_sha256"] == keyed(text.encode())
    raw = (boxed_env / "observed.jsonl").read_text()
    assert "ivan" not in raw and "acme" not in raw and "AKIA" not in raw and "please" not in raw
    assert observed.verify().ok


def test_not_checked_records_the_gap(journals):
    _, observed = journals
    assert observe("", "claude", "not checked", observed, DetectConfig()) == {}
    (record,) = observed.entries()
    assert (record["provider"], record["coverage"], record["markers_by_kind"]) == ("claude", "not checked", {})
    assert record["payload_sha256"] == keyed(b"")
    assert observed.verify().ok


def test_the_hash_of_a_text_is_keyed(journals):
    _, observed = journals
    phone = "+7 (912) 345-67-89"  # a prompt that is only a number: a bare hash is found by trying every number
    observe(phone, "chatgpt", "checked", observed, DetectConfig())
    observe(phone, "claude", "checked", observed, DetectConfig())
    first, second = (record["payload_sha256"] for record in observed.entries())
    assert first == second == keyed(phone.encode())  # the same text keeps the same hash, so a repeat can be recognised
    assert first != hashlib.sha256(phone.encode()).hexdigest()


def test_observations_stay_out_of_the_main_journal(boxed_env, journals):
    main, observed = journals
    observe("mail a@x.io", "gemini", "checked", observed, DetectConfig())
    observe("", "zai", "not checked", observed, DetectConfig())
    assert main.entries() == [] and not main.path.exists()
    assert [e["provider"] for e in observed.entries()] == ["gemini", "zai"]
    assert sorted(p.name for p in boxed_env.glob("*.jsonl")) == ["observed.jsonl"]


def test_every_occurrence_of_a_level_2_kind_is_counted(journals):
    _, observed = journals
    text = "a@x.io and a@x.io, connect to db1.acme.local; key AKIAIOSFODNN7EXAMPLE"
    # HOST is a level 2 kind: a narrower level would leave it out
    assert observe(text, "deepseek", "checked", observed, DetectConfig()) == {"EMAIL": 2, "HOST": 1, "SECRET": 1}


# What level 3 adds is in nearly every text, and none of it is a leak by itself: counted as findings, it would drown the real ones.
LEVEL_3_ONLY = {
    "an amount": "Pay $1,200.50 for the licence",
    "an amount in words": "Выручка 5 млн руб. за год",
    "a date": "The meeting is on 21.10.2026",
    "a quarter": "Results for Q3 2026",
    "a percentage": "A discount of 15% applies",
    "a number": "Order 4521 shipped",
}


@pytest.mark.parametrize("text", LEVEL_3_ONLY.values(), ids=LEVEL_3_ONLY.keys())
def test_amounts_dates_percentages_and_numbers_are_no_findings(journals, text):
    _, observed = journals
    assert observe(text, "chatgpt", "checked", observed, DetectConfig()) == {}
    (record,) = observed.entries()
    assert record["markers_by_kind"] == {} and record["coverage"] == "checked"


def test_secrets_and_personal_data_are_still_counted_among_numbers(journals):
    _, observed = journals
    text = (
        "key AKIAIOSFODNN7EXAMPLE; mail ivan.petrov@acme.com; call +7 912 345-67-89; card 4111 1111 1111 1111; "
        "IBAN DE89 3704 0044 0532 0130 00; server 10.1.2.3 and db1.acme.local; paid $300 on 2026-10-21 (12%) ref 99812"
    )
    expected = {"SECRET": 1, "EMAIL": 1, "PHONE": 1, "CARD": 1, "IBAN": 1, "IP": 1, "HOST": 1}  # no MONEY, DATE, PERCENT or NUMBER
    assert observe(text, "claude", "checked", observed, DetectConfig()) == expected
    assert observed.entries()[0]["markers_by_kind"] == expected


def test_the_project_config_applies(journals):
    _, observed = journals
    config = DetectConfig(dictionary={"Acme Corp": "CLIENT"}, allow={"ok@x.io"})
    assert observe("Acme Corp wrote to ok@x.io and no@x.io", "chatgpt", "checked", observed, config) == {"CLIENT": 1, "EMAIL": 1}


def test_a_text_with_a_lone_surrogate_counts_as_not_checked(journals):
    _, observed = journals
    text = "mail ivan.petrov@acme.com \ud800 please"  # nothing can encode it, so nothing can read it
    assert observe(text, "claude", "checked", observed, DetectConfig()) == {}
    (record,) = observed.entries()
    assert (record["provider"], record["coverage"], record["markers_by_kind"]) == ("claude", "not checked", {})
    assert record["payload_sha256"] == keyed(b"")
    assert "ivan" not in observed.path.read_text() and "please" not in observed.path.read_text()


def test_an_observation_is_never_written_through_a_symlink(journals, tmp_path):
    _, observed = journals
    target = tmp_path / "elsewhere.jsonl"
    target.write_text("keep\n")
    observed.path.symlink_to(target)
    with pytest.raises(OSError) as caught:
        observe("mail ivan.petrov@acme.com", "chatgpt", "checked", observed, DetectConfig())
    assert caught.value.errno is None and str(observed.path) not in str(caught.value)  # a fixed text, no path
    assert observed.path.is_symlink() and target.read_text() == "keep\n"


@pytest.mark.skipif(sys.platform == "win32", reason="Windows has no pipe in the file system (os.mkfifo)")
def test_a_pipe_at_the_observation_log_is_an_error_not_a_hang(journals):
    _, observed = journals
    os.mkfifo(observed.path)
    outcome = []

    def run():
        try:
            outcome.append(observe("mail ivan.petrov@acme.com", "chatgpt", "checked", observed, DetectConfig()))
        except BaseException as error:
            outcome.append(error)

    observer = threading.Thread(target=run, daemon=True)
    observer.start()
    observer.join(timeout=3)
    if observer.is_alive():
        os.close(os.open(observed.path, os.O_RDWR | os.O_NONBLOCK))  # a process that holds both ends lets a waiting open through
        observer.join(timeout=3)
        pytest.fail("observe waits on a pipe")
    (error,) = outcome
    assert isinstance(error, OSError) and error.errno is None and error.filename is None
    assert str(observed.path) not in str(error) and "ivan" not in str(error)


def test_both_journals_are_signed_by_the_device_key(journals):
    main, observed = journals
    assert observed.public_key_hex() == main.public_key_hex()


@pytest.mark.parametrize(
    ("text", "site", "coverage"),
    [
        ("hello", "ivan.petrov@acme.com", "checked"),
        ("hello", "ChatGPT", "checked"),
        ("hello", "", "checked"),
        ("hello", "chatgpt", "full"),
        ("hello", "chatgpt", "ivan.petrov@acme.com"),
        ("mail ivan.petrov@acme.com", "chatgpt", "not checked"),
        ("lone \ud800 surrogate", "chatgpt", "not checked"),
    ],
    ids=["site is text", "site case", "no site", "unknown coverage", "coverage is text", "text with not checked", "surrogate with not checked"],
)
def test_nothing_else_is_recorded(journals, text, site, coverage):
    _, observed = journals
    with pytest.raises(ValueError) as caught:
        observe(text, site, coverage, observed, DetectConfig())
    assert "ivan" not in str(caught.value) and "hello" not in str(caught.value)
    assert not observed.path.exists()
