import errno
import json
import os
import stat
import sys
import threading
import tracemalloc
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from datetime import UTC, date, datetime

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from boxed.checks import MAX_BYTES, SETTINGS, SIGNING_KEY, VERSION, Check, CheckError, _write, account_kind, due, load_checks, save_check
from boxed.cli import _check_rows, main
from boxed.config import ProjectConfig
from boxed.journal import Journal
from boxed.keys import InsecureFileKeyStore, default_keystore
from boxed.native_host import HostContext, handle
from boxed.observe import SITES, observed_journal
from boxed.vault import Vault
from support import mode_is


@pytest.fixture
def home(tmp_path):
    return tmp_path


def check(provider="chatgpt", account="me", training="off", memory="off", checked_at="2026-10-01", source="asked"):
    return Check(provider, account, training, memory, source, checked_at)


def test_a_missing_file_is_no_checks(home):
    assert load_checks(home) == []


def test_every_observed_site_has_a_settings_entry():
    assert set(SETTINGS) == set(SITES)


def test_save_replaces_the_same_account(home):
    save_check(home, check("chatgpt", "me", training="on", checked_at="2026-10-01"))
    save_check(home, check("claude", "me", training="off"))
    save_check(home, check("chatgpt", "work", training="unknown"))
    save_check(home, check("chatgpt", "me", training="off", memory="on", checked_at="2026-10-20"))
    # the other provider and the other account stay as they were; the new answer replaces the old one, it does not join it
    assert load_checks(home) == [
        check("claude", "me", training="off"),
        check("chatgpt", "work", training="unknown"),
        check("chatgpt", "me", training="off", memory="on", checked_at="2026-10-20"),
    ]


def test_due_after_30_days_and_for_unknown():
    today = date(2026, 10, 21)
    fresh = check(account="fresh", checked_at="2026-10-21")
    thirty_days = check(account="thirty", checked_at="2026-09-21")
    thirty_one_days = check(account="thirty-one", checked_at="2026-09-20")
    unknown_training = check(account="u1", training="unknown", checked_at="2026-10-21")
    unknown_memory = check(account="u2", memory="unknown", checked_at="2026-10-21")
    checks = [fresh, thirty_days, thirty_one_days, unknown_training, unknown_memory]
    assert due(checks, today) == [thirty_one_days, unknown_training, unknown_memory]
    assert due([], today) == []


def test_a_check_dated_after_today_is_due():
    today = date(2026, 10, 21)
    same_day = check(account="today", checked_at="2026-10-21")
    tomorrow = check(account="tomorrow", checked_at="2026-10-22")
    far_away = check(account="far", checked_at="9999-12-31")  # a date that never comes would otherwise never ask again
    assert due([same_day, tomorrow, far_away], today) == [tomorrow, far_away]


def test_account_kind_fails_safe():
    assert account_kind(None) == "personal-training"
    assert account_kind(check(training="unknown")) == "personal-training"
    assert account_kind(check(training="on")) == "personal-training"
    assert account_kind(check(training="off")) == "personal-private"
    assert account_kind(check(training="off", memory="unknown")) == "personal-private"  # only training decides


def entry(**changes):
    return {"provider": "chatgpt", "account": "me", "training": "off", "memory": "off", "source": "asked", "checked_at": "2026-10-01"} | changes


def unsigned(*entries, version=1):
    """What a checks.json says, before it is signed."""
    return {"version": version, "checks": list(entries)}


CONTEXT = b"boxed.si checks.json\n"  # signed before the content, so that no journal signature can pass for a signature of this file


def sign(content, keys=None):
    """The bytes of a checks.json: `content` (a dict) with the signature of the device key, which covers every other key of it."""
    key = Ed25519PrivateKey.from_private_bytes((keys or default_keystore()).get_or_create("device-signing-key", 32))
    message = CONTEXT + json.dumps(content, sort_keys=True, separators=(",", ":")).encode()
    return json.dumps(content | {"sig": key.sign(message).hex()}).encode()


def document(*entries, version=1, keys=None):
    return sign(unsigned(*entries, version=version), keys)


def plant(home, content):
    """checks.json with exactly these bytes, in the mode boxed writes it."""
    path = home / "checks.json"
    path.write_bytes(content)
    path.chmod(0o600)
    return path


DAMAGED_TEXT = "checks.json is damaged"  # what a file that cannot be read, or is not what boxed writes, says
FIXED = "training checks need to be confirmed again"  # what a file says whose signature is missing, wrong or from before signing
NESTED = b"[" * 20_000 + b"]" * 20_000  # 40 kB, under the size cap, and deeper than the parser reads

# Bytes are written as they are; a dict is signed by the device key first, so that its shape is the only thing wrong with it.
DAMAGED = {
    "not json": b"{",
    "empty": b"",
    "not utf-8": b"\xff\xfe\x00",
    "nested too deep": b"[" * 600_000,  # the size cap refuses this one before the parser sees it
    "nested under the size cap": NESTED,
    "a list": b"[]",
    "no checks": {"version": 1},
    "extra key": {"version": 1, "checks": [], "note": "x"},
    "other version": unsigned(version=2),
    "version is text": {"version": "1", "checks": []},
    "version is true": {"version": True, "checks": []},
    "checks is an object": {"version": 1, "checks": {}},
    "entry is a number": {"version": 1, "checks": [1]},
    "missing field": unsigned({k: v for k, v in entry().items() if k != "memory"}),
    "extra field": unsigned(entry(note="x")),
    "training maybe": unsigned(entry(training="maybe")),
    "training upper case": unsigned(entry(training="OFF")),
    "training true": unsigned(entry(training=True)),
    "training null": unsigned(entry(training=None)),
    "memory yes": unsigned(entry(memory="yes")),
    "provider is a list": unsigned(entry(provider=["chatgpt"])),
    "unknown provider": unsigned(entry(provider="ivan.petrov@acme.com")),
    "account with a space": unsigned(entry(account="my account")),
    "account too long": unsigned(entry(account="a" * 65)),
    "empty account": unsigned(entry(account="")),
    "account line break": unsigned(entry(account="me\n")),
    "unknown source": unsigned(entry(source="page")),
    "date in words": unsigned(entry(checked_at="yesterday")),
    "date without dashes": unsigned(entry(checked_at="20261001")),
    "date with a time": unsigned(entry(checked_at="2026-10-01T00:00:00")),
    "date is a number": unsigned(entry(checked_at=20261001)),
    "the same account twice": unsigned(entry(training="on"), entry(training="off")),
}


@pytest.mark.parametrize("content", DAMAGED.values(), ids=DAMAGED.keys())
def test_damaged_file_raises(home, content):
    (home / "checks.json").write_bytes(sign(content) if isinstance(content, dict) else content)
    with pytest.raises(CheckError) as caught:
        load_checks(home)
    assert str(caught.value) == DAMAGED_TEXT  # a fixed text, no piece of the file


def test_the_nested_file_is_under_the_size_cap_and_the_parser_gives_up_on_it():
    assert len(NESTED) < MAX_BYTES  # so that it is the parser, and not the size check, that the file has to get past
    with pytest.raises(RecursionError):
        json.loads(NESTED)


def test_a_path_that_cannot_be_read_is_damaged_not_missing(home):
    (home / "checks.json").mkdir()
    with pytest.raises(CheckError):
        load_checks(home)


def load_on_a_thread(home, release):
    """load_checks(home) where a pipe could make it wait: it must answer within seconds. `release` frees a stuck reader."""
    outcome = []

    def run():
        try:
            outcome.append(load_checks(home))
        except BaseException as error:
            outcome.append(error)

    reader = threading.Thread(target=run, daemon=True)
    reader.start()
    reader.join(timeout=3)
    if reader.is_alive():
        release()
        reader.join(timeout=3)
        pytest.fail("load_checks waits on a pipe")
    return outcome[0]


@pytest.mark.skipif(sys.platform == "win32", reason="Windows has no pipe in the file system (os.mkfifo)")
def test_a_fifo_is_damaged_not_a_hang(home):
    fifo = home / "checks.json"
    os.mkfifo(fifo)

    def release():  # a writer lets a reader that waits in open() through
        try:
            os.close(os.open(fifo, os.O_WRONLY | os.O_NONBLOCK))
        except OSError:
            pass

    assert isinstance(load_on_a_thread(home, release), CheckError)


@pytest.mark.skipif(sys.platform == "win32", reason="Windows has no pipe in the file system (os.mkfifo)")
def test_a_fifo_that_holds_valid_json_is_still_not_a_file(home):
    fifo = home / "checks.json"
    os.mkfifo(fifo, 0o600)
    holder = os.open(fifo, os.O_RDWR)  # keeps the pipe open, so that reading it has data and never ends
    try:
        os.write(holder, document(entry()))
        assert isinstance(load_on_a_thread(home, lambda: os.close(holder)), CheckError)
    finally:
        try:
            os.close(holder)
        except OSError:
            pass


def test_a_symlink_is_never_followed(home, tmp_path):
    other = tmp_path / "other"
    other.mkdir()
    target = other / "elsewhere.json"
    target.write_bytes(document(entry(account="from-the-link")))
    target.chmod(0o600)
    (home / "checks.json").symlink_to(target)
    with pytest.raises(CheckError):
        load_checks(home)
    with pytest.raises(CheckError):  # nor are its records merged into a new file
        save_check(home, check(account="mine"))
    assert (home / "checks.json").is_symlink()
    assert target.read_bytes() == document(entry(account="from-the-link"))


def test_a_dangling_symlink_is_damaged_not_missing(home, tmp_path):
    (home / "checks.json").symlink_to(tmp_path / "nowhere.json")
    with pytest.raises(CheckError):
        load_checks(home)
    with pytest.raises(CheckError):
        save_check(home, check())
    assert (home / "checks.json").is_symlink()


@pytest.mark.parametrize("mode", [0o666, 0o662, 0o660, 0o622, 0o620, 0o606, 0o602])
@pytest.mark.skipif(sys.platform == "win32", reason="a file mode means nothing on Windows: the folder decides who may read a file")
def test_a_file_that_group_or_others_can_write_is_damaged(home, mode):
    (home / "checks.json").write_bytes(document(entry()))
    (home / "checks.json").chmod(mode)
    with pytest.raises(CheckError):
        load_checks(home)


@pytest.mark.parametrize("mode", [0o600, 0o640, 0o644, 0o400])
def test_a_file_that_others_can_only_read_is_accepted(home, mode):
    (home / "checks.json").write_bytes(document(entry()))
    (home / "checks.json").chmod(mode)
    assert load_checks(home) == [check()]


def test_the_file_may_be_64_kib_and_not_a_byte_more(home):
    path = home / "checks.json"
    body = document(entry())
    for size, accepted in ((65536, True), (65537, False)):
        path.write_bytes(body + b" " * (size - len(body)))  # still valid json, only padded
        path.chmod(0o600)
        if accepted:
            assert load_checks(home) == [check()]
        else:
            with pytest.raises(CheckError):
                load_checks(home)


def test_a_huge_file_is_refused_without_reading_it_whole(home):
    path = home / "checks.json"
    path.write_bytes(document(entry()) + b" " * (8 * 1024 * 1024))
    path.chmod(0o600)
    tracemalloc.start()
    try:
        with pytest.raises(CheckError):
            load_checks(home)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 1024 * 1024


def test_save_does_not_write_a_file_that_load_would_refuse_for_its_size(home):
    saved = 0
    with pytest.raises(ValueError):
        for i in range(600):
            save_check(home, check(account=f"acc{i}"))
            saved += 1
    assert 100 < saved < 600  # a handful of accounts is far from the limit
    assert len(load_checks(home)) == saved  # the last good file is still there and readable


def test_save_does_not_overwrite_a_damaged_file(home):
    (home / "checks.json").write_bytes(b'{"version": 1, "checks": [')
    with pytest.raises(CheckError):
        save_check(home, check())
    assert (home / "checks.json").read_bytes() == b'{"version": 1, "checks": ['


@pytest.mark.parametrize(
    "bad",
    [
        check(provider="gemini2"),
        check(training="maybe"),
        check(memory="OFF"),
        check(account="my account"),
        check(account="a" * 65),
        check(source="page"),
        check(checked_at="yesterday"),
        check(checked_at="20261001"),
    ],
    ids=["provider", "training", "memory", "account space", "account long", "source", "date words", "date compact"],
)
def test_save_refuses_a_check_that_load_would_call_damaged(home, bad):
    with pytest.raises(ValueError):
        save_check(home, bad)
    assert not (home / "checks.json").exists()


def test_file_is_private(home):
    old = os.umask(0o022)  # a loose umask must not leak into the file
    try:
        save_check(home, check())
        first = stat.S_IMODE((home / "checks.json").stat().st_mode)
        save_check(home, check(training="on"))
    finally:
        os.umask(old)
    assert first == stat.S_IMODE((home / "checks.json").stat().st_mode) and mode_is(home / "checks.json", 0o600)
    assert not list(home.glob("*.part"))


def test_a_planted_link_at_the_part_name_is_not_followed(home, tmp_path):
    target = tmp_path / "elsewhere.txt"
    target.write_text("keep")
    (home / "checks.json.part").symlink_to(target)
    save_check(home, check())
    assert target.read_text() == "keep" and load_checks(home) == [check()]


@pytest.mark.skipif(sys.platform == "win32", reason="Windows has no pipe in the file system (os.mkfifo)")
def test_a_fifo_at_the_lock_name_is_an_error_not_a_hang(home):
    fifo = home / "checks.json.lock"  # this pipe hung the browser host: opening it for writing waits for a reader
    os.mkfifo(fifo)
    outcome = []

    def run():
        try:
            save_check(home, check())
        except BaseException as error:
            outcome.append(error)

    saver = threading.Thread(target=run, daemon=True)
    saver.start()
    saver.join(timeout=3)
    if saver.is_alive():
        os.close(os.open(fifo, os.O_RDONLY | os.O_NONBLOCK))  # a reader lets the stuck writer through
        saver.join(timeout=3)
        pytest.fail("save_check waits on a pipe")
    assert len(outcome) == 1 and isinstance(outcome[0], OSError)
    assert not (home / "checks.json").exists()


def test_parallel_saves_keep_every_account(home):
    barrier = threading.Barrier(8)

    def work(i):
        barrier.wait()
        for j in range(5):
            save_check(home, check(account=f"acc{i}-{j}"))

    with ThreadPoolExecutor(8) as pool:
        list(pool.map(work, range(8)))
    assert len(load_checks(home)) == 40


# ---- the signature: the file is believed only when the device key signed exactly what it says ----


def test_a_saved_file_is_signed_by_the_device_key_the_journal_uses(home):
    save_check(home, check())
    saved = json.loads((home / "checks.json").read_text())
    assert set(saved) == {"version", "checks", "sig"}
    content = {key: value for key, value in saved.items() if key != "sig"}
    public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(Journal(home / "journal.jsonl", default_keystore()).public_key_hex()))
    public.verify(bytes.fromhex(saved["sig"]), CONTEXT + json.dumps(content, sort_keys=True, separators=(",", ":")).encode())


def test_a_legacy_file_without_a_signature_is_not_believed(home):
    plant(home, json.dumps(unsigned(entry(training="off"))).encode())  # how boxed wrote it before files were signed: anybody could have
    with pytest.raises(CheckError) as caught:
        load_checks(home)
    assert str(caught.value) == FIXED


TAMPERED = {
    "an answer changed": lambda doc: doc["checks"][1].update(training="off"),
    "a date changed": lambda doc: doc["checks"][0].update(checked_at="2026-10-02"),
    "an account renamed": lambda doc: doc["checks"][0].update(account="you"),
    "a check dropped": lambda doc: doc["checks"].pop(),
    "a check added": lambda doc: doc["checks"].append(entry(account="extra")),
    "the order swapped": lambda doc: doc["checks"].reverse(),
    "the version changed": lambda doc: doc.update(version=2),
    "a key added": lambda doc: doc.update(note="x"),
    "the signature of another file": lambda doc: doc.update(sig=json.loads(document(entry(account="other")))["sig"]),
    "no signature": lambda doc: doc.pop("sig"),
    "an empty signature": lambda doc: doc.update(sig=""),
    "a short signature": lambda doc: doc.update(sig=doc["sig"][:-2]),
    "a long signature": lambda doc: doc.update(sig=doc["sig"] + "00"),
    "a signature that is not hex": lambda doc: doc.update(sig="z" * 128),
    "a signature in upper case": lambda doc: doc.update(sig=doc["sig"].upper()),
    "a signature that is a number": lambda doc: doc.update(sig=5),
    "a signature that is null": lambda doc: doc.update(sig=None),
    "a signature in a list": lambda doc: doc.update(sig=[doc["sig"]]),
}


@pytest.mark.parametrize("change", TAMPERED.values(), ids=TAMPERED.keys())
def test_a_file_that_the_signature_does_not_cover_is_not_believed(home, change):
    saved = json.loads(document(entry(), entry(account="work", training="on")))
    change(saved)
    plant(home, json.dumps(saved).encode())
    with pytest.raises(CheckError) as caught:
        load_checks(home)
    assert str(caught.value) == FIXED


def test_a_file_signed_by_another_key_is_not_believed(home, tmp_path):
    plant(home, document(entry(), keys=InsecureFileKeyStore(tmp_path / "another-device")))
    with pytest.raises(CheckError) as caught:
        load_checks(home)
    assert str(caught.value) == FIXED


def test_a_key_twice_in_the_file_is_damaged_so_that_nothing_in_it_is_outside_the_signature(home):
    text = document(entry()).decode().replace('{"version": 1, ', '{"version": 1, "version": 1, ')  # a parser keeps the last one
    assert text.count('"version"') == 2
    plant(home, text.encode())
    with pytest.raises(CheckError) as caught:
        load_checks(home)
    assert str(caught.value) == DAMAGED_TEXT


def test_save_does_not_sign_over_a_file_it_cannot_believe(home):
    legacy = json.dumps(unsigned(entry(account="old", training="off"))).encode()
    plant(home, legacy)
    with pytest.raises(CheckError) as caught:
        save_check(home, check())
    assert str(caught.value) == FIXED
    assert (home / "checks.json").read_bytes() == legacy  # nothing is signed in the person's place: boxed check reset moves the file aside


class UnusedKeys:
    def get_or_create(self, name, size):
        raise AssertionError("the key store was asked")


class LockedKeys:
    def get_or_create(self, name, size):
        raise RuntimeError("the keychain is locked")


class KeysThatLock:
    """The real key store for the first `served` requests, then a keychain that is locked."""

    def __init__(self, keys, served):
        self.keys, self.served = keys, served

    def get_or_create(self, name, size):
        if self.served <= 0:
            raise RuntimeError("the keychain is locked")
        self.served -= 1
        return self.keys.get_or_create(name, size)


def test_without_a_file_nothing_asks_for_the_key(home):
    assert load_checks(home, UnusedKeys()) == []


def test_the_key_store_can_be_handed_in(home, tmp_path):
    keys = InsecureFileKeyStore(tmp_path / "another-device")
    save_check(home, check(), keys)
    assert load_checks(home, keys) == [check()]
    with pytest.raises(CheckError) as caught:
        load_checks(home)  # the default key store holds another key
    assert str(caught.value) == FIXED


def test_a_key_store_that_fails_is_its_own_error_and_never_an_answer(home):
    save_check(home, check())
    before = (home / "checks.json").read_bytes()
    with pytest.raises(RuntimeError, match="locked"):
        load_checks(home, LockedKeys())
    with pytest.raises(RuntimeError, match="locked"):
        save_check(home, check(account="b"), LockedKeys())
    assert (home / "checks.json").read_bytes() == before and not list(home.glob("*.part"))


def test_a_save_that_cannot_sign_writes_nothing(home):
    with pytest.raises(RuntimeError, match="locked"):
        save_check(home, check(), LockedKeys())
    assert not (home / "checks.json").exists() and not list(home.glob("*.part"))


def test_a_save_that_fails_while_signing_leaves_the_old_file_whole(home, tmp_path):
    keys = InsecureFileKeyStore(tmp_path / "keys")
    save_check(home, check(), keys)
    before = (home / "checks.json").read_bytes()
    with pytest.raises(RuntimeError, match="locked"):
        save_check(home, check(account="b"), KeysThatLock(keys, served=1))  # the key reads the old file, then the keychain locks
    assert (home / "checks.json").read_bytes() == before and not list(home.glob("*.part"))
    assert load_checks(home, keys) == [check()]


def test_write_signs_the_document_it_is_given(home):  # boxed check remove builds the document itself and writes it with _write
    path = home / "checks.json"
    _write(path, json.dumps({"version": VERSION, "checks": [asdict(check())]}, indent=2) + "\n")
    assert "sig" in json.loads(path.read_text())
    assert load_checks(home) == [check()]


@pytest.mark.parametrize(
    "text",
    ['{"version": 1}', '{"version": 1, "checks": [], "sig": "00"}', "[]", "{", '{"version": 1, "checks": [{"provider": "bing"}]}'],
    ids=["no checks", "already signed", "a list", "not json", "a bad check"],
)
def test_write_refuses_a_document_that_load_would_refuse(home, text):
    with pytest.raises(ValueError):
        _write(home / "checks.json", text)
    assert not (home / "checks.json").exists() and not list(home.glob("*.part"))


# ---- every caller treats a file it cannot believe as unknown, never as training off ----

LEGACY = json.dumps(unsigned(entry(training="off"))).encode()  # right in every way but the signature, and it says training off
SET_OFF = ["check", "set", "--provider", "claude", "--account", "me", "--training", "off", "--memory", "off"]


def run_cli(capsys, *argv):
    code = main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


def test_the_cli_lists_nothing_from_a_file_it_cannot_believe(boxed_env, capsys):
    boxed_env.mkdir(parents=True, exist_ok=True)
    path = plant(boxed_env, LEGACY)
    code, out, err = run_cli(capsys, "check", "list")
    assert code == 2 and out == "" and "personal-training" in err  # no line can read training off
    assert run_cli(capsys, *SET_OFF)[0] == 2
    assert run_cli(capsys, "check", "remove", "--provider", "chatgpt", "--account", "me")[0] == 2
    assert path.read_bytes() == LEGACY


def test_after_a_reset_the_person_confirms_again_and_the_file_is_signed(boxed_env, capsys):
    boxed_env.mkdir(parents=True, exist_ok=True)
    plant(boxed_env, LEGACY)
    assert run_cli(capsys, "check", "reset")[0] == 0
    assert run_cli(capsys, *SET_OFF)[0] == 0
    assert [(c.provider, c.training) for c in load_checks(boxed_env)] == [("claude", "off")]
    assert run_cli(capsys, "check", "list")[0] == 0


CHECK_SET_MESSAGE = {"cmd": "check-set", "provider": "claude", "account": "me", "training": "off", "memory": "off"}


def host_context(home):
    keys = default_keystore()
    return HostContext(home, Vault(home / "vault.db", keys), Journal(home / "journal.jsonl", keys), ProjectConfig(), observed_journal(home, keys))


def test_the_host_calls_a_file_it_cannot_believe_unreadable(boxed_env):
    boxed_env.mkdir(parents=True, exist_ok=True)
    path = plant(boxed_env, LEGACY)
    ctx = host_context(boxed_env)
    assert [handle({"cmd": "checks"}, ctx), handle(CHECK_SET_MESSAGE, ctx)] == [{"ok": False, "error": "checks unreadable"}] * 2
    assert path.read_bytes() == LEGACY


def test_a_locked_keychain_lists_no_checks_and_writes_nothing_through_the_cli_and_the_host(boxed_env, capsys, monkeypatch):
    boxed_env.mkdir(parents=True, exist_ok=True)
    save_check(boxed_env, check())
    path = boxed_env / "checks.json"
    before = path.read_bytes()
    ctx = host_context(boxed_env)
    monkeypatch.setattr("boxed.checks.default_keystore", LockedKeys)  # neither caller hands in a key store: both take the default one
    code, out, err = run_cli(capsys, "check", "list")
    assert code == 2 and out == "" and err.startswith("boxed: error: RuntimeError: ")  # nothing is listed, so no line can read training off
    assert run_cli(capsys, *SET_OFF)[0] == 2
    assert [handle({"cmd": "checks"}, ctx), handle(CHECK_SET_MESSAGE, ctx)] == [{"ok": False, "error": "internal error"}] * 2
    assert path.read_bytes() == before and not list(boxed_env.glob("*.part"))


def test_the_dashboard_gets_no_rows_from_a_file_it_cannot_believe(boxed_env):
    boxed_env.mkdir(parents=True, exist_ok=True)
    plant(boxed_env, LEGACY)
    assert _check_rows(boxed_env, datetime.now(UTC).date()) is None  # None says it could not be read; [] would say none are recorded


# ---- Windows: the same refusals through the platform layer, and a mode that means nothing there ----


def test_windows_a_reparse_point_at_checks_json_is_damaged_and_never_followed(home, fake_msvcrt, see_as):
    path = plant(home, document(entry()))
    see_as(path, st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT)  # a plain file by its mode, a junction or a placeholder for Windows
    with pytest.raises(CheckError) as caught:
        load_checks(home)
    assert str(caught.value) == DAMAGED_TEXT
    with pytest.raises(CheckError):  # nor are its records merged into a new file
        save_check(home, check(account="mine"))
    assert path.read_bytes() == document(entry())


@pytest.mark.parametrize("mode", [0o666, 0o662, 0o620, 0o602])
def test_windows_the_mode_of_a_file_says_nothing_so_the_file_is_not_judged_by_it(home, fake_msvcrt, mode):
    plant(home, document(entry())).chmod(mode)  # every file reads 0o666 there; the folder of the home decides who may write
    assert load_checks(home) == [check()]


def test_windows_a_link_planted_at_the_part_name_is_never_written_through(home, tmp_path, fake_msvcrt, monkeypatch):
    victim = tmp_path / "victim.txt"
    victim.write_text("keep")
    lstat, planted = os.lstat, []

    def lstat_then_plant_a_link(name, *args, **kwargs):  # the old part file was removed; a link takes its name right after the look
        try:
            found = lstat(name, *args, **kwargs)
        except OSError as error:
            found = error
        if os.fspath(name).endswith(".part") and not planted:
            planted.append(name)
            os.symlink(victim, name)
        if isinstance(found, OSError):
            raise found
        return found

    monkeypatch.setattr(os, "lstat", lstat_then_plant_a_link)
    with pytest.raises(OSError):
        save_check(home, check())
    assert planted and victim.read_text() == "keep" and not (home / "checks.json").exists()


def test_checks_json_has_line_feeds_only_where_a_text_file_gets_carriage_returns(home, crlf_text_files):
    """Windows writes \\r\\n for each \\n to a file opened as text: the file would be larger on disk than the size save_check counted,
    and one close to MAX_BYTES would not load again."""
    save_check(home, check())
    data = (home / "checks.json").read_bytes()
    assert b"\r" not in data and load_checks(home) == [check()]


def test_a_load_waits_for_the_writer_that_holds_the_lock(home):
    """Read and write under one lock: a file that is being replaced is not read half way, and a writer is not held up by a reader."""
    from boxed.locks import file_lock

    save_check(home, check())
    holding, release, outcome = threading.Event(), threading.Event(), []

    def writer():
        with file_lock(home / "checks.json"):
            holding.set()
            release.wait(10)

    threading.Thread(target=writer, daemon=True).start()
    assert holding.wait(5)
    reader = threading.Thread(target=lambda: outcome.append(load_checks(home)), daemon=True)
    reader.start()
    reader.join(0.3)
    assert reader.is_alive() and outcome == []  # waiting for the lock
    release.set()
    reader.join(5)
    assert outcome == [[check()]]


def test_a_load_of_nothing_makes_no_lock_file(home):
    assert load_checks(home) == [] and list(home.iterdir()) == []


def test_windows_a_save_waits_out_a_replace_that_a_reader_of_another_make_holds_up(home, fake_msvcrt, monkeypatch):
    replace, failures = os.replace, []
    default_keystore().get_or_create(SIGNING_KEY, 32)  # the key is there already: only the save of the checks is held up

    def held_twice(old, new):
        failures.append(1)
        if len(failures) <= 2:
            raise PermissionError(errno.EACCES, "Access is denied", str(new), 5)
        return replace(old, new)

    monkeypatch.setattr(os, "replace", held_twice)
    save_check(home, check())
    assert len(failures) == 3 and load_checks(home) == [check()]
