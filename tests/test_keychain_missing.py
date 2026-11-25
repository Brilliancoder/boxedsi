"""A computer without a system keychain (a Linux server or container with no Secret Service): the commands that need a key say so in
fixed words, and the commands that only read still show what they found."""

import io
import json
import os
import stat
import sys
import tempfile

import keyring
import pytest
from keyring.backend import KeyringBackend
from keyring.errors import KeyringLocked, NoKeyringError

from boxed.cli import main
from boxed.errors import UserError
from boxed.keys import KEYCHAIN_MISSING, LOCK_FOLDER_UNSAFE, KeyringKeyStore
from boxed.skills.record import load_record

RAW = "No recommended backend was available"  # what keyring itself says


class NoKeychain(KeyringBackend):
    priority = 1

    def __init__(self, error=NoKeyringError):
        super().__init__()
        self.error = error

    def get_password(self, service, username):
        raise self.error(RAW)

    def set_password(self, service, username, password):
        raise self.error(f"{RAW} {password}")

    def delete_password(self, service, username):
        raise self.error(RAW)


@pytest.fixture
def no_keychain(monkeypatch):
    monkeypatch.setenv("BOXED_KEYSTORE", "keyring")
    previous = keyring.get_keyring()
    keyring.set_keyring(NoKeychain())
    yield
    keyring.set_keyring(previous)


@pytest.mark.parametrize("error", [NoKeyringError, KeyringLocked, RuntimeError])
def test_the_keystore_says_in_fixed_words_that_there_is_no_keychain(error):
    previous = keyring.get_keyring()
    keyring.set_keyring(NoKeychain(error))
    try:
        with pytest.raises(ValueError) as e:
            KeyringKeyStore().get_or_create("journal-key", 32)
    finally:
        keyring.set_keyring(previous)
    assert str(e.value) == KEYCHAIN_MISSING and e.value.__cause__ is None and e.value.__suppress_context__
    assert KEYCHAIN_MISSING == KEYCHAIN_MISSING.lower() and "secret service" in KEYCHAIN_MISSING


def test_mask_without_a_keychain_stops_with_the_fixed_text(no_keychain, monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO("mail ivan@acme.com"))
    assert main(["mask", "-"]) == 2
    out, err = capsys.readouterr()
    assert out == "" and err == f"boxed: error: {KEYCHAIN_MISSING}\n" and RAW not in err


@pytest.fixture
def skills_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    skill = home / ".claude" / "skills" / "calm-skill" / "SKILL.md"
    skill.parent.mkdir(parents=True)
    skill.write_text("---\nname: calm-skill\ndescription: demo\n---\nSay hello.\n")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    (tmp_path / "cwd").mkdir()
    monkeypatch.chdir(tmp_path / "cwd")
    return home


def test_skills_scan_shows_its_verdicts_without_a_keychain(no_keychain, skills_home, boxed_env, capsys):
    code = main(["skills", "scan"])
    out, err = capsys.readouterr()
    assert "OK  claude:skill:user:calm-skill" in out
    assert err.startswith("boxed: warning: the check was not saved") and RAW not in err
    assert code == 1  # all is ok, but the check was not saved
    assert load_record(boxed_env).items == {}  # neither half of it: no record without the signed journal entry
    code = main(["skills", "scan", str(skills_home / ".claude" / "skills" / "calm-skill")])
    out, err = capsys.readouterr()
    assert code == 0 and "calm-skill" in out and err == ""


def test_audit_still_runs_without_a_keychain(no_keychain, tmp_path, capsys):
    folder = tmp_path / "claude" / "-p"
    folder.mkdir(parents=True)
    line = {"type": "user", "message": {"role": "user", "content": "key AKIAIOSFODNN7EXAMPLE"}, "cwd": "/p", "sessionId": "s"}
    (folder / "s.jsonl").write_text(json.dumps(line) + "\n")
    assert main(["audit", "--claude-dir", str(tmp_path / "claude"), "--codex-dir", str(tmp_path / "none")]) == 0
    out, err = capsys.readouterr()
    assert "known key formats (1)" in out and "random for this run" in err and RAW not in err


# ---- the lock of the first key: ~/.boxed, or a folder of the user in the temporary folder ----


class MemoryKeychain(KeyringBackend):
    priority = 1

    def __init__(self):
        super().__init__()
        self.store = {}

    def get_password(self, service, username):
        return self.store.get((service, username))

    def set_password(self, service, username, password):
        self.store[(service, username)] = password

    def delete_password(self, service, username):
        self.store.pop((service, username), None)


POSIX_USER = pytest.mark.skipif(sys.platform == "win32" or os.geteuid() == 0, reason="POSIX permissions, not as root")


@pytest.fixture
def first_key(tmp_path, monkeypatch):
    """A keychain without the key yet, BOXED_HOME away from the home folder, and a temporary folder of the test's own."""
    monkeypatch.setenv("BOXED_HOME", str(tmp_path / "data"))
    temp = tmp_path / "tmp"
    temp.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(temp))
    previous = keyring.get_keyring()
    keyring.set_keyring(MemoryKeychain())
    yield temp
    keyring.set_keyring(previous)


@POSIX_USER
def test_the_first_key_is_made_when_the_home_folder_is_read_only(tmp_path, monkeypatch, first_key):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    home.chmod(0o500)
    try:
        key = KeyringKeyStore().get_or_create("journal-key", 32)
    finally:
        home.chmod(0o700)
    assert len(key) == 32 and KeyringKeyStore().get_or_create("journal-key", 32) == key
    assert not (home / ".boxed").exists()
    folder = first_key / f"boxed-{os.geteuid()}"
    assert (folder / "keychain.lock").is_file() and stat.S_IMODE(folder.lstat().st_mode) == 0o700


def test_the_first_key_is_made_when_the_home_folder_does_not_exist(tmp_path, monkeypatch, first_key):
    home = tmp_path / "gone" / "home"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    assert len(KeyringKeyStore().get_or_create("journal-key", 32)) == 32
    assert (home / ".boxed" / "keychain.lock").is_file()


@POSIX_USER
@pytest.mark.parametrize("planted", ["open", "link"])
def test_a_lock_folder_in_the_temporary_folder_that_others_could_change_is_refused(tmp_path, monkeypatch, first_key, planted):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    folder = first_key / f"boxed-{os.geteuid()}"
    if planted == "open":
        folder.mkdir(mode=0o777)
        folder.chmod(0o777)
    else:
        (tmp_path / "elsewhere").mkdir()
        folder.symlink_to(tmp_path / "elsewhere")
    home.chmod(0o500)
    try:
        with pytest.raises(UserError) as e:
            KeyringKeyStore().get_or_create("journal-key", 32)
    finally:
        home.chmod(0o700)
    assert str(e.value) == LOCK_FOLDER_UNSAFE
    assert not (tmp_path / "elsewhere" / "keychain.lock").exists()
