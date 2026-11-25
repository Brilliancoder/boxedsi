"""The isolation of the suite itself (tests/conftest.py): every test has its own BOXED_HOME and file keys, and a guard fails a test
that reaches the real boxed home or the real keychain. Nothing here touches either: the guard is tried on a stand-in folder, and on
calls that it stops before the system is asked."""

import io
import os
import shutil
import sqlite3

import keyring
import pytest
from keyring.backend import KeyringBackend

from boxed.cli import main
from boxed.keys import InsecureFileKeyStore, KeyringKeyStore, default_keystore
from boxed.paths import boxed_home_path


def test_a_test_starts_with_its_own_boxed_home_and_file_keys(boxed_env, tmp_path):
    assert boxed_home_path() == boxed_env and boxed_env.parent == tmp_path
    assert os.environ["BOXED_KEYSTORE"] == "insecure-file"
    assert isinstance(default_keystore(), InsecureFileKeyStore)


def test_every_test_runs_under_the_guard(request):
    assert "guard" in request.fixturenames  # nothing here asks for it: it is on for all


# ---- the folders: tried on a stand-in that the guard takes for the real one ----


@pytest.fixture
def stand_in(tmp_path, guard):
    """A folder with a journal in it, and a file beside it, that the guard takes for the real boxed home."""
    folder = tmp_path / "pretend-real-home"
    folder.mkdir()
    (folder / "journal.jsonl").write_bytes(b"{}\n")  # three bytes: Windows would write \r\n for the \n of a text
    (tmp_path / "outside.txt").write_text("x")
    guard.protect(folder)
    return folder


# (what the test does to the folder, what must still be true after the refusal). A look at the file system (exists, stat) raises no
# event, so these checks do not trip the guard themselves.
TOUCHES = {
    "read a file": (lambda p: (p / "journal.jsonl").read_text(), lambda p: (p / "journal.jsonl").exists()),
    "write a file": (lambda p: (p / "new.txt").write_text("x"), lambda p: not (p / "new.txt").exists()),
    "append to a file": (lambda p: open(p / "journal.jsonl", "a").close(), lambda p: (p / "journal.jsonl").stat().st_size == 3),
    "list the folder": (lambda p: os.listdir(p), lambda p: True),
    "walk the folder": (lambda p: list(p.iterdir()), lambda p: True),
    "make a folder inside": (lambda p: (p / "sub").mkdir(), lambda p: not (p / "sub").exists()),
    "make the folder again": (lambda p: p.mkdir(parents=True, exist_ok=True), lambda p: True),
    "change the mode": (lambda p: os.chmod(p, 0o700), lambda p: (p.stat().st_mode & 0o777) != 0o700),
    "delete a file": (lambda p: (p / "journal.jsonl").unlink(), lambda p: (p / "journal.jsonl").exists()),
    "move a file in": (lambda p: os.replace(p.parent / "outside.txt", p / "moved.txt"), lambda p: (p.parent / "outside.txt").exists()),
    "move a file out": (lambda p: os.replace(p / "journal.jsonl", p.parent / "taken.txt"), lambda p: (p / "journal.jsonl").exists()),
    "copy a file in": (lambda p: shutil.copy(p.parent / "outside.txt", p), lambda p: not (p / "outside.txt").exists()),
    "open a database": (lambda p: sqlite3.connect(p / "vault.db").close(), lambda p: not (p / "vault.db").exists()),
    "link to a file in": (lambda p: os.symlink(p / "journal.jsonl", p.parent / "link"), lambda p: not (p.parent / "link").is_symlink()),
    "go into it": (lambda p: os.chdir(p), lambda p: os.getcwd() != str(p.resolve())),
    "name a file by a relative path": (lambda p: open(os.path.relpath(p / "journal.jsonl")).close(), lambda p: True),
    "name a file with dot dot": (lambda p: (p.parent / "nothing" / ".." / p.name / "journal.jsonl").read_text(), lambda p: True),
    "name a file in other letters": (lambda p: (p.parent / p.name.upper() / "journal.jsonl").read_text(), lambda p: True),
}


@pytest.mark.parametrize("touch, still_true", TOUCHES.values(), ids=TOUCHES.keys())
def test_a_test_that_touches_the_real_home_fails_and_nothing_is_touched(stand_in, guard, monkeypatch, touch, still_true):
    monkeypatch.chdir(stand_in.parent)  # a relative name starts here; the working directory comes back after the test
    with pytest.raises(AssertionError, match="real boxed home") as raised:
        touch(stand_in)
    assert "boxed_env" in str(raised.value)  # it says what to use instead
    assert guard.violations and still_true(stand_in)
    guard.forgive()


def test_other_folders_are_left_alone(stand_in, tmp_path, guard):
    neighbour = tmp_path / "pretend-real-home-2"  # the same beginning, another folder
    neighbour.mkdir()
    (neighbour / "a.txt").write_text("x")
    assert (neighbour / "a.txt").read_text() == "x" and os.listdir(neighbour) == ["a.txt"]
    assert (tmp_path / "outside.txt").read_text() == "x"
    assert stand_in.exists() and (stand_in / "journal.jsonl").stat().st_size == 3  # a look is not a touch
    assert guard.violations == []


def test_a_test_that_loses_boxed_home_is_stopped_where_the_default_folder_would_be_made(tmp_path, guard, monkeypatch, capsys):
    """BOXED_HOME gone, the way a test that unsets it or a hand-run command has it: boxed falls back to ~/.boxed of whoever runs it.
    Here the home of the user is a folder in tmp_path, and its .boxed stands in for the real one."""
    user = tmp_path / "user"
    user.mkdir()
    monkeypatch.setenv("HOME", str(user))
    monkeypatch.delenv("BOXED_HOME")
    guard.protect(user / ".boxed")
    monkeypatch.setattr("sys.stdin", io.StringIO("mail ivan@acme.com"))
    assert main(["mask", "--scope", "lost", "-"]) == 2
    out, err = capsys.readouterr()
    # the guard's refusal is an AssertionError, whose message the last line of boxed never shows
    assert out == "" and err.startswith("boxed: error: Refused: ") and "ivan@acme.com" not in err
    assert not (user / ".boxed").exists() and guard.violations  # nothing made: no folder, no vault, no key, no journal record
    guard.forgive()


PLACES = [
    ".boxed",
    ".boxed/journal.jsonl",
    ".boxed/workspaces/ws-1/a.txt",
    ".codex",
    ".codex/config.toml",
    ".codex/config.toml.bak",
    ".claude/projects",
    ".claude",
    ".claude/skills/some-skill/SKILL.md",
    ".claude/settings.json",
    ".claude/settings.local.json",  # audit reads both settings files of the user
    ".claude/plugins/installed_plugins.json",
    ".claude.json",
    ".agents",
    ".agents/skills/some-skill/SKILL.md",
    ".cursor/mcp.json",
    ".gemini/settings.json",
    ".openclaw/skills",
    ".clawdbot/skills",
    "Library/Application Support/Claude",
    "Library/Application Support/Claude/claude_desktop_config.json",
    "Library/Application Support/Google/Chrome/NativeMessagingHosts",
    "Library/Application Support/Microsoft Edge/NativeMessagingHosts",
    "AppData/Local/boxed",  # Windows: install native-host writes the manifest and the launcher here
]


@pytest.mark.parametrize("place", PLACES)
def test_the_places_boxed_reads_or_writes_in_the_real_home_are_guarded(guard, place):
    """Stopped before the system is asked: nothing is read, made or changed there. A real home is the one the user database gives and
    the one HOME gave when the run began; they differ when a wrapper sets HOME."""
    assert guard.real_homes
    for home in guard.real_homes:
        with pytest.raises(AssertionError, match="real boxed home"):
            os.listdir(home / place)
    guard.forgive()


def test_the_home_of_the_user_is_not_itself_guarded(guard):
    assert all(str(home).casefold() not in guard.roots for home in guard.real_homes)


# ---- the keychain ----


class Memory(KeyringBackend):
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


def test_the_real_keychain_is_out_of_reach(guard):
    assert not type(keyring.get_keyring()).__module__.startswith("keyring.backends"), "a real keyring backend is the active one"
    calls = (
        lambda: keyring.get_password("boxed.si", "guard-probe"),
        lambda: keyring.set_password("boxed.si", "guard-probe", "a-secret-value"),
        lambda: keyring.delete_password("boxed.si", "guard-probe"),
        lambda: KeyringKeyStore().get_or_create("guard-probe", 32),
    )
    for call in calls:
        with pytest.raises(AssertionError, match="real keychain") as raised:
            call()
        assert "a-secret-value" not in str(raised.value)
    assert len(guard.violations) == len(calls)
    guard.forgive()


def test_a_test_can_put_in_its_own_keyring_and_the_guard_returns_after_it(guard, tmp_path, monkeypatch):
    for name in ("HOME", "USERPROFILE"):  # a first key is made under the lock of the user, in ~/.boxed
        monkeypatch.setenv(name, str(tmp_path))
    before = keyring.get_keyring()
    keyring.set_keyring(Memory())
    try:
        assert KeyringKeyStore().get_or_create("k", 32) == KeyringKeyStore().get_or_create("k", 32)
    finally:
        keyring.set_keyring(before)
    assert keyring.get_keyring() is before and guard.violations == []


def test_an_error_that_the_code_under_test_swallows_still_fails_the_test(guard):
    try:
        keyring.get_password("boxed.si", "guard-probe")
    except Exception:
        pass
    with pytest.raises(AssertionError, match="real keychain"):  # what the end of every test does
        guard.check()
    guard.forgive()
    guard.check()
