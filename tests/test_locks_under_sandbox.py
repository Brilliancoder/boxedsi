"""No lock of boxed is waited for without an end, a lock that is not a plain file is refused with words that
name no path, and sync takes the lock of the journal and checks it before it writes any original.

A process of the sandbox can hold a lock file through a descriptor that cannot write (flock asks for no right to write), and it
can take the lock file away and put a folder in its place. Before this, boxed mask, the prompt hook and boxed workspace sync waited
for ever on the first, and sync changed the original and then stopped on the second, with no record in the journal. No test touches
the real ~/.boxed or the keychain: conftest.py points BOXED_HOME at a temp folder and the keys at files."""

import errno
import os
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path

import pytest

from boxed import locks
from boxed.cli import main
from boxed.config import ProjectConfig
from boxed.journal import Journal, JournalEntry
from boxed.keys import InsecureFileKeyStore
from boxed.locks import file_lock
from boxed.platform import LockTimeout
from boxed.vault import Vault
from boxed.workspace import MARKER_FILE, create_workspace, sync_back

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="boxed workspace, hook and the sandbox are not supported on Windows yet")

HOLDER = (
    "import fcntl, os, sys\n"
    "fd = os.open(sys.argv[1], os.O_RDONLY)\n"  # read-only: a process that may not write the lock file can hold it all the same
    "fcntl.flock(fd, fcntl.LOCK_EX)\n"
    "print('held', flush=True)\n"
    "sys.stdin.read()\n"
)
BUSY = "boxed: error: another process holds a lock of boxed for too long; try again, or stop that process"


@contextmanager
def held_by_another_process(path: Path):
    """The lock of `path` is taken by a process of its own and kept until the block ends."""
    lock = path.with_name(path.name + ".lock")
    lock.touch()
    holder = subprocess.Popen([sys.executable, "-c", HOLDER, str(lock)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    try:
        assert holder.stdout.readline().strip() == "held"
        yield
    finally:
        holder.stdin.close()
        holder.wait(timeout=10)


@pytest.fixture
def quick(monkeypatch):
    """A lock that is held is given up on after half a second, not after the 30 that the real wait is."""
    monkeypatch.setattr(locks, "LOCK_TIMEOUT", 0.5)


def gives_up_quickly(action):
    started = time.monotonic()
    with pytest.raises(LockTimeout):
        action()
    assert time.monotonic() - started < 5


def test_a_lock_that_another_process_holds_is_given_up_on_after_the_timeout(tmp_path, quick):
    path = tmp_path / "data.json"
    with held_by_another_process(path):
        gives_up_quickly(lambda: file_lock(path).__enter__())


def test_the_lock_of_the_journal_the_vault_and_the_checks_all_have_an_end(boxed_env, quick):
    from boxed.checks import Check, save_check
    from boxed.paths import boxed_home

    home = boxed_home()
    keys = InsecureFileKeyStore(home / "insecure-keys")
    entry = JournalEntry("manual", "unknown", "unknown", 2, {}, "prepared", "0" * 64, "full", "s")
    for name, action in {
        "journal.jsonl": lambda: Journal(home / "journal.jsonl", keys).append(entry),
        "vault.db": lambda: Vault(home / "vault.db", keys).transaction("s").__enter__(),
        "checks.json": lambda: save_check(home, Check("chatgpt", "work", "off", "off", "asked", "2026-10-26")),
    }.items():
        with held_by_another_process(home / name):
            gives_up_quickly(action)


def test_a_command_that_waits_on_a_lock_gives_up_with_one_fixed_line(boxed_env, quick, capsys, monkeypatch):
    import io

    from boxed.paths import boxed_home

    home = boxed_home()
    Vault(home / "vault.db", InsecureFileKeyStore(home / "insecure-keys"))
    monkeypatch.setattr("sys.stdin", io.StringIO("mail ivan@acme.com"))
    with held_by_another_process(home / "vault.db"):
        assert main(["mask", "-"]) == 2
    out, err = capsys.readouterr()
    assert out == "" and err == BUSY + "\n"


@pytest.mark.parametrize("kind", ["folder", "link", "pipe"])
def test_a_lock_path_that_is_not_a_plain_file_is_refused_and_names_no_path(tmp_path, kind):
    lock = tmp_path / "data.json.lock"
    if kind == "folder":
        lock.mkdir()
    elif kind == "link":
        lock.symlink_to(tmp_path / "elsewhere")
    else:
        os.mkfifo(lock)
    with pytest.raises(OSError) as caught:
        with file_lock(tmp_path / "data.json"):
            pytest.fail("the lock was taken")
    assert caught.value.errno in (errno.EISDIR, errno.ELOOP, errno.ENXIO)
    assert str(tmp_path) not in str(caught.value)


# ---- sync: the lock of the journal is taken, and the journal checked, before any original is written ----


@pytest.fixture
def synced(tmp_path):
    repo = tmp_path / "project"
    repo.mkdir()
    (repo / "app.py").write_text("print('hi')\n")
    (repo / "mail.txt").write_text("write to ivan.petrov@acme.com\n")
    keys = InsecureFileKeyStore(tmp_path / "keys")
    home = tmp_path / "home"
    home.mkdir()
    vault, journal = Vault(home / "vault.db", keys), Journal(home / "journal.jsonl", keys)
    ws = create_workspace(repo, level=2, config=ProjectConfig(), vault=vault, journal=journal, home=home).workspace
    (ws.mirror / "app.py").write_text("print('hi')\n# edited by the agent\n")
    return repo, home, vault, journal, ws


def sync(synced, **kw):
    _, home, vault, journal, ws = synced
    return sync_back(ws.id, vault=vault, journal=journal, home=home, **kw)


def records(home: Path) -> int:
    return len((home / "journal.jsonl").read_text().splitlines())


def test_a_sync_whose_journal_cannot_be_locked_in_time_writes_nothing(synced, quick):
    repo, home, *_ = synced
    before = records(home)
    with held_by_another_process(home / "journal.jsonl"):
        with pytest.raises(ValueError, match="another boxed process holds the journal; nothing was synced"):
            sync(synced)
    assert (repo / "app.py").read_text() == "print('hi')\n" and records(home) == before


@pytest.mark.parametrize("kind", ["lock is a folder", "journal is a folder", "journal is a link"])
def test_a_sync_whose_journal_cannot_take_a_record_writes_nothing(synced, kind):
    repo, home, *_ = synced
    state_before = (home / "state" / f"{synced[4].id}.json").read_text()
    if kind == "lock is a folder":
        (home / "journal.jsonl.lock").unlink()
        (home / "journal.jsonl.lock").mkdir()
    else:
        journal = home / "journal.jsonl"
        journal.unlink()
        journal.mkdir() if kind == "journal is a folder" else journal.symlink_to(home / "elsewhere")
    with pytest.raises(ValueError, match="boxed cannot write its journal, so nothing was synced"):
        sync(synced)
    assert (repo / "app.py").read_text() == "print('hi')\n"
    assert (home / "state" / f"{synced[4].id}.json").read_text() == state_before


def test_a_dry_run_does_not_need_the_journal(synced, quick):
    repo, home, *_ = synced
    with held_by_another_process(home / "journal.jsonl"):
        report = sync(synced, dry_run=True)
    assert report.written == ["app.py"] and (repo / "app.py").read_text() == "print('hi')\n"


def test_a_sync_still_writes_the_original_and_one_record(synced):
    repo, home, *_ = synced
    before = records(home)
    report = sync(synced)
    assert report.written == ["app.py"] and (repo / "app.py").read_text().endswith("# edited by the agent\n")
    assert records(home) == before + 1


def test_the_journal_lock_is_free_again_after_a_sync(synced):
    repo, home, vault, journal, ws = synced
    sync(synced)
    with file_lock(home / "journal.jsonl", 1):  # not held by a sync that has ended
        pass
    journal.append(JournalEntry("manual", "unknown", "unknown", 2, {}, "prepared", "0" * 64, "full", "s"))
