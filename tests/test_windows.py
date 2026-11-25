"""What only a real Windows can show: links and junctions made by the system itself, several processes at one journal, bytes through a pipe
in a code page that is not UTF-8. Every test here is skipped elsewhere; the Windows branches of boxed.platform run on any system, with
fakes, in test_platform.py."""

import errno
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

import boxed
from boxed.checks import Check, CheckError, load_checks, save_check
from boxed.journal import NOT_PLAIN, Journal, JournalEntry
from boxed.keys import InsecureFileKeyStore
from boxed.locks import file_lock
from boxed.mask import MarkerMap
from boxed.vault import Vault

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="needs a real Windows")

SRC = str(Path(boxed.__file__).resolve().parent.parent)


def entry():
    return JournalEntry(
        channel="mcp", provider="anthropic", account_type="subscription", level=2, markers_by_kind={"EMAIL": 2}, status="sent",
        payload_sha256="ab" * 32, coverage="full", scope="ws-1", versions={"boxed": "0.1.0"},
    )


def symlink(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=target.is_dir())
    except OSError as e:  # without the privilege, or the developer mode
        pytest.skip(f"cannot make a symbolic link here: {e}")


def junction(link: Path, target: Path) -> None:
    """A directory junction, which `mklink /J` makes without any privilege."""
    done = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True)
    assert done.returncode == 0, done.stdout + done.stderr


def make_link(kind: str, link: Path, target: Path) -> None:
    (symlink if kind == "symlink" else junction)(link, target)


KINDS = ["symlink", "junction"]


@pytest.fixture
def journal(tmp_path):
    return Journal(tmp_path / "journal.jsonl", InsecureFileKeyStore(tmp_path / "keys"))


OPERATIONS = {
    "append": lambda journal: journal.append(entry()),
    "read": lambda journal: journal.read(),
    "entries": lambda journal: journal.entries(),
    "verify": lambda journal: journal.verify(),
}


@pytest.mark.parametrize("operation", OPERATIONS.values(), ids=OPERATIONS.keys())
@pytest.mark.parametrize("kind", ["symlink", "dangling symlink", "junction"])
def test_a_link_or_a_junction_at_the_journal_path_is_refused_and_never_followed(journal, tmp_path, kind, operation):
    elsewhere = tmp_path / "elsewhere"
    if kind == "symlink":
        elsewhere = tmp_path / "elsewhere.jsonl"
        other = Journal(elsewhere, InsecureFileKeyStore(tmp_path / "keys"))  # the same device key: through the link it verifies
        other.append(entry())
        other.append(entry())
        before = elsewhere.read_bytes()
    elif kind == "dangling symlink":
        elsewhere = tmp_path / "nowhere.jsonl"
    else:
        elsewhere.mkdir()
        (elsewhere / "kept.txt").write_text("keep")
    make_link("junction" if kind == "junction" else "symlink", journal.path, elsewhere)
    with pytest.raises(OSError) as caught:
        operation(journal)
    assert str(caught.value) == NOT_PLAIN and caught.value.errno is None  # the same fixed words as for a pipe or a folder on macOS
    if kind == "symlink":
        assert elsewhere.read_bytes() == before
    elif kind == "dangling symlink":
        assert not elsewhere.exists()  # not even made: the open of Windows would have made it
    else:
        assert sorted(path.name for path in elsewhere.iterdir()) == ["kept.txt"]  # nothing was made inside


@pytest.mark.parametrize("kind", KINDS)
def test_a_link_or_a_junction_at_the_lock_name_is_refused_and_nothing_is_made_behind_it(tmp_path, kind):
    behind = tmp_path / "behind"
    behind.mkdir()
    make_link(kind, tmp_path / "data.json.lock", behind)
    with pytest.raises(OSError) as caught:
        with file_lock(tmp_path / "data.json"):
            pytest.fail("the lock was taken through a link")
    assert caught.value.errno == errno.ELOOP and list(behind.iterdir()) == []


@pytest.mark.parametrize("kind", KINDS)
def test_a_link_or_a_junction_at_checks_json_is_damaged_and_never_followed(tmp_path, kind):
    behind = tmp_path / "behind"
    behind.mkdir()
    make_link(kind, tmp_path / "checks.json", behind)
    with pytest.raises(CheckError):
        load_checks(tmp_path)
    with pytest.raises(CheckError):
        save_check(tmp_path, Check("chatgpt", "me", "off", "off", "asked", "2026-10-01"))
    assert list(behind.iterdir()) == []


def test_a_dangling_link_at_the_part_name_of_checks_json_is_replaced_and_its_target_is_not_made(tmp_path):
    symlink(tmp_path / "checks.json.part", tmp_path / "nowhere.txt")  # Windows follows a link even for O_CREAT | O_EXCL
    save_check(tmp_path, Check("chatgpt", "me", "off", "off", "asked", "2026-10-01"))
    assert not (tmp_path / "nowhere.txt").exists() and len(load_checks(tmp_path)) == 1


@pytest.mark.parametrize("name", ["vault.db", "vault.db-journal", "vault.db-wal", "vault.db-shm"])
@pytest.mark.parametrize("kind", ["symlink", "dangling symlink", "junction"])
def test_a_link_or_a_junction_at_vault_db_or_beside_it_is_refused_and_nothing_is_made_behind_it(tmp_path, kind, name):
    """SQLite opens the journal of a write by name beside the database and follows a link there on Windows: a file elsewhere grew by
    the journal (4500 bytes became 12824, with the journal magic at offset 0)."""
    keys = InsecureFileKeyStore(tmp_path / "keys")
    vault = Vault(tmp_path / "vault.db", keys) if name != "vault.db" else None  # a real vault, and the link planted beside it
    if kind == "symlink":
        behind = tmp_path / "behind.bin"
        behind.write_bytes(b"precious" * 600)
        before = behind.read_bytes()
    elif kind == "dangling symlink":
        behind = tmp_path / "nowhere.bin"
    else:
        behind = tmp_path / "behind"
        behind.mkdir()
    make_link("junction" if kind == "junction" else "symlink", tmp_path / name, behind)
    markers = MarkerMap()
    markers.marker_for("EMAIL", "ivan.petrov@acme.com")
    with pytest.raises(OSError) as caught:
        (vault or Vault(tmp_path / "vault.db", keys)).save_map("ws-9", markers)
    assert caught.value.errno == errno.ELOOP
    if kind == "symlink":
        assert behind.read_bytes() == before
    elif kind == "dangling symlink":
        assert not behind.exists()  # sqlite would have made it
    else:
        assert list(behind.iterdir()) == []


def test_a_file_open_for_reading_can_be_renamed_and_deleted_by_others_as_on_posix(tmp_path):
    """The C runtime opens a file without FILE_SHARE_DELETE: nobody else can rename or delete it while it is open. boxed opens with
    all three sharing rights, so `boxed check reset` can move checks.json aside under a reader, and a lock file can be removed.
    (os.replace over an open file still fails on Windows, share right or not: platform.replace_file waits for it.)"""
    from boxed.platform import open_nofollow

    path = tmp_path / "checks.json"
    path.write_text("old")
    fd = open_nofollow(path, os.O_RDONLY)
    try:
        os.rename(path, tmp_path / "checks.json.damaged")
        assert os.read(fd, 10) == b"old"  # the reader goes on reading the file it opened
        (tmp_path / "checks.json").write_text("new")
        os.unlink(tmp_path / "checks.json")
    finally:
        os.close(fd)


def test_appends_to_a_file_open_twice_land_one_after_the_other(tmp_path):
    from boxed.platform import open_nofollow

    path = tmp_path / "log"
    first, second = (open_nofollow(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT) for _ in range(2))
    try:
        os.write(first, b"one\n")
        os.write(second, b"two\n")  # the offset of this descriptor is 0, and append writes at the end all the same
        os.write(first, b"three\n")
    finally:
        os.close(first)
        os.close(second)
    assert path.read_bytes() == b"one\ntwo\nthree\n"


CHILD = """
import sys, time
from pathlib import Path

sys.path.insert(0, sys.argv[1])
from boxed.journal import Journal, JournalEntry
from boxed.keys import InsecureFileKeyStore

root, count, go = Path(sys.argv[2]), int(sys.argv[3]), Path(sys.argv[4])
journal = Journal(root / "journal.jsonl", InsecureFileKeyStore(root / "keys"))
while not go.exists():  # all of them start together
    time.sleep(0.001)
for _ in range(count):
    journal.append(JournalEntry(
        channel="mcp", provider="anthropic", account_type="subscription", level=2, markers_by_kind={}, status="sent",
        payload_sha256="ab" * 32, coverage="full", scope="ws-1",
    ))
"""


def test_processes_appending_at_once_never_reuse_a_sequence_number_or_interleave_a_line(journal, tmp_path):
    processes, each = 4, 25
    journal.public_key_hex()  # the key is made here, once: two processes making it at the same moment are not what is tested
    go = tmp_path / "go"
    children = [subprocess.Popen([sys.executable, "-c", CHILD, SRC, str(tmp_path), str(each), str(go)]) for _ in range(processes)]
    try:
        time.sleep(2)  # python and the imports take a moment to start in each
        go.write_text("go")
        assert [child.wait(timeout=180) for child in children] == [0] * processes
    finally:
        for child in children:
            child.kill()
    lines = journal.path.read_bytes().split(b"\n")
    assert lines[-1] == b"" and len(lines) == processes * each + 1  # every line whole, ended by a line feed, none joined to another
    assert sorted(json.loads(line)["seq"] for line in lines[:-1]) == list(range(1, processes * each + 1))
    assert b"\r" not in journal.path.read_bytes() and journal.verify().ok


def test_replace_waits_for_a_program_that_holds_the_file_and_goes_on_when_it_lets_go(tmp_path):
    """What a scanner that does not share delete does to the replace of a writer: "access denied" for as long as it holds the file."""
    import threading

    from boxed.platform import replace_file

    target, source = tmp_path / "checks.json", tmp_path / "checks.json.part"
    target.write_text("old")
    source.write_text("new")
    holder = os.open(target, os.O_RDONLY)  # the C runtime opens without FILE_SHARE_DELETE
    with pytest.raises(PermissionError):
        os.replace(source, target)  # this is what a plain replace does
    threading.Timer(0.4, os.close, args=(holder,)).start()
    start = time.monotonic()
    replace_file(source, target)
    assert time.monotonic() - start >= 0.3 and target.read_text() == "new" and not source.exists()


READER = """
import sys
from pathlib import Path

sys.path.insert(0, sys.argv[1])
from boxed.checks import CheckError, load_checks

home, stop = Path(sys.argv[2]), Path(sys.argv[3])
loads = damaged = other = 0
while not stop.exists():
    try:
        load_checks(home)
        loads += 1
    except CheckError:
        damaged += 1
    except Exception:
        other += 1
print(loads, damaged, other)
"""


def test_saves_and_loads_at_once_never_fail_and_never_read_a_good_file_as_damaged(tmp_path):
    """A stress run of readers beside a writer: 29 of 826 saves failed with WinError 5 (os.replace over a file that is being read),
    and 13 of 25,178 loads read a good checks.json as damaged. Both sides take the same lock now, and a replace that something
    else holds up is tried again for a moment."""
    from boxed.keys import default_keystore

    default_keystore().get_or_create("device-signing-key", 32)  # made once here: two processes making it at one moment are not what is tested
    home, stop = tmp_path / "home", tmp_path / "stop"
    home.mkdir()
    save_check(home, Check("chatgpt", "me", "off", "off", "asked", "2026-10-01"))
    readers = [subprocess.Popen([sys.executable, "-c", READER, SRC, str(home), str(stop)], stdout=subprocess.PIPE) for _ in range(2)]
    try:
        time.sleep(2)  # python and the imports take a moment to start in each
        for i in range(200):
            save_check(home, Check("chatgpt", f"acc{i % 20}", "off", "off", "asked", "2026-10-01"))
        stop.write_text("stop")
        counts = [tuple(int(n) for n in reader.communicate(timeout=120)[0].split()) for reader in readers]
    finally:
        for reader in readers:
            reader.kill()
    assert all(loads > 0 and damaged == 0 and other == 0 for loads, damaged, other in counts), counts


def test_a_masked_text_leaves_the_program_as_utf8_with_its_line_ends_through_a_pipe(tmp_path):
    """A pipe on a Russian Windows is cp1251, and turns each line feed into a carriage return and a line feed."""
    environment = {name: value for name, value in os.environ.items() if name not in ("PYTHONUTF8", "PYTHONIOENCODING")}
    environment["BOXED_HOME"] = str(tmp_path / "home")
    text = "Привет, Иван!\nmail ivan@acme.com\r\nthe end\n"
    done = subprocess.run(
        [sys.executable, "-m", "boxed.cli", "mask", "--scope", "win", "-"], input=text.encode("utf-8"), capture_output=True, env=environment, timeout=120
    )
    assert done.returncode == 0, done.stderr
    assert done.stdout == "Привет, Иван!\nmail [EMAIL_1]\r\nthe end\n".encode("utf-8")  # as it went in: the \r\n kept, no \r added to a \n
    assert done.stderr == b"scope: win\n"


# ---- the boxed home must be in the profile of the user ----


@pytest.fixture
def profile(tmp_path, monkeypatch):
    """The profile of the user moved into the test: what `~` names on Windows is USERPROFILE."""
    folder = tmp_path / "profile"
    folder.mkdir()
    monkeypatch.setenv("USERPROFILE", str(folder))
    return folder


def test_a_junction_in_the_profile_to_a_folder_outside_it_does_not_make_the_home_inside(profile, tmp_path, monkeypatch):
    from boxed.paths import boxed_home

    outside = tmp_path / "outside"
    outside.mkdir()
    junction(profile / "link", outside)
    monkeypatch.setenv("BOXED_HOME", str(profile / "link" / "home"))
    with pytest.raises(ValueError, match="outside your user profile"):
        boxed_home()
    assert list(outside.iterdir()) == []


def test_the_case_of_the_letters_and_the_slashes_do_not_decide_where_the_home_is(profile, monkeypatch):
    from boxed.paths import boxed_home

    monkeypatch.setenv("BOXED_HOME", str(profile / "Boxed" / "Data").upper().replace("\\", "/"))
    assert boxed_home().is_dir() and (profile / "boxed" / "data").is_dir()


def test_the_default_home_is_in_the_profile_whatever_the_profile_is(profile, monkeypatch):
    from boxed.paths import boxed_home

    monkeypatch.delenv("BOXED_HOME")
    assert boxed_home() == profile / ".boxed" and (profile / ".boxed").is_dir()


def test_a_home_on_another_drive_is_refused_before_anything_is_made(profile, monkeypatch):
    from boxed.paths import boxed_home

    drive = "Y:" if profile.drive.upper() != "Y:" else "Z:"
    monkeypatch.setenv("BOXED_HOME", drive + "\\boxed-home-that-must-not-be-made")
    with pytest.raises(ValueError, match="outside your user profile"):
        boxed_home()
    assert not Path(drive + "\\boxed-home-that-must-not-be-made").exists()
