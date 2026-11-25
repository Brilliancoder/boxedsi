"""boxed.platform: what differs between POSIX and Windows, in one place.

Every function is tested on the branch of the system it runs on and, with fakes, on the other one: the `windows` fixture switches
IS_WINDOWS (read when a function runs), `fake_msvcrt` stands in for the byte locks of Windows, `see_as` for the attributes of a
junction. Tests marked windows_only need the real thing and run only there; posix_only ones need fcntl, modes or pipes."""

import errno
import io
import os
import stat
import subprocess
import sys
import threading
import time
import types
from pathlib import Path

import pytest

import boxed
from boxed import platform as host
from boxed.cli import main

SRC = str(Path(boxed.__file__).resolve().parent.parent)
posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX behaviour: fcntl, O_NOFOLLOW, file modes or pipes in the file system")
windows_only = pytest.mark.skipif(sys.platform != "win32", reason="needs a real Windows")


@pytest.fixture(params=["posix", "windows"])
def branch(request, monkeypatch):
    """Both branches of a function, on any system (the Windows one with fakes where the system is not Windows)."""
    if request.param == "posix" and sys.platform == "win32":
        pytest.skip("the POSIX branch needs a POSIX system")
    if request.param == "windows":
        request.getfixturevalue("windows")
    else:
        monkeypatch.setattr(host, "IS_WINDOWS", False)
    return request.param


def symlink(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError) as e:  # Windows without the privilege or the developer mode
        pytest.skip(f"cannot make a symbolic link here: {e}")


# ---- the flag, and an import where there is no fcntl and the open flags do not exist ----


@posix_only
def test_posix_is_not_windows_and_has_the_open_flags():
    assert host.IS_WINDOWS is False
    assert host.NOFOLLOW == os.O_NOFOLLOW != 0 and host.NONBLOCK == os.O_NONBLOCK != 0


@windows_only
def test_windows_is_windows_and_has_no_such_flags():
    assert host.IS_WINDOWS is True
    assert host.NOFOLLOW == 0 and host.NONBLOCK == 0


WITHOUT_POSIX = """
import os, sys

sys.path.insert(0, sys.argv[1])
sys.modules["fcntl"] = None  # `import fcntl` now raises ImportError, as on Windows
for name in ("O_NOFOLLOW", "O_NONBLOCK"):
    if hasattr(os, name):
        delattr(os, name)
from boxed import platform

print(platform.NOFOLLOW, platform.NONBLOCK)
"""


def test_the_layer_imports_where_fcntl_and_the_open_flags_do_not_exist():
    done = subprocess.run([sys.executable, "-c", WITHOUT_POSIX, SRC], capture_output=True, text=True, timeout=60)
    assert (done.returncode, done.stdout.split()) == (0, ["0", "0"]), done.stderr


# ---- open_nofollow ----


def test_a_plain_file_opens_and_reads(branch, tmp_path):
    path = tmp_path / "plain.txt"
    path.write_bytes(b"data")
    fd = host.open_nofollow(path, os.O_RDONLY)
    try:
        assert os.read(fd, 10) == b"data"
    finally:
        os.close(fd)


@pytest.mark.parametrize("flags", [os.O_RDONLY, os.O_WRONLY | os.O_CREAT, os.O_WRONLY | os.O_CREAT | os.O_EXCL], ids=["read", "create", "create-new"])
@pytest.mark.parametrize("target_is_there", [True, False], ids=["to a file", "dangling"])
def test_a_symlink_is_refused_and_its_target_is_left_alone(branch, tmp_path, target_is_there, flags):
    target = tmp_path / "elsewhere"
    if target_is_there:
        target.write_text("keep")
    link = tmp_path / "link"
    symlink(link, target)
    with pytest.raises(OSError) as caught:
        host.open_nofollow(link, flags)
    assert caught.value.errno in (errno.ELOOP, errno.EEXIST)  # POSIX says EEXIST for a link met by O_CREAT | O_EXCL
    assert (target.read_text() == "keep") if target_is_there else (not target.exists())  # not even created
    assert link.is_symlink()


def test_a_file_that_is_not_there_is_a_file_not_found_error(branch, tmp_path):
    with pytest.raises(FileNotFoundError):
        host.open_nofollow(tmp_path / "none", os.O_RDONLY)
    with pytest.raises(FileNotFoundError):
        host.open_nofollow(tmp_path / "no-folder" / "none", os.O_RDONLY)


def test_a_file_is_made_when_the_flags_say_so(branch, tmp_path):
    os.close(host.open_nofollow(tmp_path / "new", os.O_WRONLY | os.O_CREAT))
    assert (tmp_path / "new").is_file()


def test_making_a_file_that_is_there_already_fails_when_the_flags_say_so(branch, tmp_path):
    (tmp_path / "there").write_text("keep")
    with pytest.raises(FileExistsError):
        host.open_nofollow(tmp_path / "there", os.O_WRONLY | os.O_CREAT | os.O_EXCL)
    assert (tmp_path / "there").read_text() == "keep"


@posix_only
def test_posix_makes_a_new_file_private_from_its_first_byte(tmp_path):
    old = os.umask(0)  # a file made with the default mode would now be open to everyone
    try:
        os.close(host.open_nofollow(tmp_path / "new", os.O_WRONLY | os.O_CREAT))
    finally:
        os.umask(old)
    assert stat.S_IMODE((tmp_path / "new").stat().st_mode) == 0o600


@posix_only
def test_posix_never_waits_for_the_other_end_of_a_pipe(tmp_path):
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    outcome = []

    def run():
        try:
            outcome.append(host.open_nofollow(fifo, os.O_WRONLY))  # a plain open waits here until something reads
        except BaseException as error:
            outcome.append(error)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join(timeout=3)
    if thread.is_alive():
        os.close(os.open(fifo, os.O_RDWR | os.O_NONBLOCK))  # lets the stuck open through
        thread.join(timeout=3)
        pytest.fail("open_nofollow waits for the reader of a pipe")
    assert isinstance(outcome[0], OSError) and outcome[0].errno == errno.ENXIO


def test_windows_refuses_a_reparse_point_before_it_opens_anything(windows, tmp_path, see_as, handed_out):
    path = tmp_path / "journal.jsonl"
    path.write_text("keep")
    see_as(path, st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT)  # a file that is no link by its mode, but a reparse point
    with pytest.raises(OSError) as caught:
        windows.open_nofollow(path, os.O_WRONLY | os.O_TRUNC)
    assert caught.value.errno == errno.ELOOP
    assert handed_out == [] and path.read_text() == "keep"  # nothing was opened, so nothing was emptied


def test_windows_refuses_a_junction_as_a_link_and_not_as_a_folder(windows, tmp_path, see_as):
    junction = tmp_path / "journal.jsonl"
    junction.mkdir()  # a junction is a folder by its mode
    see_as(junction, st_file_attributes=stat.FILE_ATTRIBUTE_DIRECTORY | stat.FILE_ATTRIBUTE_REPARSE_POINT)
    with pytest.raises(OSError) as caught:
        windows.open_nofollow(junction, os.O_RDONLY)
    assert caught.value.errno == errno.ELOOP


def test_windows_says_that_a_folder_is_a_folder(windows, tmp_path):
    (tmp_path / "folder").mkdir()
    with pytest.raises(IsADirectoryError):  # the system itself says "permission denied" for a folder
        windows.open_nofollow(tmp_path / "folder", os.O_RDONLY)


@pytest.mark.parametrize(
    ("flags", "before"),
    [
        (os.O_RDONLY, "a plain file"),
        (os.O_WRONLY | os.O_CREAT, "a plain file"),
        (os.O_WRONLY | os.O_CREAT, "nothing"),
        (os.O_WRONLY | os.O_CREAT | os.O_EXCL, "nothing"),
    ],
    ids=["read a file", "create over a file", "create where nothing is", "create new where nothing is"],
)
def test_windows_a_link_planted_just_after_the_check_is_refused_and_the_target_is_not_made(windows, tmp_path, monkeypatch, flags, before):
    """The name is looked at, and a link is put there before the open: an open that follows it would make the file it points to, with
    O_CREAT and with O_CREAT | O_EXCL alike. The open itself must refuse a link, not only the look before it."""
    path, victim = tmp_path / "f", tmp_path / "victim"
    if before == "a plain file":
        path.write_text("x")
    lstat, planted = os.lstat, []

    def lstat_then_plant_a_link(name, *args, **kwargs):
        try:
            found = lstat(name, *args, **kwargs)
        except OSError as error:
            found = error
        if os.fspath(name) == os.fspath(path) and not planted:  # the look of open_nofollow at the name: the link comes right after it
            planted.append(name)
            if os.path.lexists(path):
                os.unlink(path)
            symlink(path, victim)  # to nothing
        if isinstance(found, OSError):
            raise found
        return found

    monkeypatch.setattr(os, "lstat", lstat_then_plant_a_link)
    with pytest.raises(OSError):
        windows.open_nofollow(path, flags)
    assert planted and not victim.exists()


def test_windows_closes_and_refuses_what_it_opened_when_the_handle_is_a_reparse_point(windows, tmp_path, monkeypatch, is_open):
    path = tmp_path / "f"
    path.write_text("x")
    create_file, opened = windows._create_file, []

    def says_reparse_point(name, flags):
        fd, attributes = create_file(name, flags)
        opened.append(fd)
        return fd, attributes | stat.FILE_ATTRIBUTE_REPARSE_POINT  # what the handle of a link, a junction or a placeholder reports

    monkeypatch.setattr(windows, "_create_file", says_reparse_point)
    with pytest.raises(OSError) as caught:
        windows.open_nofollow(path, os.O_RDONLY)
    assert caught.value.errno == errno.ELOOP and len(opened) == 1 and not is_open(opened[0])


def test_a_file_is_emptied_when_the_flags_say_so(branch, tmp_path):
    path = tmp_path / "f"
    path.write_text("old content")
    os.close(host.open_nofollow(path, os.O_WRONLY | os.O_TRUNC))
    assert path.read_bytes() == b""


@windows_only
def test_windows_reads_and_writes_the_bytes_as_they_are(tmp_path):
    path = tmp_path / "bytes"
    path.write_bytes(b"a\r\nb\x1ac\n")  # the C runtime's text mode would stop at the Ctrl-Z and turn the CRLF into LF
    fd = host.open_nofollow(path, os.O_RDONLY)
    try:
        assert os.read(fd, 100) == b"a\r\nb\x1ac\n"
    finally:
        os.close(fd)
    fd = host.open_nofollow(tmp_path / "written", os.O_WRONLY | os.O_CREAT)
    try:
        os.write(fd, b"x\ny\x1az\n")
    finally:
        os.close(fd)
    assert (tmp_path / "written").read_bytes() == b"x\ny\x1az\n"  # not x\r\ny


def test_a_file_that_only_a_library_opens_is_refused_when_it_is_a_link_on_windows_alone(branch, tmp_path):
    target, link = tmp_path / "target", tmp_path / "link"
    target.write_text("x")
    symlink(link, target)
    if branch == "windows":
        with pytest.raises(OSError) as caught:
            host.refuse_reparse_point(link)
        assert caught.value.errno == errno.ELOOP
    else:
        host.refuse_reparse_point(link)  # sqlite follows a link there, as it always did: macOS and Linux stay as they were
    host.refuse_reparse_point(tmp_path / "not-there")  # a name that is not there is left to the library, which makes it


# ---- the boxed home must be in the profile of the user ----


def test_windows_a_home_outside_the_profile_is_refused_before_anything_is_made(windows, tmp_path, monkeypatch):
    """A folder on C:\\ inherits Authenticated Users: Modify, so any user of the computer could replace the journal, checks.json and
    the lock files in it. A profile is left to its user, SYSTEM and the administrators."""
    from boxed.paths import boxed_home

    outside = tmp_path.parent / f"outside-{tmp_path.name}"
    monkeypatch.setenv("BOXED_HOME", str(outside))
    with pytest.raises(ValueError, match="outside your user profile"):
        boxed_home()
    assert not outside.exists()


@pytest.mark.parametrize("below", ["", "boxed-home", "a/b/c", ".boxed"], ids=["the profile itself", "a folder", "folders not there yet", "the default"])
def test_windows_a_home_in_the_profile_is_made(windows, tmp_path, monkeypatch, below):
    from boxed.paths import boxed_home

    monkeypatch.setenv("BOXED_HOME", str(tmp_path / below))
    assert boxed_home() == tmp_path / below and (tmp_path / below).is_dir()


def test_windows_a_link_in_the_profile_to_a_folder_outside_it_does_not_make_the_home_inside(windows, tmp_path, monkeypatch):
    from boxed.paths import boxed_home

    outside = tmp_path.parent / f"outside-{tmp_path.name}"
    outside.mkdir()
    symlink(tmp_path / "link", outside)  # a junction does the same on Windows; the real one is in test_windows.py
    monkeypatch.setenv("BOXED_HOME", str(tmp_path / "link" / "home"))
    with pytest.raises(ValueError, match="outside your user profile"):
        boxed_home()
    assert list(outside.iterdir()) == []


def test_windows_a_home_on_another_drive_is_outside_the_profile(windows, tmp_path, monkeypatch):
    from boxed.paths import boxed_home

    def other_drive(paths):
        raise ValueError("Paths don't have the same drive")

    monkeypatch.setattr(os.path, "commonpath", other_drive)
    with pytest.raises(ValueError, match="outside your user profile"):
        boxed_home()


@posix_only
def test_posix_the_home_may_be_anywhere(tmp_path, monkeypatch):
    from boxed.paths import boxed_home

    monkeypatch.setattr(host, "IS_WINDOWS", False)
    monkeypatch.setenv("HOME", str(tmp_path / "somebody"))
    monkeypatch.setenv("BOXED_HOME", str(tmp_path / "elsewhere"))
    assert boxed_home() == tmp_path / "elsewhere" and (tmp_path / "elsewhere").is_dir()  # macOS and Linux: the folder gets mode 700, as before


def test_windows_the_command_line_stops_at_a_home_outside_the_profile_and_makes_nothing(windows, tmp_path, monkeypatch, capsys):
    outside = tmp_path.parent / f"outside-{tmp_path.name}"
    monkeypatch.setenv("BOXED_HOME", str(outside))
    assert main(["journal", "verify"]) == 2
    out, err = capsys.readouterr()
    assert out == "" and err.startswith("boxed: error: BOXED_HOME is outside your user profile") and not outside.exists()


# ---- replace_file ----


def test_windows_replace_waits_for_a_file_that_another_holds_and_then_replaces_it(windows, tmp_path, monkeypatch):
    """A reader that opened the file without sharing delete (a scanner, an indexer) makes the replace fail with "access denied" for as
    long as it reads; a moment later the replace goes through."""
    source, target = tmp_path / "new", tmp_path / "checks.json"
    source.write_text("new")
    target.write_text("old")
    replaces, sleeps, replace = [], [], os.replace

    def held_three_times(old, new):
        replaces.append(1)
        if len(replaces) <= 3:
            raise PermissionError(errno.EACCES, "Access is denied", str(new), 5)
        return replace(old, new)

    monkeypatch.setattr(os, "replace", held_three_times)
    monkeypatch.setattr(time, "sleep", sleeps.append)
    windows.replace_file(source, target)
    assert target.read_text() == "new" and not source.exists()
    assert len(replaces) == 4 and len(sleeps) == 3 and all(0 < seconds <= 0.1 for seconds in sleeps)


def test_windows_replace_gives_up_after_a_while_with_the_error_of_the_system(windows, tmp_path, monkeypatch):
    source, target = tmp_path / "new", tmp_path / "checks.json"
    source.write_text("new")
    target.write_text("old")
    monkeypatch.setattr(windows, "_REPLACE_WAIT", 0.1)

    def held(old, new):
        raise PermissionError(errno.EACCES, "Access is denied", str(new), 5)

    monkeypatch.setattr(os, "replace", held)
    start = time.monotonic()
    with pytest.raises(PermissionError):
        windows.replace_file(source, target)
    assert 0.1 <= time.monotonic() - start < 3 and target.read_text() == "old"


@pytest.mark.parametrize("error", [FileNotFoundError(errno.ENOENT, "No such file"), IsADirectoryError(errno.EISDIR, "A folder")])
def test_windows_replace_does_not_wait_for_an_error_that_waiting_does_not_mend(windows, tmp_path, monkeypatch, error):
    replaces = []

    def broken(old, new):
        replaces.append(1)
        raise error

    monkeypatch.setattr(os, "replace", broken)
    with pytest.raises(type(error)):
        windows.replace_file(tmp_path / "a", tmp_path / "b")
    assert replaces == [1]


@posix_only
def test_posix_replace_is_os_replace_and_does_not_wait(tmp_path, monkeypatch):
    replaces = []

    def held(old, new):
        replaces.append(1)
        raise PermissionError(errno.EACCES, "Permission denied")

    monkeypatch.setattr(host, "IS_WINDOWS", False)
    monkeypatch.setattr(os, "replace", held)
    with pytest.raises(PermissionError):
        host.replace_file(tmp_path / "a", tmp_path / "b")
    assert replaces == [1]


# ---- lock_exclusive and unlock ----


@pytest.fixture(params=["posix", "windows, fake msvcrt", "windows"])
def lock_branch(request, monkeypatch):
    if request.param == "posix":
        if sys.platform == "win32":
            pytest.skip("needs fcntl")
        monkeypatch.setattr(host, "IS_WINDOWS", False)
    elif request.param == "windows, fake msvcrt":
        request.getfixturevalue("fake_msvcrt")
    elif sys.platform != "win32":
        pytest.skip("needs the real msvcrt")
    return request.param


def two_descriptors(tmp_path):
    path = tmp_path / "x.lock"
    return os.open(path, os.O_RDWR | os.O_CREAT, 0o600), os.open(path, os.O_RDWR)


def test_a_lock_taken_twice_blocks_the_second_taker_until_the_first_lets_go(lock_branch, tmp_path):
    first, second = two_descriptors(tmp_path)  # two descriptors of one file, as two holders have, in this process or in two
    got = threading.Event()

    def take():
        host.lock_exclusive(second)
        got.set()

    try:
        host.lock_exclusive(first)
        taker = threading.Thread(target=take, daemon=True)
        taker.start()
        assert not got.wait(0.3)  # still waiting
        host.unlock(first)
        assert got.wait(5)  # now it is through
        taker.join(5)
        host.unlock(second)
    finally:
        os.close(first)
        os.close(second)


def test_a_lock_can_be_taken_again_once_it_was_let_go(lock_branch, tmp_path):
    first, second = two_descriptors(tmp_path)
    try:
        for fd in (first, second, first):
            host.lock_exclusive(fd)
            host.unlock(fd)
    finally:
        os.close(first)
        os.close(second)


def test_windows_lets_go_of_the_region_it_locked_whatever_the_offset_of_the_descriptor_has_become(fake_msvcrt, tmp_path):
    fd, other = two_descriptors(tmp_path)
    try:
        os.write(fd, b"0123456789")  # the offset is at the end now
        host.lock_exclusive(fd)
        os.lseek(fd, 3, os.SEEK_SET)  # and somewhere else when the lock is let go
        host.unlock(fd)  # the lock of a region is let go by naming the same region
        assert fake_msvcrt.held == {}
    finally:
        os.close(fd)
        os.close(other)


def finishes(function, *args, within=3):
    """(True, what the call returned or raised) when it ends within `within` seconds; (False, None) while it still runs, as a loop
    that never ends would: a test of such a call must fail, not hang."""
    outcome = []

    def run():
        try:
            outcome.append(function(*args))
        except BaseException as error:
            outcome.append(error)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join(within)
    return not thread.is_alive(), (outcome[0] if outcome else None)


def test_windows_waits_on_a_lock_that_is_held_and_raises_any_other_failure(fake_msvcrt, tmp_path, monkeypatch):
    fd, other = two_descriptors(tmp_path)
    locking, attempts, sleeps = fake_msvcrt.locking, [], []

    def busy_three_times(fd, mode, nbytes):
        attempts.append(fd)
        if len(attempts) <= 3:
            raise PermissionError(errno.EACCES, "Permission denied")
        return locking(fd, mode, nbytes)

    def broken(fd, mode, nbytes):
        attempts.append(fd)
        raise OSError(errno.EBADF, "Bad file descriptor")

    try:
        with monkeypatch.context() as patch:
            patch.setattr(fake_msvcrt, "locking", busy_three_times)
            patch.setattr(time, "sleep", sleeps.append)  # no waiting in the test, but every wait is counted
            assert finishes(host.lock_exclusive, fd) == (True, None)
        assert len(attempts) == 4
        assert len(sleeps) == 3 and all(0 < seconds <= 0.1 for seconds in sleeps)  # a short sleep between tries, no busy loop
        attempts.clear()
        monkeypatch.setattr(fake_msvcrt, "locking", broken)
        done, error = finishes(host.lock_exclusive, fd)
        # not retried: a lock that cannot be taken is an error, and a loop that tried for ever would be no answer at all
        assert done and isinstance(error, OSError) and error.errno == errno.EBADF and len(attempts) == 1
    finally:
        os.close(fd)
        os.close(other)


def test_windows_waits_for_as_long_as_the_holder_holds_and_does_not_give_up_after_ten_seconds(fake_msvcrt, tmp_path):
    # msvcrt.locking in a blocking mode tries ten times, a second apart, and then fails: the fake fails at once, as if the time had gone by
    first, second = two_descriptors(tmp_path)
    outcome = []

    def take():
        try:
            host.lock_exclusive(second)
            outcome.append("locked")
        except OSError as error:
            outcome.append(error)

    try:
        host.lock_exclusive(first)
        taker = threading.Thread(target=take, daemon=True)
        taker.start()
        taker.join(0.3)
        assert taker.is_alive() and outcome == []  # still waiting, not failed
        host.unlock(first)
        taker.join(5)
        assert outcome == ["locked"]
    finally:
        os.close(first)
        os.close(second)


# ---- private_enough, owned_by_user, make_private ----


@pytest.mark.parametrize(
    "mode, private",
    [(0o600, True), (0o644, True), (0o640, True), (0o400, True), (0o620, False), (0o602, False), (0o660, False), (0o606, False), (0o666, False)],
)
def test_posix_a_file_is_private_enough_unless_the_group_or_others_can_write_it(mode, private, monkeypatch):
    if sys.platform == "win32":
        pytest.skip("the POSIX branch needs a POSIX system")
    monkeypatch.setattr(host, "IS_WINDOWS", False)
    assert host.private_enough(types.SimpleNamespace(st_mode=stat.S_IFREG | mode)) is private


def test_windows_modes_say_nothing_so_nothing_is_refused_for_them(windows):
    assert windows.private_enough(types.SimpleNamespace(st_mode=stat.S_IFREG | 0o666)) is True  # what every file reads there


@posix_only
def test_posix_a_file_is_the_users_when_the_effective_user_owns_it(tmp_path, monkeypatch):
    path = tmp_path / "f"
    path.write_text("x")
    info = path.stat()
    assert host.owned_by_user(info) is True
    monkeypatch.setattr(os, "geteuid", lambda: info.st_uid + 1)
    assert host.owned_by_user(info) is False


def test_windows_does_not_ask_who_owns_a_file(windows, monkeypatch):
    monkeypatch.delattr(os, "geteuid", raising=False)  # Windows has no geteuid, and st_uid is 0 for every file
    assert windows.owned_by_user(types.SimpleNamespace(st_uid=0)) is True


@posix_only
def test_posix_make_private_takes_the_rights_of_the_group_and_others_away(tmp_path):
    path = tmp_path / "f"
    path.write_text("x")
    path.chmod(0o644)
    fd = os.open(path, os.O_RDONLY)
    try:
        host.make_private(fd)
    finally:
        os.close(fd)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_windows_make_private_leaves_the_file_to_the_folder(windows, tmp_path, monkeypatch):
    monkeypatch.setattr(os, "fchmod", lambda *args: pytest.fail("fchmod on Windows needs write access and means nothing there"), raising=False)
    fd = os.open(tmp_path / "f", os.O_WRONLY | os.O_CREAT)
    try:
        windows.make_private(fd)
    finally:
        os.close(fd)


# ---- utf8_console ----


def stream(encoding, *, newline=None, errors="strict"):
    raw = io.BytesIO()
    return raw, io.TextIOWrapper(raw, encoding=encoding, errors=errors, newline=newline, write_through=True)


def test_a_stream_that_is_not_utf8_is_switched_and_keeps_its_error_handler(monkeypatch):
    (out_raw, out), (err_raw, err) = stream("cp1252"), stream("cp1252", errors="backslashreplace")
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", err)
    host.utf8_console()
    print("Привет", file=sys.stdout)
    print("Привет", file=sys.stderr)
    assert out_raw.getvalue() == "Привет\n".encode() and err_raw.getvalue() == "Привет\n".encode()
    assert (sys.stdout.errors, sys.stderr.errors) == ("strict", "backslashreplace")


def test_a_stream_that_is_utf8_already_is_left_as_it_is(monkeypatch):
    _, out = stream("UTF-8", errors="surrogateescape")
    monkeypatch.setattr(sys, "stdout", out)
    host.utf8_console()
    assert (out.encoding, out.errors) == ("UTF-8", "surrogateescape")  # not reconfigured: the spelling and the handler stay


def test_a_stream_that_cannot_be_reconfigured_is_skipped(branch, monkeypatch):
    monkeypatch.setattr(sys, "stdout", io.StringIO())
    monkeypatch.setattr(sys, "stderr", io.StringIO())
    host.utf8_console()


def test_windows_streams_write_line_feeds_and_not_carriage_returns(windows, monkeypatch):
    out_raw, out = stream("cp1251", newline="\r\n")  # what Python makes of a pipe on Windows: the code page, and \n becomes \r\n
    err_raw, err = stream("utf-8", newline="\r\n")
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", err)
    windows.utf8_console()
    sys.stdout.write("а\nб\n")
    sys.stderr.write("в\nг\n")
    assert out_raw.getvalue() == "а\nб\n".encode() and err_raw.getvalue() == "в\nг\n".encode()


# ---- the refusals ----


def test_the_refusal_text_is_fixed():
    assert host.not_supported_here("workspace") == "boxed workspace is not supported on Windows yet"
    assert host.not_supported_here("run") == "boxed run is not supported on Windows yet"


REFUSED = {"run": ["run", "claude"], "workspace": ["workspace", "list"], "mcp": ["mcp"], "hook": ["hook", "pre-tool-use"]}


@pytest.mark.parametrize("argv", REFUSED.values(), ids=REFUSED.keys())
def test_windows_refuses_run_workspace_mcp_and_the_hooks_before_it_touches_anything(windows_os, boxed_env, capsys, monkeypatch, argv):
    """The sandbox of macOS and the guard of the hooks are not there: nothing may look as if it were. A refusal leaves the data folder
    and the keys as they are, and it blocks (exit code 2) the way a hook that cannot run does."""
    monkeypatch.setattr(sys, "stdin", io.StringIO("{}"))
    assert main(argv) == 2
    out, err = capsys.readouterr()
    assert (out, err) == ("", f"boxed: error: boxed {argv[0]} is not supported on Windows yet\n")
    assert not boxed_env.exists()


def test_windows_the_sandbox_run_refuses(windows, tmp_path):
    from boxed.run import run_agent

    with pytest.raises(ValueError, match="boxed run is not supported on Windows yet"):
        run_agent("claude", [], cwd=tmp_path, home=tmp_path)


def test_windows_a_workspace_is_not_made(windows, tmp_path):
    from boxed.config import ProjectConfig
    from boxed.workspace import create_workspace

    with pytest.raises(ValueError, match="boxed workspace is not supported on Windows yet"):
        create_workspace(tmp_path, level=2, config=ProjectConfig(), vault=None, journal=None, home=tmp_path / "home")
    assert not (tmp_path / "home").exists()


def test_windows_the_mcp_server_is_not_built(windows):
    from boxed.mcp_server import build_server

    with pytest.raises(ValueError, match="boxed mcp is not supported on Windows yet"):
        build_server(None)
