"""file_lock: one holder at a time, and only ever on a plain file."""

import errno
import os
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

import boxed
from boxed.locks import file_lock
from support import mode_is

SRC = str(Path(boxed.__file__).resolve().parent.parent)


def lock_on_a_thread(path, release):
    """`with file_lock(path): pass` on a thread: None once it got through, or the error it raised. A lock that waits on a pipe
    never answers: `release` frees the thread, and the test fails."""
    outcome = []

    def run():
        try:
            with file_lock(path):
                outcome.append(None)
        except BaseException as error:
            outcome.append(error)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join(timeout=3)
    if thread.is_alive():
        release()
        thread.join(timeout=3)
        pytest.fail("file_lock waits on a pipe")
    return outcome[0]


def test_a_second_holder_waits_until_the_first_lets_go(tmp_path):
    path = tmp_path / "data.json"
    first_in, let_go, order = threading.Event(), threading.Event(), []

    def first():
        with file_lock(path):
            first_in.set()
            let_go.wait(10)
            order.append("first out")

    def second():
        with file_lock(path):
            order.append("second in")

    holder = threading.Thread(target=first)
    holder.start()
    assert first_in.wait(5)
    waiter = threading.Thread(target=second)
    waiter.start()
    time.sleep(0.3)  # long enough for a lock that does not hold to let the second one in
    assert order == []
    let_go.set()
    holder.join(5)
    waiter.join(5)
    assert order == ["first out", "second in"]


@pytest.mark.skipif(sys.platform == "win32", reason="a file mode means nothing on Windows: the folder decides who may read it")
def test_a_new_lock_file_is_private(tmp_path):
    old = os.umask(0)  # a file created with the default mode would now be open to everyone
    try:
        with file_lock(tmp_path / "data.json"):
            pass
    finally:
        os.umask(old)
    assert stat.S_IMODE((tmp_path / "data.json.lock").stat().st_mode) == 0o600


def test_a_lock_file_left_behind_still_works(tmp_path):
    lock = tmp_path / "data.json.lock"
    lock.write_text("left by an older run")  # not empty, and not private
    lock.chmod(0o644)
    with file_lock(tmp_path / "data.json"):
        pass
    with file_lock(tmp_path / "data.json"):
        pass
    assert lock.read_text() == "left by an older run" and mode_is(lock, 0o644)


HOLDER = """
import sys, time
from pathlib import Path

sys.path.insert(0, sys.argv[1])
from boxed.locks import file_lock

with file_lock(Path(sys.argv[2])):
    print("locked", flush=True)
    time.sleep(60)
"""


def test_a_holder_that_crashed_does_not_keep_the_lock(tmp_path):
    path = tmp_path / "data.json"
    holder = subprocess.Popen([sys.executable, "-c", HOLDER, SRC, str(path)], stdout=subprocess.PIPE)
    try:
        assert holder.stdout.readline().strip() == b"locked"
        holder.kill()  # no chance to unlock or to remove the file
        holder.wait(timeout=10)
    finally:
        holder.kill()
        holder.stdout.close()
    assert (tmp_path / "data.json.lock").exists()
    assert lock_on_a_thread(path, lambda: None) is None


@pytest.mark.skipif(sys.platform == "win32", reason="a pipe at a file name is a POSIX thing: Windows has no mkfifo")
def test_a_fifo_at_the_lock_name_is_refused_not_waited_on(tmp_path):
    fifo = tmp_path / "checks.json.lock"  # this name, as a pipe, hung the browser host
    os.mkfifo(fifo)

    def release():  # a reader lets a writer that waits in open() through
        try:
            os.close(os.open(fifo, os.O_RDONLY | os.O_NONBLOCK))
        except OSError:
            pass

    assert isinstance(lock_on_a_thread(tmp_path / "checks.json", release), OSError)


@pytest.mark.skipif(sys.platform == "win32", reason="a pipe at a file name is a POSIX thing: Windows has no mkfifo")
def test_a_fifo_with_a_reader_is_still_not_a_lock_file(tmp_path, monkeypatch):
    import fcntl

    monkeypatch.setattr(fcntl, "flock", lambda fd, how: None)  # Linux locks a pipe without a word, macOS refuses: same for both
    fifo = tmp_path / "checks.json.lock"
    os.mkfifo(fifo, 0o600)
    reader = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)  # with a reader, opening the pipe for writing works at once
    try:
        assert isinstance(lock_on_a_thread(tmp_path / "checks.json", lambda: None), OSError)
    finally:
        os.close(reader)


def test_a_folder_at_the_lock_name_is_refused(tmp_path):
    (tmp_path / "data.json.lock").mkdir()
    assert isinstance(lock_on_a_thread(tmp_path / "data.json", lambda: None), OSError)


@pytest.mark.parametrize("existing", [True, False], ids=["to a file", "dangling"])
def test_a_symlink_at_the_lock_name_is_refused(tmp_path, existing):
    target = tmp_path / "elsewhere"
    if existing:
        target.write_text("keep")
    link = tmp_path / "data.json.lock"
    link.symlink_to(target)
    with pytest.raises(OSError) as caught:
        with file_lock(tmp_path / "data.json"):
            pytest.fail("the lock was taken through a link")
    assert caught.value.errno == errno.ELOOP
    assert link.is_symlink()
    if existing:
        assert target.read_text() == "keep"
    else:
        assert not target.exists()  # not even created


# ---- Windows: the same lock as a byte lock of msvcrt, and the same refusals ----


def test_windows_the_lock_is_a_byte_lock_and_not_flock(windows_os, tmp_path):
    with file_lock(tmp_path / "data.json"):  # windows_os: fcntl does not exist for boxed.platform
        assert len(windows_os.held) == 1  # held while the block runs
    assert windows_os.held == {}  # and let go after it


def test_windows_a_reparse_point_at_the_lock_name_is_refused_and_nothing_is_locked(fake_msvcrt, tmp_path, see_as, handed_out, is_open):
    lock = tmp_path / "data.json.lock"
    lock.write_text("keep")
    see_as(lock, st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT)
    with pytest.raises(OSError) as caught:
        with file_lock(tmp_path / "data.json"):
            pytest.fail("the lock was taken on a reparse point")
    assert caught.value.errno == errno.ELOOP
    assert fake_msvcrt.held == {} and lock.read_text() == "keep"
    assert not any(is_open(fd) for fd in handed_out)


def test_windows_a_lock_that_cannot_be_taken_is_an_error_and_leaves_no_descriptor_open(fake_msvcrt, tmp_path, monkeypatch, handed_out, is_open):
    def broken(fd, mode, nbytes):
        raise OSError(errno.ENOLCK, "No locks available")  # a file system without byte locks

    monkeypatch.setattr(fake_msvcrt, "locking", broken)
    with pytest.raises(OSError) as caught:
        with file_lock(tmp_path / "data.json"):
            pytest.fail("the block ran without a lock")
    assert caught.value.errno == errno.ENOLCK
    assert not any(is_open(fd) for fd in handed_out)


WHOLE_CORE = """
import os, sys

sys.path.insert(0, sys.argv[1])
sys.modules["fcntl"] = None  # `import fcntl` now raises ImportError, as on Windows
for name in ("O_NOFOLLOW", "O_NONBLOCK"):
    if hasattr(os, name):
        delattr(os, name)
from boxed.cli import main

sys.exit(main(["--version"]))
"""


def test_the_core_starts_where_fcntl_and_the_open_flags_do_not_exist():
    """Windows has neither: boxed --help died there with ModuleNotFoundError: No module named 'fcntl'."""
    done = subprocess.run([sys.executable, "-c", WHOLE_CORE, SRC], capture_output=True, text=True, timeout=60)
    assert (done.returncode, done.stdout.strip()) == (0, f"boxed {boxed.__version__}"), done.stderr
