"""What differs between POSIX and Windows, in one place.

The rest of boxed asks this module for a file lock, for a file opened without following a link, for the question "is this file
private enough" and for the console; it never tests the platform itself. IS_WINDOWS is read when a function runs, so a test can
switch the branch.
"""

import codecs
import errno
import functools
import os
import stat
import sys
import time

try:
    import fcntl
except ImportError:  # Windows has no fcntl
    fcntl = None

IS_WINDOWS = sys.platform == "win32"
IS_MACOS = sys.platform == "darwin"  # the folders of the native host are known for macOS (and the registry for Windows) only
NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)  # POSIX: an open fails on a symbolic link. Windows has no such flag
NONBLOCK = getattr(os, "O_NONBLOCK", 0)  # POSIX: opening a pipe never waits for its other end. Windows has no pipes in the file system
_LOCK_POLL = 0.02  # seconds between two tries to take a lock that is waited for with an end, and on Windows
_REPLACE_WAIT, _REPLACE_POLL = 2.0, 0.02  # seconds a replace that something holds up is tried for on Windows, and between two tries
# CreateFileW: the access, what to do when the file is there or is not, who else may have it open, and "open a link itself"
_GENERIC_READ, _GENERIC_WRITE = 0x80000000, 0x40000000
_CREATE_NEW, _OPEN_EXISTING, _OPEN_ALWAYS = 1, 3, 4
_SHARE_ALL = 0x1 | 0x2 | 0x4  # read, write and delete: a reader does not keep a writer from replacing the file, as the C runtime's open did
_NORMAL, _OPEN_REPARSE_POINT = 0x80, 0x00200000


def _is_link(info: os.stat_result) -> bool:
    """A symbolic link, or any other reparse point (a junction, a mount point, a placeholder): Windows names the lot in one attribute."""
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT)


@functools.cache
def _kernel32():
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    return kernel32


def _create_file(path, flags: int) -> tuple[int, int]:
    """Windows: a descriptor for `path` and the attributes of what it stands for, from CreateFileW with FILE_FLAG_OPEN_REPARSE_POINT.
    That flag opens a link, a junction or any other reparse point itself and never what it points to, so a link met here, whenever it
    was put there, gives a handle to the link: nothing is made or touched behind it, with O_CREAT and with O_CREAT | O_EXCL alike.
    The file stays open for the others to read, write, delete and replace (the C runtime's os.open lets none delete or replace it),
    and the bytes are not translated. Not truncated: open_nofollow does that once it has looked at the attributes. Tests on other
    systems put a stand-in here."""
    import ctypes
    import msvcrt

    name = os.fspath(path)
    access = {os.O_RDONLY: _GENERIC_READ, os.O_WRONLY: _GENERIC_WRITE, os.O_RDWR: _GENERIC_READ | _GENERIC_WRITE}[flags & (os.O_WRONLY | os.O_RDWR)]
    if flags & os.O_CREAT:
        disposition = _CREATE_NEW if flags & os.O_EXCL else _OPEN_ALWAYS
    else:
        disposition = _OPEN_EXISTING
    sys.audit("open", name, None, flags)  # os.open tells the audit hooks (the test guard is one); a call that goes round it must
    kernel32 = _kernel32()
    handle = kernel32.CreateFileW(name, access, _SHARE_ALL, None, disposition, _NORMAL | _OPEN_REPARSE_POINT, None)
    if handle in (None, ctypes.c_void_p(-1).value):
        error = ctypes.get_last_error()
        raise OSError(None, ctypes.FormatError(error), name, error)
    try:
        fd = msvcrt.open_osfhandle(handle, os.O_APPEND if flags & os.O_APPEND else 0)
    except BaseException:
        kernel32.CloseHandle(handle)
        raise
    try:
        return fd, os.fstat(fd).st_file_attributes
    except BaseException:
        os.close(fd)
        raise


def open_nofollow(path, flags: int, mode: int = 0o600) -> int:
    """os.open that never follows a link at `path`, and never waits for the other end of a pipe.

    POSIX: O_NOFOLLOW | O_NONBLOCK. Windows has neither: a link or any other reparse point is looked for first and refused (ELOOP) before
    anything is opened, and a folder is named a folder (EISDIR; the system itself says "permission denied"). The open then asks not to
    follow a link (_create_file), so one that was put there after the look is opened as the link, and the attributes of what was opened
    say so: it is closed again and refused, and nothing was made behind it. The mode means little on Windows: the folder decides who
    can read the file."""
    if not IS_WINDOWS:
        return os.open(path, flags | NOFOLLOW | NONBLOCK, mode)
    try:
        before = os.lstat(path)
    except OSError:
        before = None  # the open says why, or makes the file
    if before is not None:
        if _is_link(before):
            raise OSError(errno.ELOOP, "a link or another reparse point", os.fspath(path))
        if stat.S_ISDIR(before.st_mode):
            raise OSError(errno.EISDIR, "a folder", os.fspath(path))
    fd, attributes = _create_file(path, flags)
    try:
        if attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise OSError(errno.ELOOP, "a link or another reparse point", os.fspath(path))
        if flags & os.O_TRUNC:
            os.ftruncate(fd, 0)  # only now: a link met by the open must not be emptied
    except BaseException:
        os.close(fd)
        raise
    return fd


def refuse_reparse_point(path) -> None:
    """For a file that only a library opens by its name (sqlite, for vault.db), where no descriptor can be checked: on Windows a link,
    a junction or any other reparse point at `path` is an OSError (ELOOP) before the file is touched; a name that is not there is
    left to the library to make. Not on macOS or Linux, where nothing changes: sqlite follows a link there, as it always did. The look
    and the open are two steps, so a link planted between them is not seen (open_nofollow compares afterwards; here there is nothing
    to compare)."""
    if not IS_WINDOWS:
        return
    try:
        info = os.lstat(path)
    except OSError:
        return
    if _is_link(info):
        raise OSError(errno.ELOOP, "a link or another reparse point", os.fspath(path))


def replace_file(source, target) -> None:
    """os.replace. On Windows it fails with "access denied" (a PermissionError) for as long as something else has the target open and
    reads it, the sharing rights of that other not mattering: a scanner, an indexer, a program of another make. Such a hold is short,
    so it is tried again every few milliseconds for about two seconds before the error is raised. Another error is raised at once."""
    if not IS_WINDOWS:
        os.replace(source, target)
        return
    deadline = time.monotonic() + _REPLACE_WAIT
    while True:
        try:
            os.replace(source, target)
            return
        except PermissionError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(_REPLACE_POLL)


class LockTimeout(TimeoutError):
    """A lock that another holds was not let go in the time lock_exclusive was given. An OSError, as any failure of a lock is."""


def lock_exclusive(fd: int, timeout: float | None = None) -> None:
    """Waits for, and takes, an exclusive lock on the file of `fd`; unlock lets it go, and so does closing the descriptor or ending the
    process. A lock belongs to its descriptor, so two descriptors of one file exclude each other, in one process or in two.

    With no `timeout` the wait has no end. With one (seconds), a lock that another still holds when it has passed is a LockTimeout: a
    process that hangs while it holds a lock would otherwise stop every other for ever.

    POSIX: flock. Windows: a lock on the first byte, which need not be inside the file. msvcrt.locking waits ten seconds at most in its
    blocking modes and then fails, and a holder may hold longer, so it is asked without waiting and asked again after a short sleep. A
    lock that is held by another is the only failure that is waited out; any other error is raised."""
    deadline = None if timeout is None else time.monotonic() + timeout
    if not IS_WINDOWS and deadline is None:
        fcntl.flock(fd, fcntl.LOCK_EX)
        return
    while True:
        try:
            if IS_WINDOWS:
                import msvcrt

                os.lseek(fd, 0, os.SEEK_SET)  # msvcrt locks from the offset of the descriptor, and the same region must be named to let it go
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except (BlockingIOError, PermissionError):  # EWOULDBLOCK, EACCES: held by another descriptor
            if deadline is not None and time.monotonic() >= deadline:
                raise LockTimeout(errno.ETIMEDOUT, "the lock is held by another") from None
            time.sleep(_LOCK_POLL)


def unlock(fd: int) -> None:
    if not IS_WINDOWS:
        fcntl.flock(fd, fcntl.LOCK_UN)
        return
    import msvcrt

    os.lseek(fd, 0, os.SEEK_SET)
    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)


HOME_OUTSIDE_PROFILE = "BOXED_HOME is outside your user profile, where other users of this computer may be able to change files: use a folder in your profile"


def refuse_home_outside_profile(home) -> None:
    """Windows: the boxed home must be in the profile of the user (the folders `~` and BOXED_HOME name, links and junctions followed).
    A profile is left to its user, SYSTEM and the administrators; a folder anywhere else gets the rights of its drive, and the root of
    C:\\ gives Authenticated Users the right to change files, so any user of the computer could replace the journal, checks.json or a
    lock file there. The rights of the folder are not read to decide: that needs a list of the principals that may be there, and the
    profiles of a domain carry administrator groups of their own, which would make a good home look bad. A ValueError of fixed words,
    before the folder is made. Not on macOS or Linux, where the home gets mode 700."""
    if not IS_WINDOWS:
        return
    profile = os.path.normcase(os.path.realpath(os.path.expanduser("~")))
    where = os.path.normcase(os.path.realpath(home))
    try:
        inside = os.path.commonpath([profile, where]) == profile
    except ValueError:  # another drive
        inside = False
    if not inside:
        from .errors import UserError

        raise UserError(HOME_OUTSIDE_PROFILE)


def private_enough(info: os.stat_result) -> bool:
    """Is the file one that only its owner can have changed? POSIX: nobody else can write it by its mode. Windows: yes, always. The
    mode bits of a file there say nothing (they read 0o666, or 0o444 for a file marked read-only), and who may write is the list of
    rights of the folder. The boxed home is in the profile of the user (refuse_home_outside_profile), and Windows leaves a profile to
    its user, SYSTEM and the administrators."""
    return IS_WINDOWS or not info.st_mode & 0o022


def owned_by_user(info: os.stat_result) -> bool:
    """Does the user running boxed own the file? POSIX: by the user number. Windows does not give it (st_uid is 0 for every file); the
    folder of the boxed home is what keeps another user out."""
    return IS_WINDOWS or info.st_uid == os.geteuid()


def user_temp_name(prefix: str) -> str:
    """The name of a folder of this user in the system's temporary folder. POSIX: one temporary folder for all users, so the name
    carries the user number. Windows: the temporary folder is the user's own (in the profile), the prefix is enough."""
    return prefix if IS_WINDOWS else f"{prefix}-{os.geteuid()}"


def private_folder(info: os.stat_result) -> bool:
    """Is it a folder (not a link to one) of this user that nobody else can read or change? Windows: the folder decides, see
    owned_by_user."""
    return stat.S_ISDIR(info.st_mode) and owned_by_user(info) and (IS_WINDOWS or not info.st_mode & 0o077)


def make_private(fd: int) -> None:
    """Takes the rights of the group and of others from the open file (mode 600). Not on Windows: there the mode is only the
    read-only mark, and fchmod needs write access to do even that."""
    if not IS_WINDOWS:
        os.fchmod(fd, 0o600)


def utf8_console() -> None:
    """boxed prints UTF-8 whatever the locale says. A masked text with Cyrillic letters must not fail on a console set to cp1252 or
    ASCII, nor leave in an encoding the next program does not read as UTF-8, and a failure must be reportable in any language. A
    stream that is not UTF-8 is switched to it before anything is written; it keeps its own error handler (stderr never raises).
    On Windows the lines end in \\n too: a pipe there turns each \\n into \\r\\n, and a masked text must come out as it went in."""
    for stream in (sys.stdout, sys.stderr):
        if not hasattr(stream, "reconfigure"):
            continue
        encoding = getattr(stream, "encoding", None)
        if isinstance(encoding, str) and codecs.lookup(encoding).name != "utf-8":
            stream.reconfigure(encoding="utf-8", errors=stream.errors)
        if IS_WINDOWS:
            stream.reconfigure(newline="\n")


def sandboxed() -> bool:
    """Is this process under a macOS sandbox profile? `boxed run` starts the agent under one, and the agent starts the MCP server, so
    the server is. False elsewhere, and where the system cannot say."""
    if sys.platform != "darwin":
        return False
    try:
        import ctypes

        library = ctypes.CDLL("/usr/lib/libsandbox.1.dylib")
        library.sandbox_check.restype = ctypes.c_int
        return library.sandbox_check(os.getpid(), None, 0) == 1  # no operation named: is there a profile at all
    except (OSError, AttributeError):
        return False


# GetDriveTypeW: removable, fixed, CD-ROM, RAM disk. 4 is a network drive; 0 and 1 (unknown, no such root) are no local disk either
_LOCAL_DRIVES = {2, 3, 5, 6}


def local_drive(drive: str) -> bool:
    """Windows: is the drive letter `drive` ("C:") a disk of this computer, not a network drive? Asks GetDriveTypeW, which looks
    at the root only. Tests on other systems put a stand-in here."""
    import ctypes

    return ctypes.windll.kernel32.GetDriveTypeW(drive + "\\") in _LOCAL_DRIVES


# The text of a refusal, the same wherever it is raised: a command that needs the macOS sandbox or the Claude Code hooks.
NOT_SUPPORTED_HERE = {
    command: f"boxed {command} is not supported on Windows yet" for command in ("run", "workspace", "mcp", "hook", "install claude", "install codex")
}


def not_supported_here(command: str) -> str:
    return NOT_SUPPORTED_HERE[command]


def refuse_on_windows(command: str) -> None:
    """A command that needs the macOS sandbox or the guard of the Claude Code hooks is refused on Windows, before it touches anything."""
    if IS_WINDOWS:
        from .errors import UserError

        raise UserError(NOT_SUPPORTED_HERE[command])
