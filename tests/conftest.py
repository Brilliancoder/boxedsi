"""Isolation for the whole suite. Every test gets its own BOXED_HOME and file keys, and a guard fails a test that reaches the real
boxed home or the real keychain, so a test can never leave a record or a key on the machine of whoever runs it.

The guard has two parts, both on for the whole run. An audit hook looks at every call that opens, makes, changes, lists or removes a
path and refuses, before the system is asked, one that lands in a real place. A keyring backend that refuses every call stands where
the keychain of the computer would. Each refusal is also written down, and the end of the test fails if the code under test caught the
error. A child process is not seen: the tests that start one pass it the environment of the test (a BOXED_HOME and file keys)."""

import errno
import os
import sys
import threading
import types
from pathlib import Path

import keyring
import pytest
from keyring.backend import KeyringBackend

try:
    import msvcrt as real_msvcrt
except ImportError:  # not Windows
    real_msvcrt = None

# What boxed itself reads or writes in the real home of the user when nothing says otherwise (paths.py, cli.py audit, install.py).
REAL_PLACES = (
    ".boxed",  # the vault, the journal, the checks, the mirrors
    ".codex",  # install codex writes config.toml; audit reads sessions
    ".claude/projects",  # audit reads the transcripts
    ".claude",  # boxed skills reads the skills, plugins, commands, agents and settings of Claude Code; audit reads the settings
    ".claude.json",  # ... and its MCP servers and the list of its projects
    ".agents",  # ... the cross-agent skills and their lock file
    ".cursor",  # ... the other agents it knows: MCP servers and skills
    ".gemini",
    ".openclaw",
    ".clawdbot",
    "Library/Application Support/Claude",  # Claude Desktop: claude_desktop_config.json
    "Library/Application Support/Google/Chrome/NativeMessagingHosts",  # install native-host writes a manifest
    "Library/Application Support/Microsoft Edge/NativeMessagingHosts",
    "AppData/Local/boxed",  # Windows: install native-host writes the manifest and the launcher
)
# The audit events that carry a path, with the places of the path in their arguments. A look (stat, exists, access) raises none.
PATH_EVENTS = {
    "open": (0,),
    "os.chdir": (0,),
    "os.chmod": (0,),
    "os.chown": (0,),
    "os.link": (0, 1),
    "os.listdir": (0,),
    "os.mkdir": (0,),
    "os.remove": (0,),
    "os.rename": (0, 1),
    "os.rmdir": (0,),
    "os.scandir": (0,),
    "os.symlink": (0, 1),
    "os.truncate": (0,),
    "os.utime": (0,),
    "sqlite3.connect": (0,),
}


class Refused(AssertionError):
    """What a refused call raises: an AssertionError, so that the test shows as failed with the reason."""


def _key(path) -> str:
    """A path as the guard compares it: absolute, with dot dot folded away, in no particular case (macOS ignores case)."""
    return os.path.abspath(os.fspath(path)).casefold().rstrip(os.sep)


def _user_homes() -> tuple[Path, ...]:
    """The home the user database names and the one HOME named when the run began; they differ when a wrapper sets HOME."""
    homes = {Path(os.path.expanduser("~"))}
    try:
        import pwd

        homes.add(Path(pwd.getpwuid(os.getuid()).pw_dir))
    except (ImportError, KeyError):  # no user database: Windows, or a container with a user that has no entry
        pass
    return tuple(sorted(homes))


class Guard:
    def __init__(self) -> None:
        self.real_homes = _user_homes()
        places = {home / place for home in self.real_homes for place in REAL_PLACES}
        self._real = tuple(sorted({_key(p) for p in places} | {_key(p.resolve()) for p in places}))
        self._stand_ins: list[str] = []
        self.roots = self._real
        self.violations: list[str] = []

    def protect(self, path) -> None:
        """Guard one more folder for this test: the tests of the guard use a stand-in for the real home."""
        self._stand_ins.append(_key(path))
        self.roots = self._real + tuple(self._stand_ins)

    def refuse(self, message: str) -> None:
        self.violations.append(message)
        raise Refused(message)

    def forgive(self) -> None:
        """Forget what was refused so far: for a test that provokes a refusal on purpose."""
        self.violations.clear()

    def check(self) -> None:
        if self.violations:
            raise Refused("this test reached what no test may touch:\n  " + "\n  ".join(self.violations))

    def reset(self) -> None:
        self.violations.clear()
        self._stand_ins.clear()
        self.roots = self._real


GUARD = Guard()
WAY_OUT = "the boxed_env of the test (a BOXED_HOME under tmp_path, file keys) or a folder under tmp_path"


def _audit(event: str, args: tuple) -> None:
    where = PATH_EVENTS.get(event)
    if where is None:
        return
    for i in where:
        arg = args[i] if i < len(args) else None
        if isinstance(arg, int):  # a file descriptor: the path was checked when it was opened
            continue
        try:
            path = _key("." if arg is None else os.fsdecode(arg))  # listdir and scandir without a path mean the working directory
        except (TypeError, ValueError, OSError):  # not a path (a connection handle), or no working directory to start from
            continue
        for root in GUARD.roots:
            if path == root or path.startswith(root + os.sep):
                GUARD.refuse(f"a test reached the real boxed home ({event} {path}): use {WAY_OUT}")


sys.addaudithook(_audit)


class NoRealKeychain(KeyringBackend):
    """Stands where the keychain of the computer would. A test that wants a keychain sets its own with keyring.set_keyring."""

    priority = 1

    def _refuse(self, action: str, service: str, username: str):
        # the password of set_password is left out of the message: it could be a key
        way_out = "BOXED_KEYSTORE=insecure-file (the boxed_env of the test sets it), or a backend of its own from keyring.set_keyring"
        GUARD.refuse(f"a test used the real keychain ({action} {service} {username}): use {way_out}")

    def get_password(self, service, username):
        self._refuse("get_password", service, username)

    def set_password(self, service, username, password):
        self._refuse("set_password", service, username)

    def delete_password(self, service, username):
        self._refuse("delete_password", service, username)


keyring.set_keyring(NoRealKeychain())


@pytest.fixture(autouse=True)
def guard():
    """On for every test. A refusal raised in the test fails it where it happened; one the code under test swallowed fails it here."""
    GUARD.reset()
    yield GUARD
    try:
        GUARD.check()
    finally:
        GUARD.reset()


@pytest.fixture(autouse=True)
def boxed_env(tmp_path, monkeypatch):
    """Every test gets its own BOXED_HOME and file keys: nothing touches ~/.boxed or the real keychain."""
    home = tmp_path / "boxed-home"
    monkeypatch.setenv("BOXED_HOME", str(home))
    monkeypatch.setenv("BOXED_KEYSTORE", "insecure-file")
    return home


# ---- the Windows branches of boxed.platform, on any system ----


def posix_create_file(path, flags):
    """What boxed.platform._create_file does, with the means of a POSIX system, for the tests of the Windows branch on one: O_NOFOLLOW
    refuses a link as FILE_FLAG_OPEN_REPARSE_POINT with a look at the attributes does, and nothing is made behind it. Not truncated,
    as on Windows; the attributes are those of the descriptor, which a test can change by wrapping this."""
    fd = os.open(path, flags & ~os.O_TRUNC | os.O_NOFOLLOW)
    return fd, getattr(os.fstat(fd), "st_file_attributes", 0)


@pytest.fixture
def macos(monkeypatch):
    """boxed.platform answers as on macOS, for a test that pins the macOS folders of the native host on any POSIX system."""
    from boxed import platform

    monkeypatch.setattr(platform, "IS_MACOS", True)
    return platform


@pytest.fixture
def windows(monkeypatch, tmp_path):
    """boxed.platform answers as on Windows: IS_WINDOWS is the one switch, and every function reads it when it runs. On a system that
    is not Windows, CreateFileW is replaced by posix_create_file. On every system the profile of the user is tmp_path (HOME for macOS
    and Linux, USERPROFILE for Windows): the boxed home of a test is below it, and a folder beside it is outside the profile."""
    from boxed import platform

    monkeypatch.setattr(platform, "IS_WINDOWS", True)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    if sys.platform != "win32":
        monkeypatch.setattr(platform, "_create_file", posix_create_file)
    return platform


class FakeMsvcrt:
    """The byte locks of Windows as msvcrt.locking has them. A lock covers nbytes from the current offset of a descriptor, and belongs
    to that descriptor (a handle, on Windows: another descriptor of this very process is refused too). While the file is locked,
    LK_NBLCK fails at once with EACCES; LK_LOCK, which waits ten seconds and then gives up, fails with EDEADLK, as if the ten seconds
    had gone by. LK_UNLCK of a lock the descriptor does not hold, or of another region than it locked, fails with EACCES."""

    LK_UNLCK, LK_LOCK, LK_NBLCK, LK_RLCK, LK_NBRLCK = 0, 1, 2, 3, 4

    def __init__(self) -> None:
        self.held: dict[int, tuple[int, int, int]] = {}  # file number -> (descriptor, offset, nbytes) of its lock
        self._guard = threading.Lock()

    def __getattr__(self, name):
        """The rest of msvcrt (open_osfhandle, for CreateFileW) is the real one where there is one: only the locks are faked."""
        if real_msvcrt is None:
            raise AttributeError(name)
        return getattr(real_msvcrt, name)

    def locking(self, fd: int, mode: int, nbytes: int) -> None:
        with self._guard:
            region = (fd, os.lseek(fd, 0, os.SEEK_CUR), nbytes)
            file = os.fstat(fd).st_ino
            if mode == self.LK_UNLCK:
                if self.held.get(file) != region:
                    raise PermissionError(errno.EACCES, "Permission denied")
                del self.held[file]
            elif file in self.held:
                if mode in (self.LK_LOCK, self.LK_RLCK):
                    raise OSError(errno.EDEADLK, "Resource deadlock avoided")
                raise PermissionError(errno.EACCES, "Permission denied")
            else:
                self.held[file] = region


@pytest.fixture
def fake_msvcrt(windows, monkeypatch):
    """`import msvcrt` finds a FakeMsvcrt, with the Windows branches on."""
    fake = FakeMsvcrt()
    monkeypatch.setitem(sys.modules, "msvcrt", fake)
    return fake


class OsWithoutWhatWindowsLacks:
    """What the modules of boxed see as `os` on Windows: the real module, except for the names Windows does not have."""

    MISSING = ("O_NOFOLLOW", "O_NONBLOCK", "geteuid", "fchmod", "mkfifo")

    def __init__(self, real) -> None:
        self._real = real

    def __getattr__(self, name):
        if name in self.MISSING:
            raise AttributeError(f"module 'os' has no attribute '{name}'")
        return getattr(self._real, name)


class FakeKey:
    """An open key of a FakeWinreg; `with` closes it."""

    def __init__(self, path: str) -> None:
        self.path = path

    def __enter__(self) -> "FakeKey":
        return self

    def __exit__(self, *error) -> None:
        return None


class FakeWinreg:
    """The part of winreg that boxed.install uses, over a tree of keys below HKEY_CURRENT_USER as the registry keeps it: SetValue makes
    every key on the way to the one it names, and they stay when that one is deleted; DeleteKey refuses a key that has subkeys; a key
    that is open tells how many subkeys and values it holds. `values` has the default value of each key that has one, `keys` each key
    that was made, with the number of values with names it holds (a test can put more in either: a key above a default value is there
    too). The other roots are not defined here, and the other value types are refused, so a call that names one fails."""

    HKEY_CURRENT_USER = "HKEY_CURRENT_USER"
    REG_SZ = 1
    KEY_READ = 0x20019

    def __init__(self) -> None:
        self.values: dict[str, str] = {}  # sub key -> its default value
        self.keys: dict[str, int] = {}  # sub key -> how many values with names it holds
        self.deleted: list[str] = []  # what DeleteKey was asked for, in order

    @staticmethod
    def _with_parents(path: str) -> set[str]:
        parts = path.split("\\")
        return {"\\".join(parts[: i + 1]) for i in range(len(parts))}

    def paths(self) -> set[str]:
        """Every key there is."""
        return set().union(*(self._with_parents(path) for path in (*self.values, *self.keys)))

    @staticmethod
    def _missing() -> FileNotFoundError:
        return FileNotFoundError(errno.ENOENT, "The system cannot find the file specified", None, 2)

    def SetValue(self, root, sub_key, kind, value) -> None:
        assert root == self.HKEY_CURRENT_USER and kind == self.REG_SZ and isinstance(value, str)
        for path in self._with_parents(sub_key):
            self.keys.setdefault(path, 0)
        self.values[sub_key] = value

    def QueryValue(self, root, sub_key) -> str:
        assert root == self.HKEY_CURRENT_USER
        if sub_key not in self.paths():
            raise self._missing()
        return self.values.get(sub_key, "")  # a key with no default value answers with an empty string

    def OpenKey(self, root, sub_key, reserved=0, access=KEY_READ) -> FakeKey:
        assert root == self.HKEY_CURRENT_USER
        if sub_key not in self.paths():
            raise self._missing()
        return FakeKey(sub_key)

    def QueryInfoKey(self, key: FakeKey) -> tuple[int, int, int]:
        """(subkeys, values, last write): the keys directly below it, and the values it holds, the default one among them."""
        below = {path[len(key.path) + 1 :].split("\\")[0] for path in self.paths() if path.startswith(key.path + "\\")}
        return len(below), (key.path in self.values) + self.keys.get(key.path, 0), 0

    def DeleteKey(self, root, sub_key) -> None:
        assert root == self.HKEY_CURRENT_USER
        self.deleted.append(sub_key)
        if sub_key not in self.paths():
            raise self._missing()
        if any(path.startswith(sub_key + "\\") for path in self.paths()):
            raise PermissionError(errno.EACCES, "Access is denied", None, 5)  # winreg does not delete a key that has subkeys
        self.values.pop(sub_key, None)
        self.keys.pop(sub_key, None)


@pytest.fixture(autouse=True)
def no_real_registry(request, monkeypatch):
    """No test writes to the registry of the user: `import winreg` finds a FakeWinreg, on every system. A test marked real_registry is
    the one exception, and it runs only when BOXED_TEST_REAL_REGISTRY=1 asks for it. (On Windows install_native_host would register a
    host that points into a temp folder, for every test that calls it.)"""
    if request.node.get_closest_marker("real_registry") is None:
        monkeypatch.setitem(sys.modules, "winreg", FakeWinreg())
    elif os.environ.get("BOXED_TEST_REAL_REGISTRY") != "1":
        pytest.skip("writes to the real registry of the user: BOXED_TEST_REAL_REGISTRY=1 runs it")


@pytest.fixture
def fake_winreg(windows, monkeypatch):
    """`import winreg` finds a FakeWinreg, with the Windows branches on."""
    fake = FakeWinreg()
    monkeypatch.setitem(sys.modules, "winreg", fake)
    return fake


@pytest.fixture
def windows_os(fake_msvcrt, monkeypatch):
    """The modules of boxed run as on Windows: no O_NOFOLLOW, O_NONBLOCK, geteuid, fchmod or mkfifo in the `os` they use, no fcntl for
    boxed.platform, byte locks from a FakeMsvcrt. A module that names one of these itself, instead of asking boxed.platform, fails.
    The standard library keeps the real os: its POSIX code paths (shutil.rmtree) are not the ones Windows runs."""
    from boxed import platform

    proxy = OsWithoutWhatWindowsLacks(os)
    for name, module in list(sys.modules.items()):
        if (name == "boxed" or name.startswith("boxed.")) and getattr(module, "os", None) is os:
            monkeypatch.setattr(module, "os", proxy)
    monkeypatch.setattr(platform, "fcntl", None)
    return fake_msvcrt


@pytest.fixture
def crlf_text_files(monkeypatch):
    """Text files as Windows writes them: a file opened in text mode with no `newline` argument gets \\r\\n for each \\n it is given
    (os.fdopen is how boxed opens the files it appends to or writes whole)."""
    real = os.fdopen

    def fdopen(fd, mode="r", buffering=-1, encoding=None, *args, **kwargs):
        if "b" not in mode and kwargs.get("newline") is None and len(args) < 2:
            kwargs["newline"] = "\r\n"
        return real(fd, mode, buffering, encoding, *args, **kwargs)

    monkeypatch.setattr(os, "fdopen", fdopen)


@pytest.fixture
def see_as(monkeypatch):
    """see_as(path, **fields): os.lstat answers for `path` as if the file had other fields (st_file_attributes with the reparse
    point bit, say, which Windows sets on a junction); every other path answers as it is. fstat is not touched."""
    real = os.lstat
    changed: dict[str, dict] = {}

    def lstat(path, *args, **kwargs):
        found = real(path, *args, **kwargs)
        fields = changed.get(os.fspath(path))
        if fields is None:
            return found
        return types.SimpleNamespace(**({name: getattr(found, name) for name in dir(found) if name.startswith("st_")} | fields))

    monkeypatch.setattr(os, "lstat", lstat)

    def see(path, **fields) -> None:
        changed[os.fspath(path)] = fields

    return see


@pytest.fixture
def handed_out(windows, monkeypatch):
    """The descriptors the Windows branch of open_nofollow got, in order (from os.open, or from CreateFileW on Windows itself): a test
    asks whether a refusal closed the one it opened."""
    fds: list[int] = []

    def remember(fd: int) -> int:
        if fd not in fds:
            fds.append(fd)
        return fd

    opens, creates = os.open, windows._create_file
    monkeypatch.setattr(os, "open", lambda *args, **kwargs: remember(opens(*args, **kwargs)))

    def create_file(path, flags):
        fd, attributes = creates(path, flags)
        return remember(fd), attributes

    monkeypatch.setattr(windows, "_create_file", create_file)
    return fds


@pytest.fixture
def is_open():
    """is_open(fd): does the descriptor still stand for an open file?"""

    def check(fd: int) -> bool:
        try:
            os.fstat(fd)
        except OSError:
            return False
        return True

    return check
