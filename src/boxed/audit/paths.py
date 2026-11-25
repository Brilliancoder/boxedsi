"""Paths that came from transcripts: which of them audit may read (folders on a local disk only) and how a report shows a path
(no user name, no value a detector finds, no control character)."""

import functools
import ntpath
import os
import re
import stat
import subprocess
import sys
import unicodedata
from pathlib import Path

from .. import platform
from ..detect import detect

# file systems whose folders are on another computer, or that mount one when a folder under them is looked at
NETWORK_FS = frozenset(
    {"9p", "acfs", "afpfs", "afs", "autofs", "beegfs", "ceph", "cifs", "coda", "davfs", "fuse.ceph-fuse", "fuse.glusterfs",
     "fuse.rclone", "fuse.s3fs", "fuse.sshfs", "ftp", "glusterfs", "gpfs", "lustre", "ncpfs", "nfs", "nfs4", "smb", "smb3",
     "smbfs", "sshfs", "webdav"}
)
# Linux file systems known to keep their folders on this computer (or in its memory). Any other type is not known to be local:
# audit does not look at a folder on it. Left out on purpose: fuseblk and fuse (no subtype: anything can stand behind them), and
# 9p of WSL (the Windows drives, aname=drvfs), which mount_table marks as not known rather than as a network share.
LOCAL_FS = frozenset(
    {"apfs", "bcachefs", "binfmt_misc", "bpf", "btrfs", "cgroup", "cgroup2", "configfs", "debugfs", "devpts", "devtmpfs",
     "ecryptfs", "efivarfs", "erofs", "exfat", "ext2", "ext3", "ext4", "f2fs", "fuse.encfs", "fuse.gocryptfs", "fusectl", "hfs",
     "hfsplus", "hugetlbfs", "iso9660", "jfs", "mqueue", "msdos", "nilfs2", "nsfs", "ntfs", "ntfs3", "overlay", "proc", "pstore",
     "ramfs", "reiserfs", "rootfs", "securityfs", "selinuxfs", "squashfs", "sysfs", "tmpfs", "tracefs", "udf", "vfat", "virtiofs",
     "xfs", "zfs"}
)


def _linux_kind(fstype: str, options: str) -> bool | None:
    """The kind (see Mounts) of a line of /proc/self/mounts: its type, and for 9p its options."""
    if fstype == "9p" and "aname=drvfs" in options:
        return None  # WSL's Windows drives: local or not, as the drive is
    return True if fstype in NETWORK_FS else False if fstype in LOCAL_FS else None
_MAX_LINKS = 40
PATH_LEVEL = 1  # a part of a path is checked for secrets and personal data; not for host names, which name many project folders
_PLACEHOLDER = re.compile(r"<[A-Z_]+>")
# what local_state says of a path: audit may look at it; it is on another computer; nobody knows (no mount table, a file system
# of an unknown type)
LOCAL, NETWORK, UNKNOWN = "local", "network", "unknown"
READ = object()  # "read the mount table now", where a caller gives none
# (mount point, kind): False a local file system, True a network or automount one, None one of an unknown type
Mounts = list[tuple[str, bool | None]]


def _unescape_mount(text: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), text)


def mount_table() -> Mounts | None:
    """(mount point, kind) from the system's own list, read without looking at the mounted folders: /proc/self/mounts on Linux, the
    output of mount(8) on macOS and BSD. None when the list cannot be read or a line of it cannot be parsed: then no path is known
    to be local. An empty list on Windows, where drive letters are asked instead (platform.local_drive)."""
    try:
        if sys.platform.startswith("linux"):
            # fields are split by one space and lines by a line break only: the kernel writes a space, tab, line break or backslash in a
            # name as an octal escape and no other character, so a no-break space or a carriage return in a mount point is part of it.
            # Bytes that are not UTF-8 are decoded as os.fsdecode does, so the point is spelled as a path a transcript names is
            encoding, errors = sys.getfilesystemencoding(), sys.getfilesystemencodeerrors()
            with open("/proc/self/mounts", encoding=encoding, errors=errors, newline="\n") as fh:
                rows = [line.rstrip("\n").split(" ") for line in fh]
            if not rows or any(len(r) < 3 for r in rows):
                return None
            return [(_unescape_mount(r[1]), _linux_kind(r[2], r[3] if len(r) > 3 else "")) for r in rows]
        if platform.IS_WINDOWS:
            return []  # drive letters: see platform.local_drive
        done = subprocess.run(["/sbin/mount"], capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError, UnicodeError):
        return None
    if getattr(done, "returncode", 0) != 0:
        return None
    table: Mounts = []
    for line in done.stdout.splitlines():
        m = re.fullmatch(r".* on (/.*) \(([^()]*)\)", line)
        if not m:
            return None  # a line that cannot be read: the list is not known whole
        fstype, *flags = [f.strip() for f in m.group(2).split(",")]
        table.append((m.group(1), fstype in NETWORK_FS or (sys.platform == "darwin" and "local" not in flags)))
    return table or None


def os_path(text: str) -> str | bytes:
    """`text` as the file calls of audit take it. A name the file system encoding cannot spell (ASCII in the C locale on Linux)
    is given as its UTF-8 bytes: the names on a Linux disk are bytes, and practically always UTF-8 whatever the locale of the
    process. Any other name, and every name on Windows, goes as it is; so does one that is not even UTF-8 (a lone surrogate from
    a transcript): the call raises UnicodeEncodeError, which the callers count as a name they cannot read."""
    if platform.IS_WINDOWS:
        return text
    try:
        text.encode(sys.getfilesystemencoding(), sys.getfilesystemencodeerrors())
        return text
    except UnicodeEncodeError:
        pass
    try:
        return text.encode("utf-8", "surrogateescape")
    except UnicodeEncodeError:
        return text


def _disk_spelling(text: str) -> str:
    """`text` spelled as its bytes on the disk read as UTF-8 (see os_path), so a path a transcript names and one the system wrote
    (a mount point, a name found in a folder: os.fsdecode's spelling) compare alike in any locale. The same text where the file
    system encoding is UTF-8."""
    try:
        raw = text.encode(sys.getfilesystemencoding(), sys.getfilesystemencodeerrors())
    except UnicodeEncodeError:
        return text  # os_path gives its UTF-8 bytes: this text already spells them
    return raw.decode("utf-8", "surrogateescape")


def _fold(text: str) -> str:
    """A path as the file system compares it: macOS volumes are case-insensitive and normalization-insensitive by default, so
    /volumes/TEAM and /Volumes/team are one folder there. Folding on a case-sensitive volume only makes more mount points match."""
    return unicodedata.normalize("NFD", text).casefold() if sys.platform == "darwin" else text


def _mount_kind(path: str, mounts: Mounts) -> bool | None:
    """The kind of the file system of the longest mount point that holds `path` (see Mounts); None when none holds it. Of mount
    points that match alike, the worst kind counts."""
    best, kinds = -1, []
    folded = _fold(_disk_spelling(path))
    for point, kind in mounts:
        root = _fold(_disk_spelling(point)).rstrip("/") or "/"
        if folded == root or folded.startswith(root if root == "/" else root + "/"):
            if len(root) > best:
                best, kinds = len(root), [kind]
            elif len(root) == best:
                kinds.append(kind)
    if not kinds or None in kinds:
        return None
    return any(kinds)


def _on_network(path: str, mounts: Mounts) -> bool:
    """Is `path` not known to be on a local file system? Looks at nothing on the disk."""
    return _mount_kind(path, mounts) is not False


def is_network_spelling(text: str) -> bool:
    """A UNC path (\\\\server\\share), a device path (\\\\?\\, \\\\.\\) or a POSIX path that starts with two slashes: each can name
    another computer, and asking the system about it can make it connect and send the user's credentials."""
    return text[:2] in ("\\\\", "//", "\\/", "/\\")


def is_local_path(text: str, mounts: "Mounts | None | object" = READ) -> bool:
    """May audit look at `text`? See local_state. With no `mounts` given, the mount table is read now."""
    return local_state(text, mount_table() if mounts is READ else mounts) == LOCAL  # type: ignore[arg-type]


def local_state(text: str, mounts: Mounts | None) -> str:
    """May audit look at `text`, a path a transcript named or a file found in a folder? LOCAL only for an absolute path on a local
    disk, followed link by link: each part is looked at (lstat, readlink) only once the part before it is known to be on a local
    disk, and a link that leads to a network path or a network mount ends the walk. A missing part ends it too: there is nothing
    further to read. NETWORK for a path that is or leads to another computer, UNKNOWN when that cannot be told: `mounts` is None
    (the mount table could not be read) or the file system is of an unknown type. Looks, never opens."""
    if not text or "\0" in text or is_network_spelling(text):
        return NETWORK
    if platform.IS_WINDOWS:
        drive, rest = ntpath.splitdrive(text)
        if len(drive) != 2 or drive[1] != ":" or not rest.startswith(("\\", "/")):
            return NETWORK
        try:
            return _walk(text, []) if platform.local_drive(drive) else NETWORK
        except (OSError, AttributeError, ValueError):
            return UNKNOWN
    if not text.startswith("/"):
        return NETWORK
    if mounts is None:
        return UNKNOWN
    return _walk(text, mounts)


def _walk(text: str, mounts: Mounts) -> str:
    windows = platform.IS_WINDOWS
    sep = "\\" if windows else "/"
    if windows:
        drive, rest = ntpath.splitdrive(text)
        done, todo = drive + "\\", [p for p in re.split(r"[\\/]", rest) if p]
    else:
        done, todo = "/", [p for p in text.split("/") if p]
    links = 0
    while todo:
        part = todo.pop(0)
        if part == ".":
            continue
        if part == "..":
            done = (ntpath.dirname(done.rstrip("\\")) or done) if windows else (os.path.dirname(done.rstrip("/")) or "/")
            if windows and not done.endswith("\\"):
                done += "\\"
            continue
        here = done + ("" if done.endswith(sep) else sep) + part
        if not windows:
            kind = _mount_kind(here, mounts)
            if kind is not False:
                return NETWORK if kind else UNKNOWN
        try:
            info = os.lstat(os_path(here))
        except (OSError, UnicodeEncodeError):  # a name that is not even UTF-8 (see os_path): no way through
            return LOCAL  # nothing there (or no way through): nothing further is read
        if not (stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT):
            done = here
            continue
        links += 1
        try:
            target = os.readlink(os_path(here))
        except OSError:
            return UNKNOWN
        if isinstance(target, bytes):  # the link of a name os_path gave as bytes
            target = target.decode("utf-8", "surrogateescape")
        if windows and target.startswith("\\\\?\\") and target[5:6] == ":":
            target = target[4:]  # \\?\C:\...: a local drive in the long spelling
        if links > _MAX_LINKS:
            return UNKNOWN
        if is_network_spelling(target):
            return NETWORK
        if windows:
            tdrive, trest = ntpath.splitdrive(target)
            if tdrive:
                if len(tdrive) != 2 or not platform.local_drive(tdrive):
                    return NETWORK
                done, todo = tdrive + "\\", [p for p in re.split(r"[\\/]", trest) if p] + todo
            else:
                todo = [p for p in re.split(r"[\\/]", target) if p] + todo
        elif target.startswith("/"):
            done, todo = "/", [p for p in target.split("/") if p] + todo
        else:
            todo = [p for p in target.split("/") if p] + todo
    return LOCAL


# ---- how a report shows a path ----


def clean(text: str) -> str:
    """A field from a transcript, safe for a terminal: control and format characters (escape sequences, line breaks, tabs, marks
    that turn the direction of the text) are written as escapes, so they cannot move the cursor or hide a line."""
    out = []
    for ch in text:
        if unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp", "Cs", "Co", "Cn"):
            out.append(f"\\x{ord(ch):02x}" if ord(ch) < 0x100 else f"\\u{ord(ch):04x}" if ord(ch) < 0x10000 else f"\\U{ord(ch):08x}")
        else:
            out.append(ch)
    return "".join(out)


def _encode(path: str) -> str:
    """How Claude Code names the transcript folder of a project: every character that is no ASCII letter or digit becomes '-'."""
    return re.sub(r"[^A-Za-z0-9]", "-", path)


def _home() -> str:
    return str(Path.home()).rstrip("/\\")


def _starts_with_code(part: str, home_code: str, windows: bool) -> bool:
    head = part[: len(home_code)]
    if windows:  # the drive letter and the names of a Windows path have no case
        head, home_code = (head.lower(), home_code.lower()) if head.isascii() else (head, home_code)
    return head == home_code and (len(part) == len(home_code) or part[len(home_code)] == "-")


@functools.lru_cache(maxsize=4096)
def _part(part: str, home_code: str, windows: bool = False) -> str:
    """One part of a path: a transcript folder named after a path in the home starts with ~ and the rest of it is shown as any
    other part; a part a detector finds a secret or personal data in is shown as its kind. The name of a transcript folder has
    every character that is no ASCII letter or digit turned into '-', so it is also checked with '_' there (ghp_ becomes ghp-)."""
    if len(home_code) > 1 and _starts_with_code(part, home_code, windows):
        rest = part[len(home_code) :]
        return "~" + (_part(rest, "", windows) if rest else "")
    found = detect(part, level=PATH_LEVEL) or ("-" in part and detect(part.replace("-", "_"), level=PATH_LEVEL))
    if found:
        return f"<{found[0].kind}>"
    return clean(part)


def _project_code(shown: str) -> str:
    """The transcript folder of a project as the report shows it: the shown project path, spelled the way Claude Code spells it."""
    pieces = re.split(f"({_PLACEHOLDER.pattern})", shown)
    return "".join(p if _PLACEHOLDER.fullmatch(p) else re.sub(r"[^A-Za-z0-9~]", "-", p) for p in pieces)


def show_path(text: str, project: str | None = None) -> str:
    """A path as a report shows it, in the terminal and in the HTML page. The home folder is ~; the transcript folder of a project
    (Claude Code names it after the whole path, -Users-name-work-app) is shown after the shown project path, so it carries no user
    name either; a part with a secret or personal data in it is shown as its kind (<EMAIL>); control characters are escaped.
    What finds the file stays: the project name, the session id in the file name, the line."""
    home = _home()
    windows = platform.IS_WINDOWS
    head = ""
    rest = after_home(text, home, windows)
    if rest is not None:
        head, text = "~", rest
    code = _encode(project) if project and project != text else None
    shown_code = _project_code(show_path(project)) if code else ""
    parts = re.split(r"([/\\])", text)
    out = []
    for p in parts:
        if p in ("", "/", "\\", "~", ".", ".."):
            out.append(p)
        elif code and p == code:
            out.append(shown_code)
        else:
            out.append(_part(p, _encode(home), windows))
    return head + "".join(out)


def after_home(text: str, home: str, windows: bool) -> str | None:
    """What follows the home folder `home` in the path `text` ("" for the home itself), or None when `text` is not in it. On
    Windows the names have no case and either slash separates them: C:\\Users\\jdoe, c:/users/JDoe and C:/Users\\jdoe are one
    folder. Works on the strings alone, never on the disk."""
    if not home:
        return None
    if not windows:
        if text == home or (text.startswith(home) and text[len(home)] in "/\\"):
            return text[len(home) :]
        return None
    lead = len(home) - len(home.lstrip("\\/"))
    names = [n for n in re.split(r"[\\/]+", home) if n]
    if not names:
        return None
    pattern = "[\\\\/]" * lead + "[\\\\/]+".join(map(re.escape, names)) + r"(?=[\\/]|\Z)"
    m = re.match(pattern, text, re.IGNORECASE)
    return text[m.end() :] if m else None


def show_locator(locator: str, project: str | None = None) -> tuple[str, str]:
    """The shown file and the line of a locator ("path:12")."""
    path, _, line = locator.rpartition(":")
    if path and line.isdigit():
        return show_path(path, project), line
    return show_path(locator, project), ""
