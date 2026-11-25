"""What a transcript, a folder name or a settings file holds is untrusted: nothing of it reaches a report, nothing it names is looked at
unless it is known to be on a local disk, and what was not read shows as not checked."""

import json
import os
import threading
from collections import Counter
from html import unescape
from pathlib import Path

import pytest

from boxed import platform as boxed_platform
from boxed.audit import paths
from boxed.audit.report import render_html, render_terminal, run_audit
from boxed.audit.sources import SentItem, claude_settings_files, iter_claude_code, iter_claude_settings, iter_codex
from boxed.cli import main

AWS = "AKIAIOSFODNN7EXAMPLE"
GHP = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
UNIX = hasattr(os, "geteuid") and os.geteuid() != 0  # a mode of 0 stops this user


def write_lines(path, *records):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join((r if isinstance(r, str) else json.dumps(r)) + "\n" for r in records))


def both(s):
    return render_terminal(s), unescape(render_html(s))


def encoded(path):
    return "".join(c if c.isascii() and c.isalnum() else "-" for c in str(path))


@pytest.fixture
def looks(monkeypatch):
    """Every path the code looks at or opens, in order."""
    seen: list[str] = []
    for name in ("lstat", "stat", "readlink", "open", "scandir"):
        real = getattr(os, name)

        def spy(path, *a, _real=real, **kw):
            seen.append(os.fspath(path))
            return _real(path, *a, **kw)

        monkeypatch.setattr(os, name, spy)
    return seen


# ---- finding: the name of a transcript folder is shown cleaned when it is the project (a record without cwd) ----


@pytest.mark.parametrize("tail", [f"-work-{AWS}", f"-work-{GHP}", "-work-app\x1b]0;owned\x07\x1b[2J"])
def test_a_transcript_folder_after_the_home_shows_no_value_and_no_control_character(tmp_path, monkeypatch, tail):
    home = tmp_path / "home" / "jdoe"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    folder = tmp_path / "claude" / (encoded(home) + tail)
    write_lines(folder / "s.jsonl", {"type": "user", "message": {"content": "mail anna@acme.com"}, "sessionId": "s"})
    s = run_audit(iter_claude_code(tmp_path / "claude", Counter()))
    assert s.projects == {folder.name}  # no cwd: the folder name is the project
    for rendered in both(s):
        for leak in (AWS, GHP[4:], "jdoe", "\x1b", "\x07", "owned\x07"):
            assert leak not in rendered, (leak, rendered)
        assert "~" in rendered
    if "app" in tail:
        assert "~-work-app\\x1b]0;owned\\x07\\x1b[2J" in render_terminal(s)
    else:
        assert "~<SECRET>" in render_terminal(s)


# ---- finding: what cannot be told local is not local; the mount table is matched as macOS compares names ----


def fake_disk(monkeypatch, folders):
    """A disk that holds only `folders`: every lstat is recorded, in order."""
    folder = os.lstat(Path(__file__).parent)
    seen: list[str] = []

    def lstat(path, *a, **kw):
        seen.append(os.fspath(path))
        if os.fspath(path) in folders:
            return folder
        raise FileNotFoundError(2, "no such file", os.fspath(path))

    monkeypatch.setattr(os, "lstat", lstat)
    return seen


def done(stdout, returncode=0):
    return lambda *a, **kw: type("Done", (), {"stdout": stdout, "returncode": returncode})()


@pytest.mark.parametrize(
    "run",
    [
        done("", 1),
        done("/dev/disk3s1s1 on / (apfs, local, journaled)\n", 1),
        done("/dev/disk3s1s1 on / (apfs, local, journaled)\nsomething else entirely\n"),
        done(""),
        "raise",
    ],
)
def test_a_mount_table_that_cannot_be_read_or_parsed_is_unknown(monkeypatch, run):
    monkeypatch.setattr(paths.sys, "platform", "darwin")
    monkeypatch.setattr(boxed_platform, "IS_WINDOWS", False)
    if run == "raise":
        def run(*a, **kw):
            raise OSError(2, "no mount")
    monkeypatch.setattr(paths.subprocess, "run", run)
    assert paths.mount_table() is None
    looked = fake_disk(monkeypatch, {"/work"})
    assert paths.local_state("/work/app", None) == paths.UNKNOWN and not paths.is_local_path("/work/app")
    assert looked == []  # nothing was looked at


def test_on_linux_a_file_system_of_an_unknown_type_is_not_local(tmp_path, monkeypatch):
    mounts = tmp_path / "mounts"
    mounts.write_bytes(b"/dev/vda1 / ext4 rw 0 0\n/dev/sdb1 /mnt/bucket fuseblk rw 0 0\nmade-up /mnt/lab fuse.examplefs rw 0 0\n")
    monkeypatch.setattr(paths.sys, "platform", "linux")
    monkeypatch.setattr(boxed_platform, "IS_WINDOWS", False)
    monkeypatch.setattr(paths, "open", lambda name, *a, **kw: open(mounts if name == "/proc/self/mounts" else name, *a, **kw), raising=False)
    table = paths.mount_table()
    assert table == [("/", False), ("/mnt/bucket", None), ("/mnt/lab", None)]
    looked = fake_disk(monkeypatch, {"/mnt", "/mnt/bucket", "/mnt/lab", "/mnt/disk"})
    assert paths.local_state("/mnt/bucket/app", table) == paths.UNKNOWN == paths.local_state("/mnt/lab/app", table)
    assert paths.local_state("/mnt/disk/app", table) == paths.LOCAL
    assert not any(p.startswith(("/mnt/bucket", "/mnt/lab")) for p in looked)
    mounts.write_bytes(b"/dev/vda1 / ext4 rw 0 0\nbroken-line\n")
    assert paths.mount_table() is None


LOCAL_TYPES = ("ext2 ext3 ext4 xfs btrfs zfs f2fs bcachefs jfs reiserfs nilfs2 tmpfs ramfs overlay squashfs erofs vfat exfat ntfs "
               "ntfs3 hfsplus apfs ecryptfs fuse.gocryptfs fuse.encfs virtiofs").split()
NETWORK_TYPES = ("nfs nfs4 cifs smb3 smbfs sshfs fuse.sshfs fuse.rclone fuse.s3fs ceph glusterfs lustre 9p afs davfs autofs "
                 "webdav").split()


def test_the_lists_of_linux_file_systems_cover_the_common_ones(tmp_path, monkeypatch):
    """A type that is in neither list is not checked, so a home folder on a common local file system must be in LOCAL_FS, or the
    main command reads nothing there. Types that can be either stay unknown: fuseblk, fuse without a subtype, the 9p of WSL."""
    assert set(LOCAL_TYPES) <= paths.LOCAL_FS and set(NETWORK_TYPES) <= paths.NETWORK_FS
    assert not paths.LOCAL_FS & paths.NETWORK_FS
    rows = [f"dev{i} /mnt/t{i} {t} rw 0 0" for i, t in enumerate([*LOCAL_TYPES, *NETWORK_TYPES, "fuseblk", "fuse"])]
    rows.append("drvfs /mnt/c 9p rw,noatime,dirsync,aname=drvfs;path=C:\\134;uid=1000 0 0")
    mounts = tmp_path / "mounts"
    mounts.write_text("\n".join(rows) + "\n")
    monkeypatch.setattr(paths.sys, "platform", "linux")
    monkeypatch.setattr(boxed_platform, "IS_WINDOWS", False)
    monkeypatch.setattr(paths, "open", lambda name, *a, **kw: open(mounts if name == "/proc/self/mounts" else name, *a, **kw), raising=False)
    kinds = [kind for _, kind in paths.mount_table()]
    assert kinds == [False] * len(LOCAL_TYPES) + [True] * len(NETWORK_TYPES) + [None, None, None]


def test_an_unknown_disk_type_says_what_to_do_without_a_path(tmp_path):
    out, page = both(run_audit([], stats=Counter({"transcripts_disk_unknown": 2})))
    for text in (out, page):
        assert "transcripts: 2 disk type not known" in text
        assert "disk type not known: nothing on it was read; report the type at github.com/boxedsi/boxedsi/issues" in text
        assert str(tmp_path) not in text and str(Path.home()) not in text
    assert "report the type" not in render_terminal(run_audit([], stats=Counter({"transcripts_not_local": 1})))


@pytest.fixture
def ascii_names(monkeypatch):
    """The C locale on Linux, on any system: the file system encoding is ASCII, and a file call given a name with a character
    outside it raises UnicodeEncodeError, which is no OSError. On Windows os_path gives every name as it is, so nothing raises there."""
    monkeypatch.setattr(paths.sys, "getfilesystemencoding", lambda: "ascii")
    monkeypatch.setattr(paths.sys, "getfilesystemencodeerrors", lambda: "surrogateescape")
    if boxed_platform.IS_WINDOWS:
        return
    for name in ("stat", "lstat", "open", "readlink", "scandir"):
        real = getattr(os, name)

        def call(path, *a, _real=real, **kw):
            if isinstance(path, str) and not path.isascii():
                raise UnicodeEncodeError("ascii", path, 0, 1, "ordinal not in range(128)")
            return _real(path, *a, **kw)

        monkeypatch.setattr(os, name, call)


def test_a_name_the_file_system_encoding_cannot_spell_is_read_by_its_utf8_bytes(tmp_path, ascii_names):
    project = tmp_path / "проект"
    (project / ".claude").mkdir(parents=True)
    (project / ".claude" / "settings.json").write_text(json.dumps({"env": {"AWS_ACCESS_KEY_ID": AWS}}), encoding="utf-8")
    claude = tmp_path / "claude"
    write_lines(claude / "-p" / "s.jsonl", {"type": "user", "message": {"content": "hello"}, "cwd": str(project), "sessionId": "s"})
    mounts = [("/", False)]
    stats, projects = Counter(), set()
    s = run_audit(iter_claude_code(claude, stats, projects, mounts), stats=stats)
    files = claude_settings_files(None, projects, stats, mounts)
    s = run_audit(iter_claude_settings(files, stats, mounts), stats=stats, summary=s)
    assert s.settings_files == 1 and [h.project for h in s.secrets] == [str(project)]
    assert not s.incomplete and "not checked" not in render_terminal(s)


@pytest.mark.skipif(boxed_platform.IS_WINDOWS, reason="links, named pipes and mount points of a POSIX system")
def test_the_checks_of_links_pipes_and_mounts_hold_for_a_name_read_by_its_bytes(tmp_path, ascii_names):
    from boxed.audit import sources

    share = tmp_path / "сеть"
    share.mkdir()
    (tmp_path / "ссылка").symlink_to(share)
    os.mkfifo(os.fsencode(tmp_path / "канал"))
    # the mount point as the system writes it in the C locale: its UTF-8 bytes decoded as ASCII with surrogateescape
    point = str(share).encode("utf-8").decode("ascii", "surrogateescape")
    mounts = [("/", False), (point, True)]
    assert paths.local_state(str(share / "app"), mounts) == paths.NETWORK
    assert paths.local_state(str(tmp_path / "ссылка" / "app"), mounts) == paths.NETWORK  # the link is followed by its bytes
    assert sources._open_local(str(tmp_path / "канал"), [("/", False)]) == (None, "access")  # no wait for a writer


def test_a_name_the_file_system_encoding_cannot_spell_that_is_not_there_is_missing(tmp_path, ascii_names):
    from boxed.audit import sources

    stats = Counter()
    files = claude_settings_files(None, [str(tmp_path / "нет")], stats, [("/", False)])
    assert sources._open_local(str(files[0][0]), [("/", False)]) == (None, "missing")
    s = run_audit(iter_claude_settings(files, stats, [("/", False)]), stats=stats)
    assert s.settings_files == 0 and not s.incomplete


def test_a_path_no_mount_point_holds_is_unknown(monkeypatch):
    looked = fake_disk(monkeypatch, {"/work"})
    assert paths.local_state("/work/app", [("/elsewhere", False)]) == paths.UNKNOWN and looked == []


@pytest.mark.parametrize("spelling", ["/volumes/team share/app", "/VOLUMES/Team Share/app", "/Volumes/Cafe\u0301/app"])
def test_on_macos_a_mount_point_matches_in_any_case_and_normalization(monkeypatch, spelling):
    monkeypatch.setattr(paths.sys, "platform", "darwin")
    table = [("/", False), ("/Volumes/team share", True), ("/Volumes/Caf\u00e9", True)]
    looked = fake_disk(monkeypatch, {"/volumes", "/VOLUMES", "/Volumes"})
    assert paths.local_state(spelling, table) == paths.NETWORK
    assert looked == [spelling.split("/")[0] + "/" + spelling.split("/")[1]]  # the first part only: never the mount point


def test_without_a_mount_table_nothing_is_read_and_all_of_it_is_not_checked(tmp_path, looks):
    claude = tmp_path / "claude"
    write_lines(claude / "-p" / "s.jsonl", {"type": "user", "message": {"content": "mail anna@acme.com"}, "cwd": "/work/p"})
    user = tmp_path / ".claude"
    user.mkdir()
    (user / "settings.json").write_text('{"env": {"DB_PASSWORD": "hunter22x"}}')
    stats = Counter()
    looks.clear()
    assert list(iter_claude_code(claude, stats, mounts=None)) == []
    files = claude_settings_files(user, ["/work/p"], stats, mounts=None)
    assert list(iter_claude_settings(files, stats, mounts=None)) == []
    assert looks == []  # not one look, not one open
    assert (stats["folders_disk_unknown"], stats["projects_disk_unknown"], stats["settings_disk_unknown"]) == (1, 1, 2)
    out = render_terminal(run_audit([], stats=stats))
    assert "transcript folders: 1 disk type not known" in out and "settings files: 2 disk type not known" in out
    assert "project folders: 1 disk type not known" in out


# ---- finding: a transcript or settings file found by a walk is opened only as a plain local file ----


def run_with_timeout(fn, seconds=20):
    box: list = []
    worker = threading.Thread(target=lambda: box.append(fn()), daemon=True)
    worker.start()
    worker.join(seconds)
    assert not worker.is_alive(), "the reader waits on a named pipe"
    return box[0]


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no named pipes")
def test_a_named_pipe_is_never_waited_on(tmp_path):
    claude = tmp_path / "claude"
    write_lines(claude / "-p" / "a.jsonl", {"type": "user", "message": {"content": "mail anna@acme.com"}, "cwd": "/work/p"})
    os.mkfifo(claude / "-p" / "b.jsonl")
    user = tmp_path / ".claude"
    user.mkdir()
    os.mkfifo(user / "settings.json")
    stats = Counter()
    items = run_with_timeout(lambda: list(iter_claude_code(claude, stats)))
    assert [i.text for i in items] == ["mail anna@acme.com"] and stats["transcripts_unread"] == 1
    assert run_with_timeout(lambda: list(iter_claude_settings(claude_settings_files(user, []), stats))) == []
    assert stats["settings_access"] == 1


def test_a_link_into_a_network_mount_is_not_followed(tmp_path, looks):
    share = tmp_path / "share"  # stands for a network mount
    (share / "t").mkdir(parents=True)
    write_lines(share / "t" / "far.jsonl", {"type": "user", "message": {"content": "mail anna@acme.com"}})
    (share / "settings.json").write_text('{"env": {"DB_PASSWORD": "hunter22x"}}')
    claude = tmp_path / "claude"
    write_lines(claude / "-p" / "near.jsonl", {"type": "user", "message": {"content": "mail bob@acme.com"}, "cwd": "/work/p"})
    (claude / "-p" / "far.jsonl").symlink_to(share / "t" / "far.jsonl")
    (claude / "into-share").symlink_to(share / "t")  # a folder link: never walked into
    user = tmp_path / ".claude"
    user.mkdir()
    (user / "settings.json").symlink_to(share / "settings.json")
    mounts = [("/", False), (str(share), True)]
    stats = Counter()
    looks.clear()
    assert [i.text for i in iter_claude_code(claude, stats, mounts=mounts)] == ["mail bob@acme.com"]
    files = claude_settings_files(user, [], stats, mounts=mounts)
    assert list(iter_claude_settings(files, stats, mounts=mounts)) == []
    assert (stats["transcripts_not_local"], stats["settings_not_local"]) == (1, 1)
    assert [p for p in looks if p == str(share) or p.startswith(str(share) + os.sep)] == []


def test_a_mount_point_inside_the_transcripts_is_not_entered(tmp_path, looks):
    claude = tmp_path / "claude"
    write_lines(claude / "-p" / "a.jsonl", {"type": "user", "message": {"content": "mail anna@acme.com"}})
    write_lines(claude / "nfs" / "b.jsonl", {"type": "user", "message": {"content": "mail bob@acme.com"}})
    stats = Counter()
    looks.clear()
    items = list(iter_claude_code(claude, stats, mounts=[("/", False), (str(claude / "nfs"), True)]))
    assert [i.text for i in items] == ["mail anna@acme.com"] and stats["folders_not_local"] == 1
    assert not any(p.startswith(str(claude / "nfs")) for p in looks)


# ---- finding: a folder that cannot be listed or passed through is not checked, not missing ----


@pytest.mark.skipif(not UNIX, reason="needs a user that a mode of 0 stops")
def test_a_folder_that_cannot_be_listed_is_counted_and_the_rest_is_read(tmp_path):
    claude = tmp_path / "claude"
    write_lines(claude / "-a" / "a.jsonl", {"type": "user", "message": {"content": "mail anna@acme.com"}})
    write_lines(claude / "-b" / "b.jsonl", {"type": "user", "message": {"content": "mail bob@acme.com"}})
    (claude / "-b").chmod(0)
    try:
        stats = Counter()
        assert [i.text for i in iter_claude_code(claude, stats)] == ["mail anna@acme.com"]
        assert stats["folders_unread"] == 1
    finally:
        (claude / "-b").chmod(0o700)


@pytest.mark.skipif(not UNIX, reason="needs a user that a mode of 0 stops")
def test_settings_behind_a_closed_folder_are_not_checked_and_both_reports_say_so(tmp_path, capsys):
    project = tmp_path / "work" / "shop"
    (project / ".claude").mkdir(parents=True)
    (project / ".claude" / "settings.json").write_text('{"env": {"DB_PASSWORD": "hunter22x"}}')
    closed = tmp_path / "closed"
    write_lines(closed / "projects" / "-p" / "s.jsonl", {"type": "user", "message": {"content": "hi"}, "cwd": str(project)})
    (project / ".claude").chmod(0)
    closed.chmod(0)
    page = tmp_path / "audit.html"
    try:
        stats = Counter()
        assert list(iter_claude_settings(claude_settings_files(None, [str(project)]), stats)) == []
        assert stats["settings_access"] == 2  # lexists said "missing" here
        assert main(["audit", "--claude-dir", str(closed / "projects"), "--codex-dir", str(tmp_path / "none"), "--html", str(page)]) == 3
    finally:
        closed.chmod(0o700)
        (project / ".claude").chmod(0o700)
    out = capsys.readouterr().out
    # the closed folder holds the transcripts and the user's settings: neither can be told missing
    assert "not checked (the report is incomplete):\n  settings files: 2 no access\n  transcript folders: 1 no access\n" in out
    assert "transcript folders: 1 no access" in page.read_text() and "settings files: 2 no access" in page.read_text()


def test_missing_folders_are_no_gap(tmp_path, capsys):
    assert main(["audit", "--claude-dir", str(tmp_path / "none"), "--codex-dir", str(tmp_path / "none2")]) == 0
    assert "not checked" not in capsys.readouterr().out


# ---- finding: a record of the wrong shape at any depth is malformed; the next record is read ----


def test_a_record_of_the_wrong_shape_inside_is_malformed_and_the_next_one_is_read(tmp_path):
    claude = tmp_path / "claude"
    good = {"type": "user", "message": {"content": "mail anna@acme.com"}, "cwd": "/work/a"}
    write_lines(
        claude / "-a" / "a.jsonl",
        {"type": "user", "message": {"content": [{"type": "text", "text": ["not", "text"]}]}},
        {"type": "user", "message": {"content": [{"type": "text", "text": {"x": 1}}]}},
        {"type": "user", "message": {"content": [{"type": "tool_result", "content": {"text": "x"}}]}},
        {"type": "user", "message": {"content": [{"type": "tool_result", "content": [{"type": "text", "text": 7}]}]}},
        {"type": "user", "message": {"content": [{"type": "tool_result", "content": [7]}]}},
        {"type": "user", "message": {"content": ["a string part"]}},
        {"type": "user", "message": {"content": 5}},
        {"type": "user", "message": {"content": [{"type": ["text"], "text": "x"}]}},
        {"type": "attachment", "rendered": [{"content": [{"text": None, "type": "tool_result", "content": 3}]}]},
        {"type": "attachment", "rendered": ["a string"]},
        good,
    )
    stats = Counter()
    assert [i.text for i in iter_claude_code(claude, stats)] == ["mail anna@acme.com"] and stats["malformed"] == 10
    codex = tmp_path / "codex"
    write_lines(
        codex / "r.jsonl",
        {"type": "session_meta", "payload": {"id": "c", "cwd": "/work/c"}},
        {"type": "response_item", "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": ["x"]}]}},
        {"type": "response_item", "payload": {"type": "function_call_output", "output": {"text": 1}}},
        {"type": "response_item", "payload": {"type": "message", "role": "user", "content": 5}},
        {"type": "response_item", "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "mail bob@acme.com"}]}},
    )
    stats = Counter()
    assert [i.text for i in iter_codex(codex, stats)] == ["mail bob@acme.com"] and stats["malformed"] == 3


# ---- finding: turn_context moves a Codex session to its folder ----


def test_a_turn_context_moves_the_codex_session_to_its_folder(tmp_path):
    codex = tmp_path / "codex"

    def msg(text):
        return {"type": "response_item", "payload": {"type": "message", "role": "user", "content": text}}

    write_lines(
        codex / "r1.jsonl",
        {"type": "session_meta", "payload": {"id": "c1", "cwd": "/work/first"}},
        msg("one"),
        {"type": "turn_context", "payload": {"cwd": "/work/second"}},
        msg("two"),
        {"type": "turn_context", "payload": {}},
        msg("three"),
    )
    write_lines(codex / "r2.jsonl", {"type": "turn_context", "payload": {"cwd": "/work/only-turn"}}, msg("four"))
    items = list(iter_codex(codex, Counter()))
    assert [(i.text, i.project, i.session) for i in items] == [
        ("one", "/work/first", "c1"),
        ("two", "/work/second", "c1"),
        ("three", "/work/second", "c1"),
        ("four", "/work/only-turn", "r2"),
    ]


# ---- finding: the home folder is ~ on Windows whatever the slashes and the case ----


@pytest.mark.parametrize(
    "text, rest",
    [
        ("C:\\Users\\JDoe", ""),
        ("C:\\Users\\JDoe\\work\\shop", "\\work\\shop"),
        ("c:/users/jdoe/work/shop", "/work/shop"),
        ("C:/Users\\JDOE\\work", "\\work"),
        ("c:\\\\Users//JDoe/x", "/x"),
        ("C:\\Users\\JDoe2\\work", None),
        ("D:\\Users\\JDoe\\work", None),
        ("\\\\server\\C$\\Users\\JDoe", None),
    ],
)
def test_after_home_on_windows_ignores_slashes_and_case(text, rest):
    assert paths.after_home(text, "C:\\Users\\JDoe", windows=True) == rest


def test_after_home_elsewhere_is_exact():
    assert paths.after_home("/home/jdoe/work", "/home/jdoe", windows=False) == "/work"
    assert paths.after_home("/home/JDoe/work", "/home/jdoe", windows=False) is None
    assert paths.after_home("/home/jdoe2", "/home/jdoe", windows=False) is None


def test_on_windows_both_reports_show_the_home_as_a_tilde(monkeypatch):
    monkeypatch.setattr(boxed_platform, "IS_WINDOWS", True)
    monkeypatch.setattr(paths, "_home", lambda: "C:\\Users\\JDoe")
    project = "c:/users/jdoe/work/shop"
    locator = "C:/Users/jdoe/.claude/projects/c--users-jdoe-work-shop/s.jsonl:3"
    s = run_audit([SentItem("claude-code", "anthropic", project, "s", None, "user_prompt", f"key {AWS}", locator)])
    for rendered in both(s):
        assert "jdoe" not in rendered.lower(), rendered
        assert "~/work/shop" in rendered and "~/.claude/projects/" in rendered


# ---- finding: a key and its value are bound by the JSON, whatever whitespace stands between them ----


def test_a_key_and_its_value_stay_bound_across_any_whitespace(tmp_path):
    user = tmp_path / ".claude"
    user.mkdir()
    gap = " \t\r\n" * 40
    text = '{"env": {"DB_PASSWORD"' + gap + ":" + gap + '"hunter22x",\n"x"' + gap + ':"y"},\n"allow": [' + gap + '"Bash(ls)"]}'
    (user / "settings.json").write_text(text)
    items = list(iter_claude_settings(claude_settings_files(user, []), Counter()))
    line = 1 + text[: text.index('"hunter22x"')].count("\n")
    assert [(i.text, i.locator.rpartition(":")[2]) for i in items][:2] == [("DB_PASSWORD: hunter22x", str(line)), ("x: y", str(line + 41))]
    assert items[2].text == "Bash(ls)"
    s = run_audit(items)
    assert s.by_kind["SECRET"] == 1


# ---- finding: the reports claim no more than was checked ----


def test_settings_advice_speaks_of_the_records_checked_with_an_old_session_out_of_the_period(tmp_path, capsys):
    user = tmp_path / "u" / ".claude"
    old = {"type": "user", "message": {"content": f"key {AWS}"}, "cwd": "/work/old", "timestamp": "2026-01-01T10:00:00Z"}
    write_lines(user / "projects" / "-work-old" / "s.jsonl", old)
    (user / "settings.json").write_text(json.dumps({"env": {"AWS_ACCESS_KEY_ID": AWS}}))
    assert main(["audit", "--claude-dir", str(user / "projects"), "--codex-dir", str(tmp_path / "none"), "--since", "2026-11-01"]) == 0
    out = capsys.readouterr().out
    assert "No match in the session records checked for this report." in out and "in no session record" not in out
    assert "0 items checked" in out


def test_a_card_number_is_not_called_a_key_to_revoke():
    card = "4111 1111 1111 1111"
    s = run_audit([SentItem("claude-code", "anthropic", "/p", "s", None, "user_prompt", f"card {card}", "/t/a.jsonl:1")])
    assert s.secrets and s.secrets[0].kind == "CARD" and s.secrets[0].known
    for rendered in both(s):
        assert "card issuer" in rendered and "revoke" not in rendered and "keys now" not in rendered
        assert "does not check that a value is real or still valid" in rendered

