import os
import shutil
from collections import Counter
from pathlib import Path

import pytest

from boxed.audit.sources import iter_claude_code, iter_codex

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def claude_root(tmp_path):
    root = tmp_path / "claude-projects"
    (root / "-work-proj").mkdir(parents=True)
    shutil.copy(FIXTURES / "claude_session.jsonl", root / "-work-proj" / "s1.jsonl")
    return root


@pytest.fixture
def codex_root(tmp_path):
    root = tmp_path / "codex-sessions" / "2026" / "10" / "04"
    root.mkdir(parents=True)
    shutil.copy(FIXTURES / "codex_rollout.jsonl", root / "rollout-c1.jsonl")
    return tmp_path / "codex-sessions"


def test_claude_items(claude_root):
    stats = Counter()
    items = list(iter_claude_code(claude_root, stats))
    path = claude_root / "-work-proj" / "s1.jsonl"
    assert [(i.role, i.locator) for i in items] == [
        ("user_prompt", f"{path}:1"),
        ("tool_result", f"{path}:3"),
        ("user_prompt", f"{path}:4"),
        ("attachment", f"{path}:6"),
    ]
    assert {(i.source, i.provider, i.project, i.session) for i in items} == {("claude-code", "anthropic", "/work/proj", "s1")}
    assert "anna@acme.com" in items[1].text


def test_malformed_counted(claude_root):
    stats = Counter()
    list(iter_claude_code(claude_root, stats))
    assert stats["malformed"] == 1


def test_codex_items(codex_root):
    items = list(iter_codex(codex_root, Counter()))
    assert [i.role for i in items] == ["user_prompt", "tool_result", "instructions", "tool_result"]
    assert {(i.source, i.provider, i.project, i.session) for i in items} == {("codex", "openai", "/work/other", "c1")}
    assert "bob@acme.com" in items[1].text
    assert "admin@acme.com" in items[2].text  # a developer message (AGENTS.md, permissions) goes to the model too


# ---- Claude Code settings files: permission rules and env values keep what was typed into them ----

from boxed.audit.sources import SETTINGS_SOURCE, claude_settings_files, iter_claude_settings  # noqa: E402

FAKE_BEARER = "Zq8vXk2mPw9rTb4nLs7dHc3fGj6yUa5e"  # invented


def settings_text():
    return (
        '{\n  "permissions": {\n    "allow": [\n      "Bash(npm test)",\n'
        f'      "Bash(curl -H \\"Authorization: Bearer {FAKE_BEARER}\\" https://api.example.test)"\n'
        '    ]\n  },\n  "env": {"DB_PASSWORD": "hunter22x", "DEBUG": "1"},\n  "model": "opus"\n}\n'
    )


def test_settings_values_are_read_with_their_line_and_key(tmp_path):
    user = tmp_path / "home" / ".claude"
    user.mkdir(parents=True)
    path = user / "settings.local.json"
    path.write_text(settings_text())
    items = list(iter_claude_settings(claude_settings_files(user, []), Counter()))
    assert [(i.text, i.locator) for i in items] == [
        ("Bash(npm test)", f"{path}:4"),
        (f'Bash(curl -H "Authorization: Bearer {FAKE_BEARER}" https://api.example.test)', f"{path}:5"),
        ("DB_PASSWORD: hunter22x", f"{path}:8"),
        ("DEBUG: 1", f"{path}:8"),
        ("model: opus", f"{path}:9"),
    ]
    assert {(i.source, i.project, i.ts, i.role) for i in items} == {(SETTINGS_SOURCE, str(tmp_path / "home"), None, "user_settings")}


def test_settings_files_of_the_user_and_of_every_project_once(tmp_path):
    user = tmp_path / ".claude"
    project = tmp_path / "work" / "shop"
    files = claude_settings_files(user, [str(project), str(project), "-work-shop", "", str(tmp_path)])
    assert files == [
        (user / "settings.json", str(tmp_path), "user_settings"),
        (user / "settings.local.json", str(tmp_path), "user_settings"),
        (project / ".claude" / "settings.json", str(project), "project_settings"),
        (project / ".claude" / "settings.local.json", str(project), "project_settings"),
    ]  # the home folder as a project is the user's own settings: read once; a folder name is no path
    assert claude_settings_files(None, [str(project)])[0][0] == project / ".claude" / "settings.json"


def test_settings_that_are_there_but_not_read_are_counted_by_why(tmp_path):
    """A missing file is no gap; a file that is there and was not read is one, and the report must say so."""
    folder = tmp_path / ".claude"
    folder.mkdir()
    (folder / "settings.json").write_text("{ not json")
    (folder / "settings.local.json").write_text('["a list", "is no settings"]')
    other = tmp_path / "p" / ".claude"
    other.mkdir(parents=True)
    (other / "settings.json").mkdir()  # a folder where the file should be
    (other / "settings.local.json").write_text('{"env": {"PAD": "' + "x" * (4 * 1024 * 1024) + '"}}')
    stats = Counter()
    files = [*claude_settings_files(folder, [str(tmp_path / "p"), str(tmp_path / "nowhere")])]
    assert list(iter_claude_settings(files, stats)) == [] and stats["settings_files"] == 0
    assert (stats["settings_json"], stats["settings_access"], stats["settings_big"]) == (2, 1, 1)  # "nowhere" is no gap
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        locked = tmp_path / "q" / ".claude"
        locked.mkdir(parents=True)
        (locked / "settings.json").write_text('{"env": {"TOKEN": "x"}}')
        (locked / "settings.json").chmod(0)
        try:
            assert list(iter_claude_settings(claude_settings_files(None, [str(tmp_path / "q")]), stats)) == []
            assert stats["settings_access"] == 2
        finally:
            (locked / "settings.json").chmod(0o600)


# ---- a transcript is hostile: its fields are checked, its folders are looked at only on a local disk ----

import json  # noqa: E402

from boxed import platform as boxed_platform  # noqa: E402
from boxed.audit import paths  # noqa: E402


def write_lines(path, *records):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join((r if isinstance(r, str) else json.dumps(r)) + "\n" for r in records))


def test_lines_of_the_wrong_shape_are_malformed_and_the_rest_is_read(tmp_path):
    claude = tmp_path / "claude"
    good = {"type": "user", "message": {"content": "mail anna@acme.com"}, "cwd": "/work/a", "sessionId": "s"}
    write_lines(
        claude / "-work-a" / "a.jsonl",
        {"type": "user", "message": "a string", "cwd": "/work/a"},
        {"type": "user", "message": ["a", "list"]},
        {"type": "user", "message": {"content": "x"}, "cwd": 7},
        {"type": "user", "message": {"content": "x"}, "sessionId": ["s"]},
        {"type": "attachment", "rendered": 5},
        {"type": ["user"]},
        good,
    )
    write_lines(claude / "-work-b" / "b.jsonl", {**good, "cwd": "/work/b"})
    stats = Counter()
    items = list(iter_claude_code(claude, stats))
    assert [i.project for i in items] == ["/work/a", "/work/b"] and stats["malformed"] == 6
    codex = tmp_path / "codex"
    write_lines(
        codex / "r1.jsonl",
        {"type": "session_meta", "payload": "a string"},
        {"type": "session_meta", "payload": {"cwd": 7}},
        {"type": "session_meta", "payload": {"id": {"x": 1}}},
        {"type": "response_item", "payload": ["a", "list"]},
        {"type": "response_item", "payload": {"type": "message", "role": 1, "content": "x"}},
        {"type": "session_meta", "payload": {"id": "c1", "cwd": "/work/c"}},
        {"type": "response_item", "payload": {"type": "message", "role": "user", "content": "mail bob@acme.com"}},
    )
    write_lines(codex / "r2.jsonl", {"type": "response_item", "payload": {"type": "function_call_output", "output": "ok"}})
    stats = Counter()
    items = list(iter_codex(codex, stats))
    assert [(i.project, i.text) for i in items] == [("/work/c", "mail bob@acme.com"), ("?", "ok")] and stats["malformed"] == 5


def test_every_folder_a_transcript_names_is_a_project(tmp_path):
    claude = tmp_path / "claude"
    write_lines(claude / "-work-a" / "a.jsonl", {"type": "assistant", "message": {"content": "hi"}, "cwd": "/work/only-answers"})
    codex = tmp_path / "codex"
    write_lines(codex / "r.jsonl", {"type": "session_meta", "payload": {"id": "c", "cwd": "/work/meta"}},
                {"type": "turn_context", "payload": {"cwd": "/work/turn"}})
    projects: set[str] = set()
    assert list(iter_claude_code(claude, Counter(), projects)) == [] and list(iter_codex(codex, Counter(), projects)) == []
    assert projects == {"/work/only-answers", "/work/meta", "/work/turn"}


def test_a_transcript_that_cannot_be_read_is_counted(tmp_path):
    if not hasattr(os, "geteuid") or os.geteuid() == 0:
        pytest.skip("needs a user that a mode of 0 stops")
    path = tmp_path / "claude" / "-p" / "s.jsonl"
    write_lines(path, {"type": "user", "message": {"content": "x"}})
    path.chmod(0)
    try:
        stats = Counter()
        assert list(iter_claude_code(tmp_path / "claude", stats)) == [] and stats["transcripts_unread"] == 1
    finally:
        path.chmod(0o600)


@pytest.fixture
def looks(monkeypatch):
    """Every path the code looks at (lstat, stat, readlink, open), in order."""
    seen: list[str] = []
    for name in ("lstat", "stat", "readlink"):
        real = getattr(os, name)

        def spy(path, *a, _real=real, **kw):
            seen.append(os.fspath(path))
            return _real(path, *a, **kw)

        monkeypatch.setattr(os, name, spy)
    return seen


def test_projects_on_a_network_path_or_mount_are_skipped_without_a_look(tmp_path, monkeypatch, looks):
    share = tmp_path / "share"  # stands for a mount point of a network file system
    local = tmp_path / "local"
    (local / ".claude").mkdir(parents=True)
    (local / ".claude" / "settings.json").write_text('{"env": {"DB_PASSWORD": "hunter22x"}}')
    (tmp_path / "jump").symlink_to("//server/share")  # a link that leads to another computer
    (tmp_path / "into-share").symlink_to(share)
    monkeypatch.setattr(paths, "mount_table", lambda: [("/", False), (str(share), True)])
    named = ["//server/share/proj", "\\\\server\\share\\proj", str(share / "proj"), str(tmp_path / "jump" / "proj"),
             str(tmp_path / "into-share" / "proj"), str(local)]
    stats = Counter()
    files = claude_settings_files(None, named, stats)
    assert [f[1] for f in files] == [str(local), str(local)] and stats["projects_not_local"] == 5
    assert [i.text for i in iter_claude_settings(files, stats)] == ["DB_PASSWORD: hunter22x"]
    far = [p for p in looks if p.startswith(("//", "\\\\")) or p == str(share) or p.startswith(str(share) + os.sep)]
    assert far == []  # nothing on the share, nothing on the server, was looked at


def test_on_windows_a_unc_path_or_a_network_drive_is_never_looked_at(monkeypatch, looks):
    monkeypatch.setattr(boxed_platform, "IS_WINDOWS", True)
    monkeypatch.setattr(boxed_platform, "local_drive", lambda drive: drive.upper() == "C:")
    for path in ("\\\\server\\share\\proj", "//server/share/proj", "\\\\?\\UNC\\server\\share", "\\\\.\\pipe\\x", "Z:\\work", "C:work"):
        assert not paths.is_local_path(path), path
    assert looks == []


def fake_disk(monkeypatch, folders):
    """A disk that holds only `folders`, the same on every system: the walk of is_local_path stops at a part that is not there, so
    the mount points of another system must be there for it to reach them. Every path looked at is recorded, in order."""
    folder = os.lstat(Path(__file__).parent)
    seen: list[str] = []

    def lstat(path, *a, **kw):
        seen.append(os.fspath(path))
        if os.fspath(path) in folders:
            return folder
        raise FileNotFoundError(2, "no such file", os.fspath(path))

    monkeypatch.setattr(os, "lstat", lstat)
    return seen


def test_the_mount_table_of_macos_marks_network_and_automount_folders(monkeypatch):
    out = (
        "/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)\n"
        "/dev/disk3s5 on /System/Volumes/Data (apfs, local, journaled, nobrowse)\n"
        "map auto_home on /System/Volumes/Data/home (autofs, automounted, nobrowse)\n"
        "//dev@files.example.test/team on /Volumes/team share (smbfs, nodev, nosuid, mounted by dev)\n"
    )
    monkeypatch.setattr(paths.sys, "platform", "darwin")
    monkeypatch.setattr(boxed_platform, "IS_WINDOWS", False)
    monkeypatch.setattr(paths.subprocess, "run", lambda *a, **kw: type("Done", (), {"stdout": out})())
    table = paths.mount_table()
    assert table == [("/", False), ("/System/Volumes/Data", False), ("/System/Volumes/Data/home", True), ("/Volumes/team share", True)]
    data = ["/System", "/System/Volumes", "/System/Volumes/Data"]
    looked = fake_disk(monkeypatch, {*data, "/System/Volumes/Data/home", "/System/Volumes/Data/work", "/Volumes", "/Volumes/team share"})
    assert not paths.is_local_path("/Volumes/team share/app", table) and not paths.is_local_path("/System/Volumes/Data/home/x", table)
    assert paths.is_local_path("/System/Volumes/Data/work", table)
    assert looked == ["/Volumes", *data, *data, "/System/Volumes/Data/work"]  # up to a mount point, never on or into it


def test_the_mount_table_of_linux_reads_escaped_and_unusual_names(tmp_path, monkeypatch):
    """/proc/self/mounts escapes a space, tab, line break and backslash in a name as \\ooo and nothing else: a no-break space, a
    carriage return or a byte that is not UTF-8 is written as it is and is part of the mount point."""
    mounts = tmp_path / "mounts"
    mounts.write_bytes(
        b"/dev/vda1 / ext4 rw,relatime 0 0\n"
        b"//files.example.test/team /mnt/team\\040share cifs rw,vers=3.0 0 0\n"
        b"files.example.test:/export /mnt/tab\\011and\\134back nfs4 rw 0 0\n"
        b"dev@files.example.test: /mnt/no\xc2\xa0break fuse.sshfs rw 0 0\n"
        b"//files.example.test/raw /mnt/raw\xff\r cifs rw 0 0\n"
        b"tmpfs /mnt/local\\040disk tmpfs rw 0 0\n"
    )
    monkeypatch.setattr(paths.sys, "platform", "linux")
    monkeypatch.setattr(paths.sys, "getfilesystemencoding", lambda: "utf-8")  # what Linux has: os.fsdecode's spelling, on any system
    monkeypatch.setattr(paths.sys, "getfilesystemencodeerrors", lambda: "surrogateescape")
    monkeypatch.setattr(boxed_platform, "IS_WINDOWS", False)
    monkeypatch.setattr(paths, "open", lambda name, *a, **kw: open(mounts if name == "/proc/self/mounts" else name, *a, **kw), raising=False)
    table = paths.mount_table()
    shares = ["/mnt/team share", "/mnt/tab\tand\\back", "/mnt/no\xa0break", "/mnt/raw\udcff\r"]
    assert table == [("/", False), *((s, True) for s in shares), ("/mnt/local disk", False)]
    looked = fake_disk(monkeypatch, {"/mnt", *shares, "/mnt/local disk", "/mnt/local disk/app"})
    for share in shares:
        assert not paths.is_local_path(share + "/app", table), share
    assert paths.is_local_path("/mnt/local disk/app", table)
    assert set(looked) == {"/mnt", "/mnt/local disk", "/mnt/local disk/app"}  # nothing on a share was looked at
