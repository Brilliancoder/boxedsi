"""`boxed hook` fails closed. Inside a masked copy any failure blocks the step (exit 2, one fixed line, a line in
hook-errors.log when the log can be written); outside a copy the hook prints nothing and exits 0, whatever fails. Until now a hook
that could not open the data folder (the case under `boxed run`) let every call through, without a word. No test touches the real
~/.boxed or the keychain: conftest.py points BOXED_HOME at a temp folder and the keys at files."""

import io
import json
import os
import sys

import pytest

from boxed.cli import main
from boxed.hooks import HOOKS
from boxed.workspace import MARKER_FILE

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="boxed hook is not supported on Windows yet")

HOOK_FAILED = "boxed: the hook failed and blocked this step; details are in the boxed hook error log"


@pytest.fixture
def mirror(tmp_path):
    """A folder the hooks take for a mirror: its marker file is there."""
    folder = tmp_path / "mirror"
    folder.mkdir()
    (folder / MARKER_FILE).write_text("{}")
    return folder


@pytest.fixture
def elsewhere(tmp_path):
    folder = tmp_path / "elsewhere"
    folder.mkdir()
    return folder


def call(capsys, monkeypatch, cwd, stdin, event="pre-tool-use"):
    """One run of `boxed hook`: the exit code, stdout and stderr. stdin is text, or bytes for input that is not UTF-8."""
    monkeypatch.chdir(cwd)
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(stdin if isinstance(stdin, bytes) else stdin.encode())))
    code = main(["hook", event])
    out, err = capsys.readouterr()
    return code, out, err


def payload(cwd, **extra):
    return json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Read", "tool_input": {"file_path": "a.txt"}, "cwd": str(cwd)} | extra)


def cannot_open_the_data_folder(kind, boxed_env, tmp_path, monkeypatch):
    """The two ways boxed_home() fails in a sandbox that allows no writes there: the folder cannot be made, or its mode is wrong and
    chmod is refused."""
    if kind == "not a folder":
        blocker = tmp_path / "blocker"
        blocker.write_text("a file where the data folder should be made")
        monkeypatch.setenv("BOXED_HOME", str(blocker / "boxed"))
        return

    def refuse(path, *args, **kwargs):
        raise PermissionError(1, "Operation not permitted", str(path))

    boxed_env.mkdir()
    boxed_env.chmod(0o755)
    monkeypatch.setattr(os, "chmod", refuse)


FAILURES = ["not a folder", "mode that cannot be set"]


@pytest.mark.parametrize("kind", FAILURES)
def test_a_hook_that_cannot_open_the_data_folder_blocks_in_a_copy(kind, mirror, boxed_env, tmp_path, capsys, monkeypatch):
    cannot_open_the_data_folder(kind, boxed_env, tmp_path, monkeypatch)
    assert call(capsys, monkeypatch, mirror, payload(mirror)) == (2, "", HOOK_FAILED + "\n")


@pytest.mark.parametrize("kind", FAILURES)
def test_a_hook_that_cannot_open_the_data_folder_says_nothing_outside_a_copy(kind, elsewhere, boxed_env, tmp_path, capsys, monkeypatch):
    cannot_open_the_data_folder(kind, boxed_env, tmp_path, monkeypatch)
    assert call(capsys, monkeypatch, elsewhere, payload(elsewhere)) == (0, "", "")


@pytest.mark.parametrize("event", list(HOOKS))
def test_every_event_blocks_in_a_copy_when_the_data_folder_cannot_be_opened(event, mirror, boxed_env, tmp_path, capsys, monkeypatch):
    cannot_open_the_data_folder("not a folder", boxed_env, tmp_path, monkeypatch)
    assert call(capsys, monkeypatch, mirror, payload(mirror), event) == (2, "", HOOK_FAILED + "\n")


def test_a_hook_that_fails_outside_a_copy_prints_nothing_and_exits_0(elsewhere, capsys, monkeypatch, boxed_env):
    def fails(payload, home):
        raise RuntimeError("a bug in a hook")

    monkeypatch.setitem(HOOKS, "pre-tool-use", fails)
    assert call(capsys, monkeypatch, elsewhere, payload(elsewhere)) == (0, "", "")
    log = (boxed_env / "hook-errors.log").read_text()  # the log still has it: the event and the class, never the message
    assert "pre-tool-use: RuntimeError: " in log and "a bug in a hook" not in log


def test_a_hook_that_fails_inside_a_copy_blocks_and_logs(mirror, capsys, monkeypatch, boxed_env):
    def fails(payload, home):
        raise RuntimeError("a bug in a hook")

    monkeypatch.setitem(HOOKS, "pre-tool-use", fails)
    assert call(capsys, monkeypatch, mirror, payload(mirror)) == (2, "", HOOK_FAILED + "\n")
    log = (boxed_env / "hook-errors.log").read_text()
    assert "pre-tool-use: RuntimeError: " in log and "a bug in a hook" not in log


def test_input_that_is_not_utf8_blocks_in_a_copy(mirror, capsys, monkeypatch):
    assert call(capsys, monkeypatch, mirror, b"\xff\xfe{}") == (2, "", HOOK_FAILED + "\n")


def test_input_that_is_not_utf8_is_ignored_outside_a_copy(elsewhere, capsys, monkeypatch):
    assert call(capsys, monkeypatch, elsewhere, b"\xff\xfe{}") == (0, "", "")


@pytest.mark.parametrize("cwd", [5, ["a"], {"a": 1}])
def test_a_cwd_that_is_not_text_is_not_a_reason_to_crash(cwd, mirror, elsewhere, capsys, monkeypatch):
    bad = json.dumps({"tool_name": "Read", "tool_input": {}, "cwd": cwd})
    assert call(capsys, monkeypatch, mirror, bad) == (2, "", HOOK_FAILED + "\n")  # the folder the process runs in is a copy
    assert call(capsys, monkeypatch, elsewhere, bad) == (0, "", "")


def test_a_hook_that_cannot_tell_where_it_is_blocks(elsewhere, capsys, monkeypatch):
    nowhere = json.dumps({"tool_name": "Read", "tool_input": {}, "cwd": "a\0b"})  # no path can have a NUL in it
    assert call(capsys, monkeypatch, elsewhere, nowhere) == (2, "", HOOK_FAILED + "\n")
