"""What the CLI refuses at level 4, how it logs a failed hook, what encoding it prints. No test touches the real
~/.boxed or the keychain: conftest.py points BOXED_HOME at a temp folder and the keys at files."""

import io
import json
import os
import re
import stat
import subprocess
import sys

import pytest

import boxed.cli
from boxed.cli import main
from boxed.config import ProjectConfig, load_config
from boxed.hooks import HOOKS
from boxed.journal import Journal
from boxed.keys import default_keystore
from boxed.vault import Vault
from boxed.workspace import MARKER_FILE, create_workspace

REFUSAL = "boxed: error: level 4 sends the task and the table schema only: use boxed plan, or ask at a level from 0 to 3"


def run(capsys, argv, stdin=None, monkeypatch=None):
    if stdin is not None:
        monkeypatch.setattr("sys.stdin", io.StringIO(stdin))
    code = main(argv)
    out, err = capsys.readouterr()
    return code, out, err


def records(boxed_env):
    path = boxed_env / "journal.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


# ---- m-level4: mask, mask-file and workspace create refuse level 4 ----


def attempt(command, extra, tmp_path, capsys, monkeypatch):
    """One of the three commands on a text with an email in it, and the place its output would land."""
    if command == "mask":
        return run(capsys, ["mask", *extra, "-"], stdin="mail ivan@acme.com", monkeypatch=monkeypatch), None
    if command == "mask-file":
        src = tmp_path / "in.csv"
        src.write_text("name,mail\nIvan,ivan@acme.com\n")
        dest = tmp_path / "out.csv"
        return run(capsys, ["mask-file", *extra, str(src), str(dest)]), dest
    project = tmp_path / "proj"
    project.mkdir()
    (project / "a.txt").write_text("mail ivan@acme.com\n")
    return run(capsys, ["workspace", "create", *extra, str(project)]), None


COMMANDS = ["mask", "mask-file", "workspace create"]


@pytest.fixture(params=COMMANDS)
def command(request):
    if request.param == "workspace create" and sys.platform == "win32":
        pytest.skip("boxed workspace is not supported on Windows yet")
    return request.param.split()[0]


def assert_nothing_happened(boxed_env, dest):
    assert not boxed_env.exists()  # not the data folder, not the vault, not a key; so no journal and no mirror either
    assert dest is None or not dest.exists()  # no clean copy


def test_level_4_is_refused_with_the_text_ask_uses(command, tmp_path, capsys, monkeypatch, boxed_env):
    """The detector treats 4 as 3: the text would be masked at 3 and the journal would call it level 4."""
    monkeypatch.chdir(tmp_path)
    (code, out, err), dest = attempt(command, ["--level", "4"], tmp_path, capsys, monkeypatch)
    assert code == 2 and out == ""
    assert err.strip() == REFUSAL
    assert_nothing_happened(boxed_env, dest)


def test_a_broken_keychain_does_not_replace_the_refusal(command, tmp_path, capsys, monkeypatch, boxed_env):
    def no_backend():
        raise RuntimeError("no keyring backend")

    monkeypatch.setattr("boxed.cli.default_keystore", no_backend)
    monkeypatch.chdir(tmp_path)
    (code, out, err), dest = attempt(command, ["--level", "4"], tmp_path, capsys, monkeypatch)
    assert code == 2 and out == "" and err.strip() == REFUSAL
    assert_nothing_happened(boxed_env, dest)


def test_level_4_in_boxed_toml_is_refused_without_a_level(command, tmp_path, capsys, monkeypatch, boxed_env):
    (tmp_path / "boxed.toml").write_text("[boxed]\nlevel = 4\n")
    monkeypatch.chdir(tmp_path)
    (code, out, err), dest = attempt(command, [], tmp_path, capsys, monkeypatch)
    assert code == 2 and out == ""
    assert err.strip() == REFUSAL
    assert_nothing_happened(boxed_env, dest)


@pytest.mark.parametrize("level", [0, 2, 3])
def test_a_level_from_0_to_3_overrides_level_4_in_boxed_toml(command, level, tmp_path, capsys, monkeypatch, boxed_env):
    (tmp_path / "boxed.toml").write_text("[boxed]\nlevel = 4\n")
    monkeypatch.chdir(tmp_path)
    (code, out, err), dest = attempt(command, ["--level", str(level)], tmp_path, capsys, monkeypatch)
    assert code == 0 and "level 4" not in err
    assert records(boxed_env)[-1]["level"] == level  # recorded at the level it was masked at
    assert dest is None or dest.exists()


def test_a_level_from_0_to_3_works_without_a_boxed_toml(command, tmp_path, capsys, monkeypatch, boxed_env):
    monkeypatch.chdir(tmp_path)
    (code, _, _), _ = attempt(command, ["--level", "3"], tmp_path, capsys, monkeypatch)
    assert code == 0 and records(boxed_env)[-1]["level"] == 3


# ---- boxed mcp refuses level 4 too ----


def mcp(cwd):
    """boxed mcp in `cwd` with nothing on stdin: a server that starts meets the end of its input at once and stops."""
    return subprocess.run([sys.executable, "-m", "boxed.cli", "mcp"], input=b"", capture_output=True, cwd=cwd, timeout=60)


@pytest.mark.skipif(sys.platform == "win32", reason="boxed mcp is not supported on Windows yet")
def test_mcp_refuses_level_4_from_boxed_toml_before_it_serves(tmp_path, boxed_env):
    """It served: text masked at 3 ([DATE_1], [MONEY_1]) and records that said level 4."""
    (tmp_path / "boxed.toml").write_text("[boxed]\nlevel = 4\n")
    done = mcp(tmp_path)
    assert done.returncode == 2 and done.stdout == b""
    assert done.stderr.decode().strip() == REFUSAL
    assert not boxed_env.exists()  # not the home, not the vault, not a key


@pytest.mark.skipif(sys.platform == "win32", reason="boxed mcp is not supported on Windows yet")
def test_mcp_still_serves_at_a_level_from_0_to_3(tmp_path):
    (tmp_path / "boxed.toml").write_text("[boxed]\nlevel = 3\n")
    done = mcp(tmp_path)
    assert (done.returncode, done.stdout, done.stderr) == (0, b"", b"")


@pytest.mark.skipif(sys.platform == "win32", reason="boxed mcp is not supported on Windows yet")
def test_mcp_in_a_mirror_made_at_level_4_refuses_too(tmp_path, boxed_env):
    """An older version could make one: the mirror keeps the level it was made at."""
    project = tmp_path / "proj"
    project.mkdir()
    (project / "a.txt").write_text("mail ivan@acme.com\n")
    boxed_env.mkdir(parents=True)
    keys = default_keystore()
    made = create_workspace(
        project, level=4, config=ProjectConfig(), vault=Vault(boxed_env / "vault.db", keys),
        journal=Journal(boxed_env / "journal.jsonl", keys), home=boxed_env,
    )
    done = mcp(made.workspace.mirror)
    assert done.returncode == 2 and done.stdout == b"" and done.stderr.decode().strip() == REFUSAL


# ---- boxed.toml is read as UTF-8, whatever the locale says ----

DICTIONARY = '[boxed]\n[boxed.dictionary]\n"Ромашка" = "CLIENT"\n'


def test_boxed_toml_is_read_as_utf8_in_a_latin_1_locale(tmp_path, boxed_env):
    """In ISO 8859-1 every byte is a letter: the term was read as other letters and nothing was masked, with exit code 0."""
    (tmp_path / "boxed.toml").write_bytes(DICTIONARY.encode("utf-8"))
    env = {**os.environ, "LC_ALL": "en_US.ISO8859-1", "PYTHONUTF8": "0", "PYTHONCOERCECLOCALE": "0"}
    env.pop("PYTHONIOENCODING", None)
    done = subprocess.run(
        [sys.executable, "-m", "boxed.cli", "mask", "-"], input="Сделка с Ромашка закрыта".encode("utf-8"),
        capture_output=True, env=env, cwd=tmp_path, timeout=60,
    )
    assert done.returncode == 0 and done.stdout.decode("utf-8") == "Сделка с [CLIENT_1] закрыта"


def test_a_boxed_toml_that_is_not_utf8_is_refused_with_a_fixed_message(tmp_path, capsys, monkeypatch):
    (tmp_path / "boxed.toml").write_bytes(DICTIONARY.encode("cp1251"))
    with pytest.raises(ValueError) as raised:
        load_config(tmp_path)
    assert str(raised.value) == "boxed.toml: not UTF-8 text"  # no path, codec, byte or position: they would quote the file
    monkeypatch.chdir(tmp_path)
    code, out, err = run(capsys, ["mask", "-"], stdin="Сделка с Ромашка закрыта", monkeypatch=monkeypatch)
    assert code == 2 and out == "" and err.strip() == "boxed: error: boxed.toml: not UTF-8 text"


# ---- m-hook-log: hook-errors.log is opened without following links, waiting on pipes or loosening its mode ----

HOOK_FAILED = "boxed: the hook failed and blocked this step; details are in the boxed hook error log"
LOG = "hook-errors.log"


@pytest.fixture
def mirror(tmp_path):
    """A folder the hooks take for a mirror: its marker file is there."""
    folder = tmp_path / "mirror"
    folder.mkdir()
    (folder / MARKER_FILE).write_text("{}")
    return folder


def fail_hook(capsys, monkeypatch, where):
    """The pre-tool-use hook given text that is not JSON, in `where`: it fails on purpose and logs why."""
    monkeypatch.chdir(where)
    return run(capsys, ["hook", "pre-tool-use"], stdin="{broken", monkeypatch=monkeypatch)


@pytest.mark.skipif(sys.platform == "win32", reason="boxed hook is not supported on Windows yet")
def test_a_failed_hook_appends_a_line_to_a_private_log(mirror, capsys, monkeypatch, boxed_env):
    for _ in range(2):
        assert fail_hook(capsys, monkeypatch, mirror) == (2, "", HOOK_FAILED + "\n")
    log = boxed_env / LOG
    lines = log.read_text().splitlines()
    assert len(lines) == 2
    # the class of the error and fixed words: the message of an error may quote a path, a setting or a value, and is never kept
    assert all(re.fullmatch(r"\d{4}-\d\d-\d\dT[\d:.]+\+00:00 pre-tool-use: ValueError: the hook failed; the message of the error is not kept", line) for line in lines)
    assert stat.S_IMODE(log.stat().st_mode) == 0o600


@pytest.mark.skipif(sys.platform == "win32", reason="boxed hook is not supported on Windows yet")
def test_a_log_that_was_left_readable_is_made_private_again(mirror, capsys, monkeypatch, boxed_env):
    boxed_env.mkdir(parents=True)
    log = boxed_env / LOG
    log.write_text("earlier\n")
    log.chmod(0o644)
    assert fail_hook(capsys, monkeypatch, mirror)[0] == 2
    assert log.read_text().startswith("earlier\n") and len(log.read_text().splitlines()) == 2
    assert stat.S_IMODE(log.stat().st_mode) == 0o600


PLANTED = ["link", "hard link", "dangling link", "pipe", "folder", "read-only file"]


def plant(kind, home, tmp_path, request):
    """Something other than a plain, writable file of its own where the log goes, and a check that nothing reached what is behind it."""
    home.mkdir(parents=True, exist_ok=True)
    log, victim = home / LOG, tmp_path / "victim.txt"
    if kind == "link":
        victim.write_bytes(b"precious\n")
        victim.chmod(0o644)
        log.symlink_to(victim)
        return lambda: victim.read_bytes() == b"precious\n" and stat.S_IMODE(victim.stat().st_mode) == 0o644
    if kind == "hard link":  # a second name of a file of the same user: a plain file, but not the log's own
        victim.write_bytes(b"precious\n")
        victim.chmod(0o644)
        os.link(victim, log)
        return lambda: victim.read_bytes() == b"precious\n" and stat.S_IMODE(victim.stat().st_mode) == 0o644
    if kind == "dangling link":
        log.symlink_to(victim)
        return lambda: not victim.exists()
    if kind == "pipe":
        os.mkfifo(log)
        reader = os.open(log, os.O_RDONLY | os.O_NONBLOCK)  # with a reader there, a write would not block: the test can fail instead of hanging
        request.addfinalizer(lambda: os.close(reader))
        return lambda: os.read(reader, 100) == b""
    if kind == "folder":
        log.mkdir()
        return lambda: list(log.iterdir()) == []
    log.write_bytes(b"earlier\n")
    log.chmod(0o400)
    return lambda: log.read_bytes() == b"earlier\n"


@pytest.mark.parametrize("where", ["mirror", "elsewhere"])
@pytest.mark.parametrize("kind", PLANTED)
@pytest.mark.skipif(sys.platform == "win32", reason="boxed hook is not supported on Windows yet")
def test_a_log_that_is_not_a_plain_file_gets_nothing_and_the_hook_exits_as_before(kind, where, mirror, tmp_path, capsys, monkeypatch, boxed_env, request):
    if kind == "read-only file" and os.geteuid() == 0:
        pytest.skip("root can write to a read-only file")
    nothing_reached = plant(kind, boxed_env, tmp_path, request)
    code, out, err = fail_hook(capsys, monkeypatch, mirror if where == "mirror" else tmp_path)
    assert (code, out, err) == ((2, "", HOOK_FAILED + "\n") if where == "mirror" else (0, "", ""))  # blocks in a mirror, silent elsewhere
    assert nothing_reached()


@pytest.mark.skipif(sys.platform == "win32", reason="boxed hook is not supported on Windows yet")
def test_a_pipe_nobody_reads_does_not_hang_the_hook(mirror, boxed_env):
    boxed_env.mkdir(parents=True)
    os.mkfifo(boxed_env / LOG)
    argv = [sys.executable, "-m", "boxed.cli", "hook", "pre-tool-use"]
    done = subprocess.run(argv, input="{broken", capture_output=True, text=True, cwd=mirror, timeout=15)  # opening a pipe for writing waits for a reader
    assert (done.returncode, done.stderr) == (2, HOOK_FAILED + "\n")


@pytest.mark.parametrize("where", ["mirror", "elsewhere"])
@pytest.mark.skipif(sys.platform == "win32", reason="boxed hook is not supported on Windows yet")
def test_an_error_text_that_cannot_be_encoded_is_logged_and_the_hook_exits_as_before(where, mirror, tmp_path, capsys, monkeypatch, boxed_env):
    def fails(payload, home):
        raise RuntimeError("no such file: caf\udcc3")  # a name with a byte that is not UTF-8, as the file system hands it over

    monkeypatch.setitem(HOOKS, "pre-tool-use", fails)
    cwd = mirror if where == "mirror" else tmp_path
    monkeypatch.chdir(cwd)
    payload = json.dumps({"tool_name": "Read", "tool_input": {}, "cwd": str(cwd)})
    assert run(capsys, ["hook", "pre-tool-use"], stdin=payload, monkeypatch=monkeypatch) == ((2, "", HOOK_FAILED + "\n") if where == "mirror" else (0, "", ""))
    log = (boxed_env / LOG).read_text()
    assert log.endswith(" pre-tool-use: RuntimeError: the hook failed; the message of the error is not kept\n") and "caf" not in log


# ---- m-encoding: the CLI prints UTF-8 whatever the locale says ----

CYRILLIC = "Привет, Иван! Почта: ivan@acme.com"
CYRILLIC_MASKED = "Привет, Иван! Почта: [EMAIL_1]"


def test_output_is_utf8_on_a_stream_that_is_not(monkeypatch):
    """A console set to cp1252 cannot hold Cyrillic letters: the streams are switched to UTF-8 before anything is written."""
    out, err = io.BytesIO(), io.BytesIO()
    monkeypatch.setattr(sys, "stdout", io.TextIOWrapper(out, encoding="cp1252", write_through=True))
    monkeypatch.setattr(sys, "stderr", io.TextIOWrapper(err, encoding="cp1252", errors="backslashreplace", write_through=True))
    monkeypatch.setattr(sys, "stdin", io.StringIO(CYRILLIC))
    assert main(["mask", "--scope", "сфера", "-"]) == 0
    assert out.getvalue().decode("utf-8") == CYRILLIC_MASKED
    assert err.getvalue().decode("utf-8") == "scope: сфера\n"
    assert (sys.stdout.encoding, sys.stdout.errors) == ("utf-8", "strict")  # the error handlers are the streams' own
    assert (sys.stderr.encoding, sys.stderr.errors) == ("utf-8", "backslashreplace")


def test_a_failure_is_reported_in_utf8_on_a_stream_that_is_not(monkeypatch):
    err = io.BytesIO()
    monkeypatch.setattr(sys, "stdout", io.TextIOWrapper(io.BytesIO(), encoding="cp1252"))
    monkeypatch.setattr(sys, "stderr", io.TextIOWrapper(err, encoding="cp1252", write_through=True))
    monkeypatch.setattr(sys, "stdin", io.StringIO("x"))
    assert main(["restore", "--scope", "сфера", "-"]) == 2
    assert err.getvalue().decode("utf-8") == f"boxed: error: {boxed.cli.UNKNOWN_SCOPE}\n"  # the name of the scope is not quoted
    assert sys.stderr.encoding == "utf-8"


def test_streams_that_are_utf8_already_are_left_alone(monkeypatch):
    out = io.TextIOWrapper(io.BytesIO(), encoding="UTF-8", errors="surrogateescape")
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stdin", io.StringIO(CYRILLIC))
    assert main(["mask", "-"]) == 0
    assert (out.encoding, out.errors) == ("UTF-8", "surrogateescape")  # not reconfigured: the spelling and the handler are as they were


def test_a_c_locale_gets_utf8_too(tmp_path, boxed_env):
    """The real thing: Python 3.13 in the C locale with UTF-8 mode off has ASCII streams and an ASCII default for open()."""
    project = tmp_path / "claude" / "-work-proj"
    project.mkdir(parents=True)
    line = {"type": "user", "cwd": "/work/проект", "timestamp": "2026-10-04T10:00:00Z", "sessionId": "s1", "message": {"content": CYRILLIC}}
    (project / "s1.jsonl").write_text(json.dumps(line, ensure_ascii=False) + "\n", encoding="utf-8")
    env = {**os.environ, "LC_ALL": "C", "LANG": "C", "PYTHONUTF8": "0", "PYTHONCOERCECLOCALE": "0"}
    env.pop("PYTHONIOENCODING", None)

    def boxed(*argv, text=None):
        return subprocess.run([sys.executable, "-m", "boxed.cli", *argv], input=text, capture_output=True, env=env, cwd=tmp_path, timeout=60)

    done = boxed("mask", "--scope", "enc", "-", text=CYRILLIC.encode("utf-8"))
    assert done.returncode == 0 and done.stdout.decode("utf-8") == CYRILLIC_MASKED
    page = tmp_path / "audit.html"
    done = boxed("audit", "--claude-dir", str(tmp_path / "claude"), "--codex-dir", str(tmp_path / "none"), "--html", str(page))
    assert done.returncode == 0 and "/work/проект" in done.stdout.decode("utf-8")
    assert "/work/проект" in page.read_bytes().decode("utf-8")


# ---- Windows: the hook log, where os has no O_NOFOLLOW, O_NONBLOCK or fchmod ----


def test_windows_the_hook_log_is_written_where_os_has_none_of_the_posix_calls(windows_os, boxed_env):
    from boxed.cli import _log_hook_error

    boxed_env.mkdir(parents=True)
    _log_hook_error(boxed_env, "pre-tool-use", ValueError("hook input is not a JSON object"))
    assert (boxed_env / LOG).read_text().endswith(" pre-tool-use: ValueError: the hook failed; the message of the error is not kept\n")


def test_windows_a_reparse_point_in_place_of_the_hook_log_gets_nothing(windows_os, see_as, boxed_env):
    from boxed.cli import _log_hook_error

    boxed_env.mkdir(parents=True)
    log = boxed_env / LOG
    log.write_text("theirs\n")
    see_as(log, st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT)  # a plain file by its mode, a junction or a placeholder for Windows
    _log_hook_error(boxed_env, "pre-tool-use", ValueError("x"))
    assert log.read_text() == "theirs\n"


# ---- Windows: a masked text leaves as UTF-8 with line feeds, whatever the pipe is set to ----


def test_windows_the_cli_writes_utf8_and_line_feeds_to_a_pipe(windows_os, monkeypatch):
    """Python turns each \\n into \\r\\n on a pipe there, and writes the code page (cp1251 on a Russian Windows): a masked text must come out
    as it went in, byte for byte, because it is hashed, compared and restored."""
    out, err = io.BytesIO(), io.BytesIO()
    monkeypatch.setattr(sys, "stdout", io.TextIOWrapper(out, encoding="cp1251", newline="\r\n", write_through=True))
    monkeypatch.setattr(sys, "stderr", io.TextIOWrapper(err, encoding="cp1251", newline="\r\n", write_through=True))
    monkeypatch.setattr(sys, "stdin", io.StringIO("Привет\nmail ivan@acme.com\n"))
    assert main(["mask", "--scope", "win", "-"]) == 0
    assert out.getvalue() == "Привет\nmail [EMAIL_1]\n".encode("utf-8")
    assert err.getvalue() == b"scope: win\n"
