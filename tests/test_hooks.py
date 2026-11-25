import argparse
import io
import json
import os
import subprocess
import sys
import time

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from boxed import hooks
from boxed.cli import main
from boxed.config import ProjectConfig
from boxed.hooks import _runs_boxed, _shell_words, hook_pre_tool_use, hook_session_start, hook_user_prompt_submit
from boxed.journal import Journal
from boxed.keys import default_keystore
from boxed.vault import Vault
from boxed.workspace import MARKER_FILE, create_workspace

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="the guard hooks of Claude Code are not supported on Windows yet (boxed hook, boxed workspace)")


@pytest.fixture(autouse=True)
def no_git_config(monkeypatch):
    """git reads neither the user's nor the system's configuration here: a test depends on, and touches, only its own."""
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")


@pytest.fixture
def ws_env(tmp_path, boxed_env):
    repo = tmp_path / "client-repo"
    (repo / "src").mkdir(parents=True)
    (repo / ".env").write_text("DB_PASSWORD=hunter22\n")
    (repo / "src" / "app.py").write_text("print('ivan.petrov@acme.com')\n")
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    home = boxed_env
    home.mkdir(parents=True, exist_ok=True)
    keys = default_keystore()
    report = create_workspace(
        repo,
        level=2,
        config=ProjectConfig(),
        vault=Vault(home / "vault.db", keys),
        journal=Journal(home / "journal.jsonl", keys),
        home=home,
    )
    return repo.resolve(), home, report.workspace


def tool(name, cwd, **tool_input):
    return {"hook_event_name": "PreToolUse", "tool_name": name, "tool_input": tool_input, "cwd": str(cwd)}


def test_prompt_with_email_blocked_in_workspace(ws_env):
    _, home, ws = ws_env
    r = hook_user_prompt_submit({"prompt": "send it to ivan.petrov@acme.com", "cwd": str(ws.mirror)}, home)
    assert r.exit_code == 2 and "EMAIL" in r.stderr and "ivan.petrov@acme.com" not in r.stderr
    last = json.loads((home / "journal.jsonl").read_text().splitlines()[-1])
    assert (last["status"], last["markers_by_kind"]) == ("blocked", {"EMAIL": 1})


def test_prompt_clean_passes(ws_env):
    _, home, ws = ws_env
    assert hook_user_prompt_submit({"prompt": "refactor the parser", "cwd": str(ws.mirror)}, home).exit_code == 0


def test_prompt_outside_workspace_passes(ws_env, tmp_path):
    _, home, _ = ws_env
    assert hook_user_prompt_submit({"prompt": "mail ivan.petrov@acme.com", "cwd": str(tmp_path)}, home).exit_code == 0


def test_read_original_denied(ws_env):
    repo, home, ws = ws_env
    r = hook_pre_tool_use(tool("Read", ws.mirror, file_path=str(repo / ".env")), home)
    assert r.exit_code == 2 and str(repo) not in r.stderr


def test_read_via_dotdot_denied(ws_env):
    repo, home, ws = ws_env
    rel = os.path.relpath(repo / ".env", ws.mirror)
    assert hook_pre_tool_use(tool("Read", ws.mirror, file_path=rel), home).exit_code == 2


def test_read_tilde_path_denied(ws_env, monkeypatch):
    repo, home, ws = ws_env
    monkeypatch.setenv("HOME", str(repo.parent))
    assert hook_pre_tool_use(tool("Read", ws.mirror, file_path=f"~/{repo.name}/.env"), home).exit_code == 2


def test_bash_cat_original_denied(ws_env):
    repo, home, ws = ws_env
    assert hook_pre_tool_use(tool("Bash", ws.mirror, command=f"cat {repo}/.env | head"), home).exit_code == 2
    rel = os.path.relpath(repo, ws.mirror)
    assert hook_pre_tool_use(tool("Bash", ws.mirror, command=f"grep -r pass {rel}"), home).exit_code == 2


def test_glob_and_grep_into_original_denied(ws_env):
    repo, home, ws = ws_env
    assert hook_pre_tool_use(tool("Glob", ws.mirror, pattern=f"{repo}/**/*.py"), home).exit_code == 2
    assert hook_pre_tool_use(tool("Grep", ws.mirror, pattern="password", path=str(repo)), home).exit_code == 2


def test_read_home_denied(ws_env):
    _, home, ws = ws_env
    assert hook_pre_tool_use(tool("Read", ws.mirror, file_path=str(home / "vault.db")), home).exit_code == 2


def test_symlink_into_original_denied(ws_env):
    repo, home, ws = ws_env
    os.symlink(repo / ".env", ws.mirror / "peek")
    assert hook_pre_tool_use(tool("Read", ws.mirror, file_path=str(ws.mirror / "peek")), home).exit_code == 2


def test_read_mirror_allowed(ws_env):
    _, home, ws = ws_env
    assert hook_pre_tool_use(tool("Read", ws.mirror, file_path=str(ws.mirror / "src" / "app.py")), home).exit_code == 0
    assert hook_pre_tool_use(tool("Read", ws.mirror, file_path="src/app.py"), home).exit_code == 0
    assert hook_pre_tool_use(tool("Grep", ws.mirror, pattern="def", path="."), home).exit_code == 0
    assert hook_pre_tool_use(tool("Bash", ws.mirror, command="ls -la && git status"), home).exit_code == 0


def test_settings_written(ws_env):
    repo, home, ws = ws_env
    settings = json.loads((ws.mirror / ".claude" / "settings.local.json").read_text())
    deny = settings["permissions"]["deny"]
    h = home.resolve()
    for verb in ("Read", "Edit"):
        assert f"{verb}(/{repo}/**)" in deny
        assert f"{verb}(/{h}/vault.db)" in deny and f"{verb}(/{h}/state/**)" in deny
    # Claude Code 2.1.301 ignores Write(path) rules and warns: file writes are covered by Edit(path)
    assert not any(rule.startswith("Write(") for rule in deny)
    # the mirror lives inside BOXED_HOME, so no rule may cover the whole home
    assert not any(rule.endswith(f"(/{h}/**)") for rule in deny)
    assert settings["permissions"]["blockReadsOutsideWorkingDirectories"] is True
    deny_read = settings["sandbox"]["filesystem"]["denyRead"]
    assert str(repo) in deny_read and str(h / "vault.db") in deny_read and str(h) not in deny_read
    commands = json.dumps(settings["hooks"])
    for hook in ("hook user-prompt-submit", "hook pre-tool-use", "hook session-start"):
        assert hook in commands


def test_session_start_note(ws_env, tmp_path):
    _, home, ws = ws_env
    out = json.loads(hook_session_start({"cwd": str(ws.mirror)}, home).stdout)
    assert "placeholder" in out["hookSpecificOutput"]["additionalContext"]
    assert hook_session_start({"cwd": str(tmp_path)}, home).stdout == ""


def run_cli(argv, stdin, monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO(stdin))
    code = main(argv)
    capsys.readouterr()
    return code


def test_hook_errors_fail_closed(ws_env, tmp_path, monkeypatch, capsys):
    _, _, ws = ws_env
    monkeypatch.chdir(ws.mirror)
    assert run_cli(["hook", "pre-tool-use"], "{broken", monkeypatch, capsys) == 2
    assert run_cli(["hook", "user-prompt-submit"], "{broken", monkeypatch, capsys) == 2
    monkeypatch.chdir(tmp_path)
    assert run_cli(["hook", "pre-tool-use"], "{broken", monkeypatch, capsys) == 0


def test_tampered_marker_fails_closed(ws_env, monkeypatch, capsys):
    _, _, ws = ws_env
    (ws.mirror / MARKER_FILE).write_text(json.dumps({"id": "deadbeef", "created_at": "x"}))
    payload = json.dumps({"tool_name": "Read", "tool_input": {"file_path": "src/app.py"}, "cwd": str(ws.mirror)})
    assert run_cli(["hook", "pre-tool-use"], payload, monkeypatch, capsys) == 2


def test_prompt_with_only_markers_passes(ws_env):
    _, home, ws = ws_env
    payload = {"prompt": "set DB_PASSWORD=[SECRET_1] and mail [EMAIL_1]", "cwd": str(ws.mirror)}
    assert hook_user_prompt_submit(payload, home).exit_code == 0


def test_hooks_use_config_snapshot(tmp_path, boxed_env):
    repo = tmp_path / "proj"
    repo.mkdir()
    (repo / "boxed.toml").write_text('[boxed]\n[boxed.dictionary]\n"Acme Corp" = "CLIENT"\n')
    (repo / "a.txt").write_text("hello\n")
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    home = boxed_env
    home.mkdir(parents=True, exist_ok=True)
    keys = default_keystore()
    from boxed.config import load_config

    ws = create_workspace(repo, level=2, config=load_config(repo), vault=Vault(home / "vault.db", keys), journal=Journal(home / "journal.jsonl", keys), home=home).workspace
    os.chmod(repo / "boxed.toml", 0)
    try:
        r = hook_user_prompt_submit({"prompt": "deal with Acme Corp", "cwd": str(ws.mirror)}, home)
    finally:
        os.chmod(repo / "boxed.toml", 0o644)
    assert r.exit_code == 2 and "CLIENT" in r.stderr


def test_hook_error_message_has_no_paths(ws_env, monkeypatch, capsys):
    repo, home, ws = ws_env
    state = home / "state" / f"{ws.id}.json"
    os.chmod(state, 0)
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"tool_name": "Read", "tool_input": {"file_path": "a"}, "cwd": str(ws.mirror)})))
    try:
        assert main(["hook", "pre-tool-use"]) == 2
    finally:
        os.chmod(state, 0o600)
    err = capsys.readouterr().err
    assert str(repo) not in err and str(home) not in err


def test_mirror_without_marker_fails_closed(ws_env, monkeypatch, capsys):
    _, _, ws = ws_env
    (ws.mirror / MARKER_FILE).unlink()
    payload = json.dumps({"tool_name": "Read", "tool_input": {"file_path": "src/app.py"}, "cwd": str(ws.mirror)})
    assert run_cli(["hook", "pre-tool-use"], payload, monkeypatch, capsys) == 2


def test_search_from_a_folder_that_contains_the_original_denied(ws_env):
    repo, home, ws = ws_env
    parent = repo.parent
    assert hook_pre_tool_use(tool("Grep", ws.mirror, pattern="password", path=str(parent)), home).exit_code == 2
    assert hook_pre_tool_use(tool("Glob", ws.mirror, pattern=f"{parent}/**/.env"), home).exit_code == 2
    assert hook_pre_tool_use(tool("Glob", ws.mirror, pattern="**/.env", path=str(parent)), home).exit_code == 2
    assert hook_pre_tool_use(tool("Bash", ws.mirror, command=f"grep -r password {parent}"), home).exit_code == 2
    assert hook_pre_tool_use(tool("Bash", ws.mirror, command="find / -name .env"), home).exit_code == 2
    code = f"python3 -c \"import os; print(os.listdir('{parent}'))\""
    assert hook_pre_tool_use(tool("Bash", ws.mirror, command=code), home).exit_code == 2


def test_search_over_boxed_home_denied(ws_env):
    _, home, ws = ws_env
    assert hook_pre_tool_use(tool("Grep", ws.mirror, pattern="client", path=str(home)), home).exit_code == 2
    assert hook_pre_tool_use(tool("Bash", ws.mirror, command=f"rg client {home}"), home).exit_code == 2


def test_home_shortcuts_that_contain_the_original_denied(ws_env, monkeypatch):
    repo, home, ws = ws_env
    monkeypatch.setenv("HOME", str(repo.parent))
    for command in ("grep -r password ~", "rg password $HOME", "ls -R ${HOME}/"):
        assert hook_pre_tool_use(tool("Bash", ws.mirror, command=command), home).exit_code == 2, command


def test_searches_inside_the_mirror_and_system_tools_allowed(ws_env):
    _, home, ws = ws_env
    assert hook_pre_tool_use(tool("Grep", ws.mirror, pattern="x", path=str(ws.mirror / "src")), home).exit_code == 0
    assert hook_pre_tool_use(tool("Glob", ws.mirror, pattern="**/*.py"), home).exit_code == 0
    assert hook_pre_tool_use(tool("Bash", ws.mirror, command="grep -r x src && /usr/bin/env python3 -V"), home).exit_code == 0
    assert hook_pre_tool_use(tool("Bash", ws.mirror, command="python3 -c 'print(4 / 2)'"), home).exit_code == 0


def test_boxed_commands_that_reveal_originals_denied(ws_env):
    _, home, ws = ws_env
    for command in (f"boxed restore --scope {ws.scope}", f"boxed workspace sync {ws.id} --dry-run", "boxed workspace list",
                    "python3 -m boxed.cli restore --scope x", "/usr/local/bin/boxed run claude", "bash -c 'boxed install codex'"):
        assert hook_pre_tool_use(tool("Bash", ws.mirror, command=command), home).exit_code == 2, command
    assert hook_pre_tool_use(tool("Bash", ws.mirror, command="boxed --version"), home).exit_code == 0


def test_boxed_mask_from_the_mirror_denied(ws_env):
    _, home, ws = ws_env
    command = f"echo 'DB_PASSWORD=hunter22' | boxed mask --scope {ws.scope}"
    assert hook_pre_tool_use(tool("Bash", ws.mirror, command=command), home).exit_code == 2


def test_shell_punctuation_quotes_and_globs_do_not_hide_paths(ws_env, monkeypatch):
    repo, home, ws = ws_env
    monkeypatch.setenv("HOME", str(repo.parent))
    for command in ("ls ~;", "cd ..; ls", "echo $(ls ~)", "grep -r x ~|head", "find /;", f"cat ~/{repo.name[:3]}*/.env",
                    "ls {~,}", '"boxed" restore --scope x', "\\boxed restore --scope x", "bo''xed restore --scope x"):
        assert hook_pre_tool_use(tool("Bash", ws.mirror, command=command), home).exit_code == 2, command
    for command in ("ls src;", "echo $(date)", "cat src/*.py | head"):
        assert hook_pre_tool_use(tool("Bash", ws.mirror, command=command), home).exit_code == 0, command


def test_glob_patterns_cut_mid_name_or_with_braces_denied(ws_env):
    repo, home, ws = ws_env
    parent = str(repo.parent)
    assert hook_pre_tool_use(tool("Glob", ws.mirror, pattern=f"{parent[:4]}*/**/.env"), home).exit_code == 2
    assert hook_pre_tool_use(tool("Glob", ws.mirror, pattern=f"{{{parent},/nowhere}}/**/.env"), home).exit_code == 2


def test_hooks_fail_closed_and_cover_monitor(ws_env):
    repo, home, ws = ws_env
    settings = json.loads((ws.mirror / ".claude" / "settings.local.json").read_text())
    guards = settings["hooks"]["PreToolUse"] + settings["hooks"]["UserPromptSubmit"]
    assert all(h["onFailure"] == "block" for entry in guards for h in entry["hooks"])
    assert "Monitor" in settings["hooks"]["PreToolUse"][0]["matcher"].split("|")
    payload = tool("Monitor", ws.mirror, command=f"tail -f {repo}/.env", description="x", timeout_ms=1000)
    assert hook_pre_tool_use(payload, home).exit_code == 2


def test_long_commands_without_boxed_are_fast(ws_env):
    _, home, ws = ws_env
    start = time.monotonic()
    assert hook_pre_tool_use(tool("Bash", ws.mirror, command='echo "' + '"' * 200_000), home).exit_code == 0
    assert time.monotonic() - start < 2


def test_the_reveal_check_is_linear_on_long_runs_of_delimiters(ws_env):
    """boxed in a run of 200k quotes, semicolons or parentheses: every one of them may start a command, none may cost a scan of the rest."""
    _, home, ws = ws_env
    quotes = 200_000
    for command, denied in (("echo " + '"' * quotes + " boxed", False), ("boxed " + '"' * quotes, False), ('"' * quotes + "boxed restore", True),
                            ("boxed " + "'" * quotes + " restore", True), ('"boxed' + '"' * quotes, False), (";" * quotes + "boxed", False),
                            ("(" * quotes + "boxed", False), ("git commit -m boxed " + '"' * quotes, False), ('("' * (quotes // 2) + " boxed run", True),
                            ("python3 -m " + '"' * quotes + " boxed", True), (" " + '"' * quotes + " boxed ", False), ("boxed " * (quotes // 6), False),
                            ("boxed" + " -x/boxed" * 20_000, False), ("boxed" + " -x/boxed" * 20_000 + " restore", True)):
        start = time.monotonic()
        result = hook_pre_tool_use(tool("Bash", ws.mirror, command=command), home)
        assert (result.exit_code == 2) == denied, command[:40]
        assert time.monotonic() - start < 3, command[:40]


def test_long_commands_with_wildcards_are_judged_in_time(ws_env):
    """A hook that runs too long is not waited for: whatever a command is made of, the guard has to answer long before that. Wildcards make
    it read folders and match names, so the work is bounded by what it reads (GLOB_SCAN), by the folders a pattern holds and its depth."""
    _, home, ws = ws_env
    for number in range(2000):
        (ws.mirror / f"file{number}.txt").write_text("a\n")
    n = 50_000
    for command, denied in (("ls " + "*" * n, False), ("ls " + "[" * n, False), ("ls " + "[[:" * (n // 3), False), ("ls " + "*/" * n, True), ("ls " + "a*" * n, False),
                            ("ls " + "{" * n, False), ("ls " + "{a" * n, False), ("ls " + "?" * n, False), ("ls " + "*a" * n + "b", False), ("ls " + "[a-" * (n // 3), False),
                            ("ls " + " ".join(f"f{k}*" for k in range(10_000)), True), ("ls " + " ".join(["*"] * n), True), ("ls " + "**/" * n, True),
                            ("ls " + "^" * n, False), ("ls " + "[!]" * (n // 3), False), ("ls " + "<->" * (n // 3), False), ("ls " + "[:a:]" * (n // 5), False)):
        start = time.monotonic()
        result = hook_pre_tool_use(tool("Bash", ws.mirror, command=command), home)
        assert (result.exit_code == 2) == denied, command[:30]
        assert time.monotonic() - start < 5, (command[:30], time.monotonic() - start)


def test_boxed_commands_get_their_own_message(ws_env):
    _, home, ws = ws_env
    result = hook_pre_tool_use(tool("Bash", ws.mirror, command="boxed workspace list"), home)
    assert result.exit_code == 2 and "your own terminal" in result.stderr


def test_home_with_a_space_that_contains_the_original_denied(tmp_path, boxed_env, monkeypatch):
    home_dir = tmp_path / "John Doe"
    repo = home_dir / "proj"
    repo.mkdir(parents=True)
    (repo / "a.txt").write_text("x\n")
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    boxed_env.mkdir(parents=True, exist_ok=True)
    keys = default_keystore()
    ws = create_workspace(repo, level=2, config=ProjectConfig(), vault=Vault(boxed_env / "vault.db", keys),
                          journal=Journal(boxed_env / "journal.jsonl", keys), home=boxed_env).workspace
    monkeypatch.setenv("HOME", str(home_dir))
    assert hook_pre_tool_use(tool("Bash", ws.mirror, command="rg x $HOME"), boxed_env).exit_code == 2


def test_session_note_asks_to_quote_masked_names(ws_env):
    _, home, ws = ws_env
    assert "quote such paths" in hook_session_start({"cwd": str(ws.mirror)}, home).stdout


@pytest.mark.parametrize("home_name", ["John Doe", "o'brien"])
@pytest.mark.parametrize(
    "command",
    ['rg x "$HOME"', 'cat "$HOME/proj/a.txt"', "cat $HOME/proj/a.txt # don't", "rg x $HOME # don't", "rg x $HOME"],
)
def test_quoted_home_forms_denied(tmp_path, boxed_env, monkeypatch, home_name, command):
    home_dir = tmp_path / home_name
    repo = home_dir / "proj"
    repo.mkdir(parents=True)
    (repo / "a.txt").write_text("x\n")
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    boxed_env.mkdir(parents=True, exist_ok=True)
    keys = default_keystore()
    ws = create_workspace(repo, level=2, config=ProjectConfig(), vault=Vault(boxed_env / "vault.db", keys),
                          journal=Journal(boxed_env / "journal.jsonl", keys), home=boxed_env).workspace
    monkeypatch.setenv("HOME", str(home_dir))
    assert hook_pre_tool_use(tool("Bash", ws.mirror, command=command), boxed_env).exit_code == 2


def test_boxed_modules_and_the_native_host_denied(ws_env):
    _, home, ws = ws_env
    for command in ("python3 -m boxed.native_host", "boxed-native-host", "~/.boxed/bin/boxed-native-host",
                    "python3 -c 'from boxed.vault import Vault'", "python3 -c 'import boxed.mask'", "uv run python -m boxed restore"):
        assert hook_pre_tool_use(tool("Bash", ws.mirror, command=command), home).exit_code == 2, command
    for command in ("ls boxed_notes.txt", "echo boxed", "python3 -m pytest -q"):
        assert hook_pre_tool_use(tool("Bash", ws.mirror, command=command), home).exit_code == 0, command


def test_every_boxed_subcommand_is_blocked_in_a_mirror(ws_env):
    from boxed.cli import build_parser

    _, home, ws = ws_env
    subcommands = next(a for a in build_parser()._actions if isinstance(a, argparse._SubParsersAction)).choices
    for name in subcommands:
        assert hook_pre_tool_use(tool("Bash", ws.mirror, command=f"boxed {name} --help"), home).exit_code == 2, name


def test_the_native_host_launcher_folder_is_guarded(ws_env):
    _, home, ws = ws_env
    for command in (f"{home}/bin/*", f"{home}/bin/boxed-native-h*", f"ls {home}/bin"):
        assert hook_pre_tool_use(tool("Bash", ws.mirror, command=command), home).exit_code == 2, command


def test_observation_and_check_files_are_guarded(ws_env):
    _, home, ws = ws_env
    for command in (f"cat {home}/observed.jsonl", f"cat {home}/checks.json"):
        assert hook_pre_tool_use(tool("Bash", ws.mirror, command=command), home).exit_code == 2, command


def bash_exit(ws_env, command):
    _, home, ws = ws_env
    return hook_pre_tool_use(tool("Bash", ws.mirror, command=command), home).exit_code


def test_boxed_module_needs_a_python_interpreter(ws_env):
    for command in ("python -m boxed restore x", "python3 -I -m boxed.cli mask -", "python3 -Im boxed", "uv run python -m boxed",
                    "/usr/bin/python3.13 -m boxed", "env python -m boxed"):
        assert bash_exit(ws_env, command) == 2, command
    for command in ("git commit -m boxed", 'git commit -m "boxed: fix"', "pytest -m boxed"):
        assert bash_exit(ws_env, command) == 0, command


def test_module_runs_stay_denied_in_every_launcher_and_flag_form(ws_env):
    for command in (
        "python3 -Imboxed.cli", "python3 -mboxed", "python3 -W ignore -m boxed", "python3 -X dev -m boxed.cli --version",
        'python3 -m "boxed"', 'python3 -m bo""xed', "python3 -m bo\\xed", "PYTHONPATH=src python3 -m boxed",
        "sudo -u me python3 -m boxed.cli", "nohup python3 -m boxed &", "(python3 -m boxed)",
        "echo $(python3 -m boxed.cli --version)", "echo `python3 -m boxed`", "uv run -m boxed", "uv run -qm boxed.cli",
        "uv run --module boxed.cli", "./p -m boxed", "$PY -m boxed", "xargs python3 -m boxed", 'bash -c "python3 -m boxed"',
        "coverage run -m boxed", "python -m cProfile -m boxed", "python3 \\\n  -m boxed", "python3 -m\tboxed.cli",
        'python3 -m ";boxed"',  # the flag stands alone before a module the words do not show
        # a flag built by a command substitution: the old check saw "-m boxed" once punctuation became spaces, and still must
        'python3 "$(echo -m)" boxed.cli', './p "$(echo -m)" bo""xed', '$PY "`echo -m`" boxed',
    ):
        assert bash_exit(ws_env, command) == 2, command


def test_git_and_pytest_options_hide_no_module_run(ws_env):
    for command in (
        "git commit -m boxed && python3 -m boxed.cli --version",
        "git commit -m x; python3 -m boxed.cli --version",
        "git commit -m x\npython3 -m boxed.cli --version",
        "git commit -m x || python3 -m boxed.cli --version",
        "git commit -m x & python3 -m boxed.cli --version",
        "pytest -m boxed | python3 -m boxed.cli --version",
        'git commit -m "$(python3 -m boxed.cli --version)"',
        'git commit -m "`python3 -m boxed.cli --version`"',
        "git commit -m boxed $(python3 -m boxed.cli --version)",
        "git commit -m boxed <(python3 -m boxed.cli --version)",
        "git -c alias.p='!python3 -m boxed.cli --version' p",
        "git -c core.editor='python3 -m boxed' commit -m x",
        # git runs a shell alias with the words after it: -m after a subcommand that is not a git built-in may be a module flag
        "git -c alias.x='!python3' x -m boxed.cli re{store,}",
        "git -c alias.x=!python3 x -m boxed",
        "git -c alias.commit=x -c alias.x=!python3 x -m boxed",
        # a -m flag whose module the words do not show (a redirect between them, a name built at run time) keeps the call denied
        "git commit -m boxed; python3 -m >/dev/null boxed.cli",
        "pytest -m boxed; python3 -m 2>/dev/null boxed.cli",
        "git commit -m boxed; uv run --module >/dev/null boxed.cli",
        'git commit -m boxed; python3 -m "$(echo boxed)"',
        "git commit -m boxed; python3 -m $'boxed'",
        # the word after a redirect operator is a file name, not the program: git and pytest named so earn no exemption
        "> git python3 -m boxed", ">git python3 -m boxed", ">& git python3 -mboxed", ">> pytest python3 -m boxed",
        "< git python3 -m boxed", "true; >git python3 -m boxed", "true &&>git python3 -m boxed", "true || 2>git python3 -m boxed",
        "(true)>git python3 -m boxed",
        # a function, an alias, eval or hash can make git or pytest anything: the line is not plain, no -m is a message
        'git() { python3 "$@"; }; git -m boxed',
        'git ( ) { python3 "$@"; }; git -m boxed',
        'pytest(){ python3 "$@";};pytest -m boxed',
        'function pytest { python3 "$@"; }; pytest -m boxed.cli',
        "alias git=python3\ngit -m boxed",
        "eval 'git() { python3 \"$@\"; }'; git -m boxed",
        "hash -p /usr/bin/python3 git; git -m boxed",
        "functions[git]='python3 \"$@\"'; git -m boxed",
        # a message is set aside only on a line of its own: any other program on the line could hide the run
        "git commit -m boxed; python3 {-m,boxed}",
        "git commit -m boxed; ./p {-m,boxed}",
        "git commit -m boxed; python3 $'\\x2dm' boxed",
        'git commit -m boxed && echo "$(python3 {-m,boxed})"',
        "git commit -m boxed && echo `python3 {-m,boxed}`",
        "git commit -m boxed && make test",
        "pytest -m boxed && npm test",
        "git -c core.editor='python3 -m bo\"\"xed' commit -m boxed",
        "./git commit -m boxed",
        "PATH=. git commit -m boxed",
        "env git commit -m boxed",
        "'git commit' -m boxed",
        "git commit -m boxed 'it",
    ):
        assert bash_exit(ws_env, command) == 2, command


def test_a_comment_a_here_doc_or_a_line_break_hides_no_module_run(ws_env):
    """bash ignores a comment and reads a here-doc body as data, so a quote opened there pairs with a later one only in a
    shlex-style parse: the git line then looks whole while the next line really runs python."""
    for command in (
        "git commit # -m '\npython3 -m boxed.cli --help\n# '",
        'git commit # -m "\npython3 -m boxed.cli --help\n# "',
        "pytest # -m '\npython3 -m boxed.cli --help\n# '",
        "git -C sub commit -a # -m '\npython3 -m boxed.cli --help\n# '",
        "git tag # -m '\npython3 -m boxed.cli --help\n# '",
        "git commit # -m 'x\npython3 -m boxed.cli --help\n# y'",
        "git commit -m boxed # -m '\npython3 -m boxed.cli --help\n# '",
        "git commit <<'EOF' # -m '\nbody\nEOF\npython3 -m boxed.cli --help\n# '",
        "git commit -a $'x\\'' # -m '\npython3 -m boxed.cli --help\n# '",
        "git commit -m boxed \\\n&& python3 -m boxed.cli --help",
        "git commit -m boxed\npython3 -m boxed.cli --help",
        "git commit -m boxed; python3 -m boxed.cli --help",
        "git commit -m boxed && python3 -m boxed.cli --help",
        "git commit -m boxed | python3 -m boxed.cli --help",
        "git commit -m boxed & python3 -m boxed.cli --help",
    ):
        assert bash_exit(ws_env, command) == 2, command


def test_git_messages_and_pytest_markers_pass(ws_env):
    for command in ("git commit -am boxed", "git commit -mboxed", 'git commit -m "boxed" -m "second"', "git tag -m boxed v1",
                    "git -C sub commit -m boxed", 'git commit -m "docs: run python -m boxed"', 'pytest -m "boxed and not slow"',
                    "pytest -mboxed -q", "pytest -m boxed tests/test_a.py::test_function", "git commit -m boxed > out.txt",
                    "git commit -m boxed 2>/dev/null", "  git commit -m boxed  \n"):
        assert bash_exit(ws_env, command) == 0, command


def test_a_message_on_a_line_with_anything_more_is_judged_as_before(ws_env):
    """Only one plain line is read as a message. Another command, a comment, an expansion or a redirect from a file on the line
    keeps every module flag a hit, as it was before the exemption: the price is a few commit messages."""
    for command in ("(git commit -m boxed)", "git commit -m boxed 2>&1 | tail -3",
                    "git add -A && git commit -m boxed", 'git commit -m "boxed: fix #12"', 'git commit -m "boxed: rename helper()"',
                    'git commit -m "boxed $USER"', "git commit -m boxed < msg.txt", "git commit -m boxed;"):
        assert bash_exit(ws_env, command) == 2, command


def file_tools(path, text):
    """The four tools that write a file, each with the path and the text."""
    return (("Write", {"file_path": path, "content": text}), ("Edit", {"file_path": path, "old_string": "a", "new_string": text}),
            ("MultiEdit", {"file_path": path, "edits": [{"old_string": "a", "new_string": "b"}, {"old_string": "c", "new_string": text}]}),
            ("NotebookEdit", {"notebook_path": path, "cell_id": "1", "new_source": text, "edit_mode": "replace"}))


def write_exits(ws_env, path, text="x = 1\n"):
    _, home, ws = ws_env
    return {name: hook_pre_tool_use(tool(name, ws.mirror, **fields), home).exit_code for name, fields in file_tools(path, text)}


def test_files_that_run_by_themselves_are_not_written(ws_env):
    """git runs .git/config and .git/hooks, python every .pth and sitecustomize.py: a file there is a command for later."""
    _, _, ws = ws_env
    os.symlink(".git/config", ws.mirror / "cfg")
    os.symlink("evil", ws.mirror / ".git-link")
    for path in (".git/config", ".git/hooks/pre-commit", "sub/.git/config", "sub/deeper/.git/hooks/post-checkout", ".git/modules/x/config", ".git",
                 "sub/.git", ".GIT/CONFIG", ".Git/Hooks/pre-push", ".git/info/attributes", "x.pth", "pkg/evil.pth", "X.PTH", "lib/.pth", "sitecustomize.py",
                 "lib/usercustomize.py", "SiteCustomize.py", "a/b/UserCustomize.PY", "cfg", ".boxed-workspace", ".claude/settings.local.json",
                 str(ws.mirror / ".git" / "config"), "./src/../.git/config"):
        assert set(write_exits(ws_env, path).values()) == {2}, path
    os.symlink(".git", ws.mirror / "g")  # a link to a git folder that is not there yet: the name hides it, the target does not
    assert set(write_exits(ws_env, "g/config").values()) == {2}


def test_ordinary_files_stay_writable(ws_env):
    for path in ("src/app.py", "README.md", ".gitignore", ".gitattributes", ".gitmodules", ".github/workflows/ci.yml", "gitconfig.md", "notes/pth.txt",
                 "mysitecustomize.py", "sitecustomize.txt", "usercustomize.py.md", "src/.claude/commands/x.md", ".claude/settings.json", "git/config",
                 "hooks/pre-commit", "pth", "src/boxed_notes.txt", "notebooks/a.ipynb", ".git-link-notes/x.txt"):
        assert set(write_exits(ws_env, path).values()) == {0}, path


# Text that would run boxed once a file holds it and something runs the file. What counts depends on what the file is: Python imports the
# package, a shell script or a Makefile runs the command, any code can hand a command line to a shell in a string or a list. Prose, markup
# and data that people read are never run: a README may show `boxed restore`, a page may have class="boxed check".
PY_RUNS = (  # an import of the package, at the start of a statement
    "import boxed\n", "import boxed.cli\n", "from boxed.vault import Vault\n", "from boxed import mask\n", "import os, boxed\n", "import os,boxed.mask as m\n",
    "if x: import boxed\n", "x = 1; import boxed\n", "def f():\n    from boxed.cli import main\n", "  import   boxed   \n", "import boxed as b\n",
    "import boxed.native_host\n", "echo hi\nimport boxed\n",
)
CODE_RUNS = (  # in any code: a dynamic import, the native host, a command line in a string or a list
    "__import__('boxed')\n", '__import__("boxed.cli")\n', "importlib.import_module('boxed.vault')\n", 'import_module(f"boxed.{name}")\n',
    "runpy.run_module('boxed', run_name='__main__')\n", "importlib.util.find_spec('boxed')\n", "boxed-native-host\n", "~/.boxed/bin/boxed-native-host\n",
    "subprocess.run(['boxed', 'restore'])\n", 'subprocess.run(["boxed", "mask", "-"], input=data)\n', "subprocess.call(['/usr/bin/boxed', '--x', 'run'])\n",
    "os.system('boxed restore --scope x')\n", 'os.system("boxed mask file")\n', 'subprocess.run("boxed restore", shell=True)\n', "cmd = 'boxed workspace list'\n",
    'execSync("boxed restore")\n', "spawn('boxed', ['mask', 'f'])\n", "exec(`boxed restore`)\n", 'os.system("sudo boxed restore")\n',
    'os.system("cd x && boxed restore")\n', "execSync('echo hi | boxed mask')\n", 'subprocess.run(["python3", "-m", "boxed"])\n',
    'os.system("python3 -m boxed.cli restore")\n', "exec('uv run -m boxed')\n", "os.system('python3 -c \"import boxed\"')\n", 'sh("boxed $@")\n',
    '{"scripts": {"restore": "boxed restore"}}\n', 'command = "boxed mask f"\n', 'args="boxed restore"\n', "node -e \"require('boxed')\"; boxed-native-host\n",
)
SHELL_RUNS = (  # in a shell script, a Makefile, a Dockerfile, a CI file: boxed as a command
    "run: boxed restore --scope x\n", "  - run: boxed mask a.txt\n", 'CMD ["boxed", "restore"]\n', "RUN boxed restore\n", "restore:\n\t@boxed restore\n",
    "restore:\n\tboxed restore\n", "-boxed restore\n", "boxed restore\n", "boxed restore --scope ws-1 > out.txt\n", "#!/bin/sh\nboxed mask < in > out\n",
    "$ boxed restore\n", "  boxed journal show\n", "boxed --version-ish restore\n", "boxed -v mask\n", "/usr/local/bin/boxed restore\n",
    "~/.local/bin/boxed run claude\n", "./boxed restore\n", "sudo boxed restore\n", "exec boxed restore\n", "env FOO=1 boxed restore\n", "nohup boxed mask &\n",
    "time boxed restore\n", "xargs boxed mask\n", "command boxed restore\n", "echo hi && boxed restore\n", "true || boxed restore\n", "ls; boxed workspace list\n",
    "cat f | boxed mask\n", "x=$(boxed mask < f)\n", "echo $(boxed restore)\n", "(boxed restore)\n", "{ boxed restore; }\n", "if true; then boxed restore; fi\n",
    "for i in 1; do boxed restore; done\n", "boxed restore &\n", "bo''xed restore\n", 'bo""xed restore\n', "b\\oxed restore\n", '"boxed" restore\n',
    "python3 -m boxed.cli restore\n", "python -m boxed\n", "python3 -Im boxed\n", "python -mboxed\n", "uv run -m boxed\n", "uv run --module boxed.cli\n",
    "/usr/bin/python3.13 -m boxed.native_host\n", "pip install x && python3 -m boxed.cli restore\n", "python3 -c 'import boxed'\n", 'python3 -c "import os, boxed"\n',
    "python3 -m boxed.native_host\n", "x\n\n\nboxed restore\n", 'bash -lc "boxed restore"\n', "sh -ec 'boxed mask f'\n", "script -qc 'boxed restore' /dev/null\n",
    "case $x in a) boxed restore ;; esac\n", "x=`boxed mask f`\n", "y = `boxed workspace list`\n", 'exec boxed "$@"\n', "echo `boxed restore`\n",
)
# text that only mentions the word: names, CSS, other languages' own boxed, a marker, a message, a command shown in a sentence
MENTIONS_BOXED = (
    "# boxed.si\n\nA boxed layout and an unboxed one. boxed.si masks secrets before they reach a model.\n", ".boxed { border: 1px solid; }\n",
    '<div class="boxed">x</div>\n', 'className="boxed"\n', "const boxed = true;\n", "import boxed from './boxed';\n", "import { boxed } from './x'\n",
    "boxed = True\n", "def boxed_value():\n    return 1\n", 'print("boxed")\n', "x.boxed()\n", "# boxed values\n", '"""The boxed run is done."""\n',
    "IntStream.range(0, 3).boxed().collect(Collectors.toList());\n", "import os, boxed_notes\n", "import boxedfoo\n", "from boxedfoo import x\n",
    "git commit -m boxed\n", 'git commit -m "boxed: fix"\n', "pytest -m boxed\n", "pytest -mboxed -q\n", "git tag -m boxed v1\n", "grep -m boxed file\n",
    "see the boxed run and boxed check pages\n", "We use a boxed plan, a boxed key and a boxed mask.\n", "the boxed workspace feature\n",
    "Run boxed restore here? No: boxed is not for agents.\n", 'The "boxed run" command is for humans.\n', "echo boxed\n", "echo 'boxed' > notes.txt\n",
    "rg boxed src\n", "unboxed restore\n", "x.boxed restore\n", "my_boxed restore\n", "boxed_restore()\n", "boxed-notes restore\n", "boxed\n", "boxed.\n",
    "boxed,\n", "boxed run-time\n", "the 'boxed' look\n", "<boxed>restore</boxed>\n", "BOXED restore\n", "Boxed restore\n", "2 boxed 3\n",
    "node -e \"require('boxed')\"\n", "require('boxed')\n", "render_template('boxed.html')\n", "open('boxed_notes.txt')\n", "[boxed]\nrestore = 1\n",
    "boxed:\n  restore: true\n", "name = \"boxedsi\"\n", "boxed = \"boxed.cli:main\"\n", "src/boxed/cli.py\n", "path: src/boxed\n", "from ui import boxed\n",
    "from utils import boxed\n", "from . import boxed, other\n", "class Boxed:\n    pass\n", "# a python class called 'boxed' for css\n", "assert uv.name == 'boxed'\n",
    "# run `boxed restore` in your terminal\n", "// call boxed run from the shell\n", "echo \"boxed $@\"\n", "boxed -h\n", "boxed --version\n", "my_boxed $@\n",
)
# sentences that look like commands to a shell script, and are not in a file that is read: the reviewed false positives
PROSE_LINES = (
    "We import boxed goods from the supplier every week.\n", '<div class="boxed check">ok</div>\n', "Use a time boxed plan for the sprint.\n",
    "and then boxed run times drop by half\n", "boxed key rotation is described below\n", "boxed plan items are listed in the table\n",
    "Run boxed restore here? No.\n", "$ boxed restore\n", "Use `boxed restore` to get the originals back.\n", "python -m boxed.cli --help shows the commands\n",
    "import boxed\n", "sudo boxed restore\n", "x = 1; import boxed\n", "boxed-native-host starts the extension\n",
)
PROSE_PATHS = ("src/new_file.txt", "docs/guide.md", "README", "README.rst", "LICENSE", "site/index.html", "data/notes.csv", "docs/page.mdx", "a.svg", "x.css")
RUN_PATHS = {  # what each kind of file is written to as, and what counts there
    PY_RUNS: ("src/new_file.py", "src/new_file.sh", "notebooks/n.ipynb"),
    CODE_RUNS: ("src/new_file.py", "src/new_file.js", "src/new_file.sh", "ci.yml", "package.json", "src/Makefile", "n.ipynb", "script"),
    SHELL_RUNS: ("src/new_file.sh", "src/Makefile", "Dockerfile", "ci.yml", "tools/run", "src/new_file.bash", "n.ipynb"),
}


def test_text_that_would_run_boxed_is_not_written(ws_env):
    for texts, paths in RUN_PATHS.items():
        for path in paths:
            for text in texts:
                for name, code in write_exits(ws_env, path, text).items():
                    assert code == 2, (path, name, text)


def test_text_that_only_mentions_boxed_is_written(ws_env):
    for path in ("src/new_file.txt", "src/new_file.py", "src/new_file.js", "src/new_file.sh", "src/Makefile", "README", "n.ipynb", "src/page.tsx"):
        for text in MENTIONS_BOXED:
            for name, code in write_exits(ws_env, path, text).items():
                assert code == 0, (path, name, text)


def test_prose_and_markup_are_never_refused(ws_env):
    """A file people read is not run: a README shows `boxed restore`, a page has class="boxed check", whatever the sentence."""
    for path in PROSE_PATHS:
        for text in (*PROSE_LINES, *PY_RUNS, *CODE_RUNS, *SHELL_RUNS):
            if text.startswith("#!"):  # a script is a script, whatever it is called (see below)
                continue
            for name, code in write_exits(ws_env, path, text).items():
                assert code == 0, (path, name, text)
    for path in ("src/new_file.py", "src/new_file.js", "src/page.tsx"):  # code that is not a shell script: the sentences are not commands
        for text in PROSE_LINES[:5]:
            for name, code in write_exits(ws_env, path, text).items():
                assert code == 0, (path, name, text)
    assert write_exits(ws_env, "src/new_file.txt", "#!/bin/sh\nboxed restore\n") == {"Write": 2, "Edit": 2, "MultiEdit": 2, "NotebookEdit": 2}  # a script
    assert write_exits(ws_env, "README", "#!/usr/bin/env python3\nimport boxed\n") == {"Write": 2, "Edit": 2, "MultiEdit": 2, "NotebookEdit": 2}


def test_a_notebook_is_judged_cell_by_cell(ws_env):
    """The JSON of a notebook holds its code in strings: the code cells are read as code, the markdown cells are text."""
    code = json.dumps({"cells": [{"cell_type": "code", "source": ["import os\n", "import boxed\n"]}, {"cell_type": "markdown", "source": ["Run boxed restore"]}]})
    text = json.dumps({"cells": [{"cell_type": "code", "source": "print(1)"}, {"cell_type": "markdown", "source": ["import boxed\n", "boxed restore\n"]}]})
    assert write_exits(ws_env, "notebooks/a.ipynb", code)["Write"] == 2
    assert write_exits(ws_env, "notebooks/a.ipynb", text)["Write"] == 0
    shell = json.dumps({"cells": [{"cell_type": "code", "source": ["!boxed restore"]}]})
    assert write_exits(ws_env, "notebooks/a.ipynb", shell)["Write"] == 2
    magic = json.dumps({"cells": [{"cell_type": "code", "source": "%%bash\nboxed mask f\n"}]})
    assert write_exits(ws_env, "notebooks/a.ipynb", magic)["Write"] == 2


def test_only_what_is_written_is_checked(ws_env):
    _, home, ws = ws_env
    removing = {"file_path": "src/app.py", "old_string": "import boxed\nboxed restore\n", "new_string": "pass\n"}
    assert hook_pre_tool_use(tool("Edit", ws.mirror, **removing), home).exit_code == 0
    assert hook_pre_tool_use(tool("Read", ws.mirror, file_path="src/app.py"), home).exit_code == 0
    markdown = {"notebook_path": "n.ipynb", "new_source": "Run boxed restore later", "cell_type": "markdown", "edit_mode": "replace"}
    assert hook_pre_tool_use(tool("NotebookEdit", ws.mirror, **markdown), home).exit_code == 0
    for odd in ({"file_path": "a.sh", "content": 123}, {"file_path": "a.sh"}, {"file_path": "a.sh", "content": None}):
        assert hook_pre_tool_use(tool("Write", ws.mirror, **odd), home).exit_code == 0
    for odd in ("x", None, [None, 3, {"new_string": 5}, "boxed restore"], {"new_string": "boxed restore"}):
        assert hook_pre_tool_use(tool("MultiEdit", ws.mirror, file_path="a.sh", edits=odd), home).exit_code == 0
    assert hook_pre_tool_use(tool("MultiEdit", ws.mirror, file_path="a.sh", edits=[{"new_string": "boxed restore"}]), home).exit_code == 2


def test_a_write_outside_the_mirror_is_still_judged_by_the_paths(ws_env):
    repo, home, ws = ws_env
    for name, fields in file_tools(str(repo / "x.txt"), "x = 1\n"):
        assert hook_pre_tool_use(tool(name, ws.mirror, **fields), home).exit_code == 2, name
    for name, fields in file_tools(str(repo.parent / "elsewhere" / "x.sh"), "boxed restore\n"):
        assert hook_pre_tool_use(tool(name, ws.mirror, **fields), home).exit_code == 2, name


def test_long_texts_are_checked_in_linear_time(ws_env):
    _, home, ws = ws_env
    start = time.monotonic()
    for text in ("boxed " * 300_000, "/boxed" * 300_000, '"' * 300_000 + "boxed", "boxed" + " -x" * 200_000 + "\n", "a/" * 200_000 + "boxed restore" * 3,
                 "import " + "a, " * 100_000 + "b\n", "x\n" * 300_000 + "boxed\n", "boxed run " * 100_000, "\\\n" * 100_000 + "boxed",
                 "xboxed run " * 50_000, "boxed" + " -x/boxed" * 20_000 + " restore", "python; " * 50_000, "if " + "a:" * 100_000 + "\n", "; " * 100_000 + "import boxed",
                 "foo boxed" + " -x;boxed" * 20_000 + " restore", "sudo " * 100_000 + "boxed restore", "time boxed plan " * 50_000, "`" * 100_000 + "boxed restore"):
        for path in ("big.sh", "big.py"):
            assert hook_pre_tool_use(tool("Write", ws.mirror, file_path=path, content=text), home).exit_code in (0, 2)
    assert time.monotonic() - start < 30


def test_a_cd_and_one_plain_git_or_pytest_line_is_two_simple_commands(ws_env):
    """cd <plain path> && <git or pytest line>: the cd is no reason to read -m boxed as a module flag (an older guard did)."""
    _, _, ws = ws_env
    for command in ("cd ./sub && git commit -m boxed", "cd ./src && pytest -m boxed", "cd ./src && git commit -am boxed", "cd ./src&&git commit -mboxed",
                    "cd . && git tag -m boxed v1", "cd ./src && git -C . commit -m 'boxed: fix'", 'cd ./src/ && git commit -m "boxed" -m second',
                    f"cd {ws.mirror}/src && git commit -m boxed", f"cd {ws.mirror} && pytest -m 'boxed and not slow'", "  cd ./src && git commit -m boxed  \n",
                    "cd ./src && git commit -m boxed > out.txt", "cd ./src && git commit -m boxed 2>/dev/null", "cd ./ && git commit -m boxed"):
        assert bash_exit(ws_env, command) == 0, command


def test_a_cd_by_a_bare_name_or_through_dotdot_earns_no_exemption(ws_env):
    """CDPATH sends `cd src` to $CDPATH/src (bash and zsh) whatever the mirror holds, and cd folds .. in the name before it follows a
    link: only ., ./x and /x, with no .. in them, are folders the guard can name."""
    for command in ("cd src && git commit -m boxed", "cd sub && pytest -m boxed", "cd src/ && git commit -am boxed", "cd src/lib && git tag -m boxed v1",
                    "cd src/.. && git commit -m boxed", "cd ./src/.. && git commit -m boxed", "cd ./src/../src && pytest -m boxed",
                    "cd .//.. && git commit -m boxed", "cd ./.. && pytest -m boxed", "cd ... && git commit -m boxed"):
        assert bash_exit(ws_env, command) == 2, command
    assert bash_exit(ws_env, "cd src && git status") == 0  # a line with nothing to set aside never needed the exemption


def test_a_cd_through_a_link_and_dotdot_goes_where_the_shell_folds_it(ws_env):
    """cd rel5/.. folds the name first (the folder that holds rel5) and then looks for it; resolve() follows the link first and lands
    four folders down. The shell started in the folder above the mirror's home, the guard saw one inside the mirror."""
    repo, home, ws = ws_env
    (ws.mirror / "src" / "a" / "b" / "c" / "d").mkdir(parents=True)
    os.symlink("src/a/b/c/d", ws.mirror / "rel5")
    up = os.path.relpath(repo.parent, ws.mirror)  # ../../..
    assert (ws.mirror / "rel5" / ".." / up).resolve().is_relative_to(ws.mirror)  # the kernel's way ends inside, the shell's does not
    for command in (f"cd rel5/../{up} && pytest -m boxed {repo.name}", f"cd rel5/../{up} && git commit -m boxed", f"cd ./rel5/../{up} && git commit -m boxed",
                    f"cd rel5/../{up} && cat {repo.name}/.env", f"cd rel5/../{up}; cat {repo.name}/.env", f"cd rel5/../{up} && ls",
                    f"cat rel5/../{up}/{repo.name}/.env", f"git -C rel5/../{up}/{repo.name} log", f"pytest rel5/../{up}/{repo.name}"):
        assert bash_exit(ws_env, command) == 2, command
    for command in ("cd rel5/.. && ls", "cat rel5/../a/b/x", "cd ./rel5 && git commit -m boxed", f"cd {ws.mirror}/rel5 && git commit -m boxed"):
        assert bash_exit(ws_env, command) == 0, command


def test_a_cd_earns_no_other_exemption(ws_env, monkeypatch):
    repo, home, ws = ws_env
    monkeypatch.setenv("HOME", str(repo.parent))
    for command in (
        # the folder leaves the mirror, or is not a plain path
        "cd .. && git commit -m boxed", "cd ../.. && git commit -m boxed", "cd / && git commit -m boxed", "cd ~ && git commit -m boxed",
        f"cd {repo} && git commit -m boxed", f"cd {home} && git commit -m boxed", f"cd {ws.mirror}/.. && git commit -m boxed",
        "cd src/../.. && git commit -m boxed", "cd - && git commit -m boxed", "cd && git commit -m boxed", "cd -- src && git commit -m boxed",
        "cd -P src && git commit -m boxed", "cd 'src' && git commit -m boxed", 'cd "src" && git commit -m boxed', "cd $HOME && git commit -m boxed",
        "cd s* && git commit -m boxed", "cd {a,b} && git commit -m boxed", "cd src extra && git commit -m boxed", "cd src\\ x && git commit -m boxed",
        "FOO=1 cd src && git commit -m boxed", "time cd src && git commit -m boxed", "builtin cd src && git commit -m boxed",
        # anything but two simple commands
        "cd src; git commit -m boxed", "cd src || git commit -m boxed", "cd src & git commit -m boxed", "cd src | git commit -m boxed",
        "cd src\ngit commit -m boxed", "cd src && git commit -m boxed && ls", "cd src && git commit -m boxed; ls", "cd src && cd lib && git commit -m boxed",
        "cd src && (git commit -m boxed)", "cd src && git commit -m boxed # c", "cd src && git commit -m boxed $(ls)", 'cd src && git commit -m boxed "$X"',
        "cd src && git commit -m boxed 'it", "(cd src && git commit -m boxed)", "{ cd src && git commit -m boxed; }", "! cd src && git commit -m boxed",
        # the line after the cd is judged as it always was
        "cd src && python3 -m boxed.cli restore", "cd src && python3 -m boxed", "cd src && boxed restore", "cd src && uv run -m boxed",
        "cd src && git commit -m boxed && python3 -m boxed", "cd src && PYTHONPATH=. python3 -m boxed", "cd src && ./git commit -m boxed",
        "cd src && env git commit -m boxed", "cd src && git -c core.editor='python3 -m boxed' commit -m x", "cd src && git -c alias.x=!python3 x -m boxed",
        "cd src && python3 -c 'import boxed'", "cd src && echo boxed restore", "cd src && sh -c 'python3 -m boxed'",
        "cd src && git commit -m boxed `python3 -m boxed`", "cd src && ls <(python3 -m boxed)",
    ):
        assert bash_exit(ws_env, command) == 2, command


def test_after_a_cd_the_line_is_read_in_the_folder_it_runs_in(ws_env):
    """Relative paths are read from src, not from the mirror: from src the way to the project is one folder longer."""
    repo, home, ws = ws_env
    up = os.path.relpath(repo / ".env", ws.mirror / "src")
    assert up.startswith("../../..")
    for command in (f"cd src && cat {up}", f"cd src && git diff --no-index -m boxed {up} /dev/null", f"cd src && pytest -m boxed {up}",
                    f"cd src && git add -f {up}", f"cd ./src && head {up}"):
        assert bash_exit(ws_env, command) == 2, command
    os.symlink(repo, ws.mirror / "src" / "peek2")  # a link that is a link only from src
    for command in ("cd src && cat peek2/.env", "cd src && ls peek2", "cd ./src && head -n1 peek2/src/app.py"):
        assert bash_exit(ws_env, command) == 2, command
    assert bash_exit(ws_env, "cd src && git add app.py") == 0
    assert bash_exit(ws_env, "cd ./src && git commit -m boxed -- app.py") == 0


def test_a_cd_line_with_a_glob_or_a_brace_earns_nothing(ws_env):
    """bash expands pe* to the link peek, which leads out of the mirror; the guard does not match names against the folder."""
    repo, home, ws = ws_env
    os.symlink(repo, ws.mirror / "peek")
    for command in ("cd . && pytest -m boxed pe*", "cd . && git commit -m boxed pe?k", "cd . && pytest -m boxed [p]eek", "cd . && pytest -m boxed {peek,x}",
                    "cd src && git commit -m 'boxed: why?'", "cd src && git commit -m boxed *.py", "cd src && git commit -m 'boxed {x}'"):
        assert bash_exit(ws_env, command) == 2, command
    assert bash_exit(ws_env, "cd . && pytest -m boxed peek2") == 0


def test_only_what_bash_skips_is_stripped_and_only_home_is_a_variable_in_a_cd_line(ws_env, monkeypatch):
    """bash skips spaces, tabs and line breaks around a command, not a carriage return or a form feed, which become part of its name;
    and $HOMEfix is the variable HOMEfix, not $HOME and fix."""
    monkeypatch.setenv("HOME", str(ws_env[0].parent))
    for command in ("\recho ~", "echo ~\r", "\x0cecho ~", "\xa0echo ~", "\rexpr 6 / 3", "expr 6 / 3\x0c", "\rcd . && git commit -m boxed",
                    "cd . && \rgit commit -m boxed", "cd . &&\r git commit -m boxed", "cd src && git commit -m boxed $HOMEfix",
                    "\x0cpytest -m boxed", "\x0cgit commit -m boxed", "cd ./src && \x0cpytest -m boxed", "cd ./src &&\x0c pytest -m boxed",
                    "cd src && gi\\t commit -m boxed", "cd src && git commit -m boxe\\d", 'cd src && git commit -m "boxed: fi\\x"',
                    "cd src && \\git commit -m boxed", "cd src && git commit -m boxed\\ x", 'cd src && git commit -m "boxed: $HOMEfix"',
                    "cd src && git commit -m boxed ${HOMEX}", "cd src && git commit -m boxed $PWD", "cd src && git commit -m boxed $0"):
        assert bash_exit(ws_env, command) == 2, command
    for command in ("\n\n cd ./src && git commit -m boxed \t\n", "cd ./src && git commit -m boxed $HOME/src", 'cd ./src && git commit -m "boxed ${HOME}/x"',
                    "\n expr 6 / 3 \n", "\t echo ~ \n"):
        assert bash_exit(ws_env, command) == 0, command


def test_a_cd_into_a_link_that_leaves_the_mirror_earns_nothing(ws_env):
    repo, home, ws = ws_env
    os.symlink(repo, ws.mirror / "peek")
    for command in ("cd peek && git commit -m boxed", "cd peek/src && pytest -m boxed", "cd peek && git commit -m x"):
        assert bash_exit(ws_env, command) == 2, command


def test_dynamic_imports_of_boxed_are_blocked(ws_env):
    for command in (
        "python -c \"import importlib; importlib.import_module('boxed.cli')\"",
        "python -c \"__import__('boxed')\"",
        "python3 -c 'from importlib import import_module as i; i(\"boxed\")'",
        "python3 -c 'import runpy; runpy.run_module(\"boxed.cli\")'",
        "python3 -c \"import runpy; runpy.run_module('boxed', run_name='__main__')\"",
        'python3 -c "import importlib; importlib.import_module(\\"boxed.vault\\")"',
        "python3 -c 'import importlib; name = \"boxed\"; importlib.import_module(name)'",
        "python3 -c \"import subprocess; subprocess.run(['boxed', 'restore'])\"",
        "python3 -c \"__import__(f'boxed.{x}')\"",
        "PYTHONPATH=src python3 -c \"__import__('boxed')\"",
        "uv run python -c \"__import__('boxed.cli')\"",
        "/usr/bin/python3.13 -c \"__import__('boxed')\"",
        "ipython -c \"__import__('boxed')\"",
        "echo \"__import__('boxed')\" | python3",
        "python3 - <<'EOF'\nimport importlib\nimportlib.import_module('boxed.cli')\nEOF",
        "echo \"__import__('boxed')\" | uv run -",  # uv runs a script from stdin without naming an interpreter
        "uv run - <<'EOF'\nimport importlib\nimportlib.import_module('boxed.cli')\nEOF",
    ):
        assert bash_exit(ws_env, command) == 2, command


def test_a_name_hidden_by_quotes_for_a_nested_shell_is_blocked(ws_env):
    """A string that a second shell reads later (git -c core.pager, sh -c, bash -c, ssh, xargs sh -c, find -exec sh -c) can
    hide the name with inner quotes or backslashes: they vanish only when that shell reads the string."""
    for command in (
        "git -c core.pager='python3 -m bo\"\"xed.cli re\"\"store x' log",
        "sh -c 'python3 -m bo\"\"xed.cli re\"\"store x'",
        'bash -c "bo\'\'xed re\'\'store x"',
        "sh -c 'bo\\xed restore x'",
        # variants
        "echo x | xargs sh -c 'bo\"\"xed re\"\"store x'",
        "find . -exec sh -c \"bo''xed restore x\" \\;",
        'ssh host "bo\'\'xed re\'\'store x"',
        "sh -c 'python3 -m bo\"\"xed'",
        "sh -c 'bo\\\nxed restore x'",
        "sh -c 'boxed-native-ho\"\"st'",
        'python3 -c "import bo\'\'xed"',
        "sh -c 'b\"o\"x\"e\"d restore x'",
        "bash -c 'bo\\\\xed restore x'",
        "sh -c 'python3 -Im bo\\xed'",
    ):
        assert bash_exit(ws_env, command) == 2, command


def test_inner_quotes_and_backslashes_do_not_block_other_commands(ws_env):
    for command in ('echo "it\'s fine"', "rg 'bo\"\"x' src", 'git commit -m "it\'s boxed: fix"', "echo 'say \"boxed\"' > note.txt",
                    "python3 -c \"print('hello')\"", 'grep -r "don\'t" src', "sh -c 'echo \"a b\"'", "sh -c 'ls src\\ dir'"):
        assert bash_exit(ws_env, command) == 0, command


def test_boxed_anywhere_in_an_import_list_is_blocked(ws_env):
    for command in ("python3 -c 'import os, boxed'", "python3 -c 'import os,boxed'", "python3 -c 'import os as o, boxed.cli'",
                    'python3 -c "import os, sys, boxed.vault"', "python3 -c 'import os.path as p, boxed as b'",
                    'python3 -c "import os, \\\nboxed"', "python3 -c 'import os; import boxed'", "python3 -c 'import boxed, os'"):
        assert bash_exit(ws_env, command) == 2, command
    for command in ("python3 -c 'import os, sys'", "python3 -c 'import os, boxed_notes'", "python3 -c 'import os, boxedfoo.x'",
                    "rg 'import os, sys' src", "python3 -c 'import os as boxed_o, sys'"):
        assert bash_exit(ws_env, command) == 0, command


def test_quoted_boxed_outside_python_code_passes(ws_env):
    for command in ('rg "boxed" src', "grep -r 'boxed.cli' .", 'echo "boxed"', 'git commit -m "boxed"', "python3 -m pytest -k boxed",
                    "sed -i 's/boxed/x/' notes.txt", 'python3 -c "print(1)"', "cat 'boxed.toml'", "pip install python-dateutil",
                    "python3 -c \"print(open('boxed_notes.txt').read())\"", "node -e \"require('boxed')\""):
        assert bash_exit(ws_env, command) == 0, command


LAUNCHERS = ("python", "python3", "python3.13", "/usr/bin/python3.13", ".venv/bin/python", "env python", "uv run python", "uv run",
             "sudo python3", "./p", "$PY", "coverage run", "python3 -I", "python3 -B -W ignore", "xargs python3", "pypy3",
             "PYTHONPATH=src python3", "nohup python3")
MODULE_RUNS = st.builds(
    "{} {}{}".format,
    st.sampled_from(LAUNCHERS),
    st.sampled_from(("-m ", "-m", "-Im ", "-Im", "-I -m ", "-W ignore -m ", "-qm ")),
    st.sampled_from(("boxed", "boxed.cli", "boxed.cli --version", "boxed.native_host")),
) | st.just("uv run --module boxed.cli")
MESSAGES = ("git commit -m boxed", 'git commit -m "boxed: fix"', "pytest -m boxed", "git commit -am boxed", "git status", "cd src", "ls -la")
RUN_WRAPS = ("{}", "({})", "echo $({})", "echo `{}`", "bash -c '{}'", "{{ {}; }}")


@settings(max_examples=300, deadline=None)
@given(
    st.lists(st.one_of(st.sampled_from(MESSAGES).map(lambda s: (False, s)), st.tuples(st.just(True), MODULE_RUNS)), min_size=1,
             max_size=5),
    st.lists(st.sampled_from(("; ", " && ", " || ", " | ", "\n", " & ")), min_size=5, max_size=5),
    st.sampled_from(RUN_WRAPS),
)
def test_a_module_run_is_denied_wherever_it_sits(parts, separators, wrap):
    if not any(is_run for is_run, _ in parts):
        return
    pieces = [wrap.format(text) if is_run else text for is_run, text in parts]
    command = "".join(piece + separators[i] for i, piece in enumerate(pieces[:-1])) + pieces[-1]
    assert _runs_boxed(*_shell_words(command)), command


GUARD_PIECES = ("git", "pytest", "python3", "uv", "-m", "-Im", "boxed", "boxed.cli", " ", "\n", "'", '"', "\\", "$(", ")", "`", ";", "|",
                "&", "<", ">", "x")


@settings(max_examples=500, deadline=None)
@given(st.lists(st.sampled_from(GUARD_PIECES), max_size=30).map("".join))
def test_the_module_guard_answers_for_any_text(command):
    assert isinstance(_runs_boxed(*_shell_words(command)), bool)


def test_a_lone_slash_in_arithmetic_is_not_a_path(ws_env):
    """A division sign between numbers: a whole line of expr, or a $(( .. )) word made of numbers and signs."""
    for command in ("expr 6 / 3", "expr 6 / 3 + 1", "expr 12 / 4 / 3", "expr 6 \\* 3 / 2", "  expr 8 / 2  ", "echo $(( 6 / 3 ))",
                    'echo "$(( 6 / 3 ))"', "ls -la $(( 6 / 3 ))", "sleep $(( 6 / 3 ))", "git log -n $(( 12 / 4 )) --oneline",
                    "echo $(( 6 / 3 )) $(( 8 / 2 ))"):
        assert bash_exit(ws_env, command) == 0, command


def test_a_line_continuation_does_not_hide_a_path(ws_env, monkeypatch):
    """Bash deletes a backslash and the line break after it before it reads the words: ls \\<newline>/ lists the root."""
    repo, home, ws = ws_env
    monkeypatch.setenv("HOME", str(repo.parent))
    cut = len(repo.name) // 2
    for command in ("ls \\\n/", "ls /\\\n", "ls ~\\\n", "ls \\\n~", "ls ..\\\n", "ls \\\n..", f"cat ~/{repo.name[:cut]}\\\n{repo.name[cut:]}/.env",
                    f"cat {repo.parent}/{repo.name[:cut]}\\\n{repo.name[cut:]}/.env", f"grep -r x {repo.parent}\\\n"):
        assert bash_exit(ws_env, command) == 2, command
    assert bash_exit(ws_env, "ls src \\\n  -la") == 0


def test_an_escaped_backslash_before_a_line_break_is_no_continuation(ws_env, monkeypatch):
    """\\\\<newline> is a backslash and then a new command: the line after it is not a rest of the first line."""
    repo, home, ws = ws_env
    monkeypatch.setenv("HOME", str(repo.parent))
    for command in ("expr 6 \\\\\n* 3 / 2", "expr 6 \\\\\\\\\n* 3 / 2", "ls \\\\\n/", "ls src \\\\\\\\\n~", "echo ~ \\\\\n~", "ls \\\\\\\\\n..", "ls \\\n/"):
        assert bash_exit(ws_env, command) == 2, command
    # an odd number of backslashes: pairs, then a continuation. ls \\\<newline>/ is ls with the file \/ (not the root)
    for command in ("expr 6 \\\n/ 3", "echo \\\n~", "echo ~ \\\n   ~", "expr 6 \\\\\\\n* 3", "ls \\\\\\\n/"):
        assert bash_exit(ws_env, command) == 0, command


def test_arithmetic_hides_no_other_path(ws_env, monkeypatch):
    monkeypatch.setenv("HOME", str(ws_env[0].parent))
    for command in ("ls /", "expr 6 / 3 /", "expr / 3", "expr 6 / 3; ls /", "expr 6 / 3 && cat /", "expr 6 / 3 | ls /", "expr 6 / 3 > /",
                    "expr 6 / x", "expr 6 / 3 ~", "echo $(( 6 / 3 )) /", "echo $(( 6 / 3 ))/", "echo /$(( 6 / 3 ))", "ls $(( 6 / 3 )); ls /",
                    "cat $(( 6 / 3 )) ~", "ls $(( 6 / 3 )) ..", "echo $(( 6 / 3 ) )", "echo $(( (6) / 3 ))", "echo $(( a / 3 ))",
                    "echo $(( 6 /\n3 ))", "echo $(( $(ls /) / 3 ))", "echo $(( 6 / `ls /` ))", "echo $(($(ls /) ))", "echo $((6 / 3 )) /",
                    "echo $$(( 6 / 3 ))", "echo \\$(( 6 / 3 ))", "x=$(( 6 / 3 ))", "echo $(( 6 / 3 ))x"):
        assert bash_exit(ws_env, command) == 2, command


def test_a_protected_path_in_another_letter_case_is_the_same_path(ws_env):
    """A mac file system ignores case: ~/PROJECT/.env opens ~/project/.env, so the guard must not tell them apart."""
    repo, home, ws = ws_env
    for variant in (str(repo).upper(), str(repo).swapcase(), f"{repo.parent}/{repo.name.title()}", f"{repo.parent}/{repo.name.upper()}/src/.."):
        for name, fields in (("Read", {"file_path": f"{variant}/.env"}), ("Grep", {"pattern": "x", "path": variant}), ("Glob", {"pattern": f"{variant}/*"}),
                             ("Edit", {"file_path": f"{variant}/.env", "old_string": "a", "new_string": "b"})):
            assert hook_pre_tool_use(tool(name, ws.mirror, **fields), home).exit_code == 2, (name, variant)
        for command in (f"cat {variant}/.env", f"ls {variant}", f"cd {variant}", f"grep -r x {variant}"):
            assert bash_exit(ws_env, command) == 2, command
    for variant in (str(home).upper(), str(home).swapcase()):
        for command in (f"cat {variant}/vault.db", f"ls {variant}/state", f"cat {variant}/Journal.jsonl", f"rg x {variant}", f"cat {variant}/WORKSPACES/ws-x/a"):
            assert bash_exit(ws_env, command) == 2, command
    assert bash_exit(ws_env, f"ls {str(repo.parent).upper()}") == 2  # a folder that holds the project, in capitals
    assert bash_exit(ws_env, f"cat {str(ws.mirror).upper()}/src/app.py") == 0  # the mirror itself is the mirror in any case
    assert bash_exit(ws_env, f"ls {str(ws.mirror).swapcase()}") == 0


def test_a_protected_path_in_another_unicode_form_is_the_same_path(tmp_path, boxed_env, monkeypatch):
    """The same file system sees é as one character or as e and an accent."""
    import unicodedata

    name = unicodedata.normalize("NFC", "projé-café")
    repo = tmp_path / name
    (repo / "src").mkdir(parents=True)
    (repo / ".env").write_text("DB_PASSWORD=hunter22\n")
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    boxed_env.mkdir(parents=True, exist_ok=True)
    keys = default_keystore()
    ws = create_workspace(repo, level=2, config=ProjectConfig(), vault=Vault(boxed_env / "vault.db", keys),
                          journal=Journal(boxed_env / "journal.jsonl", keys), home=boxed_env).workspace
    spelled = unicodedata.normalize("NFD", f"{repo}/.env")
    assert spelled != f"{repo}/.env"
    for command in (f"cat {spelled}", f"cat {spelled.upper()}"):
        assert hook_pre_tool_use(tool("Bash", ws.mirror, command=command), boxed_env).exit_code == 2, command
    assert hook_pre_tool_use(tool("Read", ws.mirror, file_path=spelled), boxed_env).exit_code == 2


def test_a_relative_path_that_leaves_the_mirror_is_blocked_wherever_it_ends(ws_env):
    """A relative path is read from where the command starts, a link target from where the link lies, and a cd moves the start: only
    a path that stays in the mirror from every base is safe, and nobody inside the mirror has a reason to climb out of it."""
    repo, home, ws = ws_env
    out = os.path.relpath(repo.parent / "elsewhere" / "x", ws.mirror)  # a folder next to the project, which no rule protects
    assert out.startswith("../../..")
    for command in (f"ln -s {out} src/link", f"cd src; cat {out}", f"cd src || cat {out}", f"(cd src && cat {out})", f"cat {out}", f"cat {out}/../../..",
                    "cat ../x", "ls ../../..", "cat ./src/../../x", f"ln -s ../{out} src/link2", "cat src/../../x", "git -C ../x log", "cp -r ../x ."):
        assert bash_exit(ws_env, command) == 2, command
    for command in ("cat src/../README.md", "ls ./src/..", "cat ./a/../b", "git diff HEAD~1..HEAD", "ls -la src/../src", "echo ..", "echo ../.."):
        assert bash_exit(ws_env, command) == 0, command  # the last two only print
    inside = tool("Bash", ws.mirror / "src", command="cat ../src/app.py")
    assert hook_pre_tool_use(inside, home).exit_code == 0  # from src, .. is the mirror
    assert hook_pre_tool_use(tool("Bash", ws.mirror / "src", command="cat ../../../x"), home).exit_code == 2


def test_a_link_in_the_mirror_to_protected_data_is_blocked_by_its_bare_name(ws_env):
    """A word without a slash was never looked at: ls peek reads the project through a link an agent made."""
    repo, home, ws = ws_env
    os.symlink(repo, ws.mirror / "peek")
    os.symlink(repo / ".env", ws.mirror / "secret")
    os.symlink(ws.mirror / "src", ws.mirror / "inside")  # a link that stays in the mirror is fine
    for command in ("ls peek", "cat secret", "grep -r x peek", "cd peek", "cat --file=secret", "head -n1 secret peek", "tail -f secret",
                    "git -C peek log", "ls -la peek"):
        assert bash_exit(ws_env, command) == 2, command
    for command in ("ls inside", "cat src/app.py", "git status", "ls nothere", "ls " + "x" * 300, "echo peekaboo", "cat inside/app.py"):
        assert bash_exit(ws_env, command) == 0, command


def test_a_wildcard_that_stands_for_a_link_out_of_the_mirror_is_blocked(ws_env):
    """The shell turns pe* into peek before ls runs: the guard has to read the names the pattern stands for, not only the text of it."""
    repo, home, ws = ws_env
    plain = ("ls *.py", "ls src/*.py", "cat src/*", "ls s*", "wc -l */*.py", "ls s*/", "cat s*/../README.md", "grep -rn x src/*.py", "ls .[!.]*",
             "ls src/a*", "echo *.md", "cat [s]rc/app.py", "ls ?rc", "ls nothing*", "ls s?c/app.p?", "ls -d .??*", "cat 'a*b'", "ls [[:digit:]]*", "ls *",
             "find . -name '*.py' -exec echo {} +", "ls [!p]eek", "ls zz/*", "sed 's/a*/b/' src/app.py", "ls -d */", "ls {1..3}", "ls ^zz",
             "ls pe*", "cat */.env", "ls [[:lower:]]*")
    for command in plain:  # nothing leads out of this mirror: none of them is blocked
        assert bash_exit(ws_env, command) == 0, command
    os.symlink(repo, ws.mirror / "peek")
    os.symlink(repo, ws.mirror / "src" / "peek2")
    os.symlink(repo / ".env", ws.mirror / "secret")
    for command in ("ls pe*", "ls p?ek", "ls [p]eek", "ls pe[e]k", "ls p*", "ls *", "ls [!x]eek", "ls [^x]eek", "ls [[:lower:]]eek", "ls [a-q]eek",
                    "ls pe?k", "ls {pe,x}*", "ls p{e,}ek", "ls ./pe*", f"ls {ws.mirror}/pe*", "cat pe*/.env", "cat */.env", "cat ./*/.env", "cat sec*",
                    "grep -r x pe*", "head -n1 pe*/src/app.py", "ls src/pe*", "cat src/*/.env", "cat s*/peek2/.env", "ls src/*", "ls -d */",
                    "cat s?c/peek2/.env", "ls $(echo pe*)", "ls 'pe*'", "ls pe\\*", "cat --file=pe*", "git -C pe* log", "ls ^zz", "cat ^zz/.env",
                    "bash -c 'ls pe*'", "sh -c \"cat */.env\"", "eval 'cat p*/.env'", "xargs -I{} sh -c 'ls pe*' ", "bash -c \"bash -c 'ls pe*'\"",
                    "ls [p:]eek", "ls [p=]eek", "ls pee[k:]", "ls [[*pe:]*", "ls [:p]eek", "ls [p:x]eek", "ls [x:p=]eek",
                    "ls {peek,[x=x]}", "ls {{peek,[x=x]},x}", "ls {a=b,peek}", "ls {x:y,peek}",
                    "ls {1..3}", "ls p{1..3}ek", "ls *eek", "ls *e*", "ls ????", "ls [a-z][a-z][a-z][a-z]", "cat s*/pe*/.env", "ls s*", "wc -l */*.py", "ls s*/",
                    "cat src/*", "ls [[:lower:]]*", "ls .*", "ls -d .*", "ls -d .?*"):  # the last three: bash before 5.2 lets .* stand for .. too
        assert bash_exit(ws_env, command) == 2, command
    for command in ("ls *.py", "ls src/*.py", "ls ?rc", "ls nothing*", "ls [!p]eek", "ls zz/*", "cat 'a*b'", "ls s?c/app.p?", "cat [s]rc/app.py",
                    "ls .[!.]*", "ls .[p]*", "ls src/a*", "echo *.md", "sed 's/a*/b/' src/app.py", "find . -name '*.py' -exec echo {} +"):
        assert bash_exit(ws_env, command) == 0, command  # the pattern stands for no link


def test_a_wildcard_before_dotdot_is_read_on_the_names_it_stands_for(ws_env):
    """s*/../../../../client-repo/.env: the text stops at the first wildcard, the shell goes on through src and climbs out of the mirror."""
    repo, home, ws = ws_env
    (ws.mirror / "src" / "deeper").mkdir()
    up = os.path.relpath(repo.parent, ws.mirror / "src")  # ../../../..
    up2 = os.path.relpath(repo.parent, ws.mirror / "src" / "deeper")
    for command in (f"cat s*/{up}/{repo.name}/.env", f"cat s?c/{up}/{repo.name}/.env", f"cat [s]rc/{up}/{repo.name}/.env",
                    f"cat {{src,x}}/{up}/{repo.name}/.env", f"cat ./s*/{up}/{repo.name}/.env", f"cat */{up}/{repo.name}/.env",
                    f"cat s*/d*/{up2}/{repo.name}/.env", f"cat */*/{up2}/{repo.name}/.env", f"ls s*/{up}", f"ls */{up}/{repo.name}",
                    f"git -C s*/{up}/{repo.name} log", f"cat {ws.mirror}/s*/{up}/{repo.name}/.env", f"cat s*/{up}/{repo.name}/s*/*.py",
                    "cat s*/../../x*", "ls s*/../..", "ls */../../..", f"bash -c 'cat s*/{up}/{repo.name}/.env'", f"sh -c \"cat */{up}/{repo.name}/.env\"",
                    "eval 'ls s*/../..'", f"eval 'eval \"ls s*/{up}\"'"):
        assert bash_exit(ws_env, command) == 2, command
    for command in ("cat s*/../src/app.py", "ls */../src", "cat s*/d*/../app.py", "cat s*/deeper/../app.py"):  # these stay in the mirror
        assert bash_exit(ws_env, command) == 0, command
    # (ls s*/.. was blocked before and is now: its text ends in /.., which a check of quoted code takes for the root)


def test_a_wildcard_in_a_name_is_read_as_a_name_too(ws_env):
    """Masked names hold brackets ([EMAIL_1].csv, quoted by the agent): a link with such a name is a link, not a pattern."""
    repo, home, ws = ws_env
    os.symlink(repo, ws.mirror / "[PERSON_1]")
    (ws.mirror / "exports").mkdir()
    (ws.mirror / "exports" / "[EMAIL_1].csv").write_text("a\n")
    assert bash_exit(ws_env, "cat '[PERSON_1]/.env'") == 2
    assert bash_exit(ws_env, "ls '[PERSON_1]'") == 2
    assert bash_exit(ws_env, "cat 'exports/[EMAIL_1].csv'") == 0  # a plain file with brackets in its name is no way out
    assert bash_exit(ws_env, "ls exports/*.csv") == 0


def test_a_lone_brace_does_not_hide_the_rest_of_a_path(ws_env):
    """A word was cut at its first brace and only what lay before it was read, but a { that closes nothing is a name, and a quoted one
    too: ./a{/../../../vault.db goes through the folder a{ (an agent can make one) to the vault, and the fuzz found the print line
    echo 'home:' "../.{ME/.,." naming a path in the folder of the other mirrors."""
    repo, home, ws = ws_env
    (ws.mirror / "a{").mkdir()
    (ws.mirror / "src" / "b{").mkdir()
    vault = os.path.relpath(home / "vault.db", ws.mirror)  # ../../vault.db
    env = os.path.relpath(repo / ".env", ws.mirror)
    for command in (f"cat ./a{{/../{vault}", f"cat a{{/../{vault}", f"cat 'a{{/../{vault}'", f"cat ./src/b{{/../../{vault}", f"head -n1 ./a{{/../{env}",
                    f"cat \"./a{{/../{env}\"", "ls ./a{/../../..", "git -C ./a{/../../.. status", f"grep -r x ./a{{/../{vault}", f"cat ./a{{/x/../../{vault}",
                    # a print line names a path in the folder of the other mirrors
                    "echo 'home:' \"../.{ME/.,.\"", "echo '../ws-x{'", 'echo "../ws-x{"', "printf '%s' \"../{ws\"", "echo ../ws-x'{'", f"echo './a{{/../{vault}'"):
        assert bash_exit(ws_env, command) == 2, command
    for command in ("cat ./a{/x", "ls ./a{", "cat ./a{/../README.md", "echo 'a{'", 'echo "{"', "echo '{}'", "echo '..' '{x}'", "echo '{'", "ls src/b{",
                    "find . -name '*.py' -exec echo {} +", "echo \"cwd: {$HOME}\"", "cat a{ ./a{/y"):
        assert bash_exit(ws_env, command) == 0, command


def test_wildcards_beyond_what_the_guard_reads_are_blocked(ws_env, monkeypatch):
    """A pattern that stands for more than a thousand names on its way, goes deeper than eight wildcards or makes the command read more than
    a hundred thousand entries is not read to the end: it is blocked."""
    repo, home, ws = ws_env
    for number in range(30):
        (ws.mirror / f"d{number}").mkdir()
        (ws.mirror / f"f{number}.txt").write_text("a\n")
    monkeypatch.setattr(hooks, "GLOB_LIMIT", 20)
    assert bash_exit(ws_env, "ls d*/x") == 2  # thirty folders to go on in
    assert bash_exit(ws_env, "ls d1*/x") == 0
    assert bash_exit(ws_env, "ls f*.txt") == 0  # plain names at the end lead nowhere new: they are not counted
    assert bash_exit(ws_env, "cat */*.txt") == 2
    monkeypatch.setattr(hooks, "GLOB_LIMIT", 1000)
    assert bash_exit(ws_env, "ls */*/*/*/*/*/*/*/x") == 0  # eight wildcards
    assert bash_exit(ws_env, "ls */*/*/*/*/*/*/*/*/x") == 2  # nine
    for number in range(100):
        (ws.mirror / f"g{number}").write_text("a\n")
    monkeypatch.setattr(hooks, "GLOB_SCAN", 50)
    assert bash_exit(ws_env, "ls *") == 2  # more than fifty names at the top
    assert bash_exit(ws_env, "ls src/*.py") == 0


def test_a_recursive_wildcard_looks_for_links_below_it(ws_env):
    """zsh's **/ goes through every folder below: it finds a link out of the mirror wherever the link lies."""
    repo, home, ws = ws_env
    (ws.mirror / "src" / "deeper").mkdir()
    for command in ("ls **/*.py", "cat **/app.py", "wc -l **/*.py", "grep -r x **/*.md", "ls src/**/*.py", "ls ***/*.py"):
        assert bash_exit(ws_env, command) == 0, command
    os.symlink(repo, ws.mirror / "src" / "deeper" / "peek3")
    for command in ("ls **/peek3", "cat **/peek3/.env", "ls **/p*", "ls src/**/peek3", "ls ***/pe*", "cat **/.env", "ls **/*", "ls **/../.."):
        assert bash_exit(ws_env, command) == 2, command


def test_zsh_number_ranges_and_classes_are_wildcards_too(ws_env):
    """<-> stands for every name that is a number, [[:alpha:]] for a letter: the redirect signs the guard turns into spaces hide the first."""
    repo, home, ws = ws_env
    os.symlink(repo, ws.mirror / "2")
    os.symlink(repo, ws.mirror / "peek")
    for command in ("ls <->", "ls <1-9>", "ls <2->", "ls <-2>", "cat <->/.env", "ls [[:digit:]]", "ls [[:alpha:]]eek", "ls [![:digit:]]eek",
                    "ls [[:alpha:][:digit:]]*"):
        assert bash_exit(ws_env, command) == 2, command


# the names real bash and zsh match with the pattern (the differential checks that against the shells), and some they do not
SHELL_MATCHES = (("*", "ab"), ("*", ""), ("a*", "a"), ("a*", "ab"), ("?", "a"), ("a?c", "abc"), ("[abc]x", "ax"), ("[!abc]x", "dx"), ("[^abc]x", "dx"),
                 ("[a-c]x", "bx"), ("[]a]x", "]x"), ("[!]a]x", "bx"), ("[[:digit:]]", "5"), ("[![:digit:]]", "a"), ("[[:alpha:][:digit:]_]x", "_x"),
                 ("[a-]x", "-x"), ("[-a]x", "-x"), ("a[", "a["), ("[a", "[a"), ("{1..3}", "2"), ("a{x}b", "axb"), ("^x", "y"), ("[a-z-9]", "9"),
                 ("[[:foo:]]", "a"), ("[z-a]", "m"), ("x*y*z", "x1y22z"), ("*.py", "app.py"), ("[[:upper:]]*", "Abc"), ("[[:alnum:]]", "7"),
                 ("[[:punct:]]", "_"), ("[[:space:]]", " "), ("[[:xdigit:]]x", "fx"), ("[!a]", "\n"), ("?", "é"), ("??", "é"), ("???", "中"),
                 ("?*", "ßb"), ("[!a]?", "é"), ("é?", "éx"), ("li[n[:]]k2", "link2"), ("[n[:]]", "n"), ("[][:alpha]-[z-a]", "]"))  # the C locale counts bytes: ?? is é; [:] is an empty class
NOT_MATCHES = (("a*", "ba"), ("?", "ab"), ("a?c", "ac"), ("[abc]x", "dx"), ("[!abc]x", "ax"), ("[^abc]x", "ax"), ("[[:digit:]]", "a"),
               ("[![:digit:]]", "5"), ("a[", "a"), ("x*y", "xz"), ("*.py", "app.pyc"), ("[[:upper:]]*", "abc"))


@pytest.mark.parametrize("pattern, name", SHELL_MATCHES)
def test_the_wildcard_matcher_matches_what_the_shell_matches(pattern, name):
    """A name too few lets a link through, so the matcher may match more than the shell but never less."""
    assert hooks._wildcard(pattern).fullmatch(name), (pattern, name)


@pytest.mark.parametrize("pattern, name", NOT_MATCHES)
def test_the_wildcard_matcher_does_not_match_everything(pattern, name):
    """... and not everything either: ls a* must not be blocked for a link named ba."""
    assert not hooks._wildcard(pattern).fullmatch(name), (pattern, name)


def test_the_wildcard_matcher_survives_any_pattern():
    for pattern in ("[", "[]", "[[", "[[:", "[[:a", "[[:alpha:", "[!", "[^]", "[a-", "]", "{", "}", "{}", "{a", "a}", "[\\]", "[a\\]b]", "*" * 50,
                    "[" * 50, "[[:" * 20, "{" * 20 + "}" * 20, "\x00", "[\x00-\xff]", "[[.a.]]", "[[=a=]]", "?" * 100 + "[a-", "[a-z-0-9]", "[%-+]"):
        hooks._wildcard(pattern).fullmatch("anything")  # no pattern raises


def test_tildes_for_the_current_previous_or_stacked_folder_are_not_followed(ws_env):
    """~+ is the folder the shell is in, ~- the one it left and ~2 one on the stack: after a cd the guard does not know which."""
    for command in ("ls ~-", "ls ~+", "ls ~-/..", "ls ~+/sub", "cd src && ls ~-/..", "cd src && git commit -m boxed ~-/..", "cat ~+/.env", "ls ~0",
                    "ls ~1/x", "ls a=~-", "ls --dir=~+", "ls x:~-", "cd src && ls ~-", "head ~-/a ~-/b", "echo ~+/../ws-other", "echo ~-", "echo ~+",
                    "printf '%s' ~+:x", "pwd ~-"):  # a print line too: where ~+/.. leads is not known, and a path in a protected folder stays blocked
        assert bash_exit(ws_env, command) == 2, command
    for command in ("ls ~x", "git log HEAD~2", "ls a~-b", "ls src~1", "echo a~-b"):  # a ~ inside a word is no tilde
        assert bash_exit(ws_env, command) == 0, command


def test_echo_printf_and_pwd_may_print_a_folder_that_holds_protected_data(ws_env, monkeypatch):
    """They read nothing: ~, / or the folder above the project is only text. Inside a protected folder it stays blocked."""
    repo, home, ws = ws_env
    monkeypatch.setenv("HOME", str(repo.parent))
    for command in ("echo $HOME", 'echo "$HOME"', "echo ${HOME}", "echo ~", "echo ~/", "echo /", "echo ..", "echo ../..", "pwd", "pwd -P",
                    "printf '%s\\n' $HOME", 'printf "%s\\n" "$HOME" ~', "echo $HOME/..", 'echo "cwd: $HOME"', "echo ../.. ../../..",
                    f"echo {home}", f"echo {home}/workspaces", f"echo {repo.parent}", "echo -n ~", "echo 'my folder:' ~", "  echo ~  "):
        assert bash_exit(ws_env, command) == 0, command


def test_echo_printf_and_pwd_stay_blocked_inside_protected_folders_and_with_anything_else(ws_env, monkeypatch):
    repo, home, ws = ws_env
    monkeypatch.setenv("HOME", str(repo.parent))
    for command in (f"echo {repo}", f"echo {repo}/.env", "echo ~/client-repo", "echo $HOME/client-repo/src", 'echo "$HOME/client-repo"',
                    f"echo {home}/vault.db", f"echo {home}/state", f"echo {home}/workspaces/ws-other", f"echo {home}/workspaces/ws-other/x",
                    f"echo {home}/journal.jsonl", "echo ~ ~/client-repo", "echo ../ws-other", "echo ../../vault.db",
                    "echo $(ls ~)", "echo `ls ~`", "echo ~ > out", "echo ~ >> out", "echo ~; ls", "echo ~ && ls", "echo ~ | cat",
                    "echo ~ &", "echo ~ # note", "echo ~\nls", "echo ~/*", "echo ~ $X", "FOO=1 echo ~", "echo ~ $(( 6 / 3 ))",
                    "sudo echo ~", "env echo ~", "command echo ~", "time echo ~", "(echo ~)", "{ echo ~; }", "! echo ~", "echo ~ \\z",
                    "ls ~", "cat ~", "echo ~ ; cat ~/client-repo/.env"):
        assert bash_exit(ws_env, command) == 2, command


def test_the_value_of_an_arithmetic_word_cannot_finish_a_protected_name(tmp_path, boxed_env, monkeypatch):
    """$(( 6 / 3 )) is 2: glued to a quoted "site" it names the project site2. Only a word of its own is set aside."""
    repo = tmp_path / "site2"
    (repo / "src").mkdir(parents=True)
    (repo / ".env").write_text("DB_PASSWORD=hunter22\n")
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    boxed_env.mkdir(parents=True, exist_ok=True)
    keys = default_keystore()
    ws = create_workspace(repo, level=2, config=ProjectConfig(), vault=Vault(boxed_env / "vault.db", keys),
                          journal=Journal(boxed_env / "journal.jsonl", keys), home=boxed_env).workspace
    monkeypatch.setenv("HOME", str(repo.parent))
    for command in (f'cat "{repo.parent}/site"$(( 6 / 3 ))/.env', f'cat "{repo.parent}/site"$(( 6 / 3 ))', f'cat ~/"site"$(( 6 / 3 ))/.env',
                    f"cat '{repo.parent}/site'$(( 6 / 3 ))/.env"):
        assert hook_pre_tool_use(tool("Bash", ws.mirror, command=command), boxed_env).exit_code == 2, command


def test_arithmetic_words_are_judged_only_on_a_plain_line(ws_env, monkeypatch):
    """The words around the arithmetic could hide a path the guard does not see ($'/', ${X:-/}, "$(ls /)", a second command): those
    lines were blocked by the division sign alone, so they stay blocked."""
    monkeypatch.setenv("HOME", str(ws_env[0].parent))
    for command in ("ls $(( 6 / 3 )) $'/'", 'ls $(( 6 / 3 )) $"/"', "ls $(( 6 / 3 )) ${X:-/}", 'ls $(( 6 / 3 )) "$(ls /)"',
                    "ls $(( 6 / 3 )) \"$(printf '\\057')\"", "ls $(( 6 / 3 )) $OLDPWD", "ls $(( 6 / 3 )); ls", "ls $(( 6 / 3 )) && ls",
                    "ls $(( 6 / 3 )) | cat", "ls $(( 6 / 3 )) > out", "ls $(( 6 / 3 )) # note", "ls $(( 6 / 3 )) *", "ls $(( 6 / 3 )) {a,b}",
                    "ls $(( 6 / 3 ))\nls", "ls $(( 6 / 3 )) \\z"):
        assert bash_exit(ws_env, command) == 2, command


def test_the_value_of_arithmetic_can_be_the_name_of_a_link(ws_env):
    """$(( 6 / 3 )) is 2, and 2 can be a link to the project: the word is replaced by its value, not by a number of the guard's own."""
    repo, home, ws = ws_env
    twos = ("ls $(( 6 / 3 ))", "ls $(( 4 - 2 ))", "ls $(( 1 + 1 ))", "ls $(( 2 * 1 ))", "ls $(( 8 % 6 ))", "ls $(( 12 / 4 - 1 ))", "ls $(( 1 + 6 / 3 - 1 ))",
            "ls $(( 6 / 3 * 1 ))", "ls $(( 100 / 50 ))", "ls $((6/3))", "ls $(( 2 ))", "git -C $(( 6 / 3 )) log", "cat $(( 6 / 3 )) src", "head $(( 9 / 3 - 1 )) src",
            "echo $(( 6 / 3 ))", "ls -la $(( 6 / 3 )) src", "sleep $(( 6 / 3 ))", "ls $(( 3 - 1 ))", "ls $(( 0 + 2 ))", "ls $(( 20 / 5 / 2 ))")
    for command in twos:
        assert bash_exit(ws_env, command) == 0, command  # no link of that name yet
    os.symlink(repo, ws.mirror / "2")
    for command in twos:
        assert bash_exit(ws_env, command) == 2, command  # the value is the link
    for command in ("ls $(( 6 / 3 + 1 ))", "ls $(( 6 / 2 ))", "ls $(( 6 - 3 ))", "ls $(( 3 * 1 ))", "ls $(( 6 / 3 * 3 ))", "ls $(( 8 / 2 ))", "ls $(( 12 / 4 ))",
                    "ls $(( 1 + 2 * 3 ))", "ls $(( 20 % 7 ))", "ls $(( 3 - 5 ))", "ls $(( 14 / 2 )) src"):
        assert bash_exit(ws_env, command) == 0, command  # another value is another name


def test_arithmetic_the_guard_cannot_compute_the_way_the_shell_does_keeps_the_old_block(ws_env):
    """A leading zero is octal in bash and decimal in zsh, a division by zero is an error and a big number wraps: a value the guard cannot
    know is not guessed, and a word with a division sign in it stays what it was, a path."""
    repo, home, ws = ws_env
    os.symlink(repo, ws.mirror / "2")
    for command in ("ls $(( 06 / 3 ))", "ls $(( 010 / 4 ))", "ls $(( 6 / 0 ))", "ls $(( 99999999999999999999 / 3 ))", "ls $(( 6 / 3 / ))", "ls $(( / 3 ))",
                    "ls $(( 6 / -3 ))", "ls $(( -6 / 3 ))", "ls $(( 6 // 3 ))", "ls $(( 6 / 3 / 1 / 0 ))", "ls $(( 6 / 3 * ))", "ls $(( 00 / 3 ))",
                    "ls $(( 4611686018427387904 / 2 ))", "ls $(( 6 / 3 ))x", "ls x$(( 6 / 3 ))", "ls $(( 6 / 3 ),)", "ls $(( 6 / 3 + a ))", "ls $(( 6 / 3 > 1 ))"):
        assert bash_exit(ws_env, command) == 2, command


def test_the_value_of_arithmetic_is_a_name_on_a_line_that_is_not_plain_too(ws_env):
    """The words around it keep the line from being replaced by its values (it could hide a path the guard does not see), but 2 is still a
    name: ls $(( 4 - 2 )) ; true lists the link called 2."""
    repo, home, ws = ws_env
    lines = ("ls $(( 4 - 2 )) ; true", "eval ls $(( 4 - 2 ))\n &", "ls $(( 1 + 1 )) # x", "ls $(( 8 % 6 )) | cat", "ls $(( 4 - 2 )) > out", "(ls $(( 4 - 2 )))",
             "ls $(( 4 - 2 )) `true`", "echo hi; ls $(( 3 - 1 )) $(( 1 + 5 ))", "cat <<EOF\\n$(( 4 - 2 ))\\nEOF", "FOO=1 ls $(( 2 * 1 ))")
    for command in lines:
        assert bash_exit(ws_env, command) == 0, command  # no link of that name yet
    os.symlink(repo, ws.mirror / "2")
    for command in lines:
        assert bash_exit(ws_env, command) == 2, command
    for command in ("ls $(( 4 - 1 )) ; true", "ls $(( 3 + 1 )) # x", "echo hi; ls $(( 3 + 1 )) $(( 1 + 5 ))"):
        assert bash_exit(ws_env, command) == 0, command  # another value is another name


def step(ws_env, name, **fields):
    """One call of a tool that writes a file in steps: what the hook says and, when it lets the call through, what the tool then does."""
    _, home, ws = ws_env
    answer = hook_pre_tool_use(tool(name, ws.mirror, **fields), home).exit_code
    if answer == 0:
        target = ws.mirror / fields["file_path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        if name == "Write":
            target.write_text(fields["content"])
        else:
            text = target.read_text() if target.exists() else ""
            for edit in fields["edits"] if name == "MultiEdit" else [fields]:
                text = text.replace(edit["old_string"], edit["new_string"], -1 if edit.get("replace_all") else 1)
            target.write_text(text)
    return answer


def test_an_edit_that_completes_boxed_in_a_file_is_refused(ws_env):
    """Neither piece runs boxed alone, the file that holds both does: the guard judges the file the edit leaves, not only the new text."""
    mirror = ws_env[2].mirror
    for number, (name, first, old, new) in enumerate((
            ("run.sh", "boxed Q\n", "Q", "restore"), ("run.sh", "boxed \n", "boxed ", "boxed mask"), ("run.sh", "python3 -m \n", "-m ", "-m boxed"),
            ("run.sh", "exec REST\n", "REST", "boxed restore"), ("run.sh", "bo\nxed restore\n", "bo\n", "bo"), ("run.sh", "#!/bin/sh\nboxed\n", "boxed\n", "boxed restore\n"),
            ("run.sh", "bo@@xed restore\n", "@@", ""), ("mod.py", "import os\nOS\n", "OS", "import boxed"),
            ("mod.py", "from MOD import x\n", "MOD", "boxed.cli"), ("run.sh", "x=1\nboxed -v\n", "-v", "mask")), 1):
        path = f"src/step{number}/{name}"
        assert step(ws_env, "Write", file_path=path, content=first) == 0, first
        assert step(ws_env, "Edit", file_path=path, old_string=old, new_string=new) == 2, (first, old, new)
        assert (mirror / path).read_text() == first  # the edit was never made
    two = [{"old_string": "A", "new_string": "boxed"}, {"old_string": "B", "new_string": "restore"}]
    assert step(ws_env, "Write", file_path="src/m.sh", content="A B\n") == 0
    assert step(ws_env, "MultiEdit", file_path="src/m.sh", edits=two) == 2
    chained = [{"old_string": "A", "new_string": "boxed X"}, {"old_string": "X", "new_string": "restore"}]  # the second edit works on the first
    assert step(ws_env, "Write", file_path="src/c.sh", content="A\n") == 0
    assert step(ws_env, "MultiEdit", file_path="src/c.sh", edits=chained) == 2
    assert step(ws_env, "Write", file_path="src/all.sh", content="boxed Q\nQ\n") == 0
    assert step(ws_env, "Edit", file_path="src/all.sh", old_string="Q", new_string="restore", replace_all=True) == 2
    assert step(ws_env, "Edit", file_path="src/all.sh", old_string="Q", new_string="restore") == 2  # the first one is enough


def test_an_edit_that_leaves_a_file_clean_is_allowed(ws_env):
    mirror = ws_env[2].mirror
    assert step(ws_env, "Write", file_path="src/ok.py", content="x = 1\n") == 0
    assert step(ws_env, "Edit", file_path="src/ok.py", old_string="x = 1", new_string="x = 2") == 0
    (mirror / "src" / "had.sh").write_text("boxed restore\necho hi\n")  # a file that runs boxed can still be cleaned
    assert step(ws_env, "Edit", file_path="src/had.sh", old_string="boxed restore\n", new_string="") == 0
    assert step(ws_env, "Write", file_path="src/new.sh", content="echo hi\n") == 0
    assert step(ws_env, "Edit", file_path="src/new.sh", old_string="hi", new_string="boxed goods") == 0
    assert step(ws_env, "Edit", file_path="src/nothing.sh", old_string="a", new_string="echo hi") == 0  # no such file: the new text alone
    assert step(ws_env, "Edit", file_path="src/nothing.sh", old_string="a", new_string="boxed restore") == 2
    assert step(ws_env, "Write", file_path="src/two.sh", content="echo a\necho b\n") == 0
    assert step(ws_env, "MultiEdit", file_path="src/two.sh", edits=[{"old_string": "a", "new_string": "x"}, {"old_string": "b", "new_string": "y"}]) == 0


def test_an_edit_is_judged_on_what_the_file_holds_now(ws_env, monkeypatch):
    """A file it cannot read as text, one that is no regular file and one that is too big to read."""
    _, home, ws = ws_env
    (ws.mirror / "big.sh").write_text("boxed restore\n" + "x" * 1000)
    monkeypatch.setattr(hooks, "EDIT_LIMIT", 100)
    answer = hook_pre_tool_use(tool("Edit", ws.mirror, file_path="big.sh", old_string="x", new_string="y"), home)
    assert answer.exit_code == 2 and "too large" in answer.stderr
    assert hook_pre_tool_use(tool("MultiEdit", ws.mirror, file_path="big.sh", edits=[{"old_string": "x", "new_string": "y"}]), home).exit_code == 2
    assert hook_pre_tool_use(tool("Write", ws.mirror, file_path="big.sh", content="echo hi\n"), home).exit_code == 0  # a Write replaces it all
    monkeypatch.undo()
    (ws.mirror / "bin.dat").write_bytes(b"boxed \n\xff\xfe")  # not text: read as text with its bad bytes replaced
    assert hook_pre_tool_use(tool("Edit", ws.mirror, file_path="bin.dat", old_string="boxed \n", new_string="boxed restore\n"), home).exit_code == 2
    os.mkfifo(ws.mirror / "pipe")  # a file that is no regular file is not read (and a read of it would never end)
    assert hook_pre_tool_use(tool("Edit", ws.mirror, file_path="pipe", old_string="a", new_string="b"), home).exit_code == 0
    assert hook_pre_tool_use(tool("Edit", ws.mirror, file_path="src", old_string="a", new_string="b"), home).exit_code == 0


def test_boxed_with_an_argument_filled_in_later_is_a_boxed_run(ws_env):
    """exec boxed "$@" runs whatever subcommand the caller gives the script."""
    for text in ('#!/bin/sh\nexec boxed "$@"\n', "boxed $@\n", "boxed $*\n", "boxed ${1}\n", "boxed $cmd --scope x\n", 'boxed "$1"\n', "sudo boxed -v $@\n",
                 "x=$(boxed $(echo x))\n", "(boxed $@)\n", "restore:\n\tboxed $(CMD)\n"):
        assert set(write_exits(ws_env, "src/w.sh", text).values()) == {2}, text
    for text in ("boxed\n", "echo boxed $@\n", "boxed.si $@\n", "my_boxed $@\n", "x.boxed $1\n", 'echo "boxed $@"\n', "boxed -h\n", "boxed --version\n"):
        assert set(write_exits(ws_env, "src/w.sh", text).values()) == {0}, text
