"""The hooks and the MCP server under `boxed run`, with the sandbox of the real macOS `sandbox-exec`.

The tests of test_run.py keep their data in pytest's temp folder, which the sandbox profile lets an agent write to, so they never
met the failures of a data folder that the profile makes read-only. These tests build everything (the home folder, the data
folder, the project, the copy) in a folder of their own inside the checkout, outside every folder the profile allows, and start
a stand-in for Claude Code (tests/sandbox_support/agent.py) with `boxed run claude`.

No test touches the real home folder, ~/.boxed or the keychain. The commands run with a made-up HOME and BOXED_HOME. The sandbox
hides boxed's file key store from the agent, as it should, so the keys of this module live in a keyring backend that keeps them in
one file (tests/sandbox_support/file_keyring.py); the module checks that the keyring library picked it before anything is stored."""

import ast
import json
import os
import re
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from types import SimpleNamespace

import pytest

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="boxed run needs the macOS sandbox and is not supported on Windows yet")

ROOT = Path(__file__).resolve().parents[1]
SUPPORT = Path(__file__).resolve().parent / "sandbox_support"
# the folders the sandbox profile lets an agent write to wherever the checkout is
SANDBOX_WRITABLE = (Path("/private/tmp"), Path("/private/var/folders"), Path("/dev"))
SYSTEM_PATH = ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]
HOOK_FAILED = "boxed: the hook failed and blocked this step; details are in the boxed hook error log"


@cache
def sandbox_works() -> bool:
    """sandbox-exec is there and can apply a profile here (it cannot inside another sandbox)."""
    if sys.platform != "darwin" or not shutil.which("sandbox-exec"):
        return False
    done = subprocess.run(["sandbox-exec", "-p", "(version 1)(allow default)", "/usr/bin/true"], capture_output=True)
    return done.returncode == 0


@dataclass
class Session:
    base: Path
    user: Path  # the made-up home folder of the agent
    home: Path  # BOXED_HOME
    original: Path
    mirror: Path
    report: dict
    before: dict  # the files of the copy that the agent must not change, as they were before it started
    env: dict  # the environment the commands of the test run in

    def journal(self) -> list[dict]:
        path = self.home / "journal.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def run_boxed(args, env, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-m", "boxed.cli", *args], env=env, capture_output=True, text=True, timeout=300, **kwargs)


def build(base: Path, mode: str = "main", boxed_on_path: bool = True, docker_socket: str = "") -> Session:
    """A made-up home, data folder and project in `base`, a copy made by the real CLI, and the stand-in agent run in it under
    `boxed run` in the given mode (see tests/sandbox_support/agent.py). boxed_on_path: whether the hooks of the copy find `boxed` on
    PATH, or are `python -I -m boxed.cli` commands."""
    user, original, logs = base / "user", base / "project", base / "logs"
    for folder in (user / ".claude" / "projects", user / ".codex" / "sessions", user / ".local" / "share" / "uv" / "tools" / "boxedsi"):
        folder.mkdir(parents=True)
    (user / ".local" / "share" / "uv" / "tools" / "boxedsi" / "code.py").write_text("print('boxed')\n")
    (user / ".claude.json").write_text('{"projects": {}}\n')
    (user / ".cache" / "uv" / "archive-v0" / "abc" / "pkg").mkdir(parents=True)
    (user / ".cache" / "uv" / "archive-v0" / "abc" / "pkg" / "__init__.py").write_text("x = 1\n")
    (user / ".codex" / "AGENTS.md").write_text("be careful\n")
    original.mkdir()
    (original / ".env").write_text("DB_PASSWORD=hunter22\n")
    (original / "app.py").write_text("print('hi')\n")
    (original / "boxed.toml").write_text(f"[boxed]\nmcp_roots = [{json.dumps(str(logs))}]\n")
    logs.mkdir()
    (logs / "app.log").write_text("login ivan.petrov@acme.com ok\n")
    (base / "elsewhere").mkdir()
    (base / "bin").mkdir()
    agent = base / "bin" / "claude"
    agent.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{SUPPORT / "agent.py"}" "$@"\n')
    agent.chmod(0o755)

    tools = [str(base / "bin"), *([str(Path(sys.executable).parent)] if boxed_on_path else []), *SYSTEM_PATH]
    if shutil.which("uv"):
        tools.append(str(Path(shutil.which("uv")).parent))
    env = {k: v for k, v in os.environ.items() if not k.startswith(("BOXED_", "PYTHON_KEYRING", "AGENT_", "UV_", "XDG_"))}
    env |= {
        "HOME": str(user),
        "BOXED_HOME": str(base / "boxed-home"),
        "BOXED_KEYSTORE": "keyring",
        "PYTHON_KEYRING_BACKEND": "file_keyring.FileKeyring",
        "BOXED_TEST_KEYRING_FILE": str(base / "keyring.json"),
        "PYTHONPATH": os.pathsep.join(filter(None, [str(SUPPORT), os.environ.get("PYTHONPATH")])),
        "PATH": os.pathsep.join(tools),
        "AGENT_MODE": mode,
        "AGENT_ORIGINAL": str(original),
        "AGENT_ELSEWHERE": str(base / "elsewhere"),
        "AGENT_MISSING_HOME": str(base / "no-such-folder"),
        "AGENT_LOG": str(logs / "app.log"),
        "AGENT_DOCKER_SOCKET": docker_socket,
    }
    # the real keychain stays closed: nothing runs before the keyring library has picked the file backend
    picked = subprocess.run(
        [sys.executable, "-c", "import keyring; k = keyring.get_keyring(); print(type(k).__module__ + '.' + type(k).__name__)"],
        env=env, capture_output=True, text=True,
    ).stdout.strip()
    assert picked == "file_keyring.FileKeyring", f"the test keyring is not in use ({picked}): the keychain must stay closed"

    made = run_boxed(["workspace", "create", str(original)], env)
    assert made.returncode == 0, made.stderr
    if mode == "lockhold":  # the lock file of the vault is there once any command has masked something; the sandbox cannot make it
        (base / "boxed-home" / "vault.db.lock").touch(mode=0o600)
    mirror = next((base / "boxed-home" / "workspaces").iterdir())
    before = {name: (mirror / name).read_bytes() for name in (".boxed-workspace", ".claude/settings.local.json")}
    done = run_boxed(["run", "claude"], env, cwd=mirror)
    lines = [line for line in done.stdout.splitlines() if line.startswith("REPORT ")]
    assert done.returncode == 0 and lines, f"the stand-in agent did not report: exit {done.returncode}\n{done.stdout}\n{done.stderr}"
    return Session(base, user, base / "boxed-home", original, mirror, json.loads(lines[-1][len("REPORT "):]), before, env)


@contextmanager
def checkout_folder():
    """A folder of its own in the checkout, outside every folder that the profile lets an agent write to."""
    if not sandbox_works():
        pytest.skip("macOS sandbox-exec only")
    cache_dir = ROOT / ".pytest_cache"
    cache_dir.mkdir(exist_ok=True)
    base = Path(tempfile.mkdtemp(prefix="sandbox-", dir=cache_dir)).resolve()
    try:
        if any(base.is_relative_to(folder) for folder in SANDBOX_WRITABLE):
            pytest.skip("the checkout is in a folder that the sandbox lets an agent write to")
        yield base
    finally:
        shutil.rmtree(base, ignore_errors=True)


@contextmanager
def socket_like_docker():
    """A socket named docker.sock that answers, which a program talks to the way it talks to the Docker daemon. The folder is short:
    the path of a socket may not be longer than 104 bytes."""
    folder = Path(tempfile.mkdtemp(prefix="bx-", dir="/tmp"))
    server = socket.socket(socket.AF_UNIX)
    server.bind(str(folder / "docker.sock"))
    server.listen()
    server.settimeout(0.2)
    stop = threading.Event()

    def answer() -> None:
        while not stop.is_set():
            try:
                client, _ = server.accept()
            except OSError:  # nobody came in 0.2 s
                continue
            with client:
                client.settimeout(2)
                try:
                    client.recv(10)
                    client.sendall(b"pong")
                except OSError:
                    pass

    thread = threading.Thread(target=answer, daemon=True)
    thread.start()
    try:
        yield str(folder / "docker.sock")
    finally:
        stop.set()
        thread.join()
        server.close()
        shutil.rmtree(folder, ignore_errors=True)


@pytest.fixture(scope="module")
def session():
    with checkout_folder() as base, socket_like_docker() as docker_socket:
        yield build(base, docker_socket=docker_socket)


@pytest.fixture(scope="module")
def stub_session():
    """The hooks of this copy are `python -I -m boxed.cli` commands: boxed is not on PATH."""
    with checkout_folder() as base:
        yield build(base, mode="stub", boxed_on_path=False)


@pytest.fixture(scope="module")
def lockhold_session():
    """The agent is gone and a process of its sandbox stays, holding the lock files of boxed."""
    with checkout_folder() as base:
        built = build(base, mode="lockhold")
        try:
            yield built
        finally:
            pid = built.report["lockhold"]["pid"]
            if pid:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass


@pytest.fixture(scope="module")
def lockdir_session():
    with checkout_folder() as base:
        yield build(base, mode="lockdir")


# ---- item 1: the hooks and the MCP server work when the data folder is read-only ----


def test_hooks_block_a_read_of_the_original_under_boxed_run(session):
    hooks = session.report["hooks"]
    assert hooks["read_original"]["code"] == 2
    assert hooks["read_original"]["stderr"].startswith("boxed: Read blocked")
    assert hooks["bash_original"]["code"] == 2


def test_hooks_let_the_work_in_the_copy_through_under_boxed_run(session):
    hooks = session.report["hooks"]
    assert (hooks["read_copy"]["code"], hooks["read_copy"]["stdout"], hooks["read_copy"]["stderr"]) == (0, "", "")
    assert hooks["session_start"]["code"] == 0 and "masked workspace" in hooks["session_start"]["stdout"]
    assert (hooks["prompt_clean"]["code"], hooks["prompt_clean"]["stderr"]) == (0, "")


def test_a_prompt_with_an_email_is_blocked_and_journaled_under_boxed_run(session):
    prompt = session.report["hooks"]["prompt_email"]
    assert prompt["code"] == 2
    assert prompt["stderr"].startswith("boxed: prompt blocked, it contains EMAIL 1.")
    assert "ivan.petrov" not in prompt["stderr"]
    blocked = [r for r in session.journal() if r["channel"] == "claude-code"]
    assert [(r["status"], r["markers_by_kind"], r["note"]) for r in blocked] == [("blocked", {"EMAIL": 1}, "UserPromptSubmit")]


def test_the_mcp_server_starts_under_boxed_run(session):
    mcp = session.report["mcp"]
    assert mcp["code"] == 0, mcp["stderr"]
    assert mcp["initialized"] and mcp["tools"] == ["read_masked", "search_masked"]


def test_the_mcp_tools_say_in_one_sentence_that_they_are_not_available_under_boxed_run_yet(session):
    """The known limit: a tool call must save the placeholders it hands out, and the profile keeps vault.db (and its lock file)
    read-only, so the call is refused, with nothing of the log, and no crash is logged. A broker outside the sandbox is the fix."""
    mcp = session.report["mcp"]
    assert session.report["sandboxed"] is True
    assert mcp["call"]["result"]["isError"] is True
    assert mcp["call"]["result"]["content"][0]["text"] == "Error executing tool read_masked: not available inside boxed run yet"
    assert "ivan.petrov" not in json.dumps(mcp["call"])
    assert "Traceback" not in mcp["stderr"] and len(mcp["stderr"]) < 1000  # it used to be about 50 KB of traceback


# ---- item 2: a hook that fails blocks inside a copy and is silent outside one ----


def test_a_hook_that_cannot_open_the_data_folder_blocks_in_the_copy_under_boxed_run(session):
    """The case that let every call through: the data folder cannot be opened, so the hook cannot read its state."""
    hook = session.report["hooks"]["no_folder_in_copy"]
    assert (hook["code"], hook["stdout"], hook["stderr"]) == (2, "", HOOK_FAILED + "\n")


def test_a_hook_that_cannot_open_the_data_folder_says_nothing_outside_a_copy_under_boxed_run(session):
    hook = session.report["hooks"]["no_folder_elsewhere"]
    assert (hook["code"], hook["stdout"], hook["stderr"]) == (0, "", "")


# ---- the ways out that the system offers: nothing may be started, or typed, outside the sandbox ----

OUT_OF_REACH = [
    "com.apple.windowserver.active",  # the window server takes the keystrokes and the screen of every program of the person
    "com.apple.backgroundtaskmanagement",  # login items and background tasks: an app that starts at the next login
    "com.apple.backgroundtaskmanagement.registrar",
    "com.apple.backgroundtaskmanagementagent",
    "com.apple.xpc.loginitemregisterd",
    "com.apple.coreservices.sharedfilelistd.xpc",
    "com.apple.siri.VoiceShortcuts.xpc",  # the shortcuts of the person, which run outside the sandbox
    "com.apple.authd",  # a request for the password of the person (osascript: do shell script with administrator privileges)
]


def test_open_does_not_start_an_app_outside_the_sandbox(session):
    """A known escape: an app of five lines, started with `open -g -j`, ran outside the sandbox, wrote where the profile
    allows no write and copied the original .env to a folder that the sandbox reads."""
    app = session.report["escapes"]["open x.app"]
    assert app["rc"] != 0
    assert app["ran outside the sandbox"] is False
    assert app["original .env read back"] is None


@pytest.mark.parametrize("operation", ["lsopen", "appleevent-send", "user-preference-write"])
def test_the_profile_denies_what_starts_something_for_a_caller_outside_it(session, operation):
    """lsopen: open, NSWorkspace, URL schemes. appleevent-send: osascript to Terminal, System Events or Finder. user-preference-write:
    defaults write, which makes the daemon of the preferences write the settings of the person, a Terminal profile that runs a command
    among them."""
    answer = session.report["escapes"]["sandbox_check"][operation]
    if answer is None:
        pytest.skip("this system has no sandbox_check")
    assert answer == 1


@pytest.mark.parametrize("service", OUT_OF_REACH)
def test_a_service_that_starts_or_types_for_a_caller_is_out_of_reach(session, service):
    assert session.report["escapes"]["mach-lookup"][service] != "reachable"


def test_the_sandbox_cannot_post_input_events_into_the_session(session):
    assert session.report["escapes"]["input events posted"] is False


def test_the_socket_of_a_container_runtime_is_refused(session):
    """Whatever talks to the Docker daemon starts containers that mount the folders of the person: outside the sandbox, and as root there."""
    assert session.report["escapes"]["docker socket"].startswith("refused")


def test_launchctl_cannot_submit_a_job(session):
    launchctl = session.report["escapes"]["launchctl submit"]
    assert launchctl["rc"] != 0 and launchctl["ran outside the sandbox"] is False


def test_the_sandbox_cannot_type_into_its_terminal(session):
    """boxed run shares the terminal of the person's shell with the agent. TIOCSTI puts characters into its input: the shell reads and runs
    them as soon as the agent ends."""
    profile = session.home / "state" / f"{session.mirror.name.removeprefix('ws-')}.sb"
    pty = str(SUPPORT / "on_a_pty.py")
    done = subprocess.run(
        [sys.executable, pty, "sandbox-exec", "-f", str(profile), sys.executable, pty, "--probe"],
        cwd=session.mirror, env=session.env, capture_output=True, text=True, timeout=120,
    )
    found = re.search(r"RESULT (\{.*\})", done.stdout)
    assert found, done.stdout + done.stderr
    outcome = ast.literal_eval(found.group(1))
    assert outcome["typed"] is False and outcome["read back"] == ""


# ---- item 3: the agent cannot change what it, boxed or the person's tools run later ----

DENIED_WRITES = [
    "append ~/.local/share/uv/tools/boxedsi/code.py",  # boxed's own code, when it is installed with uv
    "create ~/.local/share/uv/tools/boxedsi/extra.py",
    "create ~/.local/bin/boxed",
    "append ~/.claude.json",  # the MCP servers of Claude Code
    "create ~/.claude.json.tmp",
    "append ~/.codex/AGENTS.md",
    "create ~/.codex/hooks.json",
    "create ~/.codex/rules/default.rules",
    "create ~/.claude/settings.json",
    "create ~/.claude/rules/x.md",  # loaded like CLAUDE.md
    "create ~/.claude/output-styles/x.md",
    "create ~/.claude/workflows/w.js",
    "create ~/.claude/local/claude",  # the launcher of an npm install of Claude Code
    "create ~/.codex/AGENTS.override.md",  # Codex reads it instead of AGENTS.md
    "create ~/.codex/skills/x/SKILL.md",  # an unsandboxed Codex loads these
    "create ~/.codex/plugins/x",
    "create ~/.codex/agents/x.toml",
    "append ~/.cache/uv/archive-v0/abc/pkg/__init__.py",  # a wheel that the next uv run of boxed would use
    "create ~/.cache/p10k-instant-prompt.zsh",  # a script that the shell of a prompt theme sources
    "create ~/.cache/tool/cache.bin",
    "create copy/.claude/settings.json",
    "create copy/.claude/commands/evil.md",
    "append copy/.claude/settings.local.json",
    "remove copy/.claude/settings.local.json",
    "create copy/.mcp.json",
    "append copy/.boxed-workspace",
    "rename copy/.claude",
    "move away copy",
    "move away ~/.claude",
    "move away ~/.codex",
]
ALLOWED_WRITES = [
    "create copy/notes.txt",
    "append copy/app.py",
    "rename copy/notes.txt",
    "remove copy/notes-renamed.txt",
    "create copy/src/new/file.txt",
    "create ~/.claude/projects/session.jsonl",
    "create ~/.codex/sessions/rollout.jsonl",
    "create XDG_CACHE_HOME/tool/cache.bin",  # the cache folders that boxed run gives the agent in place of ~/.cache
    "create UV_CACHE_DIR/tool/cache.bin",
    "create a temporary file",
]


def test_the_agent_reports_every_write_the_test_expects(session):
    assert set(session.report["writes"]) == set(DENIED_WRITES) | set(ALLOWED_WRITES)


@pytest.mark.parametrize("label", DENIED_WRITES)
def test_a_write_that_would_change_the_agent_or_boxed_is_refused(label, session):
    assert session.report["writes"][label] == "EPERM"


@pytest.mark.parametrize("label", ALLOWED_WRITES)
def test_the_writes_the_agent_needs_for_its_work_still_work(label, session):
    assert session.report["writes"][label] == "allowed"


def test_the_caches_of_the_agent_are_not_the_caches_of_the_person(session):
    """~/.cache is read-only for the agent, so uv and the other tools that follow XDG are told another place, one folder for the copy."""
    cache = session.report["cache_env"]
    assert cache["XDG_CACHE_HOME"] and cache["UV_CACHE_DIR"]
    for folder in cache.values():
        assert not Path(folder).resolve().is_relative_to((session.user / ".cache").resolve())
        assert session.mirror.name.removeprefix("ws-") in folder


def test_what_the_agent_tried_to_change_is_as_it_was(session):
    tools = session.user / ".local" / "share" / "uv" / "tools" / "boxedsi"
    assert (tools / "code.py").read_text() == "print('boxed')\n" and not (tools / "extra.py").exists()
    assert not (session.user / ".local" / "bin" / "boxed").exists()
    assert (session.user / ".claude.json").read_text() == '{"projects": {}}\n' and not (session.user / ".claude.json.tmp").exists()
    assert (session.user / ".codex" / "AGENTS.md").read_text() == "be careful\n"
    for name in ("hooks.json", "rules", "AGENTS.override.md", "skills", "plugins", "agents"):
        assert not (session.user / ".codex" / name).exists(), name
    for name in ("settings.json", "rules", "output-styles", "workflows", "local"):
        assert not (session.user / ".claude" / name).exists(), name
    assert (session.user / ".cache" / "uv" / "archive-v0" / "abc" / "pkg" / "__init__.py").read_text() == "x = 1\n"
    assert sorted(path.name for path in (session.user / ".cache").iterdir()) == ["uv"]
    assert not (session.mirror / ".mcp.json").exists() and not (session.mirror / ".claude-old").exists()
    assert sorted(path.name for path in (session.mirror / ".claude").iterdir()) == ["settings.local.json"]
    for name, content in session.before.items():
        assert (session.mirror / name).read_bytes() == content


# ---- the profile as text: the policy it writes, checked everywhere (the sandbox itself is checked above, on macOS) ----


@dataclass
class Folders:
    user: Path
    home: Path
    original: Path
    mirror: Path


@pytest.fixture
def folders(tmp_path, monkeypatch):
    base = tmp_path.resolve()
    monkeypatch.setenv("HOME", str(base / "user"))  # the profile names the folders of the person's home
    return Folders(base / "user", base / "boxed-home", base / "project", base / "boxed-home" / "workspaces" / "ws-1")


def profile_lines(folders: Folders) -> list[str]:
    from boxed.run import sandbox_profile

    return sandbox_profile(folders.mirror, folders.original, folders.home).splitlines()


def entries(line: str) -> set[tuple[str, str]]:
    """The (kind, path) filters of a rule: literal for one path, subpath for a folder and all below it."""
    return set(re.findall(r'\((literal|subpath) "([^"]*)"\)', line))


def allowed_writes(folders: Folders) -> str:
    """The rule that lists where an agent may write: a write anywhere else is denied."""
    return next(line for line in profile_lines(folders) if line.startswith("(deny file-write* (require-not"))


def test_an_agent_may_write_only_where_its_work_and_its_own_state_need_it(folders):
    clause = allowed_writes(folders)
    assert {path for kind, path in entries(clause)} == {
        str(folders.mirror),
        f"{folders.home}/journal.jsonl",
        f"{folders.home}/journal.jsonl.lock",  # the hooks and the MCP server append to the journal under this lock
        "/private/tmp",
        "/private/var/folders",
        "/dev",
        f"{folders.user}/.claude",
        f"{folders.user}/.codex",
        f"{folders.user}/Library/Caches",
    }
    assert "(regex" not in clause  # so ~/.claude.json and its temporary files are not writable, and neither is ~/.local


def test_the_settings_hooks_and_instructions_of_the_agents_are_read_only(folders):
    state = f'(deny file-write* (subpath "{folders.home}/state")'
    read_only = set()
    for line in profile_lines(folders):
        if line.startswith("(deny file-write* ") and not line.startswith(("(deny file-write* (require-not", state)):
            read_only |= entries(line)
    user, mirror = folders.user, folders.mirror
    assert {("literal", f"{user}/.claude/{name}") for name in ("settings.json", "settings.local.json", "CLAUDE.md")} <= read_only
    assert {("literal", f"{user}/.codex/{name}") for name in ("config.toml", "AGENTS.md", "AGENTS.override.md", "hooks.json")} <= read_only
    assert {("subpath", f"{user}/.claude/{name}") for name in ("agents", "commands", "skills", "hooks", "plugins", "rules", "output-styles", "workflows", "local")} <= read_only
    assert {("subpath", f"{user}/.codex/{name}") for name in ("rules", "prompts", "skills", "plugins", "agents")} <= read_only
    assert {("literal", f"{mirror}/.mcp.json"), ("literal", f"{mirror}/.boxed-workspace"), ("subpath", f"{mirror}/.claude")} <= read_only


def test_the_folders_that_hold_those_files_cannot_be_moved_away(folders):
    (rule,) = [line for line in profile_lines(folders) if line.startswith("(deny file-write-unlink")]
    assert entries(rule) == {("literal", str(folders.mirror)), ("literal", f"{folders.user}/.claude"), ("literal", f"{folders.user}/.codex")}


def test_the_profile_closes_the_ways_out(folders):
    lines = profile_lines(folders)
    for rule in ("(deny lsopen)", "(deny appleevent-send)", "(deny user-preference-write)", "(deny file-ioctl (ioctl-command TIOCSTI))"):
        assert rule in lines
    (mach,) = [line for line in lines if line.startswith("(deny mach-lookup")]
    assert '(global-name "com.apple.windowserver.active")' in mach and '(global-name-prefix "com.apple.backgroundtaskmanagement")' in mach
    assert '(global-name "com.apple.authd")' in mach
    (sockets,) = [line for line in lines if line.startswith("(deny network-outbound")]
    assert "docker" in sockets and "unix-socket" in sockets


def test_the_cache_folder_of_the_agent_is_private_and_one_for_each_copy(tmp_path, monkeypatch):
    from boxed.run import cache_env

    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    env = cache_env("ab12cd34")
    folder = Path(env["XDG_CACHE_HOME"])
    assert folder == tmp_path / "boxed-cache-ab12cd34" and stat.S_IMODE(folder.stat().st_mode) == 0o700
    assert env["UV_CACHE_DIR"] == str(folder / "uv")
    assert cache_env("ab12cd34") == env  # again: the same folder, no error


def test_dropping_a_copy_takes_its_cache_folder_away(tmp_path, monkeypatch):
    from boxed.config import ProjectConfig
    from boxed.journal import Journal
    from boxed.keys import InsecureFileKeyStore
    from boxed.run import cache_env
    from boxed.vault import Vault
    from boxed.workspace import create_workspace, drop_workspace

    (tmp_path / "temporary").mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path / "temporary"))
    project, home = tmp_path / "project", tmp_path / "home"
    project.mkdir()
    home.mkdir()
    (project / "a.txt").write_text("x\n")
    keys = InsecureFileKeyStore(tmp_path / "keys")
    vault = Vault(home / "vault.db", keys)
    ws = create_workspace(project, level=2, config=ProjectConfig(), vault=vault, journal=Journal(home / "journal.jsonl", keys), home=home).workspace
    folder = Path(cache_env(ws.id)["XDG_CACHE_HOME"])
    (folder / "uv").mkdir()
    (folder / "uv" / "wheel").write_text("w")
    drop_workspace(ws.id, vault=vault, home=home)
    assert not folder.exists()


def test_the_agent_gets_the_cache_variables_in_place_of_the_ones_of_the_person(tmp_path, monkeypatch, folders):
    import boxed.run as run

    (folders.home / "state").mkdir(parents=True)
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    monkeypatch.setenv("UV_CACHE_DIR", "/Users/someone/.cache/uv")  # the real cache of the person
    monkeypatch.setattr(run, "find_workspace", lambda cwd, home: SimpleNamespace(id="ab12cd34", mirror=folders.mirror, original=folders.original))
    monkeypatch.setattr(run.shutil, "which", lambda name: "/bin/agent")
    seen = {}
    monkeypatch.setattr(run.subprocess, "call", lambda cmd, **kwargs: seen.update(kwargs) or 0)
    assert run.run_agent("claude", [], cwd=folders.mirror, home=folders.home) == 0
    assert seen["env"]["XDG_CACHE_HOME"] == str(tmp_path / "boxed-cache-ab12cd34")
    assert seen["env"]["UV_CACHE_DIR"] == str(tmp_path / "boxed-cache-ab12cd34" / "uv")
    assert seen["env"]["HOME"] == os.environ["HOME"]  # the rest of the environment goes through as it was


# ---- the hooks of a copy made without boxed on the PATH are `python -I -m boxed.cli`: a stub package in the copy does not replace boxed ----


def test_a_stub_package_in_the_copy_does_not_take_the_place_of_boxed_in_a_hook(stub_session):
    settings = json.loads((stub_session.mirror / ".claude" / "settings.local.json").read_text())
    command = settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    assert command.endswith(" -I -m boxed.cli hook pre-tool-use")
    stub = stub_session.report["stub"]
    assert stub["stub ran"] is False
    assert stub["hook"]["code"] == 2 and stub["hook"]["stderr"].startswith("boxed: Read blocked")


# ---- the locks: a process of the sandbox holds them, or puts a folder in place of the lock of the journal ----

# a boxed command with a wait of one second for a lock instead of 30
SHORT_WAIT = "import sys; import boxed.locks as locks; locks.LOCK_TIMEOUT = 1.0; from boxed.cli import main; sys.exit(main(sys.argv[1:]))"
LOCK_BUSY = "boxed: error: another process holds a lock of boxed for too long; try again, or stop that process"


def short_wait(session, *args, stdin="", cwd=None, sandbox=False):
    command = [sys.executable, "-c", SHORT_WAIT, *args]
    if sandbox:  # inside the sandbox, as a hook of the agent is
        command = ["sandbox-exec", "-f", str(session.home / "state" / f"{session.mirror.name.removeprefix('ws-')}.sb"), *command]
    return subprocess.run(command, input=stdin, cwd=cwd or session.base, env=session.env, capture_output=True, text=True, timeout=60)


def test_a_process_of_the_sandbox_holds_the_lock_files_through_descriptors_that_cannot_write(lockhold_session):
    assert lockhold_session.report["lockhold"]["holder started"] is True


def test_boxed_mask_gives_up_on_a_lock_that_a_process_of_the_sandbox_holds(lockhold_session):
    done = short_wait(lockhold_session, "mask", "-", stdin="mail ivan@acme.com")
    assert (done.returncode, done.stdout, done.stderr) == (2, "", LOCK_BUSY + "\n")


def test_the_prompt_hook_in_the_sandbox_gives_up_and_blocks_on_a_lock_that_a_process_of_it_holds(lockhold_session):
    s = lockhold_session
    prompt = json.dumps({"hook_event_name": "UserPromptSubmit", "cwd": str(s.mirror), "prompt": "mail ivan.petrov@acme.com"})
    done = short_wait(s, "hook", "user-prompt-submit", stdin=prompt, cwd=s.mirror, sandbox=True)
    assert (done.returncode, done.stdout, done.stderr) == (2, "", HOOK_FAILED + "\n")


def test_sync_gives_up_on_a_lock_that_a_process_of_the_sandbox_holds_and_writes_nothing(lockhold_session):
    s = lockhold_session
    (s.mirror / "app.py").write_text("print('hi')\n# edited by the agent\n")
    before = len(s.journal())
    done = short_wait(s, "workspace", "sync", s.mirror.name.removeprefix("ws-"))
    assert done.returncode == 2 and "another boxed process holds the journal; nothing was synced" in done.stderr
    assert (s.original / "app.py").read_text() == "print('hi')\n" and len(s.journal()) == before


def test_sync_stops_before_it_writes_when_the_agent_put_a_folder_in_place_of_the_journal_lock(lockdir_session):
    """A known failure: the sync changed the original, stopped on the journal, and left no record of what it had done."""
    s = lockdir_session
    lock = s.home / "journal.jsonl.lock"
    if not lock.is_dir():  # the sandbox did not let the stand-in do it: the state is made here, and sync is still tried on it
        lock.unlink(missing_ok=True)
        lock.mkdir()
    before = len(s.journal())
    done = subprocess.run(
        [sys.executable, "-m", "boxed.cli", "workspace", "sync", s.mirror.name.removeprefix("ws-")], env=s.env, cwd=s.base, capture_output=True, text=True, timeout=60
    )
    assert done.returncode == 2 and done.stderr == "boxed: error: boxed cannot write its journal, so nothing was synced\n"
    assert (s.original / "app.py").read_text() == "print('hi')\n" and len(s.journal()) == before
