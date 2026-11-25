"""A stand-in for Claude Code, started by the sandbox tests under `boxed run`. It does to a masked copy what the real agent does:
it runs the hooks named in the copy's settings the way Claude Code runs them (a shell command, the hook's JSON on stdin), starts
`boxed mcp`, tries writes outside the copy and tries the ways out of the sandbox that the system offers. AGENT_MODE picks what it does:
"main" is all of that, the others are one attack each ("stub", "lockhold", "lockdir"). It prints one line, REPORT <json>, which the test
reads. Paths come from the environment of the test."""

import ctypes
import errno
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

MODE = os.environ.get("AGENT_MODE", "main")
MIRROR = Path.cwd()
USER = Path(os.environ["HOME"])
ORIGINAL = Path(os.environ["AGENT_ORIGINAL"])
ELSEWHERE = Path(os.environ["AGENT_ELSEWHERE"])
MISSING_HOME = os.environ["AGENT_MISSING_HOME"]
LOG = os.environ["AGENT_LOG"]
SETTINGS = json.loads((MIRROR / ".claude" / "settings.local.json").read_text())
# a path in the made-up home, where the sandbox cannot write: what is written there ran outside it
ESCAPED = USER / "ESCAPED"


def hook(event: str, tool: str | None = None, cwd: Path = MIRROR, **extra) -> dict:
    """One hook the way Claude Code starts it. `extra` is the tool input, or the prompt, and `env` changes the environment."""
    env = extra.pop("env", {})
    payload = {"hook_event_name": event, "cwd": str(cwd)}
    if tool:
        payload |= {"tool_name": tool, "tool_input": extra}
    else:
        payload |= extra
    command = SETTINGS["hooks"][event][0]["hooks"][0]["command"]
    done = subprocess.run(
        command, shell=True, input=json.dumps(payload), capture_output=True, text=True, cwd=cwd, env={**os.environ, **env}, timeout=120
    )
    return {"code": done.returncode, "stdout": done.stdout, "stderr": done.stderr}


def mcp() -> dict:
    """boxed mcp over stdio, as a client talks to it: the handshake, the tool list and one tool call, each after the reply to the
    one before. Closing the input early would end the server before it answers a call."""
    with tempfile.TemporaryFile("w+") as errors:
        server = subprocess.Popen(
            [sys.executable, "-m", "boxed.cli", "mcp"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors, text=True
        )
        watchdog = threading.Timer(120, server.kill)  # a server that never answers must not hang the test
        watchdog.start()

        def ask(message: dict) -> dict | None:
            server.stdin.write(json.dumps(message) + "\n")
            server.stdin.flush()
            while "id" in message:
                line = server.stdout.readline()
                if not line:
                    return None  # the server ended without an answer
                try:
                    reply = json.loads(line)
                except ValueError:
                    continue
                if reply.get("id") == message["id"]:
                    return reply
            return None

        try:
            init = ask({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "stand-in", "version": "0"}}})
            tools = call = None
            if init:
                ask({"jsonrpc": "2.0", "method": "notifications/initialized"})
                tools = ask({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
                call = ask({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "read_masked", "arguments": {"path": LOG}}})
            server.stdin.close()
            code = server.wait(timeout=60)
        finally:
            watchdog.cancel()
            server.kill()
        errors.seek(0)
        return {
            "code": code,
            "initialized": bool(init and "result" in init),
            "tools": sorted(tool["name"] for tool in ((tools or {}).get("result") or {}).get("tools", [])),
            "call": call,
            "stderr": errors.read()[-2000:],
        }


def append(path: Path) -> None:
    with open(path, "a") as f:
        f.write("changed by the agent\n")


def create(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("made by the agent\n")


def remove(path: Path) -> None:
    path.unlink()


def rename(path: Path, target: Path) -> None:
    os.rename(path, target)


def rename_and_back(path: Path, target: Path) -> None:
    """A move out of its place; when it works, the way back, so that the probes after it find everything where it was."""
    os.rename(path, target)
    os.rename(target, path)


def writes() -> dict:
    """What the agent can write: each label says what it tried, the value is "allowed" or the name of the error."""
    done = {}

    def attempt(label: str, operation, *args) -> None:
        try:
            operation(*args)
            done[label] = "allowed"
        except OSError as e:
            done[label] = errno.errorcode.get(e.errno, str(e.errno))

    tools = USER / ".local" / "share" / "uv" / "tools" / "boxedsi"
    away = Path(tempfile.mkdtemp())  # a folder the sandbox lets the agent write to
    try:
        # what changes what the agent does later, or what runs as the person
        attempt("append ~/.local/share/uv/tools/boxedsi/code.py", append, tools / "code.py")
        attempt("create ~/.local/share/uv/tools/boxedsi/extra.py", create, tools / "extra.py")
        attempt("create ~/.local/bin/boxed", create, USER / ".local" / "bin" / "boxed")
        attempt("append ~/.claude.json", append, USER / ".claude.json")
        attempt("create ~/.claude.json.tmp", create, USER / ".claude.json.tmp")
        attempt("append ~/.codex/AGENTS.md", append, USER / ".codex" / "AGENTS.md")
        attempt("create ~/.codex/hooks.json", create, USER / ".codex" / "hooks.json")
        attempt("create ~/.codex/rules/default.rules", create, USER / ".codex" / "rules" / "default.rules")
        attempt("create ~/.claude/settings.json", create, USER / ".claude" / "settings.json")
        # instructions, styles, workflows and a launcher that a later Claude Code or Codex session loads or runs outside the sandbox
        attempt("create ~/.claude/rules/x.md", create, USER / ".claude" / "rules" / "x.md")
        attempt("create ~/.claude/output-styles/x.md", create, USER / ".claude" / "output-styles" / "x.md")
        attempt("create ~/.claude/workflows/w.js", create, USER / ".claude" / "workflows" / "w.js")
        attempt("create ~/.claude/local/claude", create, USER / ".claude" / "local" / "claude")
        attempt("create ~/.codex/AGENTS.override.md", create, USER / ".codex" / "AGENTS.override.md")
        attempt("create ~/.codex/skills/x/SKILL.md", create, USER / ".codex" / "skills" / "x" / "SKILL.md")
        attempt("create ~/.codex/plugins/x", create, USER / ".codex" / "plugins" / "x")
        attempt("create ~/.codex/agents/x.toml", create, USER / ".codex" / "agents" / "x.toml")
        # caches that the next command of the person runs code from: the wheels of uv, the script a prompt of zsh sources
        attempt("append ~/.cache/uv/archive-v0/abc/pkg/__init__.py", append, USER / ".cache" / "uv" / "archive-v0" / "abc" / "pkg" / "__init__.py")
        attempt("create ~/.cache/p10k-instant-prompt.zsh", create, USER / ".cache" / "p10k-instant-prompt.zsh")
        attempt("create ~/.cache/tool/cache.bin", create, USER / ".cache" / "tool" / "cache.bin")
        attempt("create copy/.claude/settings.json", create, MIRROR / ".claude" / "settings.json")
        attempt("create copy/.claude/commands/evil.md", create, MIRROR / ".claude" / "commands" / "evil.md")
        attempt("append copy/.claude/settings.local.json", append, MIRROR / ".claude" / "settings.local.json")
        attempt("remove copy/.claude/settings.local.json", remove, MIRROR / ".claude" / "settings.local.json")
        attempt("create copy/.mcp.json", create, MIRROR / ".mcp.json")
        attempt("append copy/.boxed-workspace", append, MIRROR / ".boxed-workspace")
        attempt("rename copy/.claude", rename_and_back, MIRROR / ".claude", MIRROR / ".claude-old")
        # a folder that holds those cannot be moved away, changed and moved back
        attempt("move away copy", rename_and_back, MIRROR, away / "copy")
        attempt("move away ~/.claude", rename_and_back, USER / ".claude", away / "claude")
        attempt("move away ~/.codex", rename_and_back, USER / ".codex", away / "codex")
        # what the agent needs to do its work
        attempt("create copy/notes.txt", create, MIRROR / "notes.txt")
        attempt("append copy/app.py", append, MIRROR / "app.py")
        attempt("rename copy/notes.txt", rename, MIRROR / "notes.txt", MIRROR / "notes-renamed.txt")
        attempt("remove copy/notes-renamed.txt", remove, MIRROR / "notes-renamed.txt")
        attempt("create copy/src/new/file.txt", create, MIRROR / "src" / "new" / "file.txt")
        attempt("create ~/.claude/projects/session.jsonl", create, USER / ".claude" / "projects" / "session.jsonl")
        attempt("create ~/.codex/sessions/rollout.jsonl", create, USER / ".codex" / "sessions" / "rollout.jsonl")
        # the cache folders that boxed run gives the agent in place of ~/.cache
        for variable in ("XDG_CACHE_HOME", "UV_CACHE_DIR"):
            if os.environ.get(variable):
                attempt(f"create {variable}/tool/cache.bin", create, Path(os.environ[variable]) / "tool" / "cache.bin")
            else:
                done[f"create {variable}/tool/cache.bin"] = "not set"
        attempt("create a temporary file", create, away / "temporary.txt")
    finally:
        shutil.rmtree(away, ignore_errors=True)
    return done


INFO_PLIST = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<plist version="1.0"><dict><key>CFBundleExecutable</key><string>x</string><key>CFBundleIdentifier</key><string>test.boxed.escape</string>'
    "<key>CFBundleName</key><string>x</string><key>CFBundlePackageType</key><string>APPL</string><key>LSUIElement</key><true/></dict></plist>\n"
)
# the services of the system that start something, or take input, for a caller outside the sandbox
SERVICES = (
    "com.apple.windowserver.active",
    "com.apple.backgroundtaskmanagement",
    "com.apple.backgroundtaskmanagement.registrar",
    "com.apple.backgroundtaskmanagementagent",
    "com.apple.xpc.loginitemregisterd",
    "com.apple.coreservices.sharedfilelistd.xpc",
    "com.apple.siri.VoiceShortcuts.xpc",
    "com.apple.authd",
)


def sandbox_check(operation: str) -> int | None:
    """What the profile says to an operation with no path or name: 0 allows it, 1 denies it. None where the system has no such call."""
    try:
        library = ctypes.CDLL("/usr/lib/libsandbox.1.dylib")
        library.sandbox_check.restype = ctypes.c_int
        return int(library.sandbox_check(os.getpid(), operation.encode(), 0))
    except (OSError, AttributeError):
        return None


def mach_lookup(name: str) -> str:
    """Can the process reach the service of this name? That is what asking it to do something needs."""
    system = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    system.bootstrap_look_up.argtypes = [ctypes.c_uint, ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint)]
    system.bootstrap_look_up.restype = ctypes.c_int
    port = ctypes.c_uint(0)
    answer = system.bootstrap_look_up(ctypes.c_uint.in_dll(system, "bootstrap_port").value, name.encode(), ctypes.byref(port))
    return {0: "reachable", 1102: "no such service"}.get(answer, f"refused ({answer})")


def input_events_posted(count: int = 100) -> bool:
    """Does a burst of mouse-moved events at the place the pointer already is reach the session? Nothing on the screen changes. The
    session counts the events; a process that may talk to the window server types into any program of the person, a terminal too."""

    class Point(ctypes.Structure):
        _fields_ = [("x", ctypes.c_double), ("y", ctypes.c_double)]

    graphics = ctypes.CDLL("/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics")
    graphics.CGEventCreate.restype = ctypes.c_void_p
    graphics.CGEventCreate.argtypes = [ctypes.c_void_p]
    graphics.CGEventGetLocation.restype = Point
    graphics.CGEventGetLocation.argtypes = [ctypes.c_void_p]
    graphics.CGEventCreateMouseEvent.restype = ctypes.c_void_p
    graphics.CGEventCreateMouseEvent.argtypes = [ctypes.c_void_p, ctypes.c_uint32, Point, ctypes.c_uint32]
    graphics.CGEventPost.argtypes = [ctypes.c_uint32, ctypes.c_void_p]
    graphics.CGEventSourceCounterForEventType.restype = ctypes.c_uint32
    graphics.CGEventSourceCounterForEventType.argtypes = [ctypes.c_int32, ctypes.c_uint32]
    mouse_moved = 5
    before = graphics.CGEventSourceCounterForEventType(0, mouse_moved)
    here = graphics.CGEventGetLocation(graphics.CGEventCreate(None))
    for _ in range(count):
        graphics.CGEventPost(0, graphics.CGEventCreateMouseEvent(None, mouse_moved, here, 0))
    time.sleep(0.5)
    return graphics.CGEventSourceCounterForEventType(0, mouse_moved) - before >= count


def escapes() -> dict:
    """The ways out of the sandbox that the system offers: each tries to get something run, or typed, outside it."""
    out = {}
    # LaunchServices: an app of five lines, started with open. It writes where the sandbox cannot and copies the original .env to a
    # folder the sandbox can read.
    loot = Path(tempfile.mkdtemp()) / "env"
    app = MIRROR / "x.app"
    (app / "Contents" / "MacOS").mkdir(parents=True)
    (app / "Contents" / "Info.plist").write_text(INFO_PLIST)
    program = app / "Contents" / "MacOS" / "x"
    program.write_text(f"#!/bin/sh\necho escaped > '{ESCAPED}'\ncp '{ORIGINAL / '.env'}' '{loot}'\n")
    program.chmod(0o755)
    opened = subprocess.run(["open", "-g", "-j", str(app)], capture_output=True, text=True, timeout=60)
    for _ in range(40 if opened.returncode == 0 else 0):  # something may be starting: it gets its time
        if ESCAPED.exists() and loot.exists():
            break
        time.sleep(0.25)
    out["open x.app"] = {
        "rc": opened.returncode,
        "ran outside the sandbox": ESCAPED.exists(),
        "original .env read back": loot.read_text() if loot.exists() else None,
    }
    out["sandbox_check"] = {name: sandbox_check(name) for name in ("lsopen", "appleevent-send", "user-preference-write")}
    out["mach-lookup"] = {name: mach_lookup(name) for name in SERVICES}
    out["input events posted"] = input_events_posted()
    # the socket of a container runtime: the test listens on one of that name, and anything that can talk to it is as good as root
    try:
        with socket.socket(socket.AF_UNIX) as client:
            client.settimeout(5)
            client.connect(os.environ["AGENT_DOCKER_SOCKET"])
            client.sendall(b"ping")
            out["docker socket"] = "answered " + client.recv(10).decode()
    except OSError as e:
        out["docker socket"] = f"refused ({errno.errorcode.get(e.errno, e.errno)})"
    # launchd: refused already, and kept so
    label = f"boxed.test.{os.getpid()}"
    submitted = subprocess.run(
        ["launchctl", "submit", "-l", label, "--", "/usr/bin/touch", str(USER / "ESCAPED-launchctl")], capture_output=True, text=True, timeout=60
    )
    if submitted.returncode == 0:
        time.sleep(2)
    subprocess.run(["launchctl", "remove", label], capture_output=True, text=True, timeout=60)
    out["launchctl submit"] = {"rc": submitted.returncode, "ran outside the sandbox": (USER / "ESCAPED-launchctl").exists()}
    return out


def stub() -> dict:
    """The agent puts a package named boxed into the copy, and the next hook runs from there, as Claude Code starts it."""
    marker = MIRROR / "stub-ran"
    (MIRROR / "boxed").mkdir()
    (MIRROR / "boxed" / "__init__.py").write_text("")
    (MIRROR / "boxed" / "cli.py").write_text(f"import sys\nopen({str(marker)!r}, 'w').write('the stub ran')\nsys.exit(0)\n")
    return {"hook": hook("PreToolUse", "Read", file_path=str(ORIGINAL / ".env")), "stub ran": marker.exists()}


def hold_the_locks() -> dict:
    """A process that outlives the agent, still inside the sandbox, holds the lock files of boxed through descriptors that cannot write:
    flock asks for no right to write."""
    home = Path(os.environ["BOXED_HOME"])
    holder = (
        "import fcntl, os, sys, time\n"
        "fds = [os.open(p, os.O_RDONLY) for p in sys.argv[2:]]\n"
        "[fcntl.flock(fd, fcntl.LOCK_EX) for fd in fds]\n"
        "open(sys.argv[1], 'w').write(str(os.getpid()))\n"
        "end = time.time() + 300\n"
        "while time.time() < end and os.path.exists(sys.argv[3]):\n"
        "    time.sleep(0.5)\n"
    )
    pid_file = MIRROR / "holder.pid"  # the copy is the one place the agent may write to that the test can read
    locks = [home / "journal.jsonl.lock", home / "vault.db.lock"]
    subprocess.Popen(
        [sys.executable, "-c", holder, str(pid_file), *map(str, locks)], start_new_session=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    for _ in range(40):
        if pid_file.exists() and pid_file.read_text():
            break
        time.sleep(0.25)
    started = pid_file.exists() and bool(pid_file.read_text())
    return {"holder started": started, "pid": int(pid_file.read_text()) if started else None}


def replace_the_journal_lock() -> dict:
    """The agent takes the lock file of the journal away and puts a folder in its place, then changes a file of the copy."""
    lock = Path(os.environ["BOXED_HOME"]) / "journal.jsonl.lock"
    steps = {}
    for label, operation in (("remove the lock file", lambda: lock.unlink()), ("make a folder in its place", lambda: lock.mkdir())):
        try:
            operation()
            steps[label] = "allowed"
        except OSError as e:
            steps[label] = errno.errorcode.get(e.errno, str(e.errno))
    with open(MIRROR / "app.py", "a") as f:
        f.write("# edited by the agent\n")
    return steps


def main() -> None:
    if MODE == "stub":
        print("REPORT " + json.dumps({"stub": stub()}))
        return
    if MODE == "lockhold":
        print("REPORT " + json.dumps({"lockhold": hold_the_locks()}))
        return
    if MODE == "lockdir":
        print("REPORT " + json.dumps({"lockdir": replace_the_journal_lock()}))
        return
    report = {"hooks": {}}
    hooks = report["hooks"]
    hooks["read_original"] = hook("PreToolUse", "Read", file_path=str(ORIGINAL / ".env"))
    hooks["bash_original"] = hook("PreToolUse", "Bash", command=f"cat {ORIGINAL}/.env")
    hooks["read_copy"] = hook("PreToolUse", "Read", file_path=str(MIRROR / "app.py"))
    hooks["session_start"] = hook("SessionStart")
    hooks["prompt_clean"] = hook("UserPromptSubmit", prompt="hello")
    hooks["prompt_email"] = hook("UserPromptSubmit", prompt="mail ivan.petrov@acme.com")
    # a hook that cannot open the boxed folder: inside a copy it blocks, anywhere else it says nothing
    hooks["no_folder_in_copy"] = hook("PreToolUse", "Read", file_path=str(ORIGINAL / ".env"), env={"BOXED_HOME": MISSING_HOME})
    hooks["no_folder_elsewhere"] = hook("PreToolUse", "Read", cwd=ELSEWHERE, file_path=str(ORIGINAL / ".env"), env={"BOXED_HOME": MISSING_HOME})
    report["mcp"] = mcp()
    from boxed.platform import sandboxed

    report["sandboxed"] = sandboxed()
    report["writes"] = writes()
    report["cache_env"] = {name: os.environ.get(name) for name in ("XDG_CACHE_HOME", "UV_CACHE_DIR")}
    report["escapes"] = escapes()
    print("REPORT " + json.dumps(report))


main()
