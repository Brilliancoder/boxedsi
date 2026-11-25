"""Run Claude Code or Codex inside a masked workspace under the macOS sandbox."""

import json
import os
import shutil
import subprocess
import sys
from collections.abc import Iterable, Mapping
from pathlib import Path

from .errors import UserError
from .hooks import find_workspace
from .platform import refuse_on_windows
from .workspace import SENSITIVE_HOME_PARTS, cache_folder


def sbpl_string(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def sandbox_profile(mirror: Path, original: Path, home: Path) -> str:
    """Everything allowed except: any access to the original project and boxed secrets, and writes outside the mirror, the temp
    folders and the agents' own state folders. Inside those, no write that changes what an agent, boxed or the person's tools run in
    a later session: the settings, hooks and instructions of the agents, the copy's .claude folder and .mcp.json, and the folders
    that hold them (a folder that can be moved away can be changed and moved back)."""
    h, o, m = home.resolve(), original.resolve(), mirror.resolve()
    user = Path.home().resolve()
    # vault.db stays reachable: the MCP server runs inside the sandbox, the vault is encrypted with a keychain key
    secret_parts = [h / part for part in SENSITIVE_HOME_PARTS if part not in ("journal.jsonl", "state", "vault.db")]
    denied = [f"(subpath {sbpl_string(str(o))})"] + [
        f"({'literal' if p.suffix else 'subpath'} {sbpl_string(str(p))})" for p in secret_parts
    ]
    # journal.jsonl.lock: the hooks and the MCP server append to the journal under a lock, which is a file next to it.
    # Not ~/.local (uv keeps the code of boxed there, and the person's later commands run it), not ~/.claude.json (it holds the MCP
    # servers that Claude Code starts) and not ~/.cache (the wheels that the next uv run unpacks, scripts that a shell sources):
    # code written there would run outside the sandbox. run_agent gives the agent a cache folder of its own.
    writable = [m, h / "journal.jsonl", h / "journal.jsonl.lock", Path("/private/tmp"), Path("/private/var/folders"), Path("/dev")]
    writable += [user / ".claude", user / ".codex", user / "Library" / "Caches"]
    allowed_writes = " ".join(f"(subpath {sbpl_string(str(p))})" for p in writable)
    # files and folders that change what agents do in later, unsandboxed sessions, and the mirror's own guard files
    agent_config = [user / ".claude" / name for name in ("settings.json", "settings.local.json", "CLAUDE.md")]
    agent_config += [user / ".codex" / name for name in ("config.toml", "AGENTS.md", "AGENTS.override.md", "hooks.json")]
    agent_config += [m / ".mcp.json", m / ".boxed-workspace"]
    agent_dirs = [user / ".claude" / name for name in ("agents", "commands", "skills", "hooks", "plugins", "rules", "output-styles", "workflows", "local")]
    agent_dirs += [user / ".codex" / name for name in ("rules", "prompts", "skills", "plugins", "agents")]
    agent_dirs += [m / ".claude"]
    read_only = " ".join([f"(literal {sbpl_string(str(p))})" for p in agent_config] + [f"(subpath {sbpl_string(str(p))})" for p in agent_dirs])
    # the folders that hold the files above are writable themselves: they must not be renamed or removed, or moved away and back
    in_place = " ".join(f"(literal {sbpl_string(str(p))})" for p in (m, user / ".claude", user / ".codex"))
    # The ways out. In each, the system starts something for the caller, or types for it, outside the sandbox and none of these rules:
    # LaunchServices opens an app (`open -g -j x.app` ran the five lines of a script the agent wrote), an Apple Event tells another
    # program what to do (osascript to Terminal), the preferences daemon writes the settings of the person (a Terminal profile that runs
    # a command), TIOCSTI puts characters into the terminal whose input the shell of the person reads when the agent ends, the window
    # server takes keystrokes, login items and background tasks start an app at the next login, Shortcuts runs the shortcuts of the
    # person, the authorization daemon asks the person for a password and runs a command as root (osascript: do shell script with
    # administrator privileges), and the socket of a container runtime starts containers that mount the folders of the person.
    # launchctl and the setuid tools (sudo, su, crontab, at) are refused by the system already.
    no_way_out = [
        "(deny lsopen)",
        "(deny appleevent-send)",
        "(deny user-preference-write)",
        "(deny file-ioctl (ioctl-command TIOCSTI))",
        '(deny mach-lookup (global-name "com.apple.windowserver.active") (global-name-prefix "com.apple.backgroundtaskmanagement")'
        ' (global-name "com.apple.xpc.loginitemregisterd") (global-name "com.apple.coreservices.sharedfilelistd.xpc")'
        ' (global-name "com.apple.siri.VoiceShortcuts.xpc") (global-name "com.apple.authd"))',
        r'(deny network-outbound (remote unix-socket (path-regex #"(docker|containerd|podman[^/]*)\.sock$")))',
    ]
    return "\n".join(
        [
            "(version 1)",
            "(allow default)",
            f"(deny file-read* file-write* {' '.join(denied)})",
            f"(deny file-write* (subpath {sbpl_string(str(h / 'state'))}))",
            f"(deny file-write* (require-not (require-any {allowed_writes})))",
            f"(deny file-write* {read_only})",
            f"(deny file-write-unlink {in_place})",
            *no_way_out,
        ]
    ) + "\n"


def build_agent_command(agent: str, args: list[str], profile: Path, agent_path: str) -> list[str]:
    cmd = ["sandbox-exec", "-f", str(profile), agent_path]
    if agent == "claude":
        cmd += ["--settings", json.dumps({"sandbox": {"enabled": False}})]  # the OS sandbox replaces Claude's own
    elif agent == "codex":
        cmd += ["--dangerously-bypass-approvals-and-sandbox"]  # macOS cannot nest sandboxes; ours is the outer one
    else:
        raise ValueError(f"unknown agent {agent!r}")
    return cmd + args


def cache_env(ws_id: str) -> dict[str, str]:
    """~/.cache is read-only for the agent, so uv and the other tools that follow XDG are told a folder of their own, one for each copy,
    in the temporary folder of the person (the profile lets the agent write there). Whatever UV_CACHE_DIR said is replaced: it would
    name a place the sandbox does not let the agent write to, or the real cache."""
    folder = cache_folder(ws_id)
    folder.mkdir(mode=0o700, exist_ok=True)
    return {"XDG_CACHE_HOME": str(folder), "UV_CACHE_DIR": str(folder / "uv")}


# The variables an agent signs in with, by agent: they reach it even when they look like credentials, or it could not start. The agent
# and every process it starts (a test, a script in the copy) can read them.
AGENT_KEYS = {
    "claude": ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN"),
    "codex": ("OPENAI_API_KEY", "CODEX_API_KEY"),
}
# Kept whatever their name or value: the working directory, and the proxies the agent needs to reach its provider (a proxy may carry
# a password of its own).
ALWAYS_KEPT = frozenset(
    {"PWD", "OLDPWD"} | {name for base in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY") for name in (base, base.lower())}
)
_CREDENTIAL_KINDS = frozenset({"SECRET", "PRIVATE_KEY", "JWT"})
NOT_ON_PATH = {agent: f"{agent} not found on PATH" for agent in AGENT_KEYS}


def agent_env(agent: str, environ: Mapping[str, str], keep: Iterable[str] = ()) -> tuple[dict[str, str], list[str]]:
    """The environment for the agent and the names of the variables taken out of it. Out goes what looks like a credential: a name
    with a word of credentials in it (KEY, TOKEN, SECRET, PASSWORD, AUTH, ...) or a value in which the detectors of boxed find a
    secret, a private key or a JWT. The agent's own sign-in variables (AGENT_KEYS), the ones named with --keep-env and ALWAYS_KEPT
    stay; so does everything else, PATH, HOME and the locale among them."""
    from .detect import detect
    from .detect.patterns import names_a_credential

    kept = ALWAYS_KEPT | set(AGENT_KEYS[agent]) | set(keep)
    env, removed = {}, []
    for name, value in environ.items():
        if name not in kept and (
            names_a_credential(name) or any(d.kind in _CREDENTIAL_KINDS for d in detect(value, level=0, ner=[]))
        ):
            removed.append(name)
        else:
            env[name] = value
    return env, sorted(removed)


def run_agent(agent: str, args: list[str], cwd: Path, home: Path, keep_env: Iterable[str] = ()) -> int:
    refuse_on_windows("run")
    ws = find_workspace(cwd, home)
    if ws is None:
        raise UserError("run this inside a boxed workspace (boxed workspace create <project>)")
    agent_path = shutil.which(agent)
    if not agent_path:
        raise UserError(NOT_ON_PATH[agent])
    profile = home / "state" / f"{ws.id}.sb"
    profile.write_text(sandbox_profile(ws.mirror, ws.original, home))
    profile.chmod(0o600)
    env, removed = agent_env(agent, os.environ, keep_env)
    if removed:  # names only, never a value
        print(f"boxed: kept out of the agent's environment: {', '.join(removed)} (--keep-env NAME passes one)", file=sys.stderr)
    return subprocess.call(build_agent_command(agent, args, profile, agent_path), cwd=ws.mirror, env={**env, **cache_env(ws.id)})
