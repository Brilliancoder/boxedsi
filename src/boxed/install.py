"""Wire boxed into Claude Code (plugin marketplace), Codex (MCP server in config.toml) and Chrome or Edge (native host)."""

import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path, PurePath, PureWindowsPath

from . import platform as plat
from .errors import UserError, one_of
from .native_host import HOST_NAME
from .paths import boxed_home_path
from .platform import open_nofollow

EXTENSION_ID_RE = re.compile(r"[a-p]{32}")
# where each browser looks for native messaging hosts, below the user's home (macOS)
HOST_DIRS = {
    "chrome": Path("Library/Application Support/Google/Chrome/NativeMessagingHosts"),
    "edge": Path("Library/Application Support/Microsoft Edge/NativeMessagingHosts"),
}
# on Windows both browsers look in the registry of the user (HKCU): the default value of this key, plus the host name, is the path of the manifest
WINDOWS_KEYS = {
    "chrome": r"Software\Google\Chrome\NativeMessagingHosts",
    "edge": r"Software\Microsoft\Edge\NativeMessagingHosts",
}
LAUNCHER_CMD = "boxed-native-host.cmd"
NATIVE_HOST_NOT_HERE = "boxed install native-host works on macos and windows only"


def refuse_native_host_here() -> None:
    """Linux browsers look in other folders (and snap or flatpak ones in others again), not tried with a real browser yet: refused
    before anything is written, rather than a manifest in the folders of macOS that no browser reads."""
    if not (plat.IS_WINDOWS or plat.IS_MACOS):
        raise UserError(NATIVE_HOST_NOT_HERE)


def _mcp_command() -> tuple[str, list[str]]:
    """Without boxed on the PATH, Python with -I (see workspace.boxed_command): the server starts in the folder of the copy too."""
    exe = shutil.which("boxed")
    return (exe, ["mcp"]) if exe else (sys.executable, ["-I", "-m", "boxed.cli", "mcp"])


def marketplace_dir() -> Path:
    """The plugin marketplace: packaged inside the wheel, or the repository root in a source checkout."""
    packaged = Path(__file__).resolve().parent / "_claude_plugin"
    if (packaged / ".claude-plugin" / "marketplace.json").is_file():
        return packaged
    repo = Path(__file__).resolve().parents[2]
    if (repo / ".claude-plugin" / "marketplace.json").is_file():
        return repo
    raise UserError("boxed plugin files not found; reinstall boxedsi")


def install_claude(repo: Path, dry_run: bool) -> list[str]:
    commands = [f"claude plugin marketplace add {shlex.quote(str(repo))}", "claude plugin install boxed@boxed"]
    if not dry_run:
        for command in commands:
            subprocess.run(shlex.split(command), check=True)
    return commands


def install_codex(config_path: Path, dry_run: bool = False) -> bool:
    """Add [mcp_servers.boxed] to Codex config. Returns False if it is already there. Keeps a .bak copy.
    A dry run checks everything and returns what a real run would, but writes nothing: no folder, no copy, no config.
    The config is UTF-8 whatever the code page of the system is."""
    text = config_path.read_text(encoding="utf-8") if config_path.exists() else ""
    if "boxed" in (tomllib.loads(text).get("mcp_servers") or {}):
        return False
    command, args = _mcp_command()
    block = f"[mcp_servers.boxed]\ncommand = {json.dumps(command)}\nargs = {json.dumps(args)}\n"
    new = text.rstrip("\n") + "\n\n" + block if text else block
    tomllib.loads(new)  # never write a config Codex cannot parse
    if dry_run:
        return True
    if text:
        shutil.copy2(config_path, config_path.with_name(config_path.name + ".bak"))
    else:
        config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(new, encoding="utf-8")
    return True


def _write_new(path: Path, text: str, mode: int, newline: str | None = None) -> None:
    """Write through a fresh file and rename it into place: a symlink planted at `path` is replaced, never followed. The file is UTF-8,
    and each line feed becomes `newline` (None: what the system uses)."""
    part = path.with_name(path.name + ".part")
    part.unlink(missing_ok=True)
    fd = open_nofollow(part, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, "w", encoding="utf-8", newline=newline) as f:
        f.write(text)
    os.replace(part, path)


def _launcher_text() -> str:
    """The browser starts the host without our environment, so a custom BOXED_HOME is carried over here."""
    lines = ["#!/bin/sh"]
    if os.environ.get("BOXED_HOME"):
        lines.append(f"export BOXED_HOME={shlex.quote(str(boxed_home_path()))}")
    lines.append(f'exec {shlex.quote(sys.executable)} -P -m boxed.native_host "$@"')  # -P: never import from the cwd
    return "\n".join(lines) + "\n"


def _cmd_launcher_text() -> str:
    """The same launcher for Windows, a .cmd file. It is UTF-8, and `chcp 65001` comes first, so that a path with letters outside the
    code page of the system (a user named Иван) is read as it is written; a % in a path is doubled, because it starts a variable in a
    .cmd file. A frozen program has no -m: its own command starts the host, and the arguments the browser adds are left out."""

    def quote(text: str) -> str:
        return text.replace("%", "%%")

    lines = ["@echo off", "chcp 65001 >nul"]
    if os.environ.get("BOXED_HOME"):
        lines.append(f'set "BOXED_HOME={quote(str(boxed_home_path()))}"')
    if getattr(sys, "frozen", False):
        lines.append(f'"{quote(sys.executable)}" native-host')
    else:
        lines.append(f'"{quote(sys.executable)}" -P -m boxed.native_host %*')  # -P: never import from the cwd
    return "\n".join(lines) + "\n"


def extension_dir() -> Path:
    """The browser extension to load unpacked: packaged inside the wheel, or extension/ in a source checkout."""
    packaged = Path(__file__).resolve().parent / "_extension"
    if (packaged / "manifest.json").is_file():
        return packaged
    return Path(__file__).resolve().parents[2] / "extension"


def _manifest(launcher: Path, extension_id: str) -> dict:
    return {
        "name": HOST_NAME,
        "description": "boxed.si: masks text on this computer for the browser side panel",
        "path": str(launcher),
        "type": "stdio",
        "allowed_origins": [f"chrome-extension://{extension_id}/"],
    }


def _registry_key(browser: str) -> str:
    return rf"{WINDOWS_KEYS[browser]}\{HOST_NAME}"


def _shown_key(browser: str) -> PurePath:
    """The key as a person reads it, for the lines boxed prints. Only the registry of the user (HKCU) is ever touched."""
    return PureWindowsPath("HKCU\\" + _registry_key(browser))


def _windows_host_folder(home: Path | None) -> Path:
    """Where the manifest and the launcher live on Windows: %LOCALAPPDATA%\\boxed\\native-host, below `home` when one is given."""
    local = Path(home).absolute() / "AppData" / "Local" if home else Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    return local / "boxed" / "native-host"


def install_native_host(
    extension_id: str, *, browsers: tuple[str, ...] = ("chrome", "edge"), dry_run: bool = False, home: Path | None = None
) -> list[PurePath]:
    """Register the native messaging host for the extension. Returns what was written: the manifests, one per browser (macOS), or the
    one manifest and then the registry key of each browser (Windows).

    macOS: the manifest points at <home>/.boxed/bin/boxed-native-host, a launcher that runs this Python. Windows: both browsers read
    the path of one manifest from HKCU\\Software\\<vendor>\\<browser>\\NativeMessagingHosts\\si.boxed.host, and it points at
    %LOCALAPPDATA%\\boxed\\native-host\\boxed-native-host.cmd.
    """
    refuse_native_host_here()
    if not isinstance(extension_id, str) or not EXTENSION_ID_RE.fullmatch(extension_id):
        raise UserError("the extension id is 32 letters from a to p: copy it from the extensions page of the browser")
    if any(b not in HOST_DIRS for b in browsers):
        raise UserError(f"unknown browser; choose from {one_of(HOST_DIRS)}")
    if plat.IS_WINDOWS:
        folder = _windows_host_folder(home)
        manifest, launcher = folder / f"{HOST_NAME}.json", folder / LAUNCHER_CMD
        shown = [_shown_key(b) for b in browsers]
        if dry_run:
            return [manifest, *shown]
        import winreg

        folder.mkdir(parents=True, exist_ok=True)
        _write_new(launcher, _cmd_launcher_text(), 0o700, newline="\r\n")
        _write_new(manifest, json.dumps(_manifest(launcher, extension_id), indent=2) + "\n", 0o644)
        for browser in browsers:
            winreg.SetValue(winreg.HKEY_CURRENT_USER, _registry_key(browser), winreg.REG_SZ, str(manifest))
        return [manifest, *shown]
    home = (Path(home) if home else Path.home()).absolute()
    launcher = home / ".boxed" / "bin" / "boxed-native-host"
    manifests = [home / HOST_DIRS[b] / f"{HOST_NAME}.json" for b in browsers]
    if dry_run:
        return manifests
    launcher.parent.parent.mkdir(mode=0o700, parents=True, exist_ok=True)  # the data folder, as boxed_home() makes it
    launcher.parent.mkdir(mode=0o700, exist_ok=True)
    _write_new(launcher, _launcher_text(), 0o700)
    for path in manifests:
        path.parent.mkdir(parents=True, exist_ok=True)
        _write_new(path, json.dumps(_manifest(launcher, extension_id), indent=2) + "\n", 0o644)
    return manifests


def _is_link(path: Path) -> bool:
    return path.is_symlink() or os.path.isjunction(path)


def _delete_key_and_empty_parents(winreg, sub_key: str) -> None:
    """Delete the key, then each key above it that is left with no subkey and no value, up to but not including the first one below
    HKEY_CURRENT_USER (`Software`). SetValue made all of them, and DeleteKey takes away only the last: a browser that has no other
    host would keep Software\\Google\\Chrome\\NativeMessagingHosts for good. A key above that something else uses is not empty."""
    winreg.DeleteKey(winreg.HKEY_CURRENT_USER, sub_key)
    parent = sub_key.rpartition("\\")[0]
    try:
        while "\\" in parent:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, parent) as key:
                subkeys, values, _ = winreg.QueryInfoKey(key)
            if subkeys or values:
                return
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, parent)
            parent = parent.rpartition("\\")[0]
    except OSError:  # something put a key there at this moment, or took it away: what was asked for is done
        return


def remove_native_host(*, dry_run: bool = False, home: Path | None = None) -> list[PurePath]:
    """Take the registration of install_native_host away: the manifests and the launcher (macOS), or the registry keys and the folder
    of the manifest (Windows). Only what boxed made: a folder with anything else in it stays, and so does the data folder. Returns
    what was removed, or would be with dry_run; nothing when nothing was installed."""
    refuse_native_host_here()
    found: list[PurePath] = []
    if plat.IS_WINDOWS:
        import winreg

        for browser in WINDOWS_KEYS:
            try:
                winreg.QueryValue(winreg.HKEY_CURRENT_USER, _registry_key(browser))
            except FileNotFoundError:
                continue
            found.append(_shown_key(browser))
            if not dry_run:
                _delete_key_and_empty_parents(winreg, _registry_key(browser))
        folder = _windows_host_folder(home)
        if folder.is_dir() and not _is_link(folder):
            ours = {f"{HOST_NAME}.json", LAUNCHER_CMD}
            ours |= {name + ".part" for name in ours}  # what an install that was interrupted leaves
            if {entry.name for entry in folder.iterdir()} <= ours:
                found.append(folder)
            if not dry_run:
                for entry in list(folder.iterdir()):  # a list: the folder changes while it is walked
                    if entry.name in ours:
                        entry.unlink()
                try:
                    folder.rmdir()
                    folder.parent.rmdir()  # %LOCALAPPDATA%\\boxed, when nothing else of boxed is in it
                except OSError:
                    pass
        return found
    home = (Path(home) if home else Path.home()).absolute()
    launcher = home / ".boxed" / "bin" / "boxed-native-host"
    found = [path for path in [*(home / HOST_DIRS[b] / f"{HOST_NAME}.json" for b in HOST_DIRS), launcher] if os.path.lexists(path)]
    if not dry_run:
        for path in found:
            path.unlink()
        try:
            launcher.parent.rmdir()  # the bin folder, when it is empty; the data folder around it is not ours to delete
        except OSError:
            pass
    return found
